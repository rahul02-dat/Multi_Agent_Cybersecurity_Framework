#!/usr/bin/env python3
"""
agent_orchestrator.py
=====================
Phase 3: Autonomous Multi-Agent Threat Intelligence System
----------------------------------------------------------
Async Producer–Consumer Orchestration Layer
  producer_task   : Reads LOG_FILE line-by-line, triages each record with
                    WatchdogAgent (O(1)), and pushes flagged items onto a
                    bounded asyncio.Queue.
  worker_task     : Pool of NUM_WORKERS coroutines.  Each pulls from the
                    queue and offloads ThreatAnalystAgent.analyze() — a
                    blocking requests.post() call — to a ThreadPoolExecutor
                    via asyncio.to_thread(), keeping the event loop free for
                    sibling workers during every LLM round-trip.
  async_main      : Wires the queue, worker pool, and producer together;
                    drains the queue with queue.join(); tears down workers
                    gracefully on completion or interruption.
  main            : Synchronous entry point.  Owns the try/except/finally
                    that guarantees _print_summary() is always printed,
                    regardless of how the async pipeline terminates.

Phase 2 agents (WatchdogAgent, ThreatAnalystAgent) and all UI/banner helpers
are preserved verbatim per the Phase 3 upgrade constraints.

Why agents are instantiated in main(), not async_main()
-------------------------------------------------------
asyncio.run() can be interrupted by KeyboardInterrupt in a way that bypasses
the running coroutine's exception handlers on Python < 3.11.  Keeping
watchdog, analyst, and counters in the synchronous scope of main() means the
finally block can always read their final state and print the summary,
regardless of where the async code was cut short.

Data Contract  (each JSONL line must carry these keys)
  source_dataset, timestamp, protocol, flow_duration (microseconds),
  source_port, destination_port, bytes_per_second,
  packets_per_second, ground_truth_label

Usage
  python3 agent_orchestrator.py

Requirements
  Python  3.9+  (3.11+ recommended for reliable Ctrl-C async delivery)
  pip     install requests          (only non-stdlib dependency)
  Ollama  running locally:          ollama serve
  Model   pulled:                   ollama pull qwen3-coder:latest
"""

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime

import requests


# =============================================================================
#  ANSI Colour Palette
#  All styling goes through this namespace so disabling colour is trivial:
#  simply null-out the values below (or set env var NO_COLOR=1).
# =============================================================================

class C:
    """Terminal ANSI escape codes.  Use C.R to reset all styling."""
    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    R   = "\033[0m"   if _enabled else ""   # Reset
    B   = "\033[1m"   if _enabled else ""   # Bold
    D   = "\033[2m"   if _enabled else ""   # Dim
    RED = "\033[91m"  if _enabled else ""
    GRN = "\033[92m"  if _enabled else ""
    YLW = "\033[93m"  if _enabled else ""
    CYN = "\033[96m"  if _enabled else ""
    WHT = "\033[97m"  if _enabled else ""
    MAG = "\033[95m"  if _enabled else ""
    BLU = "\033[94m"  if _enabled else ""


# =============================================================================
#  Configuration  (edit these constants to match your environment)
# =============================================================================

LOG_FILE       = "/Users/rahulmac/Documents/Projects/projects/cyberML/unified_network_logs.jsonl"
OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_MODEL   = "."   # choose your model (e.g. qwen3-coder:latest, deepseek-r1:8b, etc.)
OLLAMA_TIMEOUT = 120           # seconds — raise on slow hardware / large models

PROGRESS_EVERY = 1_000         # print a heartbeat every N records

# ── Phase 3: Async orchestration constants ────────────────────────────────────
NUM_WORKERS:   int = 3       # Consumer worker coroutines in the pool
QUEUE_MAXSIZE: int = 1_000   # asyncio.Queue capacity — acts as backpressure valve:
                              # once full, queue.put() suspends the producer until
                              # a worker drains a slot, capping in-flight memory.
YIELD_EVERY:   int = 500     # Yield event-loop control every N raw file lines in
                              # producer_task so workers are scheduled concurrently
                              # with file reading (see producer_task docstring).

# ── Watchdog thresholds ──────────────────────────────────────────────────────
PPS_THRESHOLD   = 1_000                 # packets/second  (Rule 1)
SAFE_PORTS      = frozenset({80, 443, 22, 53})  # excluded from Rule 1
TUNNEL_DURATION = 100_000_000           # microseconds -> 100 s  (Rule 2)
TUNNEL_PORT     = 443
TUNNEL_PROTO    = "TCP"


# =============================================================================
#  Agent 1 — WatchdogAgent
# =============================================================================

class WatchdogAgent:
    """
    Lightweight, deterministic triage engine (Agent 1).

    Designed to handle tens of millions of log records with sub-microsecond
    overhead per record.  Only records that match a heuristic rule are
    escalated to the expensive LLM agent, keeping the overall system
    efficient and cost-free even on large datasets.

    Rules implemented
    -----------------
    Rule 1  Volumetric Anomaly
        Flag when packets_per_second > 1 000 AND destination_port is NOT one
        of the standard web/admin ports (80, 443, 22, 53).
        Rationale: legitimate traffic to non-standard ports rarely sustains
        >1 000 pps.  Matches DDoS amplification, UDP floods, brute-force
        scanners, and botnet beaconing on high/odd ports.

    Rule 2  Long-Lived TLS / DNS-over-HTTPS (DoH) Tunneling
        Flag when protocol == "TCP" AND destination_port == 443 AND
        flow_duration > 100 000 000 µs (100 seconds).
        Rationale: legitimate HTTPS connections rarely persist as a single
        continuous flow for >100 s.  Matches malware C2 channels and data
        exfiltration disguised as DNS-over-HTTPS.
    """

    def __init__(self) -> None:
        self.rule1_hits: int = 0   # volumetric-anomaly counter
        self.rule2_hits: int = 0   # TLS/DoH-tunnel counter

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, log: dict) -> "tuple[bool, str]":
        """
        Evaluate a single log record against every heuristic rule.

        Parameters
        ----------
        log : dict
            Parsed JSON object from one JSONL line.

        Returns
        -------
        (flagged, rule_description)
            flagged           True when at least one rule fires.
            rule_description  Short human-readable diagnostic string, or ''
                              when no rule fires.
        """
        # ── Safe field extraction with type coercion ──────────────────────
        try:
            pps      = float(log.get("packets_per_second", 0))
            dst_port = int(log.get("destination_port",     0))
            protocol = str(log.get("protocol",             "")).strip().upper()
            duration = float(log.get("flow_duration",      0))
        except (ValueError, TypeError) as exc:
            # Malformed record — warn but never halt the stream
            _warn(f"WatchdogAgent: field cast error on record: {exc}")
            return False, ""

        # ── Rule 1: Volumetric Anomaly ────────────────────────────────────
        if pps > PPS_THRESHOLD and dst_port not in SAFE_PORTS:
            self.rule1_hits += 1
            return True, (
                f"[RULE-1  VOLUMETRIC ANOMALY] "
                f"packets_per_second={pps:,.1f} > {PPS_THRESHOLD:,} | "
                f"destination_port={dst_port} (non-standard port)"
            )

        # ── Rule 2: Long-Lived TLS / DoH Tunneling ────────────────────────
        if (protocol == TUNNEL_PROTO
                and dst_port == TUNNEL_PORT
                and duration > TUNNEL_DURATION):
            self.rule2_hits += 1
            seconds = duration / 1_000_000
            return True, (
                f"[RULE-2  TLS/DoH TUNNEL] "
                f"TCP:443 | flow_duration={seconds:,.1f}s "
                f"(threshold={TUNNEL_DURATION // 1_000_000}s)"
            )

        return False, ""


# =============================================================================
#  Agent 2 — ThreatAnalystAgent
# =============================================================================

class ThreatAnalystAgent:
    """
    LLM-backed deep-analysis agent (Agent 2).

    Communicates exclusively with a locally hosted Ollama instance — fully
    air-gapped, zero external API calls, zero data exfiltration.

    For every record escalated by WatchdogAgent it:
      1. Builds a structured SOC-analyst prompt embedding the raw log payload.
      2. POSTs to the Ollama /api/generate endpoint (stream=False for atomic
         responses).
      3. Strips Qwen3 chain-of-thought <think> traces from the reply.
      4. Renders a colour-coded Intelligence Report to the terminal.
    """

    def __init__(
        self,
        api_url: str = OLLAMA_URL,
        model:   str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
    ) -> None:
        self.api_url             = api_url
        self.model               = model
        self.timeout             = timeout
        self.reports_generated: int = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, log: dict, rule_desc: str = "") -> str:
        """
        Request a threat-analysis report from the local LLM.

        The prompt instructs the model to:
          • In 2 sentences identify the probable threat, citing specific
            log fields (ports, duration, byte/packet rates, protocol).
          • In 1 sentence recommend the single most effective mitigation.

        Parameters
        ----------
        log       : dict   The flagged log record from WatchdogAgent.
        rule_desc : str    The triggered-rule description for context.

        Returns
        -------
        str  LLM analysis text, or a formatted error message on failure.
        """
        payload = {
            "model":  self.model,
            "prompt": self._build_prompt(log, rule_desc),
            # stream=False  ->  Ollama blocks until the full response is ready
            # and returns one JSON object (avoids NDJSON stream parsing).
            "stream": False,
            "options": {
                "temperature": 0.2,   # Low variance -> consistent, factual output
                "num_predict": 380,   # Budget for 2-sentence + 1-sentence reply
            },
        }

        try:
            resp = requests.post(
                self.api_url,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()

            # Ollama /api/generate response schema (stream=False):
            # { "model": "...", "response": "<full text>", "done": true, ... }
            raw_text = resp.json().get("response", "").strip()

            if not raw_text:
                return "(LLM returned an empty response — check model health)"

            # Qwen3 models may emit <think>…</think> chain-of-thought blocks;
            # strip them so only the final answer reaches the report.
            analysis = _strip_thinking(raw_text)
            self.reports_generated += 1
            return analysis

        # ── Graceful error handling (never crash the pipeline) ────────────
        except requests.exceptions.ConnectionError:
            return (
                f"{C.RED}[ThreatAnalystAgent] CONNECTION REFUSED - "
                f"Ollama is not reachable at {self.api_url}. "
                f"Start the server with: ollama serve{C.R}"
            )
        except requests.exceptions.Timeout:
            return (
                f"{C.RED}[ThreatAnalystAgent] REQUEST TIMED OUT after "
                f"{self.timeout}s.  Raise OLLAMA_TIMEOUT or use a "
                f"smaller / quantised model.{C.R}"
            )
        except requests.exceptions.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            return f"{C.RED}[ThreatAnalystAgent] HTTP {code}: {exc}{C.R}"
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            return f"{C.RED}[ThreatAnalystAgent] Response parse error: {exc}{C.R}"

    def print_report(
        self,
        log:      dict,
        rule:     str,
        analysis: str,
        line_no:  int,
    ) -> None:
        """
        Render a colour-coded Intelligence Report block to stdout.

        Visual hierarchy (ANSI colours):
          Yellow / bold  ->  Report header & separators  (high-urgency framing)
          Cyan           ->  Field labels & analysis text (informational)
          Magenta        ->  Triggered rule               (alert classification)
          White          ->  Raw field values             (neutral data)
        """
        W   = 72
        fat = "=" * W     # thick separator (report header / footer)
        mid = "-" * W     # thin separator  (section dividers)

        # Pull display fields with safe fallbacks
        ts    = log.get("timestamp",          "N/A")
        src   = log.get("source_dataset",     "N/A")
        proto = log.get("protocol",           "N/A")
        sport = log.get("source_port",        "N/A")
        dport = log.get("destination_port",   "N/A")
        bps   = log.get("bytes_per_second",   "N/A")
        pps   = log.get("packets_per_second", "N/A")
        dur   = log.get("flow_duration",      "N/A")
        label = log.get("ground_truth_label", "N/A")

        # ── Header ────────────────────────────────────────────────────────
        print(f"\n{C.YLW}{C.B}{fat}{C.R}")
        print(
            f"{C.YLW}{C.B}  [!!] INTELLIGENCE REPORT #{self.reports_generated}"
            f"   |  stream line {line_no:,}{C.R}"
        )
        print(f"{C.YLW}{mid}{C.R}")

        # ── Log metadata ──────────────────────────────────────────────────
        print(f"{C.CYN}  Timestamp          {C.WHT}{ts}{C.R}")
        print(f"{C.CYN}  Source Dataset     {C.WHT}{src}{C.R}")
        print(f"{C.CYN}  Protocol           {C.WHT}{proto}{C.R}")
        print(f"{C.CYN}  Src Port           {C.WHT}{sport}{C.R}")
        print(f"{C.CYN}  Dst Port           {C.WHT}{dport}{C.R}")
        print(f"{C.CYN}  Bytes / sec        {C.WHT}{bps}{C.R}")
        print(f"{C.CYN}  Packets / sec      {C.WHT}{pps}{C.R}")
        print(f"{C.CYN}  Flow Duration (us) {C.WHT}{dur}{C.R}")
        print(f"{C.CYN}  Ground Truth       {C.WHT}{label}{C.R}")
        print(f"{C.CYN}  Alert Rule         {C.MAG}{rule}{C.R}")

        # ── LLM analysis body ─────────────────────────────────────────────
        print(f"{C.YLW}{mid}{C.R}")
        print(f"{C.CYN}{C.B}  LLM THREAT ANALYSIS  >>  {self.model}{C.R}")
        print(f"{C.YLW}{mid}{C.R}")
        for line in analysis.splitlines():
            print(f"{C.CYN}  {line}{C.R}")
        print(f"{C.YLW}{C.B}{fat}{C.R}\n")

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_prompt(self, log: dict, rule_desc: str) -> str:
        """
        Craft a structured SOC-analyst prompt embedding the raw log payload.

        Design choices:
          • Role priming ("You are an expert Cybersecurity Analyst…") improves
            domain-specific accuracy on instruct-tuned models.
          • json.dumps(default=str) ensures non-serialisable values (e.g.
            numpy types from upstream pipeline) never crash the prompt build.
          • Explicit output format ("2 sentences … 1 sentence") constrains
            the reply length and prevents verbose boilerplate.
        """
        log_json = json.dumps(log, indent=2, default=str)
        return (
            "You are an expert Cybersecurity Analyst operating in a live SOC "
            "(Security Operations Center).\n"
            "A real-time SIEM engine has escalated the following network flow "
            "record for your immediate analysis.\n\n"
            f"TRIGGERED ALERT RULE:\n{rule_desc}\n\n"
            f"RAW NETWORK FLOW LOG:\n```json\n{log_json}\n```\n\n"
            "Respond with ONLY the sections below — no preamble, no repetition "
            "of raw values verbatim:\n\n"
            "THREAT ANALYSIS: In exactly 2 sentences, identify the most probable "
            "threat this flow represents. Reference specific field values "
            "(destination_port, flow_duration, bytes_per_second, "
            "packets_per_second, protocol) in your reasoning.\n\n"
            "MITIGATION: In exactly 1 sentence, state the single most effective "
            "immediate action a network defender should take right now.\n\n"
            "Be technical, precise, and actionable."
        )


# =============================================================================
#  Utility Functions
# =============================================================================

def _strip_thinking(text: str) -> str:
    """
    Remove Qwen3 chain-of-thought <think>...</think> blocks from LLM output.

    Qwen3 instruct and coder models sometimes include internal reasoning
    traces wrapped in <think> tags before the final answer.  These traces
    are useful for debugging the model but clutter the terminal report.
    This regex is non-greedy and DOTALL so it handles multi-line blocks.
    """
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    return cleaned.strip()


def _warn(msg: str) -> None:
    """Non-blocking dim-yellow warning to stderr — never interrupts stdout."""
    print(f"{C.YLW}{C.D}  [W]  {msg}{C.R}", file=sys.stderr, flush=True)


def _build_banner() -> str:
    """
    Dynamically construct a box-drawing startup banner.

    Width is computed once so every row has exactly the same inner length,
    guaranteeing the ║ borders align regardless of content.
    """
    W     = 76      # total width including border glyphs
    inner = W - 2   # usable interior characters per row

    def row(text: str = "") -> str:
        """Pad text to exactly `inner` characters and wrap in box borders."""
        pad = inner - len(text)
        if pad < 0:
            text = text[: inner - 3] + "..."   # hard-truncate overlong lines
            pad = 0
        return f"\u2551{text}{' ' * pad}\u2551"

    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    src = os.path.basename(LOG_FILE)

    return "\n".join([
        f"\u2554{'=' * inner}\u2557",
        row("  AUTONOMOUS MULTI-AGENT THREAT INTELLIGENCE SYSTEM"),
        row("  Phase 2  -  Real-Time SIEM Orchestrator"),
        f"\u2560{'=' * inner}\u2563",
        row(f"  Agent 1  ->  WatchdogAgent       (Python heuristics)"),
        row(f"  Agent 2  ->  ThreatAnalystAgent  (Ollama / {OLLAMA_MODEL})"),
        row(f"  Source   ->  {src}"),
        row(f"  Started  ->  {now}"),
        f"\u255a{'=' * inner}\u255d",
    ])


def _print_summary(
    total:   int,
    flagged: int,
    watch:   WatchdogAgent,
    analyst: ThreatAnalystAgent,
    elapsed: float,
    errors:  int,
) -> None:
    """Render the final aligned statistics block after the stream ends."""
    flag_pct   = (flagged / total  * 100) if total   else 0.0
    throughput = (total   / elapsed)      if elapsed else 0.0
    W          = 72

    def stat(label: str, value: str, col: str = C.WHT) -> None:
        """One right-aligned statistics row."""
        print(f"  {C.WHT}{label:<40}{col}{value}{C.R}")

    print(f"\n{C.GRN}{C.B}{'=' * W}{C.R}")
    print(f"{C.GRN}{C.B}  ORCHESTRATION COMPLETE  -  SUMMARY STATISTICS{C.R}")
    print(f"{C.GRN}{'-' * W}{C.R}")
    stat("Total Logs Scanned",              f"{total:>14,}")
    stat("Total Logs Flagged",              f"{flagged:>14,}",      C.YLW)
    stat("Overall Flag Rate",               f"{flag_pct:>13.3f}%",  C.YLW)
    stat("Rule-1 Hits  (Volumetric)",       f"{watch.rule1_hits:>14,}", C.CYN)
    stat("Rule-2 Hits  (TLS/DoH Tunnel)",   f"{watch.rule2_hits:>14,}", C.CYN)
    stat("Intelligence Reports Issued",     f"{analyst.reports_generated:>14,}", C.MAG)
    stat("JSON Parse Errors Skipped",       f"{errors:>14,}", C.RED if errors else C.WHT)
    stat("Total Elapsed Time",              f"{elapsed:>13.2f}s")
    stat("Average Throughput",              f"{throughput:>8,.0f} logs/sec")
    print(f"{C.GRN}{'=' * W}{C.R}\n")


# =============================================================================
#  Phase 3 — Async Producer-Consumer Infrastructure
# =============================================================================

class _Counters:
    """
    Lightweight mutable counter namespace shared between producer_task and
    main()'s finally block.

    Thread-safety rationale
    -----------------------
    All mutations occur exclusively on the asyncio event-loop thread:

      • producer_task is a coroutine — its body runs on the event-loop thread
        between await checkpoints.
      • worker_task updates (if any were added here) would also happen after
        `await asyncio.to_thread()` returns, which resumes on the event-loop
        thread, not the worker thread.

    Because no mutation crosses thread boundaries, no locking is required.
    """
    __slots__ = ("total_scanned", "total_flagged", "parse_errors")

    def __init__(self) -> None:
        self.total_scanned: int = 0
        self.total_flagged: int = 0
        self.parse_errors:  int = 0


async def producer_task(
    queue:    asyncio.Queue,
    watchdog: WatchdogAgent,
    counters: _Counters,
) -> None:
    """
    Phase 3 Producer — streams LOG_FILE line-by-line, triages each record
    with WatchdogAgent, and enqueues (record, rule_desc, line_no) tuples for
    the consumer worker pool.

    Cooperative multitasking strategy
    ----------------------------------
    File I/O is intentionally synchronous (plain open()) per the Phase 3
    zero-new-dependency constraint.  Without mitigation, a tight file-read
    loop would monopolise the event loop, starving worker coroutines of
    scheduling time and negating the concurrency benefit.

    Two mechanisms restore fairness:

      1. ``await asyncio.sleep(0)`` every YIELD_EVERY (500) raw lines.
         This is a cooperative yield: it relinquishes the event loop to the
         scheduler without any real sleep, allowing waiting worker coroutines
         (blocked on queue.get()) to be dispatched and run their next steps.
         Cost: one scheduling round-trip per 500 lines — negligible overhead.

      2. ``await queue.put(item)`` auto-suspends when the queue is full
         (at QUEUE_MAXSIZE), providing natural backpressure: the fast
         producer blocks until a worker drains a slot, capping peak memory
         at QUEUE_MAXSIZE × (record size) regardless of dataset volume.

    Args
    ----
    queue    : Bounded asyncio.Queue connecting producer → workers.
    watchdog : Initialised WatchdogAgent; evaluate each record in O(1).
    counters : Shared _Counters namespace updated on the event-loop thread.

    Raises
    ------
    OSError  Propagated to async_main on file I/O failure so the finally
             block can cancel workers before the exception reaches main().
    """
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            for line_no, raw in enumerate(fh, start=1):

                # ── Cooperative yield ─────────────────────────────────────
                # asyncio.sleep(0) hands control back to the event-loop
                # scheduler so waiting workers (queue.get()) get a turn.
                # Without this, the tight for-loop would block all other
                # coroutines until EOF — defeating the async architecture.
                if line_no % YIELD_EVERY == 0:
                    await asyncio.sleep(0)

                raw = raw.strip()
                if not raw:
                    continue             # silently skip blank / empty lines

                # ── Step 1: Parse JSON ────────────────────────────────────
                try:
                    record: dict = json.loads(raw)
                except json.JSONDecodeError as exc:
                    counters.parse_errors += 1
                    _warn(f"Line {line_no}: JSON decode error — {exc}")
                    continue             # skip malformed record, keep going

                counters.total_scanned += 1

                # ── Step 2: Agent 1 — WatchdogAgent triage ───────────────
                # Pure Python heuristics; O(1) per record; no I/O.
                # Returns (bool, rule_desc_string).
                flagged, rule_desc = watchdog.analyze(record)

                # ── Step 3: Enqueue flagged records for LLM analysis ─────
                # await blocks here if the queue is at QUEUE_MAXSIZE,
                # applying backpressure and preventing unbounded memory use.
                if flagged:
                    counters.total_flagged += 1
                    await queue.put((record, rule_desc, line_no))

                # ── Progress heartbeat ────────────────────────────────────
                if counters.total_scanned % PROGRESS_EVERY == 0:
                    rate = counters.total_flagged / counters.total_scanned * 100
                    print(
                        f"{C.D}  [~] Scanned {counters.total_scanned:>10,}  |  "
                        f"Flagged {counters.total_flagged:>7,}  |  "
                        f"Rate {rate:.3f}%{C.R}",
                        flush=True,
                    )

    except OSError as exc:
        # Propagate to async_main so its finally block cancels workers first.
        print(f"{C.RED}[FATAL] File I/O error in producer: {exc}{C.R}")
        raise


async def worker_task(
    queue:   asyncio.Queue,
    analyst: ThreatAnalystAgent,
) -> None:
    """
    Phase 3 Consumer Worker — drains the shared queue and runs deep LLM-backed
    threat analysis on every escalated record.

    Why asyncio.to_thread()?
    ------------------------
    ThreatAnalystAgent.analyze() calls requests.post() under the hood — a
    synchronous, blocking HTTP operation that can stall for up to OLLAMA_TIMEOUT
    seconds (default 120 s).  Awaiting it directly on the event loop would
    freeze all concurrency for that duration: the producer couldn't enqueue,
    sibling workers couldn't run, and the queue would pile up unbounded.

    asyncio.to_thread() dispatches the call to Python's default
    ThreadPoolExecutor (capacity: min(32, os.cpu_count() + 4) threads).
    The event loop remains fully live while the HTTP round-trip executes in
    a background thread; the await resumes only after the thread returns,
    posting the result back to the event-loop thread safely.

    CancelledError lifecycle
    ------------------------
    Workers run in an infinite while-loop until explicitly cancelled by
    async_main after queue.join() completes.

      CancelledError at ``await queue.get()``
          Worker was idle (nothing in queue) when cancelled.  No item was
          dequeued, so task_done() must NOT be called.  ``return`` exits cleanly.

      CancelledError at ``await asyncio.to_thread(...)``
          An item WAS dequeued above, so task_done() MUST be called.
          In Python ≥ 3.8, asyncio.CancelledError inherits from BaseException
          (not Exception), so it bypasses the ``except Exception`` clause.
          The ``finally`` block still runs, calling task_done() before the
          CancelledError propagates — this is the correct behaviour.

    Args
    ----
    queue   : Shared asyncio.Queue (same instance as the producer uses).
    analyst : Shared ThreatAnalystAgent; analyze() is called in a thread.
              reports_generated is incremented inside the thread — a benign
              race under the GIL with NUM_WORKERS=3; acceptable for a counter.
    """
    while True:

        # ── Await next work item ─────────────────────────────────────────
        # CancelledError here means the worker was shut down while idle —
        # no item was dequeued, so task_done() must not be called.
        try:
            record, rule_desc, line_no = await queue.get()
        except asyncio.CancelledError:
            return   # clean exit; event loop will mark this task done

        # ── Process the dequeued item ────────────────────────────────────
        try:
            # Offload the blocking HTTP call to the thread pool.
            # The event loop is free to schedule other workers or the
            # producer while this thread waits for the Ollama response.
            analysis = await asyncio.to_thread(
                analyst.analyze, record, rule_desc
            )

            # print_report() is pure stdout I/O.  It is safe to call here
            # on the event-loop thread once the awaited thread has returned.
            analyst.print_report(record, rule_desc, analysis, line_no)

        except Exception as exc:
            # Belt-and-suspenders: ThreatAnalystAgent.analyze() already
            # handles requests.Timeout, ConnectionError, HTTPError, and
            # JSONDecodeError internally, returning formatted error strings.
            # This clause catches any unforeseen exception so a single bad
            # record never kills the worker.
            #
            # NOTE: asyncio.CancelledError (BaseException, not Exception)
            # is intentionally NOT caught here.  It propagates to the
            # finally block below, which calls task_done() before allowing
            # the cancellation to exit the while-loop naturally.
            _warn(
                f"Worker: unexpected error on stream line {line_no} — "
                f"{type(exc).__name__}: {exc}"
            )

        finally:
            # Always decrement the queue's internal join-counter, regardless
            # of whether processing succeeded, raised, or was cancelled.
            # This unblocks queue.join() in async_main once all items are done.
            queue.task_done()


async def async_main(
    watchdog: WatchdogAgent,
    analyst:  ThreatAnalystAgent,
    counters: _Counters,
) -> None:
    """
    Phase 3 Async Orchestrator — wires the Producer-Consumer pipeline.

    Receives pre-initialised agents and the shared counter namespace from
    main() so that main()'s finally block can unconditionally call
    _print_summary() regardless of how or where the pipeline terminates.
    (See module docstring for the Python < 3.11 rationale.)

    Shutdown sequence
    -----------------
    1. producer_task() reads LOG_FILE line-by-line to EOF, triaging every
       record and enqueuing flagged ones.  It naturally terminates on EOF
       (or raises OSError on I/O failure).

    2. ``await queue.join()`` blocks until every item placed by the producer
       has been fully processed by a worker — i.e. task_done() has been
       called NUM_FLAGGED times.  This guarantees no analysis is silently
       dropped before the summary is printed.

    3. Worker tasks are cancelled.  At this point all workers are blocked on
       ``await queue.get()`` (queue is empty post-join).  cancel() injects
       CancelledError into that await, causing each worker's ``return`` to
       execute cleanly.  ``asyncio.gather(return_exceptions=True)`` awaits
       their teardown so worker finally blocks run before async_main returns.

    CancelledError (Python 3.11+ Ctrl-C)
    -------------------------------------
    In Python 3.11+, asyncio.run() installs a SIGINT handler that cancels
    the main task before re-raising KeyboardInterrupt.  CancelledError is
    suppressed here (``pass``) so that async_main returns normally, giving
    the finally block time to cancel workers and drain their teardown.
    main()'s ``except KeyboardInterrupt`` then prints the user message and
    falls through to the finally block for the summary.

    Args
    ----
    watchdog : Initialised WatchdogAgent, passed through to producer_task.
    analyst  : Initialised ThreatAnalystAgent, shared across all workers.
    counters : Shared _Counters namespace updated by producer_task.
    """
    # Bounded queue: producer suspends on put() once QUEUE_MAXSIZE slots are
    # occupied, applying backpressure so memory usage stays O(QUEUE_MAXSIZE).
    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)

    # Initialised before the try block so the finally clause can always
    # iterate workers even if an exception fires during task creation.
    workers: list[asyncio.Task] = []

    try:
        # ── Spin up the consumer worker pool ──────────────────────────────
        # Tasks are scheduled immediately; they block on queue.get() until
        # the producer enqueues the first flagged record.
        workers = [
            asyncio.create_task(
                worker_task(queue, analyst),
                name=f"threat-analyst-worker-{i}",
            )
            for i in range(NUM_WORKERS)
        ]

        # ── Run the producer to EOF ────────────────────────────────────────
        # producer_task yields every YIELD_EVERY lines so workers receive
        # CPU time concurrently with file reading.
        await producer_task(queue, watchdog, counters)

        # ── Drain the queue ────────────────────────────────────────────────
        # Blocks until every item enqueued by the producer has had
        # task_done() called by a worker — i.e. fully analysed and reported.
        await queue.join()

    except asyncio.CancelledError:
        # Swallow CancelledError so async_main can return normally and let
        # its finally block cancel workers cleanly.  main()'s except clause
        # prints the "Interrupted" message.
        pass

    finally:
        # ── Graceful worker teardown ───────────────────────────────────────
        # Workers are sitting on ``await queue.get()`` (queue drained, or
        # interrupted mid-flight).  cancel() injects CancelledError into
        # that await; each worker catches it and returns.
        for w in workers:
            w.cancel()

        # Await all worker teardowns before returning.
        # return_exceptions=True prevents any worker's CancelledError from
        # propagating here and masking the real reason for shutdown.
        await asyncio.gather(*workers, return_exceptions=True)


# =============================================================================
#  Orchestrator — main()
# =============================================================================

def main() -> None:
    """
    Synchronous entry point for the Phase 3 async orchestrator.

    Responsibilities
    ----------------
    • Render the startup banner and verify the log file exists.
    • Instantiate shared state (agents, counters, wall-clock timer) on the
      main thread, outside the event loop, so the finally block below can
      always access their final values regardless of async termination path.
    • Launch the async pipeline with asyncio.run(async_main(...)).
    • Guarantee that _print_summary() is ALWAYS called — on normal
      completion, Ctrl-C (KeyboardInterrupt), or file I/O failure — via the
      unconditional finally block.

    Guaranteed summary printing across Python versions
    --------------------------------------------------
    asyncio.run() may re-raise KeyboardInterrupt after cancelling the main
    task (Python 3.11+) OR propagate it immediately, bypassing async_main's
    exception handlers (Python 3.9–3.10).  By owning the agents/counters and
    the finally block here — in synchronous scope — _print_summary() fires
    regardless of which path asyncio takes.  asyncio.run() then becomes
    strictly responsible for event-loop lifecycle; main() handles I/O and
    reporting.
    """
    # ── Startup banner ────────────────────────────────────────────────────────
    print(f"\n{C.GRN}{C.B}{_build_banner()}{C.R}\n")

    # ── Pre-flight: verify the log file exists before doing anything else ──────
    if not os.path.isfile(LOG_FILE):
        print(
            f"{C.RED}{C.B}[FATAL] Log file not found:\n"
            f"  {LOG_FILE}\n"
            f"  Check the path, mount point, or Phase-1 output location.{C.R}"
        )
        sys.exit(1)

    mb = os.path.getsize(LOG_FILE) / 1_048_576
    print(f"{C.GRN}[OK] Log file verified  ({mb:,.2f} MB){C.R}")
    print(
        f"{C.GRN}[OK] Agents initialised — "
        f"{NUM_WORKERS} consumer worker(s) | "
        f"queue capacity {QUEUE_MAXSIZE:,}{C.R}"
    )
    print(
        f"{C.D}     Heartbeat every {PROGRESS_EVERY:,} records — "
        f"Ctrl-C at any time for a partial summary\n{C.R}"
    )

    # ── Instantiate shared state on the synchronous (main) thread ─────────────
    # Kept here — not inside async_main — so the finally block below can
    # always reach them.  See module docstring for the full rationale.
    watchdog = WatchdogAgent()
    analyst  = ThreatAnalystAgent()
    counters = _Counters()
    t0       = time.perf_counter()

    # ── Run the async pipeline ────────────────────────────────────────────────
    try:
        # asyncio.run() creates a fresh event loop, runs async_main to
        # completion (or until cancelled / interrupted), then tears it down.
        # All three arguments are pre-initialised objects from this scope.
        asyncio.run(async_main(watchdog, analyst, counters))

    except KeyboardInterrupt:
        # User pressed Ctrl-C.
        # • Python 3.11+: async_main's finally already cancelled workers;
        #   asyncio.run() re-raises KeyboardInterrupt after async cleanup.
        # • Python 3.9–3.10: may arrive here directly, bypassing async_main.
        # In both cases, the finally block below guarantees the summary.
        print(
            f"\n{C.YLW}{C.B}[!] Interrupted by user (Ctrl-C) — "
            f"printing partial summary below.{C.R}"
        )

    except OSError as exc:
        # Propagated from producer_task (via async_main) on file I/O failure.
        print(f"{C.RED}[FATAL] File I/O error: {exc}{C.R}")
        sys.exit(1)   # SystemExit still triggers finally below

    finally:
        # Always executed: on clean EOF, Ctrl-C, or I/O error.
        # agents' internal counters (rule1_hits, reports_generated, etc.)
        # reflect all work completed up to the point of termination.
        elapsed = time.perf_counter() - t0
        _print_summary(
            counters.total_scanned,
            counters.total_flagged,
            watchdog,
            analyst,
            elapsed,
            counters.parse_errors,
        )


# =============================================================================
#  Entry-point guard
# =============================================================================

if __name__ == "__main__":
    main()