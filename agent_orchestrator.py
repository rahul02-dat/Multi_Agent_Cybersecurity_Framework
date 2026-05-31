#!/usr/bin/env python3
"""
agent_orchestrator.py
=====================
Phase 2: Autonomous Multi-Agent Threat Intelligence System
----------------------------------------------------------
Architecture
  Agent 1  ->  WatchdogAgent       : Fast Python heuristics for stream triage
  Agent 2  ->  ThreatAnalystAgent  : Local Ollama LLM for deep-dive analysis

Data Contract  (each JSONL line must carry these keys)
  source_dataset, timestamp, protocol, flow_duration (microseconds),
  source_port, destination_port, bytes_per_second,
  packets_per_second, ground_truth_label

Usage
  python3 agent_orchestrator.py

Requirements
  Python  3.9+
  pip     install requests          (only non-stdlib dependency)
  Ollama  running locally:          ollama serve
  Model   pulled:                   ollama pull qwen3-coder:latest
"""

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
#  Orchestrator — main()
# =============================================================================

def main() -> None:
    """
    Entry point.

    Opens the unified JSONL log stream, reads it line-by-line without
    loading the entire file into memory (safe for multi-GB datasets), then
    routes every record through the two-agent pipeline:

        raw line  ->  json.loads()
                   ->  WatchdogAgent.analyze()
                   ->  [if suspicious] ThreatAnalystAgent.analyze()
                                       ThreatAnalystAgent.print_report()

    Catches KeyboardInterrupt gracefully so Ctrl-C always prints a partial
    summary rather than a raw traceback.
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
    print(f"{C.GRN}[OK] Agents initialised{C.R}")
    print(
        f"{C.D}     Heartbeat every {PROGRESS_EVERY:,} records — "
        f"Ctrl-C at any time for a partial summary\n{C.R}"
    )

    # ── Instantiate agents ────────────────────────────────────────────────────
    watchdog = WatchdogAgent()
    analyst  = ThreatAnalystAgent()

    # ── Runtime counters ──────────────────────────────────────────────────────
    total_scanned: int = 0
    total_flagged: int = 0
    parse_errors:  int = 0
    t0 = time.perf_counter()

    # ── Main stream loop ──────────────────────────────────────────────────────
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            for line_no, raw in enumerate(fh, start=1):

                raw = raw.strip()
                if not raw:
                    continue                  # silently skip blank / empty lines

                # ── Step 1: Parse JSON ────────────────────────────────────
                try:
                    record: dict = json.loads(raw)
                except json.JSONDecodeError as exc:
                    parse_errors += 1
                    _warn(f"Line {line_no}: JSON decode error — {exc}")
                    continue                  # skip malformed record, keep going

                total_scanned += 1

                # ── Step 2: Agent 1 — Watchdog triage ────────────────────
                #   Returns (bool, rule_string).  O(1) per record — no I/O.
                flagged, rule_desc = watchdog.analyze(record)

                # ── Step 3: Agent 2 — LLM deep-dive (escalated only) ─────
                #   Only records that passed Watchdog are sent to the LLM,
                #   keeping Ollama inference calls proportional to anomalies
                #   rather than total volume.
                if flagged:
                    total_flagged += 1
                    analysis = analyst.analyze(record, rule_desc)
                    analyst.print_report(record, rule_desc, analysis, line_no)

                # ── Progress heartbeat ────────────────────────────────────
                if total_scanned % PROGRESS_EVERY == 0:
                    rate = total_flagged / total_scanned * 100
                    print(
                        f"{C.D}  [~] Scanned {total_scanned:>10,}  |  "
                        f"Flagged {total_flagged:>7,}  |  "
                        f"Rate {rate:.3f}%{C.R}",
                        flush=True,
                    )

    except KeyboardInterrupt:
        print(
            f"\n{C.YLW}{C.B}[!] Interrupted by user (Ctrl-C) — "
            f"printing partial summary below.{C.R}"
        )
    except OSError as exc:
        print(f"{C.RED}[FATAL] File I/O error: {exc}{C.R}")
        sys.exit(1)
    finally:
        # Always print summary — even on interrupt or error — so the analyst
        # retains diagnostic value from a partial run.
        elapsed = time.perf_counter() - t0
        _print_summary(
            total_scanned, total_flagged,
            watchdog, analyst,
            elapsed, parse_errors,
        )


# =============================================================================
#  Entry-point guard
# =============================================================================

if __name__ == "__main__":
    main()