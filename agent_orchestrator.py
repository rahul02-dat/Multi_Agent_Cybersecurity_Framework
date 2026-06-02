#!/usr/bin/env python3
"""
agent_orchestrator.py
=====================
Phase 4: Autonomous Multi-Agent Threat Intelligence System
----------------------------------------------------------
Architecture: Async Producer-Consumer + LangGraph Agent Debate

1. WatchdogAgent (Producer): Deterministic, ultra-fast triage. Flags anomalies.
2. LangGraph SOC Team (Consumers): 
   - Node 1: Analyst Agent (Proposes threat theory)
   - Node 2: Red Team Critic (Devil's advocate, hunts for false positives)
   - Node 3: Lead Judge (Outputs objective final JSON verdict)
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import TypedDict

# LangGraph & LangChain dependencies
from langgraph.graph import StateGraph, START, END
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

# =============================================================================
#  ANSI Colour Palette
# =============================================================================
class C:
    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    R   = "\033[0m"   if _enabled else ""
    B   = "\033[1m"   if _enabled else ""
    D   = "\033[2m"   if _enabled else ""
    RED = "\033[91m"  if _enabled else ""
    GRN = "\033[92m"  if _enabled else ""
    YLW = "\033[93m"  if _enabled else ""
    CYN = "\033[96m"  if _enabled else ""
    WHT = "\033[97m"  if _enabled else ""
    MAG = "\033[95m"  if _enabled else ""
    BLU = "\033[94m"  if _enabled else ""

# =============================================================================
#  Configuration
# =============================================================================
LOG_FILE          = "unified_network_logs.jsonl" # Update to your local path
OLLAMA_BASE_URL   = "http://localhost:11434"
OLLAMA_MODEL      = "gemma3:12b" # Update to your local model
NUM_WORKERS       = 3
QUEUE_MAXSIZE     = 1000
YIELD_EVERY       = 500
PROGRESS_EVERY    = 1000

# Watchdog thresholds
PPS_THRESHOLD   = 1000
SAFE_PORTS      = frozenset({80, 443, 22, 53})
TUNNEL_DURATION = 100_000_000
TUNNEL_PORT     = 443
TUNNEL_PROTO    = "TCP"

# =============================================================================
#  Agent 1 — WatchdogAgent (Heuristics)
# =============================================================================
class WatchdogAgent:
    def __init__(self) -> None:
        self.rule1_hits: int = 0
        self.rule2_hits: int = 0

    def analyze(self, log: dict) -> "tuple[bool, str]":
        try:
            pps      = float(log.get("packets_per_second", 0))
            dst_port = int(log.get("destination_port",     0))
            protocol = str(log.get("protocol",             "")).strip().upper()
            duration = float(log.get("flow_duration",      0))
        except (ValueError, TypeError) as exc:
            _warn(f"WatchdogAgent: field cast error on record: {exc}")
            return False, ""

        if pps > PPS_THRESHOLD and dst_port not in SAFE_PORTS:
            self.rule1_hits += 1
            return True, (
                f"[RULE-1 VOLUMETRIC ANOMALY] pps={pps:,.1f} | port={dst_port}"
            )

        if (protocol == TUNNEL_PROTO and dst_port == TUNNEL_PORT and duration > TUNNEL_DURATION):
            self.rule2_hits += 1
            return True, (
                f"[RULE-2 TLS/DoH TUNNEL] flow_duration={duration/1_000_000:,.1f}s"
            )

        return False, ""

# =============================================================================
#  Agent 2, 3, 4 — LangGraph SOC Debate Team
# =============================================================================

# 1. Define the Graph State
class AgentState(TypedDict):
    raw_log: dict
    watchdog_rule: str
    analyst_hypothesis: str
    critic_rebuttal: str
    final_report: dict

# 2. Define the Nodes
async def analyst_node(state: AgentState) -> dict:
    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.2)
    prompt = f"""You are an expert SOC Analyst. A deterministic Watchdog flagged this log:
    Rule Triggered: {state['watchdog_rule']}
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    
    In exactly 2 sentences, state your hypothesis on why this represents a malicious attack. Cite specific data points."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    # Remove Qwen think tags if present
    content = response.content.split('</think>')[-1].strip() if '</think>' in response.content else response.content.strip()
    return {"analyst_hypothesis": content}

async def critic_node(state: AgentState) -> dict:
    # Slightly higher temperature for devil's advocate creativity
    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.4)
    prompt = f"""You are a Red Team Critic. Your job is to prevent false positives by arguing against the Analyst.
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    Analyst Hypothesis: {state['analyst_hypothesis']}
    
    In exactly 2 sentences, play devil's advocate. Provide a plausible benign explanation for this traffic behavior (e.g. streaming, updates, misconfiguration)."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content = response.content.split('</think>')[-1].strip() if '</think>' in response.content else response.content.strip()
    return {"critic_rebuttal": content}

async def judge_node(state: AgentState) -> dict:
    # Temperature 0.0 + JSON format enforcement
    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.0, format="json")
    prompt = f"""You are the Lead SOC Judge. You must evaluate the debate and make a final ruling.
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    Analyst Argues: {state['analyst_hypothesis']}
    Critic Argues: {state['critic_rebuttal']}
    
    Output your final verdict strictly as a JSON object with these exactly keys:
    "is_threat" (boolean), "threat_type" (string, or "False Positive"), "justification" (1 sentence explaining who won the debate)."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content = response.content.split('</think>')[-1].strip() if '</think>' in response.content else response.content.strip()
    
    try:
        report = json.loads(content)
    except json.JSONDecodeError:
        report = {"is_threat": True, "threat_type": "Parse Error", "justification": "Failed to parse Judge JSON output."}
        
    return {"final_report": report}

# 3. Compile the Graph
def build_soc_graph():
    workflow = StateGraph(AgentState)
    workflow.add_node("analyst", analyst_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("judge", judge_node)
    
    workflow.add_edge(START, "analyst")
    workflow.add_edge("analyst", "critic")
    workflow.add_edge("critic", "judge")
    workflow.add_edge("judge", END)
    
    return workflow.compile()

def print_debate_report(log: dict, rule: str, state: dict, line_no: int, report_id: int):
    W = 72
    fat = "=" * W
    mid = "-" * W

    print(f"\n{C.YLW}{C.B}{fat}{C.R}")
    print(f"{C.YLW}{C.B}  [!!] LANGGRAPH DEBATE REPORT #{report_id}   |  stream line {line_no:,}{C.R}")
    print(f"{C.YLW}{mid}{C.R}")

    print(f"{C.CYN}  Timestamp          {C.WHT}{log.get('timestamp', 'N/A')}{C.R}")
    print(f"{C.CYN}  Dst Port           {C.WHT}{log.get('destination_port', 'N/A')}{C.R}")
    print(f"{C.CYN}  Ground Truth       {C.WHT}{log.get('ground_truth_label', 'N/A')}{C.R}")
    print(f"{C.CYN}  Alert Rule         {C.MAG}{rule}{C.R}")

    print(f"{C.YLW}{mid}{C.R}")
    print(f"{C.RED}{C.B}  [ANALYST]  {C.R}{C.WHT}{state.get('analyst_hypothesis', '')}{C.R}\n")
    print(f"{C.BLU}{C.B}  [CRITIC]   {C.R}{C.WHT}{state.get('critic_rebuttal', '')}{C.R}")
    print(f"{C.YLW}{mid}{C.R}")
    
    judge_data = state.get("final_report", {})
    threat_col = C.RED if judge_data.get("is_threat") else C.GRN
    print(f"{C.MAG}{C.B}  [JUDGE VERDICT] {C.R}")
    print(f"{C.CYN}  Threat Level:      {threat_col}{str(judge_data.get('is_threat')).upper()}{C.R}")
    print(f"{C.CYN}  Classification:    {C.WHT}{judge_data.get('threat_type')}{C.R}")
    print(f"{C.CYN}  Justification:     {C.WHT}{judge_data.get('justification')}{C.R}")
    print(f"{C.YLW}{C.B}{fat}{C.R}\n")

# =============================================================================
#  Phase 3/4 — Async Producer-Consumer Infrastructure
# =============================================================================
class _Counters:
    __slots__ = ("total_scanned", "total_flagged", "parse_errors", "reports_generated")
    def __init__(self) -> None:
        self.total_scanned: int = 0
        self.total_flagged: int = 0
        self.parse_errors:  int = 0
        self.reports_generated: int = 0

async def producer_task(queue: asyncio.Queue, watchdog: WatchdogAgent, counters: _Counters) -> None:
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            for line_no, raw in enumerate(fh, start=1):
                if line_no % YIELD_EVERY == 0: await asyncio.sleep(0)

                raw = raw.strip()
                if not raw: continue

                try: record: dict = json.loads(raw)
                except json.JSONDecodeError as exc:
                    counters.parse_errors += 1
                    continue

                counters.total_scanned += 1
                flagged, rule_desc = watchdog.analyze(record)

                if flagged:
                    counters.total_flagged += 1
                    await queue.put((record, rule_desc, line_no))

                if counters.total_scanned % PROGRESS_EVERY == 0:
                    rate = counters.total_flagged / counters.total_scanned * 100
                    print(f"{C.D}  [~] Scanned {counters.total_scanned:>10,}  |  Flagged {counters.total_flagged:>7,}  |  Rate {rate:.3f}%{C.R}", flush=True)
    except OSError as exc:
        print(f"{C.RED}[FATAL] File I/O error in producer: {exc}{C.R}")
        raise

async def worker_task(queue: asyncio.Queue, soc_graph, counters: _Counters) -> None:
    while True:
        try:
            record, rule_desc, line_no = await queue.get()
        except asyncio.CancelledError:
            return

        try:
            initial_state = {
                "raw_log": record,
                "watchdog_rule": rule_desc,
                "analyst_hypothesis": "",
                "critic_rebuttal": "",
                "final_report": {}
            }
            
            # Use ainvoke for true asyncio non-blocking execution!
            final_state = await soc_graph.ainvoke(initial_state)
            
            counters.reports_generated += 1
            print_debate_report(record, rule_desc, final_state, line_no, counters.reports_generated)

        except Exception as exc:
            _warn(f"Worker error on line {line_no} — {type(exc).__name__}: {exc}")
        finally:
            queue.task_done()

async def async_main(watchdog: WatchdogAgent, counters: _Counters) -> None:
    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    soc_graph = build_soc_graph()
    workers: list[asyncio.Task] = []

    try:
        workers = [
            asyncio.create_task(worker_task(queue, soc_graph, counters), name=f"langgraph-worker-{i}")
            for i in range(NUM_WORKERS)
        ]
        await producer_task(queue, watchdog, counters)
        await queue.join()

    except asyncio.CancelledError:
        pass
    finally:
        for w in workers: w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

# =============================================================================
#  Utility & Main Loop
# =============================================================================
def _warn(msg: str) -> None:
    print(f"{C.YLW}{C.D}  [W]  {msg}{C.R}", file=sys.stderr, flush=True)

def _print_summary(total: int, flagged: int, watch: WatchdogAgent, elapsed: float, errors: int, reports: int) -> None:
    flag_pct   = (flagged / total  * 100) if total   else 0.0
    throughput = (total   / elapsed)      if elapsed else 0.0
    W = 72
    def stat(label: str, value: str, col: str = C.WHT): print(f"  {C.WHT}{label:<40}{col}{value}{C.R}")

    print(f"\n{C.GRN}{C.B}{'=' * W}{C.R}")
    print(f"{C.GRN}{C.B}  ORCHESTRATION COMPLETE  -  SUMMARY STATISTICS{C.R}")
    print(f"{C.GRN}{'-' * W}{C.R}")
    stat("Total Logs Scanned", f"{total:>14,}")
    stat("Total Logs Flagged", f"{flagged:>14,}", C.YLW)
    stat("Overall Flag Rate", f"{flag_pct:>13.3f}%", C.YLW)
    stat("Rule-1 Hits  (Volumetric)", f"{watch.rule1_hits:>14,}", C.CYN)
    stat("Rule-2 Hits  (TLS/DoH Tunnel)", f"{watch.rule2_hits:>14,}", C.CYN)
    stat("Graph Debates Completed", f"{reports:>14,}", C.MAG)
    stat("JSON Parse Errors Skipped", f"{errors:>14,}", C.RED if errors else C.WHT)
    stat("Total Elapsed Time", f"{elapsed:>13.2f}s")
    stat("Average Throughput", f"{throughput:>8,.0f} logs/sec")
    print(f"{C.GRN}{'=' * W}{C.R}\n")

def main() -> None:
    W = 76
    print(f"\n{C.GRN}{C.B}\u2554{'='*(W-2)}\u2557\n\u2551{' '*2}AUTONOMOUS MULTI-AGENT THREAT INTELLIGENCE SYSTEM{' '*(W-53)}\u2551\n\u2551{' '*2}Phase 4  -  LangGraph Adversarial Debate{' '*(W-44)}\u2551\n\u255a{'='*(W-2)}\u255d{C.R}\n")

    if not os.path.isfile(LOG_FILE):
        print(f"{C.RED}{C.B}[FATAL] Log file not found: {LOG_FILE}{C.R}")
        sys.exit(1)

    print(f"{C.GRN}[OK] Agents initialised — {NUM_WORKERS} async LangGraph worker(s){C.R}\n")
    
    watchdog = WatchdogAgent()
    counters = _Counters()
    t0 = time.perf_counter()

    try:
        asyncio.run(async_main(watchdog, counters))
    except KeyboardInterrupt:
        print(f"\n{C.YLW}{C.B}[!] Interrupted by user (Ctrl-C) — printing partial summary.{C.R}")
    except OSError as exc:
        print(f"{C.RED}[FATAL] File I/O error: {exc}{C.R}")
        sys.exit(1)
    finally:
        elapsed = time.perf_counter() - t0
        _print_summary(counters.total_scanned, counters.total_flagged, watchdog, elapsed, counters.parse_errors, counters.reports_generated)

if __name__ == "__main__":
    main()