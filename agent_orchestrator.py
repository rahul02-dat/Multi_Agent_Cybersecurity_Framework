#!/usr/bin/env python3
"""
agent_orchestrator.py
=====================
Phase 5: Autonomous Multi-Agent Threat Intelligence System (IPS Upgrade)
----------------------------------------------------------
Architecture: Async Producer-Consumer + Fine-Tuned Gemma Debate + Active IPS

1. WatchdogAgent: Deterministic triage.
2. LangGraph SOC Team (Fine-Tuned Gemma Experts): 
   - Node 1: Analyst Agent (Trained for Threat Detection)
   - Node 2: Red Team Critic (Trained for Adversarial Benign Explanations)
   - Node 3: Lead Judge (Trained for Strict JSON Arbitration)
   - Node 4: Remediation Agent (Trained for Bash/Firewall Scripting)
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import TypedDict, Literal

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
#  Configuration & Fine-Tuned Ensemble
# =============================================================================
LOG_FILE          = "unified_network_logs.jsonl" 
OLLAMA_BASE_URL   = "http://localhost:11434"

# Custom Fine-Tuned Gemma Models (You will build these via Ollama Modelfiles)
ANALYST_MODEL     = "gemma4:e4b-mlx"
CRITIC_MODEL      = "gemma4:latest"
JUDGE_MODEL       = "gemma3:12b"
REMEDIATION_MODEL = "gemma3:12b"

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
            return True, (f"[RULE-1 VOLUMETRIC ANOMALY] pps={pps:,.1f} | port={dst_port}")

        if (protocol == TUNNEL_PROTO and dst_port == TUNNEL_PORT and duration > TUNNEL_DURATION):
            self.rule2_hits += 1
            return True, (f"[RULE-2 TLS/DoH TUNNEL] flow_duration={duration/1_000_000:,.1f}s")

        return False, ""

# =============================================================================
#  Agent 2, 3, 4, 5 — LangGraph Fine-Tuned SOC Debate Team
# =============================================================================

class AgentState(TypedDict):
    raw_log: dict
    watchdog_rule: str
    analyst_hypothesis: str
    critic_rebuttal: str
    final_report: dict
    remediation_plan: dict

async def analyst_node(state: AgentState) -> dict:
    llm = ChatOllama(model=ANALYST_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.1)
    prompt = f"""Rule Triggered: {state['watchdog_rule']}
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    In exactly 2 sentences, state your hypothesis on why this represents a malicious attack."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    return {"analyst_hypothesis": response.content.strip()}

async def critic_node(state: AgentState) -> dict:
    llm = ChatOllama(model=CRITIC_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.3)
    prompt = f"""Raw Data: {json.dumps(state['raw_log'], default=str)}
    Analyst Hypothesis: {state['analyst_hypothesis']}
    In exactly 2 sentences, play devil's advocate. Provide a plausible benign explanation for this traffic behavior."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    return {"critic_rebuttal": response.content.strip()}

async def judge_node(state: AgentState) -> dict:
    llm = ChatOllama(model=JUDGE_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.0, format="json")
    prompt = f"""Raw Data: {json.dumps(state['raw_log'], default=str)}
    Analyst Argues: {state['analyst_hypothesis']}
    Critic Argues: {state['critic_rebuttal']}
    Output a JSON object: {{"is_threat": bool, "threat_type": str, "justification": str}}."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    try:
        report = json.loads(response.content.strip())
    except json.JSONDecodeError:
        report = {"is_threat": True, "threat_type": "Parse Error", "justification": "Failed to parse Judge output."}
    return {"final_report": report}

async def remediation_node(state: AgentState) -> dict:
    llm = ChatOllama(model=REMEDIATION_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.0, format="json")
    prompt = f"""Raw Data: {json.dumps(state['raw_log'], default=str)}
    Judge Verdict: {json.dumps(state['final_report'], default=str)}
    Output a JSON object: {{"firewall_command": str, "rollback_command": str, "risk_warning": str}}."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    try:
        plan = json.loads(response.content.strip())
    except json.JSONDecodeError:
        plan = {"firewall_command": "echo 'Parse Error'", "rollback_command": "echo 'Error'", "risk_warning": "Parse Error"}
    return {"remediation_plan": plan}

def router(state: AgentState) -> Literal["remediation", "__end__"]:
    if state["final_report"].get("is_threat"):
        return "remediation"
    return "__end__"

def build_soc_graph():
    workflow = StateGraph(AgentState)
    workflow.add_node("analyst", analyst_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("judge", judge_node)
    workflow.add_node("remediation", remediation_node)
    
    workflow.add_edge(START, "analyst")
    workflow.add_edge("analyst", "critic")
    workflow.add_edge("critic", "judge")
    workflow.add_conditional_edges("judge", router, {"remediation": "remediation", "__end__": END})
    workflow.add_edge("remediation", END)
    
    return workflow.compile()

def print_debate_report(log: dict, rule: str, state: dict, line_no: int, report_id: int):
    W = 72
    fat = "=" * W
    mid = "-" * W

    print(f"\n{C.YLW}{C.B}{fat}{C.R}")
    print(f"{C.YLW}{C.B}  [!!] FINE-TUNED DEBATE REPORT #{report_id}   |  stream line {line_no:,}{C.R}")
    print(f"{C.YLW}{mid}{C.R}")

    print(f"{C.CYN}  Timestamp          {C.WHT}{log.get('timestamp', 'N/A')}{C.R}")
    print(f"{C.CYN}  Dst Port           {C.WHT}{log.get('destination_port', 'N/A')}{C.R}")
    print(f"{C.CYN}  Ground Truth       {C.WHT}{log.get('ground_truth_label', 'N/A')}{C.R}")
    print(f"{C.CYN}  Alert Rule         {C.MAG}{rule}{C.R}")

    print(f"{C.YLW}{mid}{C.R}")
    print(f"{C.RED}{C.B}  [ANALYST ({ANALYST_MODEL})]  {C.R}{C.WHT}{state.get('analyst_hypothesis', '')}{C.R}\n")
    print(f"{C.BLU}{C.B}  [CRITIC ({CRITIC_MODEL})]    {C.R}{C.WHT}{state.get('critic_rebuttal', '')}{C.R}")
    print(f"{C.YLW}{mid}{C.R}")
    
    judge_data = state.get("final_report", {})
    threat_col = C.RED if judge_data.get("is_threat") else C.GRN
    print(f"{C.MAG}{C.B}  [JUDGE VERDICT ({JUDGE_MODEL})] {C.R}")
    print(f"{C.CYN}  Threat Level:      {threat_col}{str(judge_data.get('is_threat')).upper()}{C.R}")
    print(f"{C.CYN}  Classification:    {C.WHT}{judge_data.get('threat_type')}{C.R}")
    print(f"{C.CYN}  Justification:     {C.WHT}{judge_data.get('justification')}{C.R}")
    
    remediation = state.get("remediation_plan", {})
    if remediation:
        print(f"{C.YLW}{mid}{C.R}")
        print(f"{C.RED}{C.B}  [ACTIVE REMEDIATION ENGAGED ({REMEDIATION_MODEL})] {C.R}")
        print(f"{C.CYN}  Deploying Firewall: {C.RED}{remediation.get('firewall_command', 'N/A')}{C.R}")
        print(f"{C.CYN}  Rollback Script:    {C.CYN}{remediation.get('rollback_command', 'N/A')}{C.R}")
        print(f"{C.CYN}  Risk Warning:       {C.YLW}{remediation.get('risk_warning', 'N/A')}{C.R}")

    print(f"{C.YLW}{C.B}{fat}{C.R}\n")

# =============================================================================
#  Async Producer-Consumer Infrastructure
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
                except json.JSONDecodeError:
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
                "final_report": {},
                "remediation_plan": {}
            }
            
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
    print(f"\n{C.GRN}{C.B}\u2554{'='*(W-2)}\u2557\n\u2551{' '*2}AUTONOMOUS MULTI-AGENT THREAT INTELLIGENCE SYSTEM{' '*(W-53)}\u2551\n\u2551{' '*2}Phase 5  -  Fine-Tuned Specialized Gemma Ensemble{' '*(W-49)}\u2551\n\u255a{'='*(W-2)}\u255d{C.R}\n")

    if not os.path.isfile(LOG_FILE):
        print(f"{C.RED}{C.B}[FATAL] Log file not found: {LOG_FILE}{C.R}")
        sys.exit(1)

    print(f"{C.GRN}[OK] Agents initialised — {NUM_WORKERS} async LangGraph worker(s) using Gemma Fine-Tunes{C.R}\n")
    
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