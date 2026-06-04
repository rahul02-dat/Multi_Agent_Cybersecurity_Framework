#!/usr/bin/env python3
"""
agent_orchestrator.py
=====================
Phase 6: Multi-Agent Threat Intelligence System (RAG + Active IPS)
----------------------------------------------------------
Architecture: Async Producer-Consumer + ChromaDB RAG + Local Gemma Swarm

1. WatchdogAgent (Producer): High-speed heuristic triage.
2. ChromaDB (Vector Store): Local, air-gapped threat intelligence storage.
3. LangGraph SOC Team (Consumers):
   - Node 0: Intel Retriever (Fetches context using nomic-embed-text)
   - Node 1: Analyst Agent (gemma4:e4b-mlx)
   - Node 2: Red Team Critic (gemma4:latest)
   - Node 3: Lead Judge (gemma3:12b)
   - Node 4: Remediation Agent (gemma3:12b)
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import TypedDict, Literal

# LangGraph & LangChain dependencies
from langgraph.graph import StateGraph, START, END
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_core.messages import HumanMessage
from langchain_community.vectorstores import Chroma

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
#  Configuration & Local Model Mapping
# =============================================================================
LOG_FILE          = "unified_network_logs.jsonl" 
OLLAMA_BASE_URL   = "http://localhost:11434"

# Using your exact local models to completely bypass Hugging Face
ANALYST_MODEL     = "gemma4:e4b-mlx"
CRITIC_MODEL      = "gemma4:latest"
JUDGE_MODEL       = "gemma3:12b"
REMEDIATION_MODEL = "gemma3:12b"
EMBEDDING_MODEL   = "nomic-embed-text"

NUM_WORKERS       = 2  # Set to 2 to give your 12B model breathing room in memory
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
#  Vector Database Setup (Local Threat Intelligence Platform)
# =============================================================================
def initialize_threat_intel_db():
    print(f"{C.CYN}[*] Initializing local ChromaDB with Threat Intelligence entries...{C.R}")
    embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL, base_url=OLLAMA_BASE_URL)
    
    # Concrete security indicators mapped directly to your dataset signatures
    threat_intel_docs = [
        "Threat ID: TIP-01 - DNS-over-HTTPS (DoH) Tunneling Indicator: Extended network sessions using TCP port 443 with low packet variance, lasting over 100 seconds with symmetric byte flow metrics, strongly indicates automated data exfiltration or active command-and-control (C2) channels.",
        "Threat ID: TIP-02 - Volumetric DDoS Attack Vectors: Packet bursts climbing past 1,000 packets-per-second targeting specialized or atypical listener ports (e.g., 8080) are primary signatures of flood tools like DoS Hulk or LOIC attempting resource starvation.",
        "Operational Baseline: Safe Content Delivery Networks (CDNs): Heavy data packets hitting port 443 or 80 with short, rapid lifetimes are typical behavior of distributed cloud delivery nodes or multimedia streams, not malignant data exfiltration.",
        "Operational Baseline: Legitimate Admin SSH/Web Management: High volume connections on port 22 or 443 originating from known internal networks indicate routine administrative actions or configuration deployments."
    ]
    
    db = Chroma.from_texts(threat_intel_docs, embeddings)
    print(f"{C.GRN}[OK] Local ChromaDB Vector Store successfully running in memory.{C.R}\n")
    return db

# =============================================================================
#  LangGraph Multi-Agent Nodes (RAG + Active IPS)
# =============================================================================

class AgentState(TypedDict):
    raw_log: dict
    watchdog_rule: str
    threat_intel_context: str
    analyst_hypothesis: str
    critic_rebuttal: str
    final_report: dict
    remediation_plan: dict

def get_intel_retriever_node(db):
    """Factory to safely access ChromaDB without locking the async runtime loop."""
    async def intel_retriever_node(state: AgentState) -> dict:
        query = f"Rule: {state['watchdog_rule']} Port: {state['raw_log'].get('destination_port')}"
        # Execute blocking database search safely within an execution thread
        docs = await asyncio.to_thread(db.similarity_search, query, k=2)
        context = "\n- " + "\n- ".join([d.page_content for d in docs])
        return {"threat_intel_context": context}
    return intel_retriever_node

async def analyst_node(state: AgentState) -> dict:
    llm = ChatOllama(model=ANALYST_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.1)
    prompt = f"""You are an expert SOC Analyst. A deterministic Watchdog flagged this log:
    Rule Triggered: {state['watchdog_rule']}
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    
    Retrieved Threat Intel Context: {state['threat_intel_context']}
    
    In exactly 2 sentences, state your hypothesis on why this represents a malicious attack. Ground your reasoning explicitly on data patterns found in the Threat Intel."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content = response.content.split('</think>')[-1].strip() if '</think>' in response.content else response.content.strip()
    return {"analyst_hypothesis": content}

async def critic_node(state: AgentState) -> dict:
    llm = ChatOllama(model=CRITIC_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.3)
    prompt = f"""You are a Red Team Critic. Your job is to prevent false positives by challenging the Analyst.
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    Retrieved Threat Intel Context: {state['threat_intel_context']}
    Analyst Hypothesis: {state['analyst_hypothesis']}
    
    In exactly 2 sentences, play devil's advocate. Provide a plausible benign explanation for this traffic behavior by mapping it to safe baselines described in the Threat Intel."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content = response.content.split('</think>')[-1].strip() if '</think>' in response.content else response.content.strip()
    return {"critic_rebuttal": content}

async def judge_node(state: AgentState) -> dict:
    llm = ChatOllama(model=JUDGE_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.0, format="json")
    prompt = f"""You are the Lead SOC Judge. Evaluate the debate and issue a final ruling.
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    Analyst Argues: {state['analyst_hypothesis']}
    Critic Argues: {state['critic_rebuttal']}
    
    Output your final verdict strictly as a JSON object with these exact keys:
    "is_threat" (boolean), "threat_type" (string, or "False Positive"), "justification" (1 sentence explaining who won the debate)."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content = response.content.split('</think>')[-1].strip() if '</think>' in response.content else response.content.strip()
    
    try:
        report = json.loads(content)
    except json.JSONDecodeError:
        report = {"is_threat": True, "threat_type": "Parse Error", "justification": "Failed to parse Judge JSON output."}
    return {"final_report": report}

async def remediation_node(state: AgentState) -> dict:
    llm = ChatOllama(model=REMEDIATION_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.0, format="json")
    prompt = f"""You are a SOC Mitigation Engineer. 
    Raw Data: {json.dumps(state['raw_log'], default=str)}
    Judge Verdict: {json.dumps(state['final_report'], default=str)}
    
    Generate active containment scripts for this threat.
    Output a strict JSON object with these exact keys:
    "firewall_command" (A string containing a valid Linux `iptables` or `ufw` command to block or rate-limit the offending traffic).
    "rollback_command" (The bash command to undo the block).
    "risk_warning" (1 sentence detailing the structural impact of deploying this block)."""
    
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content = response.content.split('</think>')[-1].strip() if '</think>' in response.content else response.content.strip()
    
    try:
        plan = json.loads(content)
    except json.JSONDecodeError:
        plan = {"firewall_command": "echo 'Containment Error'", "rollback_command": "echo 'N/A'", "risk_warning": "Parse Error"}
    return {"remediation_plan": plan}

def router(state: AgentState) -> Literal["remediation", "__end__"]:
    if state["final_report"].get("is_threat"):
        return "remediation"
    return "__end__"

def build_soc_graph(db):
    workflow = StateGraph(AgentState)
    
    workflow.add_node("intel_retriever", get_intel_retriever_node(db))
    workflow.add_node("analyst", analyst_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("judge", judge_node)
    workflow.add_node("remediation", remediation_node)
    
    workflow.add_edge(START, "intel_retriever")
    workflow.add_edge("intel_retriever", "analyst")
    workflow.add_edge("analyst", "critic")
    workflow.add_edge("critic", "judge")
    workflow.add_conditional_edges("judge", router, {"remediation": "remediation", "__end__": END})
    workflow.add_edge("remediation", END)
    
    return workflow.compile()

# =============================================================================
#  Output Presentation & Log Handlers
# =============================================================================
def print_debate_report(log: dict, rule: str, state: dict, line_no: int, report_id: int):
    W = 72
    fat = "=" * W
    mid = "-" * W

    print(f"\n{C.YLW}{C.B}{fat}{C.R}")
    print(f"{C.YLW}{C.B}  [!!] LANGGRAPH RAG DEBATE REPORT #{report_id}   |  line {line_no:,}{C.R}")
    print(f"{C.YLW}{mid}{C.R}")

    print(f"{C.CYN}  Timestamp          {C.WHT}{log.get('timestamp', 'N/A')}{C.R}")
    print(f"{C.CYN}  Dst Port           {C.WHT}{log.get('destination_port', 'N/A')}{C.R}")
    print(f"{C.CYN}  Ground Truth       {C.WHT}{log.get('ground_truth_label', 'N/A')}{C.R}")
    print(f"{C.CYN}  Alert Rule         {C.MAG}{rule}{C.R}")

    print(f"{C.YLW}{mid}{C.R}")
    print(f"{C.MAG}{C.B}  [VDB THREAT INTELLIGENCE INJECTED] {C.R}{C.WHT}{state.get('threat_intel_context', '')}{C.R}")
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
#  Async Producer-Consumer Pipeline Execution Infrastructure
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
        print(f"{C.RED}[FATAL] Ingestion Pipeline stream fail: {exc}{C.R}")
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
                "threat_intel_context": "",
                "analyst_hypothesis": "",
                "critic_rebuttal": "",
                "final_report": {},
                "remediation_plan": {}
            }
            
            final_state = await soc_graph.ainvoke(initial_state)
            counters.reports_generated += 1
            print_debate_report(record, rule_desc, final_state, line_no, counters.reports_generated)

        except Exception as exc:
            _warn(f"Orchestration thread trace failure on log line {line_no} — {exc}")
        finally:
            queue.task_done()

async def async_main(watchdog: WatchdogAgent, counters: _Counters, db) -> None:
    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    soc_graph = build_soc_graph(db)
    workers: list[asyncio.Task] = []

    try:
        workers = [
            asyncio.create_task(worker_task(queue, soc_graph, counters), name=f"soc-worker-{i}")
            for i in range(NUM_WORKERS)
        ]
        await producer_task(queue, watchdog, counters)
        await queue.join()

    except asyncio.CancelledError:
        pass
    finally:
        for w in workers: w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

def _warn(msg: str) -> None:
    print(f"{C.YLW}{C.D}  [W]  {msg}{C.R}", file=sys.stderr, flush=True)

def main() -> None:
    W = 76
    print(f"\n{C.GRN}{C.B}\u2554{'='*(W-2)}\u2557\n\u2551{' '*2}AUTONOMOUS MULTI-AGENT THREAT INTELLIGENCE SYSTEM{' '*(W-53)}\u2551\n\u2551{' '*2}Phase 6  -  Vector Store RAG & Active System Remediation{' '*(W-59)}\u2551\n\u255a{'='*(W-2)}\u255d{C.R}\n")

    if not os.path.isfile(LOG_FILE):
        print(f"{C.RED}{C.B}[FATAL] Log target data file missing: {LOG_FILE}{C.R}")
        sys.exit(1)

    # Boot database locally using Ollama embedding driver
    db = initialize_threat_intel_db()

    print(f"{C.GRN}[OK] Pipeline online — Multi-Model Air-Gapped Swarm ready.{C.R}\n")
    
    watchdog = WatchdogAgent()
    counters = _Counters()
    t0 = time.perf_counter()

    try:
        asyncio.run(async_main(watchdog, counters, db))
    except KeyboardInterrupt:
        print(f"\n{C.YLW}{C.B}[!] Process terminated via keyboard interruption flag.{C.R}")
    finally:
        elapsed = time.perf_counter() - t0
        # Print end metrics block
        print(f"\n{C.GRN}{C.B}{'=' * 72}{C.R}")
        print(f"  Execution Time: {elapsed:.2f}s  |  Scanned Logs: {counters.total_scanned:,}  |  Debates: {counters.reports_generated}")
        print(f"{C.GRN}{'=' * 72}{C.R}\n")

if __name__ == "__main__":
    main()