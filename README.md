# Autonomous Multi-Agent Threat Intelligence System 🛡️🤖

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Enabled-orange.svg)](https://python.langchain.com/v0.1/docs/langgraph/)
[![Ollama](https://img.shields.io/badge/Ollama-Local_LLMs-black.svg)](https://ollama.com/)
[![ChromaDB](https://img.shields.io/badge/Vector_DB-Chroma-12D2A5.svg)](https://www.trychroma.com/)

An air-gapped, multi-agent Intrusion Prevention System (IPS) that leverages localized Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG) to dynamically analyze network traffic, debate threat hypotheses, and generate active firewall mitigations.

## 📖 Executive Summary
Modern Security Operations Centers (SOCs) suffer from severe alert fatigue due to deterministic Intrusion Detection Systems (IDS). This project introduces a **two-tier architecture**:
1. **Algorithmic Triage:** A high-speed heuristic Watchdog processes raw network traffic to filter benign events.
2. **Adversarial AI Swarm:** Flagged anomalies are routed to a LangGraph-orchestrated LLM swarm running natively via Ollama. An **Analyst** agent proposes a threat theory, a **Critic** acts as a Red Team "Devil's Advocate" to find benign explanations, and a **Judge** arbitrates the debate to deploy active Bash/Firewall mitigation scripts.

All agent reasoning is strictly grounded by a **ChromaDB Vector Store** containing textbook threat intelligence, minimizing LLM hallucinations.

---

## 🏗️ System Architecture

```mermaid
graph TD
    classDef data fill:#f9f,stroke:#333,stroke-width:2px;
    classDef heuristic fill:#ffd,stroke:#333,stroke-width:2px;
    classDef llm fill:#bbf,stroke:#333,stroke-width:2px;
    classDef action fill:#dfd,stroke:#333,stroke-width:2px;

    Logs[(Raw Network Logs)]:::data --> Watchdog{Watchdog Filter}:::heuristic
    Watchdog -->|Benign Traffic| Drop[Discarded]
    Watchdog -->|Flagged Anomaly| RAG
    
    RAG[(Local ChromaDB)]:::data -->|Injects Threat Intel| Swarm
    
    subgraph "The Adversarial AI Swarm (Gemma Models)"
        Swarm[LangGraph Routing]:::llm --> Analyst[1. Analyst: Proposes Threat]:::llm
        Analyst --> Critic[2. Critic: Argues Benign]:::llm
        Critic --> Judge{3. Judge: Verdict}:::llm
    end

    Judge -->|False Positive| Report[Log Debate Report]:::action
    Judge -->|Threat Confirmed| IPS[Generate Firewall Script]:::action
    IPS --> Report
