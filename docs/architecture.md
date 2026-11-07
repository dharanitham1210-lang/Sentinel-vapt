# SentinelVAPT: Production Platform Architecture

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗   ██╗ █████╗ ██████╗ ████████╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║   ██║███████║██████╔╝   ██║   
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ╚████╔╝ ██║  ██║██║        ██║   
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   
```

**System:** SentinelVAPT (Autonomous, Evidence-Driven Security Assessment Platform)  
**Classification:** Enterprise Security Architecture  
**Standards Alignment:** NIST SP 800-115, OWASP WSTG, CWE, CVE, CVSS v3.1, MITRE ATT&CK  

---

## 1. System Overview & Core Tenets

SentinelVAPT is an evidence-driven, conversational security assessment platform engineered for professional vulnerability assessment and penetration testing (VAPT) consultancies. It automates testing workflows from initial reconnaissance through to client-ready reporting, with an unbreakable architectural guarantee: **the human analyst remains in deterministic control of all consequential actions.**

### Core Tenets:
1. **Zero Hallucination Guarantee:** No scanner output, CVE, CVSS vector, or risk score is ever fabricated. Every reported issue links to immutable machine artifacts.
2. **Deterministic Scope Gate:** Scope enforcement is 100% deterministic Python code (`ipaddress`, socket pinning, DNS pre-resolution). The LLM cannot bypass it.
3. **Dual Human Approval Gates:** Action-level approvals for active exploitation/intrusive attacks, and report-level approvals prior to client delivery.
4. **Strict Separation of Evidence vs. Inference:** Raw machine outputs (`OBSERVED EVIDENCE`) are stored immutably with SHA-256 hashes; model deductions (`AI INFERENCE`) carry calibrated confidence scores (0–100%) and link to evidence IDs.
5. **Cryptographically Chained Audit Ledger:** Blockchain-style append-only ledger where record $N$ stores $\text{SHA-256}(Record_{N-1})$.

---

## 2. High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph UI ["Frontend Enterprise Console (React / Vite + Tailwind)"]
        Dashboard[Security Dashboard]
        ScopeMgr[Scope & RoE Manager]
        Workspace[Conversational Agent Workspace]
        FindingsView[Findings & Evidence Ledger]
        ApprovalsCenter[Dual Approval Gates Modal]
        IntMatrix[Truthful Integration Matrix]
        AuditView[Audit Hash-Chain Verifier]
    end

    subgraph Core ["Platform Core (FastAPI + Pydantic v2)"]
        API[REST & SSE API Gateway]
        ScopeGate["Scope Gate (Deterministic Engine)"]
        AuthRBAC["Auth & RBAC (Argon2id / scrypt)"]
        AuditLedger["Audit Ledger (SHA-256 Chained)"]
        GroundingValidator["Grounding Validator (Anti-Hallucination)"]
    end

    subgraph Agent ["Agent Orchestration & State Engine"]
        ConvPlanner[Conversational Intent Planner]
        StateMachine["Assessment State Machine (Plan-Act-Observe-Reflect-Replan)"]
        ActionDeduper["Action Hasher H(tool, target, params)"]
        ProposalEngine["Adaptive Proposal Synthesizer"]
    end

    subgraph Correlation ["Normalization & Risk Engine"]
        Normalizer[Unified Finding Normalizer]
        Correlator[Multi-Tool Deduplication & Merge Engine]
        MergeLog[Reversible Merge Log]
        RiskScorer["Explainable Risk Scorer f(CVSS, Exposure, KEV, Crit, Conf)"]
    end

    subgraph Adapters ["Tool Adapters (Process Boundary Isolation)"]
        NmapAd["Nmap (Live Subprocess + XML)"]
        ZapAd["OWASP ZAP (Live REST API + Spider)"]
        NiktoAd["Nikto (Live CLI + Output Parser)"]
        NucleiAd["Nuclei (Live CLI + JSONL Stream)"]
        NessusAd["Tenable Nessus (.nessus v2 XML Import)"]
        BurpAd["PortSwigger Burp (XML Issue Import)"]
        OpenVasAd["OpenVAS / GVM (GVM XML Import / GMP)"]
        MsfAd["Metasploit msfrpcd (Approval Gated & Lab Only)"]
    end

    subgraph Storage ["Persistent Storage Layer"]
        DB[(PostgreSQL / SQLite with SQLAlchemy 2.0)]
        ArtifactsStore[(Content-Addressed Artifacts / SHA-256 .raw)]
        LocalNVD[(Local NVD Benchmark / CWE Cache)]
    end

    UI -->|REST & SSE| API
    API --> ScopeGate
    ScopeGate -->|In-Scope| ConvPlanner
    ScopeGate -->|Violation| AuditLedger
    ConvPlanner --> GroundingValidator
    ConvPlanner --> StateMachine
    StateMachine --> ActionDeduper
    ActionDeduper --> Adapters
    Adapters --> ArtifactsStore
    ArtifactsStore --> Normalizer
    Normalizer --> Correlator
    Correlator --> RiskScorer
    RiskScorer --> DB
    AuditLedger --> DB
```

---

## 3. Data Flow & Execution Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Human Lead Analyst
    participant UI as Sentinel Console
    participant Gate as Deterministic Scope Gate
    participant Agent as Conversational Agent
    participant Adapter as Scanner Adapter
    participant Store as Artifact Storage
    participant Correlator as Correlation Engine
    participant Audit as Hash-Chained Audit Ledger

    Analyst->>UI: Submit Natural-Language Goal ("Audit 10.10.20.5 with web focus")
    UI->>Gate: Validate Target Scope (10.10.20.5)
    alt Out of Scope
        Gate-->>Audit: Log SCOPE_REJECT (Audit Hash Chain Updated)
        Gate-->>UI: Hard Rejection (403 Forbidden)
    else In Scope
        Gate->>Agent: Request Structured Plan
        Agent->>UI: Present Ordered Assessment Plan (Ordered Steps + Rationale + Risk Class)
        Analyst->>UI: Approve Assessment Plan
        UI->>Adapter: Execute Tool (e.g. Nmap -sV -Pn --top-ports 100)
        Adapter->>Store: Save Raw Output (SHA-256 Verified .raw)
        Store->>Correlator: Ingest & Normalize Output
        Correlator->>Correlator: Corroborate & Calibrate Confidence
        Correlator->>UI: Display Correlated Findings & Traceable Evidence IDs
        opt Active Exploitation / Offensive Validation Triggered
            Agent->>UI: Create Approval Request (Metasploit Exploit / Active Attack)
            Analyst->>UI: Type Target Identifier to Confirm Approval
            UI->>Audit: Record APPROVAL_APPROVED (Actor, Timestamp, Justification)
            UI->>Adapter: Launch Gated Offensive Check
        end
        UI->>Analyst: Generate Client-Ready PDF Report (Sections 7.1–7.6)
    end
```

---

## 4. Key Architectural Subsystems

### 4.1 Deterministic Scope Gate
- Pure Python mathematical evaluation using `ipaddress` and socket pinning.
- Blocks public IPv4/IPv6 ranges by default.
- Prevents DNS rebinding by resolving hostnames prior to tool execution and confirming all resolved IPs are inside the authorized CIDR.
- Sanitizes URLs to eliminate userinfo spoofing (`http://authorized@evil.com`).

### 4.2 Adaptive State Machine (Plan -> Act -> Observe -> Reflect -> Replan)
- Tracks discovered assets, open ports, and identified technology stacks.
- Deduplicates scanner actions using action hashes $H(tool, target, parameters)$ to prevent repetitive loops.
- Synthesizes next-step proposals ("Why this scan now") that explicitly cite triggering Evidence IDs.

### 4.3 Multi-Tool Correlation & Deduplication Engine
- Matches vulnerabilities based on composite keys: `(asset, port, normalized_cve)` or `(asset, path, cwe)`.
- Cross-tool corroboration increases confidence to $\ge 0.90$.
- Single-source version banner detections are flagged as `suspected` with automated false-positive triage inferences.
- Generates a transparent `merge_log` and preserves original findings in `_unmerged_items` for 1-click unmerging.

### 4.4 Cryptographic Audit Ledger
- Append-only blockchain-style ledger.
- Record $N$ calculates $\text{SHA-256}(id \parallel ts \parallel aid \parallel actor \parallel action \parallel target \parallel payload\_hash \parallel prev\_hash)$.
- Provides a verification endpoint `/api/audit/integrity` that scans the ledger and pinpoints any tampered records.

