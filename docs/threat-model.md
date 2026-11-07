# SentinelVAPT Platform Threat Model (STRIDE Methodology)

**System:** SentinelVAPT (Autonomous, Evidence-Driven Security Assessment Platform)  
**Methodology:** Microsoft STRIDE Threat Modeling Framework  
**Scope:** Core Web Application, API Gateway, Scanner Orchestration Workers, Content-Addressed Storage, and Audit Ledger.

---

## 1. System Decomposition & Trust Boundaries

```
[ Human Analyst ] (Untrusted Browser Client)
       │ (TLS + HMAC-SHA256 Bearer Token)
[ TRUST BOUNDARY 1: Web Interface ]
       ▼
[ FastAPI Gateway & RBAC Layer ]
       │
[ TRUST BOUNDARY 2: Scope Gate & Approval Gate ]
       ▼
[ Orchestrator & Tool Adapters ]
       │ (Subprocess Array / Isolated Network Egress)
[ TRUST BOUNDARY 3: Execution Sandbox & Lab Network ]
       ▼
[ Scanner Containers & Target Lab Infrastructure ]
```

---

## 2. STRIDE Threat Analysis & Architectural Countermeasures

### 2.1 Spoofing (Identity & Attribution)
* **Threat S1: Analyst Identity Spoofing:** An unauthorized party claims to be an administrator or lead analyst to issue offensive commands or alter rules of engagement.
  * *Countermeasure:* Password hashing using memory-hard `scrypt` ($N=16384, r=8, p=1$) with cryptographically random salts; constant-time comparison `hmac.compare_digest`; cryptographically signed HMAC-SHA256 session tokens with strict expiration.
* **Threat S2: Subsystem Identity Spoofing:** An adversarial tool output attempts to impersonate another scanner (e.g. forging an OpenVAS XML to claim a bogus vulnerability).
  * *Countermeasure:* Content-addressed storage verifies the exact SHA-256 hash of all imported artifacts. Ingestion pathways strictly log source tool metadata to the hash-chained audit ledger.

### 2.2 Tampering (Data Integrity)
* **Threat T1: Tampering with Scope Gate Rules:** An attacker or hijacked LLM prompt attempts to modify the allowlist to scan public infrastructure or cloud metadata (`169.254.169.254`).
  * *Countermeasure:* The Scope Gate is implemented entirely in deterministic Python code. All scope changes require Lead Analyst authorization and are recorded in the immutable audit log.
* **Threat T2: Tampering with Historical Audit Logs:** An operator attempts to erase or alter a record of an offensive exploit execution.
  * *Countermeasure:* Append-only hash-chained ledger. Record $N$ stores $\text{SHA-256}(Record_{N-1})$. Modifying any prior record breaks all subsequent cryptographic links; the `verify_audit_integrity()` method flags the exact `broken_at_id`.
* **Threat T3: Tampering with Raw Evidence Files:** An operator modifies a scan log to invent or delete findings.
  * *Countermeasure:* Content-addressed storage stores artifacts named by their SHA-256 hash. Any byte alteration changes the hash and fails evidentiary verification.

### 2.3 Repudiation (Attributability)
* **Threat R1: Denying Approval of Intrusive Scans or Exploits:** A user authorizes an active exploit against a target and later denies responsibility.
  * *Countermeasure:* Non-Negotiable Rule 3 enforces mandatory recorded approval: approver username, timestamp, exact module/parameters, target typing confirmation, justification, and outcome. All recorded in the cryptographically chained audit log.

### 2.4 Information Disclosure (Confidentiality)
* **Threat I1: Exposure of Raw Vulnerability Data to Unauthorized Parties:** A Viewer-role user accesses raw sensitive evidence or target credentials.
  * *Countermeasure:* Strict RBAC hierarchy (`ADMIN`, `LEAD_ANALYST`, `ANALYST`, `VIEWER`). Viewers have read-only access to summarized reports; credential parameters are masked.
* **Threat I2: SSRF and DNS Rebinding via Target Input:** An attacker registers a domain that initially resolves to an authorized IP, then changes DNS records to point to cloud internal endpoints.
  * *Countermeasure:* Pre-resolution socket pinning. The Scope Gate resolves hostnames to all target IPs before egress and validates every resolved IP against the private/lab allowlist and exclusions.

### 2.5 Denial of Service (Availability)
* **Threat D1: Unbounded Scanner Execution Resource Exhaustion:** An aggressive scanner runs indefinitely, exhausting worker CPU and memory.
  * *Countermeasure:* Hard timeout policies enforced via subprocess management (`timeout` parameter in `run_subprocess`), process group termination, and rate-limiting controls.
* **Threat D2: DoS against Scoped Targets:** Scanners overwhelm lab servers with excessive packet rates.
  * *Countermeasure:* Rate-limiting parameters (`rate_limit_rps`), conservative top-ports defaults, and explicit prohibition of denial-of-service attack modules.

### 2.6 Elevation of Privilege (Authorization)
* **Threat E1: LLM Prompt Injection Bypassing Human Checkpoints:** A maliciously crafted target banner tricks the conversational LLM into executing an offensive exploit autonomously.
  * *Countermeasure:* The LLM possesses **zero direct tool execution permissions**. Every tool invocation must pass through the deterministic Scope Gate and Human Approval Gate. If an exploit module is proposed, it is physically halted in pending status until a human approves it.
* **Threat E2: Command Injection via Scanner Parameters:** An attacker supplies shell metacharacters in target or parameter fields (e.g. `127.0.0.1; rm -rf /`).
  * *Countermeasure:* Strict argument-array subprocess execution (`subprocess.run(["nmap", ...])`). Shell execution (`shell=True`) is completely forbidden across the entire codebase.

---

## 3. Threat Model Summary Matrix

| Threat ID | STRIDE Category | Risk Level | Architectural Mitigation | Status |
|---|---|---|---|---|
| S1 | Spoofing | High | Scrypt memory-hard hashing + HMAC tokens | **Mitigated** |
| T1 | Tampering | Critical | Deterministic Scope Gate (Zero LLM) | **Mitigated** |
| T2 | Tampering | High | SHA-256 Hash-Chained Audit Ledger | **Mitigated** |
| T3 | Tampering | High | Content-Addressed Storage (SHA-256) | **Mitigated** |
| R1 | Repudiation | High | Human Approval Gate with Target Confirmation | **Mitigated** |
| I1 | Info Disclosure | Medium | RBAC Hierarchy (Argon2/scrypt tokens) | **Mitigated** |
| I2 | Info Disclosure | Critical | Pre-Resolution DNS Pinning & Private Default | **Mitigated** |
| D1 | Denial of Service | Medium | Hard Process Timeouts & Graceful Error Classes | **Mitigated** |
| E1 | Elevation of Priv | Critical | Decoupled LLM Planning from Execution Pipeline | **Mitigated** |
| E2 | Elevation of Priv | Critical | Argument Arrays Only (No Shell String Concat) | **Mitigated** |

