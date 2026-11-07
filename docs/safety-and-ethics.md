# SentinelVAPT: Safety, Ethics & Governance Framework

**Platform:** SentinelVAPT (Autonomous, Evidence-Driven Security Assessment Platform)  
**Document:** Ethical Operating Framework & Governance Alignment  
**Alignment:** Hackathon Section 13 Safety Requirements, CREST Code of Conduct, NIST SP 800-115  

---

## 1. Ethical Security Principles

Autonomous AI systems operating in offensive security domains introduce severe systemic risks if left unconstrained. SentinelVAPT is designed with a **Safety-by-Design** philosophy that ensures all operations comply with ethical, legal, and operational security boundaries.

### Core Ethical Pillars:
1. **Explicit, Verifiable Authorization:** No scan or assessment action can be initiated without recorded client authorization, Rules of Engagement (RoE) definition, and an immutable audit entry.
2. **Deterministic Containment:** AI models must never possess the autonomous authority to expand assessment scope, scan external third parties, or execute destructive exploits.
3. **Evidentiary Integrity:** Security consultancies depend on unimpeachable credibility. Findings must never be simulated, hallucinated, or exaggerated.
4. **Human Primacy:** The platform augments and accelerates human security analysts, but consequential and offensive decisions remain exclusively within human discretion.

---

## 2. Safety Controls Mapping (Hackathon Section 13)

| Safety Requirement | SentinelVAPT Architectural Implementation | Verification Method |
|---|---|---|
| **Deterministic Scope Control** | `ScopeGate` evaluates all target inputs against CIDRs, DNS resolutions, exclusions, and port limits using deterministic Python code (`ipaddress` math). Public IPs are hard-blocked by default. | Unit tests verify rejection of public IPs, CIDR boundaries, IPv4-mapped IPv6, and URL userinfo tricks (`test_scope_gate.py`). |
| **Non-Autonomous Exploitation** | Active attack modules (Metasploit exploit modules, ZAP active scan payloads, offensive PoCs) cannot execute without an explicit approval token issued through the Human Approval Gate. | `test_metasploit_approval_gate_enforcement` verifies that exploit modules strictly fail without an unexpired, lab-confirmed human approval record. |
| **Target Confirmation Typing** | To prevent accidental clicks on high-consequence approvals, the approval modal forces the human operator to re-type the exact target identifier. | `test_approval_service_lifecycle_and_target_confirmation` asserts that mismatched target typing rejects execution. |
| **Grounded Vulnerability Claims** | The `GroundingValidator` parses all candidate LLM outputs and checks CVE/CWE identifiers against raw tool outputs and an authoritative NVD benchmark dictionary. | `test_grounding_validator_blocks_fabricated_cve` confirms that non-existent CVEs (e.g. `CVE-2099-99999`) are rejected from publication. |
| **Immutable Chain of Custody** | An append-only, SHA-256 hash-chained audit ledger logs every action, target, actor, and payload hash. | `verify_audit_integrity()` verifies the mathematical continuity of all records and detects tampering (`test_audit_chain.py`). |
| **Separation of Evidence vs. Inference** | The data model and UI distinctly badge `OBSERVED EVIDENCE` (raw stdout, HTTP transcripts, hashes) separately from `AI INFERENCE` (hypotheses, confidence 0–100%). | Visual tokens and schema separation ensure analysts never confuse model speculation with raw scanner artifacts. |
| **Truthful Integration Disclosures** | The Integration Matrix dynamically checks tool reachability and accurately labels commercial tools (Nessus, Burp) as Import-Only unless licensed. | Integration matrix auto-probes binary paths and API endpoints without marketing exaggeration (`test_adapter_registry_contains_all_tools`). |

---

## 3. Responsible Disclosure & Lab Isolation

- **Default Network Boundaries:** SentinelVAPT ships with an isolated Docker network (`172.28.0.0/16`) hosting deliberate training applications (OWASP Juice Shop, DVWA).
- **Public Range Prohibition:** By default, all public Internet IP ranges are blocked at the engine level. Any override requires explicit administrator credentials and signed authorization statements.
- **Client-Ready Reporting:** All generated reports include formal classification markings, standards disclaimers, methodology outlines, and clickable Evidence IDs (`EVID-XXXX`) ensuring that clients can verify every reported vulnerability against raw machine evidence.

