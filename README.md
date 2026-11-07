# SentinelVAPT — Autonomous, Evidence-Driven Security Assessment Platform

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](backend)
[![React: Vite](https://img.shields.io/badge/Frontend-React%20%2B%20Tailwind-teal.svg)](frontend)
[![Quality Tests: 69/69 Passing](https://img.shields.io/badge/Acceptance%20Tests-69%2F69%20Passing-emerald.svg)](backend/tests)
[![Audit Chain: SHA-256](https://img.shields.io/badge/Audit%20Ledger-SHA--256%20Chained-teal.svg)](docs/decisions/ADR-0002-cryptographic-audit-chain.md)
[![MITRE ATT&CK: Enterprise v14](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20v14-orange.svg)](backend/app/mitre.py)

> **SentinelVAPT** is an enterprise-grade, conversational, evidence-driven security assessment platform engineered for professional vulnerability assessment and penetration testing (VAPT) consultancies. It automates testing workflows from initial scoped reconnaissance through to client-ready VAPT reporting, while keeping a human analyst in deterministic control of all consequential actions.

---

## 1. Non-Negotiable Core Rules & Architectural Guarantees

1. **Zero Hallucination:** Never fabricate scanner output, CVEs, CVSS scores, evidence, or risk scores. Every finding links to an immutable raw machine artifact.
2. **Deterministic Scope Gate (Code, not LLM):** Scope enforcement is 100% deterministic Python code (`ipaddress` math, socket pre-resolution, private/lab IP default, public IP blocking). The LLM can never bypass it.
3. **Dual Human Approval Gates:** Active exploitation and offensive validation (Metasploit, active ZAP payloads) strictly require recorded human approval (approver identity, timestamp, exact command, target confirmation typing, justification, lab verification). Reports require lead analyst sign-off.
4. **Strict Evidence vs. Inference Separation:** Distinct data model and visual badges: solid neutral `OBSERVED EVIDENCE` (raw stdout, HTTP transcripts, hashes) vs. outlined `AI INFERENCE` (calibrated confidence 0–100%, linked evidence IDs).
5. **Schema-Enforced Grounding Validator:** Pydantic v2 validator rejects any hallucinated CVE or CWE not present in tool output or in an authoritative local NVD cache.
6. **Integration Transparency:** Truthful dynamic Integration Matrix (Live / Import-Only / Config-Required). Commercial tools (Nessus, Burp) are never falsely claimed as live without active licensed credentials.
7. **Lab-Isolated Targets:** Ships with a containerized lab environment (OWASP Juice Shop, DVWA) on an isolated Docker network (`172.28.0.0/16`). Public internet ranges are blocked by default.
8. **Cryptographically Chained Audit Ledger:** Append-only SHA-256 hash-chained ledger storing every operator and agent decision, with automated `verify_audit_integrity()` tamper detection.

---

## 2. Quick Start & Execution

### One-Command Startup (Docker Compose)

```bash
# Launch platform and isolated lab targets
make up
# Or:
docker-compose up -d
```
- **Console Web UI:** `http://localhost:5173`
- **FastAPI Backend:** `http://localhost:8000`
- **Interactive API Documentation:** `http://localhost:8000/docs`
- **Isolated Lab Targets:**
  - OWASP Juice Shop: `http://localhost:3000` (Container internal: `172.28.0.20:3000`)
  - DVWA: `http://localhost:8081` (Container internal: `172.28.0.21:80`)

### Local Development Startup

```bash
# 1. Backend (Terminal 1)
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000

# 2. Frontend (Terminal 2)
cd frontend
npm install
npm run dev
```

---

## 3. Automated Test Suite (69/69 Passing)

Execute the comprehensive quality bar and acceptance test suite:

```bash
# Run all 69 unit, integration, and quality acceptance tests
pytest backend/tests -v
```

### The 10 Quality Bar Acceptance Tests:
1. `test_acceptance_1_scope_gate_rejection`: Public target `8.8.8.8` rejected by Scope Gate with an immutable audit entry.
2. `test_acceptance_2_plan_rationale_and_adaptive_replanning`: Structured plan selection + state machine adaptive replanning upon port discovery.
3. `test_acceptance_3_multi_scanner_ingestion`: Ingests and normalizes Nmap, ZAP, Nikto, Nessus, Burp, and OpenVAS outputs.
4. `test_acceptance_4_deduplication_and_unmerge`: Merges duplicate findings with corroboration boost; 1-click unmerge verified.
5. `test_acceptance_5_traceability_to_raw_artifact`: Finding traces to raw machine artifact in $\le 3$ clicks.
6. `test_acceptance_6_metasploit_approval_lifecycle`: Metasploit exploit modules cannot execute without recorded human approval; expired tokens rejected.
7. `test_acceptance_7_scanner_timeout_handling`: Subprocess execution timeout and error classification (`ErrorClass.TIMEOUT`).
8. `test_acceptance_8_grounding_validator_blocks_hallucination`: Hallucinated CVEs (e.g. `CVE-2099-99999`) blocked from publication.
9. `test_acceptance_9_pdf_report_all_sections`: Generates client-ready PDF report containing mandatory sections 7.1–7.6.
10. `test_acceptance_10_audit_hash_chain_tamper_detection`: Hash chain verifies intact; tampering with any record flags `broken_at_id`.

Plus 5 dedicated tests for MITRE ATT&CK Enterprise Matrix mapping and Differential Retest Engine (`test_mitre_and_diff.py`).

---

## 4. Truthful Tool Integration Matrix

| Tool | Category | Status | License | Integration Architecture |
|---|---|---|---|---|
| **Nmap** | Network Discovery | **LIVE / IMPORT** | NPSL / GPL-2.0 | Subprocess CLI with XML stream parsing; non-ping `-Pn` default. |
| **OWASP ZAP** | Web App Scanner | **LIVE / IMPORT** | Apache-2.0 | REST API client; passive spidering allowed; active attacks gated. |
| **Nikto** | Web Server Scanner | **LIVE / IMPORT** | GPL-2.0 | Subprocess CLI with text log parsing. |
| **Nuclei** | Template Scanner | **LIVE / IMPORT** | MIT | CLI template scanner with JSONL stream parsing. |
| **Tenable Nessus** | Infrastructure Scanner | **IMPORT-ONLY** | Commercial (User-Supplied) | Truthful transparency: offline `.nessus` v2 XML parser. Live mode requires commercial API key. |
| **PortSwigger Burp** | Web App Scanner | **IMPORT-ONLY** | Commercial (User-Supplied) | Offline Burp XML issues export parser. |
| **OpenVAS / GVM** | Vulnerability Scanner | **IMPORT-ONLY** | GPL-3.0-or-later | Offline OpenVAS XML report parser. |
| **Metasploit MSF** | Offensive Validation | **LIVE (GATED & LAB-ONLY)** | BSD-3-Clause | Live `msfrpcd` client. Check modules allowed; exploit modules strictly locked behind human approval. |

---

## 5. Bonus Modules: MITRE ATT&CK & Retest Engine

- **MITRE ATT&CK Enterprise Matrix (v14):**
  - Deterministically maps findings from scanner evidence directly into 14 Enterprise ATT&CK tactics (Reconnaissance, Initial Access, Execution, Defense Evasion, Credential Access, Discovery, Collection, Impact).
  - One-click export to official **MITRE ATT&CK Navigator v4.5 Layer JSON** (`/api/assessments/{id}/mitre/navigator`).
- **Retest & Differential Assessment Engine:**
  - Compares baseline ($t_0$) vs retest ($t_1$) scan runs.
  - Automatically categorizes findings as `NEW`, `RESOLVED`, or `RECURRENT`.
  - Calculates posture risk score delta ($\Delta$) with percentage improvement indicator.
  - Produces a **Selective Retest Action Plan** that recommends only the specific tool probes required to verify remediations without repeating full unneeded scans.

---

## 6. Architecture & Documentation Directory

- [`docs/architecture.md`](docs/architecture.md) — Complete system architecture, component diagrams, execution pipelines.
- [`docs/integration-matrix.md`](docs/integration-matrix.md) — Comprehensive adapter capabilities and licensing assumptions.
- [`docs/threat-model.md`](docs/threat-model.md) — STRIDE security analysis of the platform itself.
- [`docs/safety-and-ethics.md`](docs/safety-and-ethics.md) — Ethical hacking framework and Section 13 safety mapping.
- [`docs/demo/SentinelVAPT_Sample_Client_Report.pdf`](docs/demo/SentinelVAPT_Sample_Client_Report.pdf) — Complete sample client-ready PDF report generated directly by the platform.
- [`DEMONSTRATION_SCRIPT.md`](DEMONSTRATION_SCRIPT.md) — 7-minute judge demonstration script mapping to the 7 live-demo checks.
- [`docs/decisions/`](docs/decisions/) — Architecture Decision Records (ADR-0001 to ADR-0007).
- [`LICENSE`](LICENSE) — Apache License 2.0.
