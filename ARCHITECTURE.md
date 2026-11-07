# Architecture

## Overview

```
┌──────────────────────────────┐      REST/JSON       ┌─────────────────────┐
│ Frontend (React + Vite)      │ ◄──────────────────► │ Backend (FastAPI)   │
│  Dashboard · Wizard · Detail │   /api/* (port 8000) │  SQLite (vulnpilot.db)
│  Recharts · Tailwind         │                      └─────────┬───────────┘
└──────────────────────────────┘                                │
                                                ┌───────────────┼────────────────┐
                                                ▼               ▼                ▼
                                      ┌──────────────┐ ┌─────────────┐ ┌──────────────┐
                                      │ Scope engine │ │ LLM planner │ │ ReportLab PDF│
                                      │ (allowlist)  │ │ (+ fallback)│ │ (VAPT report)│
                                      └──────────────┘ └─────────────┘ └──────────────┘
                                                        ┌───────────────────┐
                                                        │ Scanner adapters  │
                                                        │ nmap (subprocess) │
                                                        │ nikto (subprocess)│
                                                        │ ZAP (HTTP API)    │
                                                        └───────────────────┘
```

## Data model (SQLite)

- `assessments` – name, target, scope, allowed targets, authorization statement,
  status, plan JSON, approval status, demo flag.
- `findings` – normalized common format (title, severity, confidence, CVSS,
  asset/url/parameter, source + filename + sha256, evidence, remediation, CWE/CVE,
  dedup key, risk score + reason, demo flag).
- `scan_runs` – tool, target, command, stdout/stderr, import count, status.
- `audit_logs` – append-only event trail.

## Pipeline

1. **Validate scope** (`app/scope.py`): every target must be localhost/private/
   lab-suffix; public IPs/hostnames rejected.
2. **Plan** (`app/planner.py`): LLM via env-configured OpenAI-compatible endpoint,
   else deterministic fallback — always labelled with its generator.
3. **Collect**: live execution (subprocess/API) or file import with SHA-256.
4. **Normalize** (`app/normalization.py`): nmap XML/JSON, ZAP JSON, Nikto text,
   generic JSON → common finding schema; source evidence preserved verbatim.
5. **Dedupe & score** (`app/dedup.py`): key = title|asset|url|parameter;
   risk = CVSS × confidence with an explicit reason string.
6. **Report** (`app/report.py`): PDF built only from stored evidence + audit trail.

## Error handling philosophy

Truthful degradation: if a scanner binary/API is absent, the app reports
Import-only and guides the user to upload real output — it never invents results.
