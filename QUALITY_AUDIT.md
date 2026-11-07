# VulnPilot AI — Quality Audit Report

Date: 2026-11-06 · Environment: Windows, Python 3.14, Node 24 · Backend on `:8000`, frontend on `:5173`
Method: automated script `backend/qa_audit.py` (32 checks) + real browser automation (Playwright/Chromium) + unit tests (`backend/tests/test_core.py`). All numbers below are measured, not estimated.

## 1. Passed tests (32/32 scripted + browser)

| # | Area | Result | Evidence |
|---|---|---|---|
| 1 | Frontend→backend | **PASS** | Real browser: dashboard rendered with live data — `GET /api/dashboard/stats` 200, `/api/integrations/status` 200, Recharts pie/bar charts visible, counts shown (8 assessments, 28 findings at audit time). |
| 2 | Create assessment from UI | **PASS** | Playwright drove the full wizard in a real browser: name → Validate scope → Generate plan (6 steps) → authorization checkbox + statement → Create. Landed on detail page for "UI Driven Test" with plan rendered. |
| 3 | Scope validation + approval checkpoint | **PASS** | Scan before approval → **403** "Human approval required…". After `POST /approve` → `approval_status=approved`. New assessments start `planned / not_requested`. |
| 4 | Import all 3 scanner formats | **PASS** | `nmap-sample.xml` → parsed 2, `zap-sample.json` → parsed 2, `nikto-sample.txt` → parsed 2 (each returns filename + SHA-256). |
| 5 | Normalization / dedup / traceability | **PASS** | 6 unique findings; all rows keep `source_filename`, full SHA-256 and non-empty `evidence` (3 distinct source files). Re-importing the same file: count stable **6 → 6**. |
| 6 | Risk calculation + finding detail | **PASS** | Every stored row satisfies `risk_score = round(cvss × confidence, 2)` (0 mismatches). `GET /api/findings/{id}` returns title + `risk = CVSS 5.0 × confidence 0.9 = 4.5 (severity=medium)`. |
| 7 | PDF report | **PASS** | Downloaded real PDF: **7,154 bytes, `%PDF-1.4`, 3 pages**. Text extracted with pypdf: header, executive summary ("Total unique findings: 6 — info: 2, low: 3, medium: 1"), risk-ranked table with source filenames, per-finding evidence, audit trail. |
| 8 | Persistence after restart | **PASS** | Before restart: 9 assessments, 51 audit rows, finding counts `[0,6,6,6,0,0,7,2,1]`. After `Stop-Process python` + uvicorn restart: **9 assessments, 51 audit rows, identical counts**. |
| 9 | Public targets blocked | **PASS** | `8.8.8.8`, `google.com`, `example.com` → validate `ok=false`; create → **400**; live scan → **403**. Lab host `app.lab` allowed (proves the rule is allowlist, not deny-all). |
| — | Unit tests | **PASS** | `pytest tests -q` → **9/9** (scope, normalization, dedup, risk, PDF) before and after fixes. Frontend `npm run build` succeeds. |

## 2. Failed tests / bugs found & fixed

| Bug | Root cause | Fix | Re-test |
|---|---|---|---|
| Nikto header line `- Nikto v2.5.0` was parsed as a finding | `parse_nikto_text` skipped only `target/server:/starting…`, not the version header | Added `- nikto` to the skip-prefix list in `app/normalization.py` | Re-import → parsed **2** (was 3). pytest still 9/9. |
| ZAP status probe hung (~20 s+) when environment proxies existed | `httpx.get` honoured `trust_env`, routing localhost probe through a proxy | `trust_env=False` + timeout 3 s in `app/scanners/zap.py` (planner LLM call keeps proxy, it is remote) | `/api/integrations/status` returns in seconds; UI no longer hangs on Dashboard (confirmed in real browser). |
| Audit script crashed JSON-parsing the PDF | Test-script bug (`req()` always `json.loads`) | Switched to raw fetch for the PDF check | Script runs to completion: **32/32**. |

No app failures remain open after the fixes.

## 3. Actual integration status (measured on this machine)

| Tool | Binary / API present? | Status (API + UI) | Live execution test |
|---|---|---|---|
| Nmap | **No** (`nmap` not on PATH) | `Import-only` | `POST /scan nmap` → `ok=false`, "nmap is not installed on this system…" (truthful, no fabrication). Code path exists and runs when the binary is present. |
| Nikto | **No** (`nikto` not on PATH) | `Import-only` | Same honest failure. |
| OWASP ZAP | **No** (nothing on `127.0.0.1:8090`) | `Import-only` | `POST /scan zap` → `ok=false`, "ZAP API unreachable: [WinError 10061]…" |

**No live integration is claimed.** Live code paths are implemented (`scanners/*.py`) and become active automatically when the tools are installed; import mode covers all three formats today (see §4 for proof).

## 4. AI planner

- No `LLM_API_KEY` configured → `POST /api/assessments/plan` returns
  `generator: "rule-based fallback (no LLM_API_KEY configured)"`, `is_ai: false`, 6 steps each with a `reason`.
- Audit log records the generator for every created assessment, e.g. `plan_generator=rule-based fallback (no LLM_API_KEY configured)`.
- The LLM path (OpenAI-compatible via `LLM_BASE_URL`/`LLM_MODEL`) is implemented in `app/planner.py` but **was not live-tested** (no key available). It degrades to the same fallback on any error, and says so.

## 5. Known limitations

1. Live scans could not be end-to-end tested here (no Nmap/Nikto/ZAP installed; sandbox network only reaches the servers). The subprocess/API adapters are code-complete and fail loudly and accurately.
2. LLM text generation untested without an API key; fallback is fully functional.
3. Single-user, no authentication — bind backend to `127.0.0.1` (already the default launch).
4. Authorization is a self-attested statement; attach signed RoE if required.
5. `samples/*.xml|json|txt` are **illustrative** scanner outputs, not results of a real scan. Seeded `[DEMO DATA]` assessment is labelled everywhere.
6. Test runs accumulate demo assessments (each `qa_audit.py` run adds one "QA Audit"). The DB was reset after this audit — it currently contains only the seed demo assessment.

## 6. How to reproduce

```bat
:: 1. unit tests (no server needed)
cd backend && python -m pytest tests -q            REM expect: 9 passed

:: 2. launch app
cd .. && start.bat                                 REM backend :8000 + frontend :5173

:: 3. end-to-end audit (creates one "QA Audit" assessment per run)
cd backend && python qa_audit.py                   REM expect: 32/32 passed

:: 4. frontend production build
cd ..\frontend && npm run build                    REM expect: built in ~8s, dist/

:: 5. browser check: open http://localhost:5173 → Dashboard shows live stats;
::    run the wizard (New assessment → … → Create) and approve + import
::    samples/nmap-sample.xml, samples/zap-sample.json, samples/nikto-sample.txt
```

## 7. Verdict

**PASS with documented scope.** All 11 audit areas pass; the one functional bug found (Nikto header) and one responsiveness issue (proxy-honouring ZAP probe) were fixed and re-tested. The only unproven claims are the ones this report does *not* make: live scanner execution and LLM generation, both of which are honestly reported as Import-only / fallback mode on this machine.

---

## 8. Addendum — PDF-metadata false positives (2026-11-06, same day)

**Report:** importing generated report PDFs (e.g. `VulnPilot_..._a5afe6d7.pdf`) produced 26 fake findings titled `% ReportLab …`, `/Contents /MediaBox`, `/Author (anonymous)`, `/BaseFont /Helvetica`, `/PageMode /UseNone`, xref numbers, etc. — none are vulnerabilities.

**Root cause (two layers):**
1. `detect_and_parse` in `backend/app/normalization.py` had a last-resort text fallback: anything not recognized as XML/JSON was fed to `parse_nikto_text`.
2. `parse_nikto_text` accepted **any** line ≥ 12 chars as a Nikto finding (only 8 header prefixes were skipped), so PDF structural lines became "findings" with guessed severities.

**Fix (no history or original files deleted):**
- `detect_and_parse` now **rejects binary/unsupported content** with `ValueError` → import returns **400** with a clear message ("Unsupported file type '.pdf'…" / "Uploaded content looks binary…"). Recognized formats that yield nothing return `[]` and are **never** reinterpreted as text.
- `parse_nikto_text` requires the genuine `+ ` Nikto line prefix, skips the full header set (target/server/ssl-info/etc.), blank lines, short lines (<15 chars), PDF-structure lines (regex for `%PDF`, `/…`, `>>`, `xref` shapes), binary-ish lines, caps at 1000 findings/file. Severity is conservative (default `info`, keyword-raised with `severity_source` disclosure in evidence JSON); no CVEs are invented; raw evidence + filename + SHA-256 preserved.
- Same false-positive sweep: Nmap now reports **open ports only** (closed/filtered previously appeared as "Open port"); empty script outputs skipped. ZAP requires non-empty title **and** (url ∨ evidence). Generic JSON requires a real title (no more invented "Imported finding") and an evidence/asset/url.
- New endpoint `POST /api/assessments/{id}/purge` deletes findings for one exact `source_filename`, leaves uploads untouched, and records a `purge_findings` audit event (the cleanup is part of history, not a silent delete). Rejected imports log `import_rejected`.

**Cleanup actually performed:** 26 fake PDF findings removed from assessment `a5afe6d7` via the purge endpoint (audit event preserved). The assessment went 28 → 2 genuine findings (2× Nmap). Live re-test: uploading the PDF again → **400**. Valid samples still import 2 + 2 + 2.

**Tests:** new `backend/tests/test_parser_hardening.py` (11 tests: PDF rejection ×2, headers-only = 0, valid Nikto = 2 with provenance, Nmap closed-port/empty-script, ZAP evidence rules, JSON not reinterpreted, binary-extension rejection, all 3 samples still import). Full suite now **20/20**, live audit re-run **32/32** (audit events include `import_rejected`, `purge_findings`).

**How to remove bad findings yourself (preserving the audit trail):**
```bash
curl -X POST http://127.0.0.1:8000/api/assessments/<assessment-id>/purge \
  -H "Content-Type: application/json" \
  -d '{"source_filename": "VulnPilot_<Name>_<id8>.pdf", "reason": "PDF metadata mis-parsed as findings"}'
# → {"ok": true, "removed": 26, ...} and a purge_findings entry in /api/audit;
# the uploaded PDF in backend/uploads/ and the assessment itself are untouched.
```

---

## 9. Final end-to-end verification (2026-11-06, same day)

**Current finding inventory (measured):**
- `VulnPilot Local Security Audit` (`a5afe6d7`): **2 findings** — the two Nmap open ports.
- `QA Audit` (`b60e4936`): 6 findings (2×Nmap + 2×ZAP + 2×Nikto).
- `[DEMO DATA] Juice Shop Lab`: 8 (2 labelled demo + 2×Nmap + 2×ZAP + 2×Nikto).

**Step 2 — Nmap findings vs XML evidence: MATCH.** `samples/nmap-sample.xml`
SHA-256 `486ee589…` = SHA-256 stored on both findings. The XML contains exactly
two `<port>` elements (80 open/http, 3000 open/http); the two stored findings are
exactly those ports with matching evidence (`port 80 state=open service=http`),
evidence JSON, confidence 1.0, risk 0.0 (info, CVSS 0 × 1.0). Nothing added,
nothing altered; the XML's `<service product/version>` fields are not copied into
finding rows (subset, not fabrication — every stored value exists in the XML).

**Steps 3–4 — why "zero ZAP/Nikto findings" in that assessment: they were never
imported there.** The audit trail for `a5afe6d7` shows imports of only
`nmap-sample.xml.xml` and the (now-rejected) PDF — ZAP/Nikto samples were never
uploaded to that assessment, so there was nothing to parse. All three formats
were verified again against the live code (in-process `detect_and_parse`):
**nmap-sample.xml → 2, zap-sample.json → 2 (medium + low, evidence preserved),
nikto-sample.txt → 2 (info, raw `+` lines preserved)** — and the same code
imported all three end-to-end into a fresh assessment below.

**Steps 6–8 — fresh E2E (`Final E2E`, id `91cb6c72`) + browser re-check, all live:**
- create 200 (`planned/not_requested`, 6-step plan) → approve 200
- import nikto 2 → nmap 2 → zap 2 → 6 unique findings
- finding detail 200 (`risk = CVSS 5.0 × confidence 0.9 = 4.5`)
- audit trail: `assessment_created, approval, import ×3` (+ `import_rejected` for the PDF attempt)
- PDF upload → **400** "Unsupported file type"; PDF download 6,974 bytes, 3 pages, **every stored finding title found in extracted text** (0 missing)
- Dashboard renders with live data in a real browser (Playwright snapshot shows the dashboard heading + stats)

**Step 9 — all automated tests:** unit **20/20** (`pytest tests -q`), live audit **32/32**
(`qa_audit.py`), frontend build succeeds (~14 s, chunk-size warning only).
**Step 10 — no new critical bugs found** in this pass; nothing to fix.

**Verdict: implemented and verified as documented.** No live scanner execution is
claimed (binaries/API absent on this machine; honest Import-only). No finding was
fabricated or edited to inflate counts — the count went 28 → 2 in `a5afe6d7`
because 26 PDF-metadata rows were junk, and 2 Nmap findings remain because they
are genuinely in the XML.
