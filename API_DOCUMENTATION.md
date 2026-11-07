# API Documentation

Base: `http://127.0.0.1:8000` · Interactive docs: `/docs`

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness + time |
| GET | `/api/dashboard/stats` | Counts, severity/source breakdown, recent assessments |
| GET | `/api/integrations/status` | Live / Import-only status for Nmap, Nikto, ZAP |
| GET | `/api/audit` | Audit log (`?assessment_id=`) |
| POST | `/api/assessments/validate-scope` | `{target, scope, allowed_targets}` → ok/checks/reasons |
| POST | `/api/assessments/plan` | `{target, scope, allowed_targets}` → AI plan (labelled generator) |
| POST | `/api/assessments` | Create (requires scope OK + authorization) |
| GET | `/api/assessments` / `/{id}` | List / detail (includes plan + counts) |
| POST | `/api/assessments/{id}/approve` | `{approved, note}` — human checkpoint |
| POST | `/api/assessments/{id}/purge` | Purge findings from one exact `source_filename` (audit-logged) |
| POST | `/api/assessments/{id}/import` | Multipart file upload → normalized, deduped findings (`400` if the file is binary/unsupported, e.g. PDF) |
| POST | `/api/assessments/{id}/scan` | `{tool: nmap\|nikto\|zap, target}` — needs approval + scope |
| GET | `/api/assessments/{id}/findings` | Findings (`?severity=`) sorted by risk |
| GET | `/api/findings/{id}` | Single finding detail |
| GET | `/api/assessments/{id}/report` | PDF download |

## Examples

Create (lab target only):

```bash
curl -X POST http://127.0.0.1:8000/api/assessments -H "Content-Type: application/json" -d "{
  \"name\": \"Juice Shop lab\", \"target\": \"127.0.0.1\",
  \"scope\": \"Local vulnerable training app\", \"allowed_targets\": [\"127.0.0.1\"],
  \"authorized\": true, \"auth_statement\": \"I own this lab VM.\"
}"
```

Public target (expected: 400):

```bash
curl -X POST http://127.0.0.1:8000/api/assessments -H "Content-Type: application/json" -d "{
  \"name\": \"bad\", \"target\": \"8.8.8.8\", \"scope\": \"x\",
  \"allowed_targets\": [\"8.8.8.8\"], \"authorized\": true, \"auth_statement\": \"abcdefghij\"
}"
```

Import:

```bash
curl -X POST http://127.0.0.1:8000/api/assessments/<id>/import -F "file=@samples/zap-sample.json"
```

Import formats accepted: Nmap XML / JSON, OWASP ZAP JSON (`{"alerts": [...]}`),
Nikto text, generic findings JSON (`findings`/`vulnerabilities`/`results` arrays).
