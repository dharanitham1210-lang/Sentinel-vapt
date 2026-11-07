# Security model

## Hard rules

1. **Authorized targets only.** `app/scope.py` allows strictly:
   - `localhost`, `host.docker.internal`, `host.containers.internal`, `::1`, `127.x`
   - Private ranges `10/8`, `172.16/12`, `192.168/16`, link-local `169.254/16`
   - Hostnames ending `.local`, `.lan`, `.home`, `.internal`, `.intranet`, `.lab`,
     `.test`, `.corp`
   - Hostnames that resolve **exclusively** to private addresses
   Everything else (public IPs, public DNS names) is rejected at validation time,
   again at scan time, and again per-target before execution.
2. **Explicit authorization** is mandatory: checkbox + written statement stored on
   the assessment and mirrored in audit logs.
3. **Human approval checkpoint:** live scans require `approval_status = approved`;
   approval is separate from authorization and is itself audit-logged.
4. **Conservative scanner defaults:** Nmap `-sV -Pn --top-ports 100`, Nikto with
   `-ask no`; timeouts enforced; no exploit modules are exposed or implemented.
5. **No fabricated evidence.** Findings originate only from parsed scanner output;
   imports record filename + SHA-256; the PDF explicitly states that AI text is
   explanatory only. Sample/demo artifacts are labelled DEMO DATA.
6. **Local-first storage.** SQLite file + uploads stay on your machine; no
   telemetry. LLM calls are opt-in via environment variables.

## Known limitations (MVP)

- No authentication/multi-user — single-user local tool; bind to `127.0.0.1`.
- Authorization statements are self-attested; attach signed RoE documents if needed.
- ZAP live mode requires a running ZAP daemon with the API enabled.
- Scan rate control relies on tool defaults; add `--max-rate` for fragile labs.

See SECURITY notes in each module for enforcement points.
