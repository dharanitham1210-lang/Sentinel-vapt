# SentinelVAPT: Truthful Integration Matrix

**Platform:** SentinelVAPT (Autonomous, Evidence-Driven Security Assessment Platform)  
**Standard:** Full Integration Transparency & Licensing Integrity (Non-Negotiable Rule 6)  
**Last Updated:** November 2026  

---

## 1. Authoritative Operational Capabilities

SentinelVAPT dynamically probes tool availability and enforces honest reporting of adapter capabilities. **We do not claim commercial tools operate live when they require proprietary licenses**, and we do not misrepresent complex multi-container daemon tools.

| Tool Name | Category | Operational Mode | License Model | Live Execution Prerequisites | Import Support | Known Limitations & Assumptions |
|---|---|---|---|---|---|---|
| **Nmap** | Network Discovery | **LIVE / IMPORT** | NPSL / GPL-2.0 (Process Boundary) | `nmap` binary on system PATH. | `.xml`, `.json`, raw stdout | Raw SYN scans (`-sS`) require elevated administrator / root privileges; unprivileged execution defaults to TCP connect. Target host must be reachable over network. |
| **OWASP ZAP** | Web Application Scanner | **LIVE / IMPORT** | Apache-2.0 | Active ZAP daemon listening on configured port (e.g., `127.0.0.1:8090`). | `.json`, `.xml` alerts export | Passive spidering is unconstrained. Active attack modules with payloads are **strictly locked behind the Human Approval Gate**. |
| **Nikto** | Web Server Scanner | **LIVE / IMPORT** | GPL-2.0 (Process Boundary) | `nikto` binary on system PATH. | `.txt`, `.json`, `.xml` | Can generate high traffic volumes; non-stealthy by design. Requires active HTTP/HTTPS listener. |
| **ProjectDiscovery Nuclei** | Template-Based Vulnerability Scanner | **LIVE / IMPORT** | MIT | `nuclei` binary on system PATH. | `.jsonl`, `.json` stream | Requires downloaded community templates; template rate limits must be configured to prevent target exhaustion. |
| **Tenable Nessus** | Host & Infrastructure Scanner | **IMPORT-ONLY** (Default) / Config-Required | Commercial / Proprietary | Valid commercial Tenable Nessus / Tenable.io license and configured REST API keys (`NESSUS_API_KEY`, `NESSUS_API_URL`). | **Full `.nessus` v2 XML Support** | **Never falsely claimed as Live by default.** Standard mode is offline ingestion of verified `.nessus` reports. Live scanning requires enterprise license. |
| **PortSwigger Burp Suite** | Web Application Scanner | **IMPORT-ONLY** (Default) / Config-Required | Commercial / Proprietary | Valid Burp Suite Enterprise Edition REST API agent (`BURP_ENTERPRISE_API_URL`). | **Full Burp XML Issues Export Support** | **Never falsely claimed as Live by default.** Ingests XML issue exports from Burp Suite Pro. Live REST invocation is gated behind commercial enterprise licensing. |
| **OpenVAS / Greenbone (GVM)** | Vulnerability Management | **IMPORT-ONLY** (Default) / Live via GMP | GPL-3.0-or-later (Process / Protocol Boundary) | Reachable Greenbone GMP daemon (`gvmd`) or local container stack socket. | **Full OpenVAS XML Report Support** | Greenbone Community Edition requires significant container resources and hours for feed synchronization. Truthfully provided as Import-Only for standard deployments. |
| **Metasploit Framework (MSF)** | Offensive Validation & Exploitation | **LIVE (HUMAN-APPROVED & LAB-ONLY)** | BSD-3-Clause | Active `msfrpcd` daemon or `msfconsole` binary on system PATH. | Live RPC session / msf output log | **Strict Non-Negotiable Rule 3 Enforcement:** Auxiliary check modules allowed for non-destructive validation. **Exploit modules strictly blocked without explicit human approval token, target typing confirmation, and confirmed lab-only flag.** |

---

## 2. Dynamic Integration Probing

The platform does not rely on static text. It dynamically queries adapter health via `/api/integrations/matrix`:
1. **Binary Check:** Probes `shutil.which()` for CLI tools.
2. **REST API Check:** Issues a non-blocking timeout probe (0.6s) to configured local API endpoints (e.g. ZAP, GMP).
3. **Licensing Check:** Verifies user-supplied credentials before enabling commercial endpoints.

---

## 3. Supported Evidence Ingestion Formats

All imported artifacts are hashed with SHA-256 upon receipt and stored in content-addressed storage (`artifacts/{aid}/{sha256}.raw`):
- **Nmap:** Standard `-oX` XML format and JSON outputs.
- **OWASP ZAP:** JSON alerts export (`{"site": [{"alerts": [...]}]}`).
- **Nikto:** Standard stdout text logs (`+ OSVDB-XXXX: ...`).
- **Nuclei:** JSON-lines stream (`{"template-id": "...", "info": {...}}`).
- **Nessus:** `.nessus` v2 XML export (`<NessusClientData_v2>`).
- **Burp Suite:** Burp XML issue export (`<issues><issue>...</issues>`).
- **OpenVAS:** Greenbone XML report format (`<report><results><result>...</report>`).
- **Metasploit:** Live RPC output transcripts.

