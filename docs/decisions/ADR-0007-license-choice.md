# ADR 0007: Open Source License Selection (Apache-2.0)

## Status
Accepted

## Context
SentinelVAPT orchestrates, ingests from, or interacts with multiple third-party tools and libraries, each carrying distinct open-source or commercial licenses:
- **Core Dependencies:** FastAPI (MIT), Pydantic (MIT), SQLAlchemy (MIT), ReportLab (BSD-like / Free Software), pytest (MIT), httpx (BSD-3-Clause).
- **Process & Protocol Boundaries:**
  - Nmap (GPL-2.0 via process boundary / subprocess XML stream)
  - OWASP ZAP (Apache-2.0 via REST API)
  - Nikto (GPL-2.0 via process boundary / CLI)
  - Nuclei (MIT via CLI)
  - Metasploit (BSD-3-Clause via CLI / RPC)
  - Greenbone / OpenVAS (GPL-3.0 via GMP protocol and offline XML report parsing)
  - Nessus & Burp Suite (Commercial user-supplied exports)

## Decision
We selected the **Apache License 2.0** for SentinelVAPT:
1. **Permissive Commercial Usability:** Permissive terms allow deployment and integration by enterprise security consultancies and clients.
2. **Patent Protection Clause:** Section 3 provides explicit patent grant and protection against patent litigation, which is critical for enterprise security tooling.
3. **Boundary Integrity:** By communicating with copyleft scanners (Nmap, Nikto, GVM) strictly through external process boundaries (subprocess standard input/output) and network protocols (REST/GMP), the core SentinelVAPT distribution avoids derivative work triggers under GPL-2.0 and GPL-3.0.

## Consequences
- Legally robust and commercially friendly architecture.
- Full compatibility with all direct software dependencies.

