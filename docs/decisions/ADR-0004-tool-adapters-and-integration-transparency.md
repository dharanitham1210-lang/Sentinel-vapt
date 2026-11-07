# ADR 0004: Tool Adapters and Truthful Integration Matrix Architecture

## Status
Accepted

## Context
Non-negotiable rule 6 requires integration transparency: building and displaying a truthful Integration Matrix (Live / Import-only / Planned / Unsupported) for all tools without fabricating live capabilities for commercial tools (Nessus, Burp Suite Pro) or tools requiring heavy local daemon stacks (OpenVAS). Non-negotiable rule 3 mandates that offensive execution (Metasploit) is strictly gated by recorded human approval and verified to run in lab environments only. Non-negotiable rule 1 mandates that every finding trace back to a raw tool artifact with verified SHA-256 integrity.

## Decision
1. **Common Tool Adapter Hierarchy:** All adapters inherit from `BaseAdapter` (`backend/app/adapters/base.py`) which defines:
   - Declarative capabilities, supported formats, limitations, assumptions.
   - Dynamic `get_health()` probe verifying binary availability on system PATH or live API reachability.
   - Argument-array command generation (strictly no shell string concatenation) to prevent command injection.
2. **Dynamic Integration Matrix:** `AdapterRegistry` evaluates runtime availability and generates an honest matrix:
   - **Nmap:** Live (CLI + XML stream) when binary on PATH; Import-only otherwise.
   - **OWASP ZAP:** Live when API is responsive at configured port; active scan gated; Import-only otherwise.
   - **Nikto:** Live (CLI) when binary on PATH; Import-only otherwise.
   - **ProjectDiscovery Nuclei:** Live (CLI + JSONL stream) when binary on PATH; Import-only otherwise.
   - **Tenable Nessus:** Declared as Import-Only (.nessus v2 XML parser). Never falsely reported as Live unless commercial license credentials are explicitly configured.
   - **PortSwigger Burp Suite:** Declared as Import-Only (Burp XML issue export parser).
   - **OpenVAS / Greenbone:** Declared as Import-Only (GVM XML report parser).
   - **Metasploit Framework:** Live but strictly approval-gated and lab-only. Auxiliary check modules are allowed; exploit modules raise `APPROVAL_REQUIRED` unless a valid, unexpired, lab-confirmed approval token is provided.
3. **Content-Addressed Artifact Storage:** All raw scanner outputs (uploaded or generated) are hashed via SHA-256 and stored as immutable `.raw` artifacts indexed by byte length, line count, and source tool. Every finding links to an artifact ID (`art-XXXXXXXXXXXX`).

## Consequences
- Guaranteed compliance with licensing and operational transparency.
- 1-click traceability from findings back to verified raw tool outputs.

