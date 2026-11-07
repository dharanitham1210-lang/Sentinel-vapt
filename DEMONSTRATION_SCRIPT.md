# SentinelVAPT: 7-Minute Judge Demonstration Script

**Platform:** SentinelVAPT (Autonomous, Evidence-Driven Security Assessment Platform)  
**Track:** AI Agent for Automated Penetration Testing (DataOps Innovation Hackathon)  
**Execution Environment:** Isolated Lab Network (`172.28.0.0/16`)  

---

## Walkthrough Summary (Mapping to the 7 Live-Demo Checks)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             7 LIVE-DEMO CHECKS                                   │
├─────────────────────────┬─────────────────────────┬──────────────────────────────┤
│ 1. Scope Gate Blocking  │ 2. Adaptive Replanning  │ 3. Multi-Tool Ingestion      │
│    (Deterministic Code) │    (Evidence-Triggered) │    (Nmap, ZAP, Nessus, Burp) │
├─────────────────────────┼─────────────────────────┼──────────────────────────────┤
│ 4. Correlation & Unmerge│ 5. 1-Click Traceability │ 6. Human Approval Gate       │
│    (Corroboration Boost)│    (Report -> Artifact) │    (Target Typing Confirm)   │
├─────────────────────────┴─────────────────────────┴──────────────────────────────┤
│ 7. Cryptographic Audit Integrity Verification (SHA-256 Hash Chained Ledger)      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

### Step 1: Launch & Truthful Integration Matrix (60 seconds)
1. **Launch:** Run `make up` or `start.bat`. Open browser to `http://localhost:5173`.
2. **Design Discipline:** Highlight the restrained enterprise console (slate neutral palette, deep teal accent, 1px precision borders, tabular numerals, zero AI-sparkles or glassmorphism).
3. **Truthful Integration Matrix (Check 3 & Non-Negotiable Rule 6):**
   - Navigate to **Integration Matrix**.
   - Show the dynamic status of all 8 tools: Nmap, ZAP, Nikto, Nuclei, Nessus, Burp, OpenVAS, Metasploit.
   - Point out that commercial tools (Nessus, Burp) are truthfully displayed as **Import-Only** with clear licensing disclosures, and Metasploit is marked as **Live (Approval Gated & Lab-Only)**.

---

### Step 2: The Deterministic Scope Gate (Check 1 & Non-Negotiable Rule 2) (60 seconds)
1. Navigate to **Engagements & Scope**.
2. Open the **Scope Gate Sandbox & Simulator**.
3. Type a public internet address: `8.8.8.8` &rarr; click **Check Scope Gate**.
   - Result: **HARD REJECT (OUT OF SCOPE)** with rule `PUBLIC_IP_BLOCKED`.
4. Try a URL userinfo trick: `http://authorized.local@evil.com` &rarr; click **Check Scope Gate**.
   - Result: **HARD REJECT**. Host correctly resolved as `evil.com`, rejecting spoofing attempt.
5. Emphasize: *This is not an LLM prompt. This is 100% deterministic Python code that cannot be jailbroken.*
6. Open **Audit Ledger**: Show the immediate `SCOPE_REJECT` audit record committed to the cryptographic ledger.

---

### Step 3: Conversational Planning & Adaptive Replanning (Check 2) (90 seconds)
1. Navigate to **Agent Workspace**.
2. In the conversational input box, type:
   `"Run external assessment on 127.0.0.1 with focus on web services and OWASP Top 10"`
3. Click **Send**.
4. Review the generated **Auditable Assessment Plan**:
   - Ordered steps, tool per step, parameters, rationale, and risk class badges (`passive`, `intrusive`, `active`).
5. **Adaptive State Loop:**
   - Run Nmap scan or import scan output.
   - Show the **Adaptive Replanning Engine** immediately detecting the open HTTP port (e.g. port 80/3000) and synthesizing targeted ZAP and Nikto proposals.
   - Highlight the **"Why this scan now"** field citing the exact triggering Evidence ID!

---

### Step 4: Multi-Tool Correlation & Reversible Unmerge (Check 4) (60 seconds)
1. Navigate to **Findings & Evidence**.
2. Point out cross-tool corroborated findings (e.g., Apache or Log4j detected across multiple tools).
3. Click on a corroborated finding to open the **Finding Drawer**:
   - **Corroboration Confidence Boost:** Show confidence elevated from 0.80 to 0.95.
   - **Merge Log:** Displays the exact merge reason and contributing tools.
   - **1-Click Unmerge:** Show that individual tool observations are preserved in `_unmerged_items`.
   - **Observed vs. AI Inference:** Show solid neutral **Observed Evidence** badge distinctly separated from outlined **AI Inference** badge.

---

### Step 5: 1-Click Evidence Traceability (Check 5 & Non-Negotiable Rule 1) (45 seconds)
1. In the Finding Drawer, click **Inspect Artifact** on any finding.
2. The **Raw Artifact Modal** opens instantly:
   - Displays the exact raw machine file (XML/JSON/log).
   - Verifies the SHA-256 hash.
   - Proves zero hallucination: every claim maps directly to machine bytes in $\le 2$ clicks.

---

### Step 6: Dual Human Approval Gate & Lab-Only Exploitation (Check 6 & Rule 3) (60 seconds)
1. In the Workspace, locate an active Metasploit validation proposal or trigger an active exploit module.
2. Show that execution is physically blocked with **"Approval Required"**.
3. Navigate to **Approvals Center** &rarr; click **Review Request**.
4. The **Approval Modal** appears:
   - Shows target, module, command, justification, and **Lab-Only: Confirmed** status.
   - Attempt to click Authorize with an empty field &rarr; disabled.
   - Type the target confirmation identifier (`127.0.0.1` or `10.10.20.5`) &rarr; click **Authorize & Execute**.
5. The approval is recorded, signed by the Lead Analyst, and committed to the audit chain.

---

### Step 7: Cryptographic Audit Ledger & Client-Ready Report (Check 7 & Check 9) (45 seconds)
1. Navigate to **Audit Ledger**.
2. Click **Verify Audit Integrity**:
   - The engine walks the SHA-256 chain and displays:
     `AUDIT CHAIN STATUS: VERIFIED INTACT // UNTAMPERED (N blocks chained)`
3. Click **Export VAPT PDF** from the top bar:
   - Show the downloaded publication-grade PDF covering sections 7.1–7.6:
     - 7.1 Executive Summary with Scope Boundaries
     - 7.2 Methodology (NIST SP 800-115 / OWASP WSTG) & Asset Inventory
     - 7.3 Severity Distribution & Prioritized Risk Matrix
     - 7.4 Detailed Findings with Clickable Traceable Evidence IDs (`EVID-XXXX`)
     - 7.5 Business & Technical Impact + Remediation
     - 7.6 Limitations, Failures & Recorded Human Approvals Log
     - Appendices with Truthful Integration Matrix and Cryptographic Ledger Verification.
