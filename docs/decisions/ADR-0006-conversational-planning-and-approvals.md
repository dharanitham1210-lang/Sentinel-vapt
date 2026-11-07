# ADR 0006: Conversational Agent Planning, State Memory Loop, and Human Approval Gates

## Status
Accepted

## Context
Autonomous security agents risk running out of control, generating repetitive scans, executing destructive exploits, or hallucinating vulnerabilities.
Non-negotiable rule 2 mandates deterministic scope gating for every tool invocation.
Non-negotiable rule 3 mandates explicit human approval for active exploitation (with approver identity, timestamp, exact command/parameters, target typing confirmation, justification, outcome, and lab-only verification).
Non-negotiable rule 5 mandates Pydantic schema validation and a grounding validator that rejects ungrounded CVEs.

## Decision
1. **Conversational Agent Architecture:**
   - Intent parsing (`ConversationalAgent`) translates natural-language goals into structured `AssessmentPlanSchema` steps with tool, parameters, rationale, risk class (`passive`, `intrusive`, `active`), and estimated duration.
   - Every request is validated by `ScopeGate` before any planning or execution begins; out-of-scope targets trigger an immediate hard rejection and an audit event.
2. **Grounding Validator:**
   - `GroundingValidator` verifies that any CVE emitted by LLMs is either present in the raw tool artifacts for that assessment or exists in the authoritative local NVD cache. Hallucinated CVEs (e.g. `CVE-2099-XXXXX`) are blocked from publication.
3. **Adaptive State Machine (Plan -> Act -> Observe -> Reflect -> Replan):**
   - `AssessmentStateMachine` maintains structured engagement memory: discovered assets, open ports, fingerprinted technologies (e.g. WordPress, Apache, Nginx), and executed action hashes $H(tool, target, params)$.
   - Automatically synthesizes targeted next-step proposals (e.g., discovered HTTP listener $\to$ proposes ZAP & Nikto; critical RCE $\to$ proposes validation).
   - Every proposal explicitly documents "Why this scan now" with direct foreign-key references to triggering Evidence IDs.
4. **Approval Gate Service:**
   - `ApprovalService` manages pending, approved, denied, and expired approval tokens.
   - Enforces target identifier re-typing confirmation to prevent accidental clicks.
   - Rejects execution on expired tokens or unconfirmed lab flags.

## Consequences
- Guaranteed human-in-the-loop oversight for all consequential or destructive operations.
- Prevention of circular/redundant scans through cryptographic action hashing.
- Complete elimination of hallucinated vulnerability identifiers.

