# ADR 0005: Multi-Tool Finding Correlation and Explainable Risk Scoring

## Status
Accepted

## Context
Non-negotiable rule 1 mandates: "Never fabricate scanner output, CVEs, CVSS scores, evidence, or risk scores. Every finding must trace to a raw tool artifact. If data is missing, show 'Not available'." In addition, running multiple scanning tools against the same infrastructure produces duplicate, conflicting, or partial findings. We must deduplicate them without destroying distinct per-tool evidence, calibrate confidence based on corroboration, and provide a reversible 1-click unmerge capability.

## Decision
1. **Composite Correlation Identity:**
   - Primary: Normalized CVE + Target Asset + Port.
   - Secondary: CWE + Target Asset + Path/Parameter.
   - Tertiary: Normalized Canonical Vulnerability Title + Target Asset + Port.
2. **Corroboration Confidence Boost:**
   - Multi-tool corroboration (e.g., OpenVAS + Nessus confirming an identical flaw) elevates finding confidence to $\ge 0.90$ and elevates status from `suspected` to `confirmed`.
   - Single-source detections based purely on version strings are classified as `suspected` (confidence capped at 0.65) and flagged with automated false-positive triage inferences regarding OS vendor backports.
3. **Preservation of Distinct Raw Evidence & Merge Log:**
   - Findings maintain distinct, attributable evidence sections preserving each contributing tool's name, source artifact, and raw text.
   - A structured `merge_log` explicitly records the justification for merging, contributing tools, and confidence calibration.
   - Original unmerged finding dictionaries are preserved in `_unmerged_items` enabling immediate 1-click unmerge.
4. **Transparent Risk Formula:**
   $\text{Risk} = \min\left(10.0, \text{CVSS} \times \text{Exposure Factor} \times \text{Exploit Factor} \times \text{Criticality Factor} \times \text{Confidence}\right)$
   - If CISA KEV or EPSS exploit intelligence is absent, the engine reports `"Not available (no live CISA/EPSS match; factor default 1.00)"` and never invents a fabricated score.

## Consequences
- High-fidelity correlation that reduces analyst fatigue while preserving complete evidentiary provenance.
- Defensible mathematical explanation for every risk priority in executive reports.

