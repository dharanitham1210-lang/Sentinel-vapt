"""Assessment Diff & Retest Workflow Engine.

Compares findings between two assessments (e.g. Baseline t0 vs Retest t1).
Computes:
- New findings (introduced since baseline)
- Resolved findings (remediated)
- Recurrent findings (still present, possibly with severity shifts)
- Overall risk trend (+ / - risk score delta)
- Retest Action Plan: selective scanner commands to verify specific findings.
"""
from __future__ import annotations

import json
from typing import Any


def _finding_fingerprint(f: dict[str, Any]) -> str:
    """Stable fingerprint for cross-assessment finding matching."""
    if f.get("dedup_key"):
        return str(f["dedup_key"])
    asset = (f.get("asset") or "").strip().lower()
    cwe = (f.get("cwe") or "").strip().upper()
    cve = (f.get("cve") or "").strip().upper()
    title = (f.get("title") or "").strip().lower()
    return f"{asset}|{cwe}|{cve}|{title}"


def compute_assessment_diff(
    current_assessment: dict[str, Any],
    prior_assessment: dict[str, Any],
    current_findings: list[dict[str, Any]],
    prior_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute difference and retest plan between current and prior assessments."""
    curr_map = {_finding_fingerprint(f): f for f in current_findings}
    prior_map = {_finding_fingerprint(f): f for f in prior_findings}

    new_keys = set(curr_map.keys()) - set(prior_map.keys())
    resolved_keys = set(prior_map.keys()) - set(curr_map.keys())
    recurrent_keys = set(curr_map.keys()) & set(prior_map.keys())

    new_findings = [curr_map[k] for k in new_keys]
    resolved_findings = [prior_map[k] for k in resolved_keys]
    recurrent_findings = []

    for k in recurrent_keys:
        cf = curr_map[k]
        pf = prior_map[k]
        recurrent_findings.append({
            "current": cf,
            "prior": pf,
            "severity_changed": cf.get("severity") != pf.get("severity"),
            "risk_delta": round(float(cf.get("risk_score") or 0.0) - float(pf.get("risk_score") or 0.0), 2),
        })

    # Sort each list by risk score descending
    new_findings.sort(key=lambda x: float(x.get("risk_score") or 0.0), reverse=True)
    resolved_findings.sort(key=lambda x: float(x.get("risk_score") or 0.0), reverse=True)

    curr_risk = round(sum(float(f.get("risk_score") or 0.0) for f in current_findings), 2)
    prior_risk = round(sum(float(f.get("risk_score") or 0.0) for f in prior_findings), 2)
    risk_delta = round(curr_risk - prior_risk, 2)
    risk_percentage_change = (
        round(((curr_risk - prior_risk) / prior_risk) * 100, 1) if prior_risk > 0 else 0.0
    )

    # Compute severity breakdowns
    def _sev_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    curr_counts = _sev_counts(current_findings)
    prior_counts = _sev_counts(prior_findings)
    sev_deltas = {sev: curr_counts[sev] - prior_counts[sev] for sev in curr_counts}

    # Selective Retest Recommendations
    retest_recommendations = []
    # For resolved findings, suggest how to verify resolution
    for rf in resolved_findings:
        src = (rf.get("source") or "scanner").lower()
        target = rf.get("url") or rf.get("asset") or current_assessment.get("target")
        retest_recommendations.append({
            "finding_title": rf.get("title"),
            "severity": rf.get("severity"),
            "status": "resolved_verification_needed",
            "recommended_tool": src,
            "target": target,
            "verification_goal": f"Verify {rf.get('title')} is no longer detectable on {target}",
            "rationale": f"Previously observed via {src} with CVSS {rf.get('cvss', 'N/A')}.",
        })

    # For recurrent findings, suggest validation
    for item in recurrent_findings:
        cf = item["current"]
        src = (cf.get("source") or "scanner").lower()
        target = cf.get("url") or cf.get("asset") or current_assessment.get("target")
        retest_recommendations.append({
            "finding_title": cf.get("title"),
            "severity": cf.get("severity"),
            "status": "recurrent_remediation_needed",
            "recommended_tool": src,
            "target": target,
            "verification_goal": f"Verify remediation for recurrent finding on {target}",
            "rationale": f"Still active with risk score {cf.get('risk_score', 'N/A')}.",
        })

    return {
        "current_assessment": {
            "id": current_assessment.get("id"),
            "name": current_assessment.get("name"),
            "target": current_assessment.get("target"),
            "total_findings": len(current_findings),
            "total_risk": curr_risk,
            "severity_counts": curr_counts,
        },
        "prior_assessment": {
            "id": prior_assessment.get("id"),
            "name": prior_assessment.get("name"),
            "target": prior_assessment.get("target"),
            "total_findings": len(prior_findings),
            "total_risk": prior_risk,
            "severity_counts": prior_counts,
        },
        "summary": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "recurrent_count": len(recurrent_findings),
            "risk_delta": risk_delta,
            "risk_percentage_change": risk_percentage_change,
            "severity_deltas": sev_deltas,
            "posture_improved": risk_delta < 0,
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "recurrent_findings": recurrent_findings,
        "retest_recommendations": retest_recommendations[:20],
    }

