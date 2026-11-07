"""Unified Vulnerability Normalization, Correlation, and Deduplication Engine.

Maintains:
1. Universal Finding Schema across Nmap, ZAP, Nikto, Nuclei, Nessus, Burp, OpenVAS, Metasploit.
2. Cross-tool corroboration: findings verified by multiple tools gain confidence and 'confirmed' status.
3. Single-source banner detections remain 'suspected' with lower confidence.
4. Transparent Merge Log detailing exact merge reasons.
5. Reversible 1-click unmerge by preserving distinct original records in `_unmerged_items`.
6. False-positive triage heuristics surfaced as AI inference with explicit reasoning.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .normalization import SEVERITY_ORDER, norm_severity
from .risk import calculate_risk


def generate_correlation_key(f: Dict[str, Any]) -> str:
    """Generate composite correlation key.

    Matches findings that refer to the same vulnerability on the same asset:
    1. If a standardized CVE is present -> match on (asset, port, CVE).
    2. Else if a CWE and endpoint/parameter are present -> match on (asset, CWE, endpoint_path).
    3. Else match on normalized title + asset + port.
    """
    asset = (f.get("asset") or "").strip().lower()
    port = str(f.get("parameter") or f.get("port") or "").split("/")[0].strip()
    cve = (f.get("cve") or "").strip().upper()
    cwe = (f.get("cwe") or "").strip().upper()
    url = (f.get("url") or "").strip().lower().split("?")[0].rstrip("/")

    if cve and cve.startswith("CVE-"):
        return f"cve|{asset}|{port}|{cve}"

    if cwe and cwe.startswith("CWE-") and (url or port):
        return f"cwe|{asset}|{port}|{cwe}|{url}"

    # Normalized title
    raw_title = (f.get("title") or "").strip().lower()
    # Strip tool prefixes like "Nessus: ", "Burp: ", "Nikto: ", "Nuclei: "
    norm_title = re.sub(r"^(nessus|burp|nikto|nuclei|nmap|zap|openvas|metasploit):\s*", "", raw_title)
    # Remove punctuation
    norm_title = re.sub(r"[^a-z0-9]", "", norm_title)[:40]

    return f"title|{asset}|{port}|{norm_title}"


def evaluate_false_positive_heuristics(f: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze finding characteristics to surface transparent AI triage inferences."""
    evidence = str(f.get("evidence", "")).lower()
    title = str(f.get("title", "")).lower()
    source = str(f.get("source", "")).lower()

    reasons = []
    is_suspect_fp = False

    # Heuristic 1: Version banner only without dynamic PoC
    if any(k in evidence for k in ["banner", "version detection", "server header"]) and not any(k in evidence for k in ["payload", "poc", "injected", "extracted"]):
        reasons.append("Finding relies solely on version banner inspection. Vendor backported patches (Debian, Ubuntu, RedHat) may have remediated the vulnerability without updating the version string.")
        is_suspect_fp = True

    # Heuristic 2: Potential WAF interception
    if any(k in evidence for k in ["403 forbidden", "406 not acceptable", "access denied", "cloudflare", "imperva", "akamai"]):
        reasons.append("Evidence indicates WAF / security gateway response. The backend application may not have processed the attack payload directly.")
        is_suspect_fp = True

    return {
        "is_suspect_false_positive": is_suspect_fp,
        "triage_reason": "; ".join(reasons) if reasons else "No anomalous false-positive heuristics detected.",
    }


def correlate_and_dedupe(
    findings: List[Dict[str, Any]],
    asset_criticality: str = "medium",
    is_public_exposed: bool = False,
) -> List[Dict[str, Any]]:
    """Merge duplicate findings across tools, calibrate confidence, and calculate transparent risk."""
    buckets: Dict[str, List[Dict[str, Any]]] = {}

    for f in findings:
        key = generate_correlation_key(f)
        buckets.setdefault(key, []).append(f)

    correlated: List[Dict[str, Any]] = []

    for key, items in buckets.items():
        if len(items) == 1:
            primary = dict(items[0])
            source_tool = primary.get("source", "import")
            initial_conf = float(primary.get("confidence", 0.70))

            # Single-source banner check
            fp_eval = evaluate_false_positive_heuristics(primary)
            if fp_eval["is_suspect_false_positive"]:
                status = "suspected"
                initial_conf = min(initial_conf, 0.65)
            else:
                status = "confirmed" if source_tool in ("metasploit", "nuclei") else "suspected"

            primary["status"] = status
            primary["confidence"] = initial_conf
            primary["fp_triage"] = fp_eval

            risk_bd = calculate_risk(
                cvss=float(primary.get("cvss", 0.0)),
                severity=primary.get("severity", "info"),
                is_public_exposed=is_public_exposed,
                asset_criticality=asset_criticality,
                confidence=initial_conf,
            )
            primary["risk_score"] = risk_bd.final_score
            primary["risk_reason"] = risk_bd.reason_formula
            primary["risk_breakdown"] = risk_bd.__dict__
            primary["dedup_key"] = hashlib.sha256(key.encode()).hexdigest()[:16]
            primary["source_tools"] = [source_tool]
            primary["merge_log"] = {
                "is_merged": False,
                "contributing_tools": [source_tool],
                "reason": "Single source observation.",
            }
            primary["_unmerged_items"] = [dict(primary)]
            correlated.append(primary)
            continue

        # Multiple items merged: sort by severity descending
        sorted_items = sorted(
            items,
            key=lambda x: (SEVERITY_ORDER.get(norm_severity(x.get("severity", "info")), 0), float(x.get("cvss", 0.0))),
            reverse=True,
        )
        primary = dict(sorted_items[0])

        tools = sorted(list({it.get("source", "import") for it in sorted_items}))
        filenames = sorted(list({it.get("source_filename", "") for it in sorted_items if it.get("source_filename")}))
        shas = sorted(list({it.get("source_file_sha256", "") for it in sorted_items if it.get("source_file_sha256")}))

        # Corroboration increases confidence:
        # Cross-tool independent corroboration boosts confidence to 0.90+
        max_base_conf = max(float(it.get("confidence", 0.70)) for it in sorted_items)
        corroborated_conf = min(0.95, max_base_conf + 0.15) if len(tools) > 1 else max_base_conf

        # Combine distinct evidence trails
        evidence_trails = []
        for it in sorted_items:
            tool_name = it.get("source", "tool").upper()
            src_file = it.get("source_filename", "artifact")
            ev_snippet = it.get("evidence", "").strip()
            evidence_trails.append(f"[{tool_name} from {src_file}]:\n{ev_snippet}")

        primary["source_tools"] = tools
        primary["source"] = "; ".join(tools)
        primary["source_filename"] = "; ".join(filenames)
        primary["source_file_sha256"] = "; ".join(shas)
        primary["evidence"] = "\n\n--- [Cross-Tool Corroboration] ---\n\n".join(evidence_trails)
        primary["confidence"] = corroborated_conf
        primary["status"] = "confirmed" if len(tools) > 1 else "suspected"

        fp_eval = evaluate_false_positive_heuristics(primary)
        primary["fp_triage"] = fp_eval

        risk_bd = calculate_risk(
            cvss=float(primary.get("cvss", 0.0)),
            severity=primary.get("severity", "info"),
            is_public_exposed=is_public_exposed,
            asset_criticality=asset_criticality,
            confidence=corroborated_conf,
        )
        primary["risk_score"] = risk_bd.final_score
        primary["risk_reason"] = risk_bd.reason_formula
        primary["risk_breakdown"] = risk_bd.__dict__
        primary["dedup_key"] = hashlib.sha256(key.encode()).hexdigest()[:16]

        primary["merge_log"] = {
            "is_merged": True,
            "merged_count": len(sorted_items),
            "contributing_tools": tools,
            "corroboration_boost": f"Confidence adjusted from {max_base_conf:.2f} to {corroborated_conf:.2f} via {len(tools)} independent tools ({', '.join(tools)}).",
            "reason": f"Correlated {len(sorted_items)} findings on key '{key}' across {', '.join(tools)}.",
        }
        primary["_unmerged_items"] = [dict(it) for it in sorted_items]

        correlated.append(primary)

    # Sort final correlated list by risk_score descending
    return sorted(correlated, key=lambda x: -float(x.get("risk_score", 0.0)))

