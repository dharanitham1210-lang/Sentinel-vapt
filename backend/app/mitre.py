"""MITRE ATT&CK Enterprise Matrix Mapper and Navigator Layer Exporter.

Deterministic mapping from CWE, CVE, and vulnerability types to MITRE ATT&CK
Tactics and Techniques (Enterprise Matrix v14).
"""
from __future__ import annotations

import json
from typing import Any


# Standard Tactics in Kill Chain order
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "recon"},
    {"id": "TA0042", "name": "Resource Development", "short": "res-dev"},
    {"id": "TA0001", "name": "Initial Access", "short": "init-access"},
    {"id": "TA0002", "name": "Execution", "short": "execution"},
    {"id": "TA0003", "name": "Persistence", "short": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "short": "priv-esc"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "def-evasion"},
    {"id": "TA0006", "name": "Credential Access", "short": "cred-access"},
    {"id": "TA0007", "name": "Discovery", "short": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "lat-movement"},
    {"id": "TA0009", "name": "Collection", "short": "collection"},
    {"id": "TA0011", "name": "Command and Control", "short": "c2"},
    {"id": "TA0010", "name": "Exfiltration", "short": "exfiltration"},
    {"id": "TA0040", "name": "Impact", "short": "impact"},
]

# CWE to MITRE ATT&CK Mapping
CWE_TO_TECHNIQUE: dict[str, list[dict[str, str]]] = {
    # Public-Facing Exploitation / Web
    "CWE-89": [
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
        {"tactic_id": "TA0009", "tactic_name": "Collection", "technique_id": "T1213", "technique_name": "Data from Information Repositories"},
    ],
    "CWE-79": [
        {"tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059.007", "technique_name": "Command and Scripting Interpreter: JavaScript"},
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1189", "technique_name": "Drive-by Compromise"},
    ],
    "CWE-78": [
        {"tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    "CWE-22": [
        {"tactic_id": "TA0009", "tactic_name": "Collection", "technique_id": "T1005", "technique_name": "Data from Local System"},
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    "CWE-200": [
        {"tactic_id": "TA0043", "tactic_name": "Reconnaissance", "technique_id": "T1592", "technique_name": "Gather Victim Host Information"},
    ],
    "CWE-693": [
        {"tactic_id": "TA0005", "tactic_name": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses"},
    ],
    "CWE-287": [
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1078", "technique_name": "Valid Accounts"},
        {"tactic_id": "TA0006", "tactic_name": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force"},
    ],
    "CWE-306": [
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    "CWE-502": [
        {"tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
    ],
    "CWE-918": [
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
        {"tactic_id": "TA0007", "tactic_name": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery"},
    ],
    "CWE-352": [
        {"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1189", "technique_name": "Drive-by Compromise"},
    ],
}

# Keyword fallbacks for scanner output without explicit CWE
KEYWORD_MAPPINGS = [
    (["port", "open port", "service banner", "nmap"], {
        "tactic_id": "TA0007", "tactic_name": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery"
    }),
    (["sql", "injection", "sqli"], {
        "tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"
    }),
    (["cross site", "xss"], {
        "tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059.007", "technique_name": "Command and Scripting Interpreter: JavaScript"
    }),
    (["header", "csp", "clickjacking", "x-frame-options"], {
        "tactic_id": "TA0005", "tactic_name": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses"
    }),
    (["traversal", "directory browsing", "path traversal"], {
        "tactic_id": "TA0009", "tactic_name": "Collection", "technique_id": "T1005", "technique_name": "Data from Local System"
    }),
    (["rce", "remote code execution", "command injection"], {
        "tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"
    }),
    (["auth", "login", "password", "credential", "default cred"], {
        "tactic_id": "TA0006", "tactic_name": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force"
    }),
    (["version", "outdated", "apache", "nginx", "banner"], {
        "tactic_id": "TA0043", "tactic_name": "Reconnaissance", "technique_id": "T1592", "technique_name": "Gather Victim Host Information"
    }),
]


def map_finding_to_mitre(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Deterministically map a finding to MITRE ATT&CK techniques."""
    results: list[dict[str, str]] = []
    cwe = (finding.get("cwe") or "").strip().upper()
    if cwe in CWE_TO_TECHNIQUE:
        results.extend(CWE_TO_TECHNIQUE[cwe])

    # If no CWE match, inspect title / evidence keywords
    if not results:
        title = (finding.get("title") or "").lower()
        evidence = str(finding.get("evidence") or "").lower()
        combined = f"{title} {evidence}"
        for keywords, mapping in KEYWORD_MAPPINGS:
            if any(k in combined for k in keywords):
                if mapping not in results:
                    results.append(mapping)
                break

    # Default fallback to Recon / Discovery if nothing matched
    if not results:
        results.append({
            "tactic_id": "TA0043",
            "tactic_name": "Reconnaissance",
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
        })

    return results


def generate_mitre_matrix(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate structured MITRE ATT&CK Enterprise Matrix overview."""
    tactics_map: dict[str, dict[str, Any]] = {
        t["id"]: {
            "id": t["id"],
            "name": t["name"],
            "short": t["short"],
            "techniques": {},
            "total_findings": 0,
        }
        for t in TACTICS
    }

    SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    for f in findings:
        mapped = map_finding_to_mitre(f)
        fid = f.get("id") or f.get("title", "unknown")
        sev = (f.get("severity") or "info").lower()
        weight = SEVERITY_WEIGHT.get(sev, 1)

        for m in mapped:
            tid = m["tactic_id"]
            if tid not in tactics_map:
                continue

            tech_id = m["technique_id"]
            tactic_entry = tactics_map[tid]
            tactic_entry["total_findings"] += 1

            if tech_id not in tactic_entry["techniques"]:
                tactic_entry["techniques"][tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": m["technique_name"],
                    "finding_ids": [],
                    "findings_count": 0,
                    "max_severity": sev,
                    "max_weight": weight,
                }

            t = tactic_entry["techniques"][tech_id]
            t["findings_count"] += 1
            if fid not in t["finding_ids"]:
                t["finding_ids"].append(fid)
            if weight > t["max_weight"]:
                t["max_weight"] = weight
                t["max_severity"] = sev

    # Format output
    tactics_list = []
    for t_def in TACTICS:
        t_data = tactics_map[t_def["id"]]
        techniques_list = list(t_data["techniques"].values())
        techniques_list.sort(key=lambda x: (-x["max_weight"], -x["findings_count"]))
        tactics_list.append({
            "id": t_data["id"],
            "name": t_data["name"],
            "short": t_data["short"],
            "total_findings": t_data["total_findings"],
            "techniques": techniques_list,
        })

    active_tactics = [t for t in tactics_list if t["total_findings"] > 0]
    return {
        "total_findings_mapped": len(findings),
        "active_tactics_count": len(active_tactics),
        "tactics": tactics_list,
    }


def generate_navigator_layer(assessment_name: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate official MITRE ATT&CK Navigator v4.5 Layer JSON."""
    matrix = generate_mitre_matrix(findings)
    techniques_layer = []

    SEV_SCORES = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}

    for tactic in matrix["tactics"]:
        for tech in tactic["techniques"]:
            score = SEV_SCORES.get(tech["max_severity"], 10)
            techniques_layer.append({
                "techniqueID": tech["technique_id"].split(".")[0],
                "subtechniqueID": tech["technique_id"] if "." in tech["technique_id"] else None,
                "tactic": tactic["short"],
                "score": score,
                "comment": f"Findings ({tech['findings_count']}): {', '.join(tech['finding_ids'][:5])}",
                "enabled": True,
            })

    return {
        "name": f"SentinelVAPT - {assessment_name}",
        "versions": {
            "attack": "14",
            "navigator": "4.5",
            "layer": "4.3",
        },
        "domain": "enterprise-attack",
        "description": f"MITRE ATT&CK coverage generated by SentinelVAPT for assessment: {assessment_name}",
        "gradient": {
            "colors": ["#38bdf8", "#facc15", "#fb923c", "#ef4444"],
            "minValue": 0,
            "maxValue": 100,
        },
        "techniques": techniques_layer,
    }

