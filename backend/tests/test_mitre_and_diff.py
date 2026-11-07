"""Tests for MITRE ATT&CK Matrix mapping, Navigator export, and Assessment Diff/Retest engine."""
import pytest
from app.mitre import (
    map_finding_to_mitre,
    generate_mitre_matrix,
    generate_navigator_layer,
)
from app.diff import compute_assessment_diff


def test_mitre_cwe_mapping():
    # CWE-89 (SQLi) should map to T1190 (Exploit Public-Facing App) and T1213
    f_sqli = {"title": "SQL Injection in login", "cwe": "CWE-89", "severity": "critical"}
    mapped = map_finding_to_mitre(f_sqli)
    tech_ids = [m["technique_id"] for m in mapped]
    assert "T1190" in tech_ids

    # CWE-79 (XSS) should map to JavaScript command interpreter and drive-by compromise
    f_xss = {"title": "Stored Cross Site Scripting", "cwe": "CWE-79", "severity": "high"}
    mapped_xss = map_finding_to_mitre(f_xss)
    tech_ids_xss = [m["technique_id"] for m in mapped_xss]
    assert "T1059.007" in tech_ids_xss


def test_mitre_keyword_fallback_and_default():
    # Finding without CWE but with 'port 80 open' should map to Network Service Discovery (T1046)
    f_port = {"title": "Open port 80 detected by nmap", "evidence": "tcp open http", "cwe": "", "severity": "info"}
    mapped = map_finding_to_mitre(f_port)
    assert any(m["technique_id"] == "T1046" for m in mapped)

    # Finding with unrecognized details should fall back to Recon / Active Scanning (T1595)
    f_misc = {"title": "Unknown proprietary behavior", "evidence": "no obvious tags", "cwe": "", "severity": "low"}
    mapped_misc = map_finding_to_mitre(f_misc)
    assert any(m["technique_id"] == "T1595" for m in mapped_misc)


def test_mitre_matrix_aggregation():
    findings = [
        {"id": "f1", "title": "SQL Injection", "cwe": "CWE-89", "severity": "critical"},
        {"id": "f2", "title": "Missing CSP", "cwe": "CWE-693", "severity": "medium"},
        {"id": "f3", "title": "Open port 22", "evidence": "ssh port open", "cwe": "", "severity": "info"},
    ]
    matrix = generate_mitre_matrix(findings)
    assert matrix["total_findings_mapped"] == 3
    assert matrix["active_tactics_count"] >= 2
    # Verify tactics list exists
    tactics = {t["name"]: t for t in matrix["tactics"]}
    assert "Initial Access" in tactics
    assert tactics["Initial Access"]["total_findings"] >= 1


def test_mitre_navigator_layer_format():
    findings = [
        {"id": "f1", "title": "Command Injection", "cwe": "CWE-78", "severity": "critical"},
    ]
    layer = generate_navigator_layer("Test Lab Engagement", findings)
    assert layer["name"] == "SentinelVAPT - Test Lab Engagement"
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) >= 1
    tech = layer["techniques"][0]
    assert "techniqueID" in tech
    assert "score" in tech
    assert tech["score"] == 100  # Critical severity weight


def test_assessment_diff_and_retest_plan():
    curr_meta = {"id": "aid_curr", "name": "Juice Shop Sprint 2", "target": "127.0.0.1"}
    prior_meta = {"id": "aid_prior", "name": "Juice Shop Sprint 1", "target": "127.0.0.1"}

    # Prior findings: f_resolved (fixed in current), f_recurrent (still present)
    prior_findings = [
        {"id": "p1", "dedup_key": "k_fixed", "title": "SQLi in /rest/user/login", "severity": "critical", "risk_score": 9.5, "source": "zap", "url": "http://127.0.0.1:3000/rest/user/login"},
        {"id": "p2", "dedup_key": "k_still_here", "title": "Missing CSP header", "severity": "low", "risk_score": 2.5, "source": "nikto", "url": "http://127.0.0.1:3000"},
    ]

    # Current findings: f_recurrent (still present), f_new (newly introduced bug)
    curr_findings = [
        {"id": "c1", "dedup_key": "k_still_here", "title": "Missing CSP header", "severity": "low", "risk_score": 2.5, "source": "nikto", "url": "http://127.0.0.1:3000"},
        {"id": "c2", "dedup_key": "k_new_vuln", "title": "Exposed .git directory", "severity": "high", "risk_score": 7.0, "source": "nuclei", "url": "http://127.0.0.1:3000/.git/"},
    ]

    diff = compute_assessment_diff(curr_meta, prior_meta, curr_findings, prior_findings)

    # Validate classification
    assert len(diff["new_findings"]) == 1
    assert diff["new_findings"][0]["title"] == "Exposed .git directory"

    assert len(diff["resolved_findings"]) == 1
    assert diff["resolved_findings"][0]["title"] == "SQLi in /rest/user/login"

    assert len(diff["recurrent_findings"]) == 1
    assert diff["recurrent_findings"][0]["current"]["title"] == "Missing CSP header"

    # Validate risk shift: prior = 9.5 + 2.5 = 12.0; curr = 2.5 + 7.0 = 9.5; delta = -2.5 (improved)
    assert diff["summary"]["risk_delta"] == -2.5
    assert diff["summary"]["posture_improved"] is True

    # Validate Retest Action Recommendations
    retest = diff["retest_recommendations"]
    assert len(retest) >= 2
    tool_targets = [r["recommended_tool"] for r in retest]
    assert "zap" in tool_targets

