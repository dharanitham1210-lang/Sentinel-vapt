import pytest
from app.correlation import correlate_and_dedupe, generate_correlation_key
from app.risk import calculate_risk


def test_composite_cve_correlation_and_confidence_boost():
    # Finding from OpenVAS
    f1 = {
        "title": "OpenVAS: Apache Log4j RCE",
        "severity": "critical",
        "cvss": 10.0,
        "confidence": 0.85,
        "asset": "10.10.20.25",
        "parameter": "8080/tcp",
        "source": "openvas",
        "source_filename": "openvas_report.xml",
        "source_file_sha256": "sha_openvas_1",
        "evidence": "JNDI lookup callback detected on 8080.",
        "cve": "CVE-2021-44228",
    }

    # Finding from Nessus
    f2 = {
        "title": "Nessus: Apache Log4j Core Vulnerability",
        "severity": "critical",
        "cvss": 10.0,
        "confidence": 0.80,
        "asset": "10.10.20.25",
        "parameter": "8080/tcp",
        "source": "nessus",
        "source_filename": "nessus_scan.nessus",
        "source_file_sha256": "sha_nessus_1",
        "evidence": "log4j-core-2.14.1.jar identified on classpath.",
        "cve": "CVE-2021-44228",
    }

    # Dedupe and correlate
    merged = correlate_and_dedupe([f1, f2])
    assert len(merged) == 1
    m = merged[0]

    # Corroborated status
    assert m["status"] == "confirmed"
    # Corroboration boosted confidence
    assert m["confidence"] == 0.95
    assert set(m["source_tools"]) == {"openvas", "nessus"}
    assert "openvas" in m["source"] and "nessus" in m["source"]

    # Both raw evidence snippets preserved
    assert "JNDI lookup callback detected" in m["evidence"]
    assert "log4j-core-2.14.1.jar" in m["evidence"]

    # Merge log verified
    assert m["merge_log"]["is_merged"] is True
    assert m["merge_log"]["merged_count"] == 2
    assert "Confidence adjusted" in m["merge_log"]["corroboration_boost"]

    # Unmerge records preserved
    assert len(m["_unmerged_items"]) == 2


def test_single_source_version_banner_marked_suspected():
    banner_finding = {
        "title": "Apache 2.4.49 Path Traversal",
        "severity": "high",
        "cvss": 7.5,
        "confidence": 0.80,
        "asset": "192.168.1.15",
        "parameter": "80/tcp",
        "source": "nmap",
        "evidence": "Server banner header reported: Apache/2.4.49 (Debian)",
        "cve": "CVE-2021-41773",
    }

    result = correlate_and_dedupe([banner_finding])
    assert len(result) == 1
    r = result[0]
    assert r["status"] == "suspected"
    assert r["fp_triage"]["is_suspect_false_positive"] is True
    assert "backported" in r["fp_triage"]["triage_reason"]


def test_transparent_risk_formula_breakdown():
    # Known exploited vulnerability (CISA KEV) on critical asset
    rb_critical = calculate_risk(
        cvss=9.8,
        severity="critical",
        is_public_exposed=True,
        known_exploited_cisa=True,
        asset_criticality="critical",
        confidence=0.95,
    )
    # Score capped at 10.0
    assert rb_critical.final_score == 10.0
    assert rb_critical.exploitability_factor == 1.25
    assert "CISA Known Exploited" in rb_critical.exploit_intel_source
    assert "Score" in rb_critical.reason_formula

    # Internal asset without KEV
    rb_internal = calculate_risk(
        cvss=7.5,
        severity="high",
        is_public_exposed=False,
        is_authenticated=True,
        known_exploited_cisa=None,
        epss_score=None,
        asset_criticality="medium",
        confidence=0.80,
    )
    assert rb_internal.exposure_factor == 0.75
    assert rb_internal.exploitability_factor == 1.00
    assert "Not available" in rb_internal.exploit_intel_source
    assert rb_internal.final_score < 7.5

