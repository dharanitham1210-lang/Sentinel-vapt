import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.dedup import dedupe, risk_score
from app.normalization import detect_and_parse, parse_nmap_xml, parse_zap_json
from app.scope import validate_host, validate_scope


# ---- scope validation ----
def test_localhost_allowed():
    assert validate_host("127.0.0.1")["ok"]
    assert validate_host("localhost")["ok"]
    assert validate_host("192.168.1.10")["ok"]
    assert validate_host("10.0.0.5")["ok"]
    assert validate_host("app.lab")["ok"]


def test_public_blocked():
    assert not validate_host("8.8.8.8")["ok"]
    assert not validate_host("93.184.216.34")["ok"]
    assert not validate_host("google.com")["ok"]
    assert not validate_host("example.com")["ok"]


def test_validate_scope_requires_text_and_target():
    v1 = validate_scope("Test lab", ["127.0.0.1"])
    assert v1["ok"]
    v2 = validate_scope("", ["127.0.0.1"])
    assert not v2["ok"]
    v3 = validate_scope("scope", ["8.8.8.8"])
    assert not v3["ok"]


# ---- normalization ----
def test_parse_nmap_xml():
    xml = """<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/>
    <ports><port portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>"""
    out = parse_nmap_xml(xml, "test.xml", "abc")
    assert len(out) == 1
    assert "80" in out[0]["title"]
    assert out[0]["source"] == "nmap"
    assert out[0]["source_filename"] == "test.xml"


def test_parse_zap_json():
    data = {"alerts": [{"alert": "SQL Injection", "risk": "High", "url": "http://127.0.0.1/a?id=1",
                        "param": "id", "evidence": "' OR 1=1", "solution": "Use prepared statements",
                        "cwesid": "89"}]}
    out = parse_zap_json(data, "zap.json", "def")
    assert len(out) == 1
    assert out[0]["severity"] == "high"
    assert out[0]["parameter"] == "id"


def test_detect_nikto_text():
    txt = b"+ Server: Apache/2.4.49\r\n+ /admin/ - user and password.\r\n"
    out = detect_and_parse(txt, "nikto.txt")
    # first line is skipped as server header; second line kept
    assert len(out) >= 1
    assert out[0]["source"] == "nikto"


# ---- dedup + risk ----
def test_dedupe_merges_same_finding():
    f1 = {"title": "Missing header", "severity": "low", "confidence": 0.8, "cvss": 3.0,
          "asset": "127.0.0.1", "url": "http://127.0.0.1", "parameter": "",
          "source": "zap", "source_filename": "a.json", "source_file_sha256": "x",
          "evidence": "e1", "evidence_json": {}, "remediation": "", "references": [], "cwe": "", "cve": ""}
    f2 = dict(f1, source="nikto", source_filename="b.txt", evidence="e2")
    out = dedupe([f1, f2])
    assert len(out) == 1
    assert "a.json" in out[0]["source_filename"] and "b.txt" in out[0]["source_filename"]


def test_risk_transparent():
    s, r = risk_score({"cvss": 8.0, "confidence": 0.5, "severity": "high"})
    assert s == 4.0 and "CVSS" in r


# ---- report generation ----
def test_report_pdf(tmp_path):
    from app.report import generate_pdf
    out = str(tmp_path / "report.pdf")
    p = generate_pdf(
        {"name": "t", "target": "127.0.0.1", "scope": "lab", "status": "approved",
         "approval_status": "approved", "created_at": "2026-01-01"},
        [{"title": "Test", "severity": "high", "risk_score": 7.5, "confidence": 0.9,
          "asset": "127.0.0.1", "url": "http://127.0.0.1", "parameter": "",
          "source": "zap", "source_filename": "z.json", "source_file_sha256": "deadbeef",
          "evidence": "ev", "remediation": "fix", "risk_reason": "r"}],
        [{"created_at": "2026-01-01", "event": "import", "detail": "ok"}],
        out,
    )
    assert os.path.exists(p) and os.path.getsize(p) > 1000
