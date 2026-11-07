"""Parser-hardening regression tests.

Root cause under test: a generated PDF report was uploaded back into the app and
the last-resort text parser turned PDF structure/metadata lines into fake
"Nikto vulnerabilities". These tests pin the hardened behaviour.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from app.normalization import (
    detect_and_parse,
    parse_nikto_text,
    parse_nmap_xml,
    parse_zap_json,
)

PDF_JUNK = (
    b"%PDF-1.4\r\n"
    b"1 0 obj << /Type /Catalog /Pages 8 0 R >> endobj\r\n"
    b"/Author (anonymous) /Creator (unsp) /Title (VulnPilot VAPT)\r\n"
    b"/BaseFont /Helvetica /Encoding /WinAnsiEncoding /Name /F1 /Subtype /Type1\r\n"
    b"/Contents 9 0 R /MediaBox [ 0 0 595.2756 841.8898 ] /Parent 8 0 R\r\n"
    b"/PageMode /UseNone /Pages 8 0 R /Type /Catalog\r\n"
    b"/Filter [ /ASCII85Decode /FlateDecode ] /Length 1025\r\n"
    b"0000000000 65535 f \r\n0000000061 00000 n \r\n"
) + b"\x93\x88 binary flate stream \x00\x01\x02"


def test_pdf_upload_rejected_not_parsed():
    with pytest.raises(ValueError):
        detect_and_parse(PDF_JUNK, "VulnPilot_report.pdf")


def test_pdf_lines_never_become_nikto_findings():
    assert parse_nikto_text(PDF_JUNK.decode("utf-8", errors="ignore"), "x.pdf", "s") == []


def test_pdf_metadata_headlines_ignored_even_as_text():
    txt = (
        "% ReportLab Generated PDF document (opensource)\n"
        "/Contents /MediaBox\n"
        "/Author (anonymous)\n"
        "/BaseFont /Helvetica\n"
        "/PageMode /UseNone\n"
        "/Count 1 /Kids [ 5 0 R ] /Type /Pages\n"
        "0000000000 65535 f\n"
    )
    assert parse_nikto_text(txt, "junk.txt", "s") == []


def test_valid_nikto_findings_kept_with_provenance():
    txt = (
        "- Nikto v2.5.0\n"
        "+ Target IP: 127.0.0.1\n"
        "+ Target Hostname: localhost\n"
        "+ Server: Apache/2.4.49 (Unix)\n"
        "+ /admin/ - user and password.\n"
        "+ OPTIONS: HTTP method TRACE methodology appears to be supported on this server. Method TRACE may allow XST attacks.\n"
        "\n"
        "arbitrary prose that is not a nikto line and is quite long indeed\n"
        "+ short\n"
    )
    out = parse_nikto_text(txt, "nikto.txt", "abc123")
    assert len(out) == 2
    assert out[0]["title"] == "/admin/ - user and password."
    assert out[0]["source"] == "nikto"
    assert out[0]["source_filename"] == "nikto.txt"
    assert out[0]["source_file_sha256"] == "abc123"
    assert "OPTIONS" in out[1]["title"]
    for f in out:
        assert f["evidence"]  # raw line preserved
        assert f["cve"] == ""  # never invented


def test_headers_only_yields_zero_findings():
    txt = "- Nikto v2.5.0\n+ Target IP: 127.0.0.1\n+ Target Port: 80\n+ Server: Apache/2.4.49\n"
    assert parse_nikto_text(txt, "n.txt", "s") == []


def test_nmap_closed_ports_not_reported_as_open():
    xml = (
        '<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/><ports>'
        '<port portid="80"><state state="open"/><service name="http"/></port>'
        '<port portid="22"><state state="closed"/><service name="ssh"/></port>'
        '<port portid="81"><state state="filtered"/><service name="http-alt"/></port>'
        "</ports></host></nmaprun>"
    )
    out = parse_nmap_xml(xml, "n.xml", "s")
    assert len(out) == 1 and out[0]["title"] == "Open port 80/http"


def test_nmap_empty_script_output_skipped():
    xml = (
        '<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/><ports>'
        '<port portid="80"><state state="open"/><service name="http"/>'
        '<script id="http-title" output=""/></port>'
        "</ports></host></nmaprun>"
    )
    out = parse_nmap_xml(xml, "n.xml", "s")
    assert len(out) == 1  # port only, no empty script finding


def test_zap_requires_title_and_evidence():
    data = {"alerts": [
        {"alert": "Real alert", "risk": "High", "url": "http://127.0.0.1/a", "evidence": "e", "solution": "s"},
        {"alert": "", "risk": "Low", "url": "http://127.0.0.1/b", "evidence": "e"},
        {"alert": "Bare title only", "risk": "Low"},
    ]}
    out = parse_zap_json(data, "z.json", "s")
    assert len(out) == 1 and out[0]["title"] == "Real alert"


def test_json_without_findings_is_not_reinterpreted_as_text():
    assert detect_and_parse(b'{"unrelated": "object"}', "x.json") == []
    assert detect_and_parse(b'{"findings": []}', "x.json") == []


def test_unsupported_binary_extensions_rejected():
    for name in ("a.pdf", "a.png", "a.zip", "a.exe"):
        with pytest.raises(ValueError):
            detect_and_parse(b"just some text bytes", name)


def test_valid_samples_still_import():
    from app.normalization import file_sha256  # noqa: F401
    root = Path(__file__).resolve().parent.parent.parent / "samples"
    nmap_raw = (root / "nmap-sample.xml").read_bytes()
    nmap = detect_and_parse(nmap_raw, "nmap-sample.xml")
    assert len(nmap) == 2 and all(f["source"] == "nmap" for f in nmap)

    zap_raw = (root / "zap-sample.json").read_bytes()
    zap = detect_and_parse(zap_raw, "zap-sample.json")
    assert len(zap) == 2 and all(f["source"] == "zap" for f in zap)

    nikto_raw = (root / "nikto-sample.txt").read_bytes()
    nikto = detect_and_parse(nikto_raw, "nikto-sample.txt")
    assert len(nikto) == 2 and all(f["source"] == "nikto" for f in nikto)
