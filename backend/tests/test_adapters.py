import datetime
import sqlite3
import pytest

from app.adapters.base import ErrorClass, ExecutionMode
from app.adapters.burp_adapter import BurpAdapter
from app.adapters.metasploit_adapter import MetasploitAdapter
from app.adapters.nessus_adapter import NessusAdapter
from app.adapters.nikto_adapter import NiktoAdapter
from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.openvas_adapter import OpenVASAdapter
from app.adapters.registry import registry
from app.adapters.zap_adapter import ZapAdapter
from app.storage import get_raw_artifact_content, save_raw_artifact


@pytest.fixture
def test_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE artifacts (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            byte_size INTEGER NOT NULL DEFAULT 0,
            line_count INTEGER NOT NULL DEFAULT 0,
            source_tool TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL DEFAULT '',
            content_bytes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    yield conn
    conn.close()


def test_adapter_registry_contains_all_tools():
    expected_tools = {"nmap", "zap", "nikto", "nuclei", "nessus", "burp", "openvas", "metasploit"}
    registered_names = {a.name for a in registry.list_all()}
    assert expected_tools.issubset(registered_names)

    matrix = registry.get_integration_matrix()
    assert len(matrix) >= 8
    # Truthfulness check: commercial tools must not be claimed as live without configuration
    for item in matrix:
        if item["tool_name"] in ("nessus", "burp"):
            assert item["mode"] in ("import_only", "config_required")
            assert item["license_type"].startswith("Commercial")


def test_nmap_adapter_parse_xml():
    adapter = NmapAdapter()
    sample_xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="10.10.20.5" addrtype="ipv4"/>
        <hostnames><hostname name="target.lab"/></hostnames>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache" version="2.4.52"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="closed"/>
            <service name="ssh"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    findings = adapter.parse_output(sample_xml, filename="sample.xml")
    assert len(findings) == 1
    f = findings[0]
    assert f["asset"] == "10.10.20.5"
    assert "80" in f["title"]
    assert f["source"] == "nmap"
    assert f["confidence"] == 1.0
    assert "Apache 2.4.52" in f["evidence"]


def test_nessus_adapter_parse_xml():
    adapter = NessusAdapter()
    sample_nessus = """<?xml version="1.0"?>
    <NessusClientData_v2>
      <Report name="Lab Scan">
        <ReportHost name="192.168.1.100">
          <ReportItem port="443" svc_name="https" protocol="tcp" severity="3" pluginID="10400" pluginName="SSL Self-Signed Certificate" pluginFamily="General">
            <synopsis>The SSL certificate is self-signed.</synopsis>
            <description>The remote service presents a self-signed SSL certificate.</description>
            <solution>Install a trusted certificate from an authorized CA.</solution>
            <plugin_output>Subject: CN=lab.internal</plugin_output>
            <cvss3_base_score>7.5</cvss3_base_score>
            <cwe>295</cwe>
          </ReportItem>
        </ReportHost>
      </Report>
    </NessusClientData_v2>
    """
    findings = adapter.parse_output(sample_nessus, filename="nessus_test.nessus")
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["cvss"] == 7.5
    assert f["cwe"] == "CWE-295"
    assert f["source"] == "nessus"
    assert "CN=lab.internal" in f["evidence"]


def test_burp_adapter_parse_xml():
    adapter = BurpAdapter()
    sample_burp = """<?xml version="1.0"?>
    <issues burpVersion="2026.1">
      <issue>
        <name>SQL injection</name>
        <host ip="10.10.20.15">http://10.10.20.15</host>
        <path>/api/login</path>
        <location>/api/login [user]</location>
        <severity>High</severity>
        <confidence>Certain</confidence>
        <issueDetail>Boolean-based blind SQL injection observed on parameter 'user'.</issueDetail>
        <remediationDetail>Use parameterized prepared statements.</remediationDetail>
      </issue>
    </issues>
    """
    findings = adapter.parse_output(sample_burp, filename="burp.xml")
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "Burp: SQL injection"
    assert f["severity"] == "high"
    assert f["confidence"] == 0.95
    assert "parameter 'user'" in f["evidence"]


def test_openvas_adapter_parse_xml():
    adapter = OpenVASAdapter()
    sample_openvas = """<?xml version="1.0"?>
    <report>
      <report>
        <results>
          <result id="res-1">
            <name>Apache Log4j Remote Code Execution</name>
            <host>10.10.20.25</host>
            <port>8080/tcp</port>
            <threat>High</threat>
            <severity>10.0</severity>
            <description>Log4j JNDI injection payload triggered remote callback.</description>
            <nvt oid="1.3.6.1.4.1.25623.1.0.147205">
              <cve>CVE-2021-44228</cve>
            </nvt>
          </result>
        </results>
      </report>
    </report>
    """
    findings = adapter.parse_output(sample_openvas, filename="openvas.xml")
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert f["cvss"] == 10.0
    assert f["cve"] == "CVE-2021-44228"
    assert "Log4j JNDI injection" in f["evidence"]


def test_nuclei_adapter_parse_jsonl():
    adapter = NucleiAdapter()
    sample_jsonl = '{"template-id":"cve-2023-1234","info":{"name":"Example RCE","severity":"critical","classification":{"cvss-score":9.8,"cve-id":"CVE-2023-1234","cwe-id":"CWE-78"}},"host":"http://10.10.20.5","matched-at":"http://10.10.20.5/vuln","extracted-results":["root:x:0:0"]}\n'
    findings = adapter.parse_output(sample_jsonl, filename="nuclei.jsonl")
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "Nuclei: Example RCE"
    assert f["severity"] == "critical"
    assert f["cvss"] == 9.8
    assert f["cve"] == "CVE-2023-1234"
    assert f["cwe"] == "CWE-78"
    assert "root:x:0:0" in f["evidence"]


def test_metasploit_approval_gate_enforcement():
    adapter = MetasploitAdapter()

    # Case 1: Auxiliary check module is allowed without explicit approval
    res_aux = adapter.validate_offensive_approval("auxiliary/scanner/http/http_version", "10.10.20.5", None)
    assert res_aux["ok"] is True
    assert res_aux["requires_approval"] is False

    # Case 2: Exploit module without approval is strictly blocked
    res_exploit_no_appr = adapter.validate_offensive_approval("exploit/unix/webapp/wp_admin_rce", "10.10.20.5", None)
    assert res_exploit_no_appr["ok"] is False
    assert res_exploit_no_appr["error_class"] == ErrorClass.APPROVAL_REQUIRED

    # Case 3: Exploit module with unconfirmed lab flag is rejected
    unconfirmed_appr = {
        "id": "appr-1", "status": "approved", "target": "10.10.20.5",
        "lab_confirmed": 0, "expires_at": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
    }
    res_no_lab = adapter.validate_offensive_approval("exploit/unix/webapp/wp_admin_rce", "10.10.20.5", unconfirmed_appr)
    assert res_no_lab["ok"] is False
    assert res_no_lab["error_class"] == ErrorClass.SCOPE_VIOLATION
    assert "lab-only" in res_no_lab["reason"]

    # Case 4: Valid, lab-confirmed, unexpired approval succeeds
    valid_appr = {
        "id": "appr-2", "status": "approved", "target": "10.10.20.5",
        "lab_confirmed": 1, "expires_at": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
    }
    res_valid = adapter.validate_offensive_approval("exploit/unix/webapp/wp_admin_rce", "10.10.20.5", valid_appr)
    assert res_valid["ok"] is True
    assert res_valid["requires_approval"] is True


def test_content_addressed_artifact_storage(test_db):
    sample_content = b"SCAN ARTIFACT DATA 2026\nLINE 2\nLINE 3\n"
    res = save_raw_artifact(
        assessment_id="asm-test-01",
        tool_name="nmap",
        filename="scan.xml",
        data=sample_content,
        db=test_db,
    )
    assert res["id"].startswith("art-")
    assert len(res["sha256"]) == 64
    assert res["byte_size"] == len(sample_content)
    assert res["line_count"] == 3

    # Retrieve artifact
    retrieved = get_raw_artifact_content(res["id"], db=test_db)
    assert retrieved is not None
    assert retrieved["sha256"] == res["sha256"]
    assert "SCAN ARTIFACT DATA" in retrieved["content"]

