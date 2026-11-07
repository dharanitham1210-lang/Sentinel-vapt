import datetime
import sqlite3
import pytest

from app.audit import AuditService
from app.scope_gate import (
    EngagementScope,
    ScopeGate,
    ScopeViolationError,
    extract_host_and_port,
    is_private_ip,
    normalize_ip,
)


@pytest.fixture
def mock_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id TEXT DEFAULT 'system',
            event TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT 'system',
            target TEXT NOT NULL DEFAULT '',
            payload_hash TEXT NOT NULL DEFAULT '',
            prev_hash TEXT NOT NULL DEFAULT '',
            entry_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    yield conn
    conn.close()


def test_url_userinfo_extraction():
    # Attempting to bypass scope with userinfo trick: http://authorized@evil.com
    host, port = extract_host_and_port("http://authorized.local@evil.com:8080/path")
    assert host == "evil.com"
    assert port == 8080

    # Userinfo with password
    host, port = extract_host_and_port("https://admin:secret@192.168.1.5:443/login")
    assert host == "192.168.1.5"
    assert port == 443


def test_ipv4_mapped_ipv6_normalization():
    # ::ffff:192.168.1.1 should normalize to private IPv4
    assert is_private_ip("::ffff:192.168.1.1") is True
    # ::ffff:8.8.8.8 should normalize to public IPv4
    assert is_private_ip("::ffff:8.8.8.8") is False


def test_cidr_boundary_containment():
    scope = EngagementScope(
        allowed_cidrs=["10.10.20.0/24"],
        allow_public_ips=False,
    )
    gate = ScopeGate(scope)

    # Within CIDR
    assert gate.check_target("10.10.20.0")["ok"] is True
    assert gate.check_target("10.10.20.1")["ok"] is True
    assert gate.check_target("10.10.20.254")["ok"] is True
    assert gate.check_target("10.10.20.255")["ok"] is True

    # Just outside CIDR
    res_outside = gate.check_target("10.10.21.1")
    assert res_outside["ok"] is False
    assert res_outside["rule"] == "CIDR_OUT_OF_SCOPE"


def test_exclusions_precedence_over_allowed_cidr():
    # Subnet allowed, but gateway (10.10.20.1) and DB server (10.10.20.50) are excluded
    scope = EngagementScope(
        allowed_cidrs=["10.10.20.0/24"],
        exclusions=["10.10.20.1", "10.10.20.50"],
    )
    gate = ScopeGate(scope)

    assert gate.check_target("10.10.20.2")["ok"] is True
    assert gate.check_target("10.10.20.1")["ok"] is False
    assert gate.check_target("10.10.20.1")["rule"] == "EXCLUDED_IP"
    assert gate.check_target("10.10.20.50")["ok"] is False
    assert gate.check_target("10.10.20.50")["rule"] == "EXCLUDED_IP"


def test_public_ip_blocking_by_default(mock_db):
    scope = EngagementScope(
        allowed_cidrs=["10.0.0.0/8"],
        allow_public_ips=False,
    )
    gate = ScopeGate(scope, audit_logger=AuditService, db=mock_db, assessment_id="asm-001")

    res = gate.check_target("8.8.8.8", actor="analyst_test")
    assert res["ok"] is False
    assert res["rule"] == "PUBLIC_IP_BLOCKED"

    # Verify audit entry was created for scope rejection
    cur = mock_db.execute("SELECT * FROM audit_logs WHERE event = 'SCOPE_REJECT'")
    row = cur.fetchone()
    assert row is not None
    assert row["target"] == "8.8.8.8"
    assert row["actor"] == "analyst_test"


def test_wildcard_domain_matching():
    scope = EngagementScope(
        allowed_hostnames=["*.target.local", "api.partner.corp"],
    )
    gate = ScopeGate(scope)

    assert gate.check_target("app.target.local")["ok"] is True
    assert gate.check_target("auth.sub.target.local")["ok"] is True
    assert gate.check_target("api.partner.corp")["ok"] is True
    assert gate.check_target("unauthorized.corp")["ok"] is False


def test_port_restriction_enforcement():
    scope = EngagementScope(
        allowed_cidrs=["192.168.1.0/24"],
        allowed_ports=[80, 443, 8443],
    )
    gate = ScopeGate(scope)

    assert gate.check_target("http://192.168.1.10:80")["ok"] is True
    assert gate.check_target("https://192.168.1.10:8443")["ok"] is True

    # Port 22 SSH not in allowed list
    res_ssh = gate.check_target("192.168.1.10:22")
    assert res_ssh["ok"] is False
    assert res_ssh["rule"] == "PORT_OUT_OF_SCOPE"


def test_tool_allowlist_enforcement():
    scope = EngagementScope(
        allowed_tools=["nmap", "zap", "nikto"],
    )
    gate = ScopeGate(scope)

    assert gate.check_tool("nmap")["ok"] is True
    assert gate.check_tool("NMAP")["ok"] is True
    assert gate.check_tool("zap")["ok"] is True

    res_metasploit = gate.check_tool("metasploit")
    assert res_metasploit["ok"] is False
    assert res_metasploit["rule"] == "TOOL_NOT_PERMITTED"


def test_time_window_enforcement():
    now_utc = datetime.datetime.now(datetime.timezone.utc).time()

    # Create window that includes right now
    start_ok = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).time()
    end_ok = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).time()

    scope_ok = EngagementScope(time_window_start=start_ok, time_window_end=end_ok)
    gate_ok = ScopeGate(scope_ok)
    assert gate_ok.check_time_window()["ok"] is True

    # Create window in the past (e.g. 2 hours ago to 1 hour ago)
    past_start = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).time()
    past_end = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).time()

    scope_expired = EngagementScope(time_window_start=past_start, time_window_end=past_end)
    gate_expired = ScopeGate(scope_expired)
    res_time = gate_expired.check_time_window()
    assert res_time["ok"] is False
    assert res_time["rule"] == "TIME_WINDOW_VIOLATION"


def test_enforce_or_raise():
    scope = EngagementScope(
        allowed_cidrs=["192.168.1.0/24"],
        allowed_tools=["nmap"],
    )
    gate = ScopeGate(scope)

    # Valid check does not raise
    gate.enforce_or_raise("192.168.1.5", tool="nmap")

    # Invalid target raises ScopeViolationError
    with pytest.raises(ScopeViolationError) as exc_info:
        gate.enforce_or_raise("10.0.0.1", tool="nmap")
    assert "not inside any allowed engagement CIDRs" in str(exc_info.value)

