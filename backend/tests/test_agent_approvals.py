import datetime
import sqlite3
import pytest

from app.agent.conversational import ConversationalAgent
from app.agent.grounding_validator import GroundingValidator
from app.agent.state_machine import AssessmentStateMachine
from app.approvals import ApprovalService
from app.scope_gate import EngagementScope, ScopeGate


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
    conn.execute(
        """
        CREATE TABLE approvals (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            request_type TEXT NOT NULL DEFAULT 'action',
            requester TEXT NOT NULL,
            approver TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            target TEXT NOT NULL,
            tool TEXT NOT NULL DEFAULT '',
            command TEXT NOT NULL DEFAULT '',
            params_json TEXT NOT NULL DEFAULT '{}',
            justification TEXT NOT NULL DEFAULT '',
            lab_confirmed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            decided_at TEXT DEFAULT '',
            outcome_notes TEXT DEFAULT ''
        )
        """
    )
    yield conn
    conn.close()


def test_grounding_validator_blocks_fabricated_cve():
    # Only Log4Shell is in raw evidence
    evidence_cves = {"CVE-2021-44228"}
    validator = GroundingValidator(raw_evidence_cves=evidence_cves)

    # Valid grounded CVE passes
    res_valid = validator.validate_finding_claims({
        "title": "Log4j RCE",
        "cve": "CVE-2021-44228",
        "cwe": "CWE-502",
        "cvss": 10.0,
    })
    assert res_valid.is_grounded is True

    # Hallucinated / non-existent CVE is blocked
    res_hallucinated = validator.validate_finding_claims({
        "title": "Fabricated Vuln",
        "cve": "CVE-2099-99999",  # Not in evidence and not in NVD benchmark
        "cwe": "CWE-79",
        "cvss": 8.0,
    })
    assert res_hallucinated.is_grounded is False
    assert "CVE-2099-99999" in res_hallucinated.rejected_cves


def test_state_machine_adaptive_replanning():
    sm = AssessmentStateMachine(assessment_id="asm-01")

    # Ingest Nmap finding discovering port 80 and 8080 open with Apache
    nmap_findings = [
        {"asset": "10.10.20.5", "parameter": "80/tcp", "evidence": "Apache 2.4.52 on port 80", "title": "Open port 80"},
        {"asset": "10.10.20.5", "parameter": "8080/tcp", "evidence": "Apache Tomcat on port 8080", "title": "Open port 8080"},
    ]
    sm.ingest_findings(nmap_findings, triggering_artifact_id="art-nmap-1")

    state = sm.get_structured_state()
    assert "10.10.20.5" in state["assets"]
    assert set(state["assets"]["10.10.20.5"]["ports"]) == {80, 8080}
    assert "Apache HTTP Server" in state["technologies"]

    # Check that ZAP and Nikto proposals were generated for the discovered ports
    proposals = state["pending_proposals"]
    tools_proposed = {p["tool"] for p in proposals}
    assert "nikto" in tools_proposed
    assert "zap" in tools_proposed

    # Verify that proposals reference the triggering evidence ID
    for p in proposals:
        assert p["triggering_evidence_id"] == "art-nmap-1"
        assert "discovered" in p["why_now"].lower() or "confirmed" in p["why_now"].lower()


def test_conversational_agent_scope_enforcement():
    scope = EngagementScope(allowed_cidrs=["10.10.20.0/24"], allow_public_ips=False)
    gate = ScopeGate(scope)
    agent = ConversationalAgent(gate)

    # In-scope request succeeds
    res_in_scope = agent.plan_assessment("Run external scan on 10.10.20.5", "10.10.20.5")
    assert res_in_scope["ok"] is True
    assert len(res_in_scope["steps"]) >= 3

    # Out-of-scope request is strictly blocked
    res_out_of_scope = agent.plan_assessment("Scan public target 8.8.8.8", "8.8.8.8")
    assert res_out_of_scope["ok"] is False
    assert "Scope Violation" in res_out_of_scope["error"]


def test_approval_service_lifecycle_and_target_confirmation(mock_db):
    # 1. Create approval request
    req = ApprovalService.create_request(
        mock_db,
        assessment_id="asm-test",
        request_type="action",
        requester="lead_analyst_1",
        target="10.10.20.5",
        tool="metasploit",
        command="use exploit/multi/handler",
        justification="Verify remote shell in isolated lab environment.",
        lab_confirmed=True,
        ttl_minutes=60,
    )
    appr_id = req["id"]
    assert req["status"] == "pending"

    # 2. Re-typing target mismatch fails
    with pytest.raises(ValueError) as exc:
        ApprovalService.decide_request(
            mock_db,
            approval_id=appr_id,
            approver="admin_user",
            approved=True,
            typed_target_confirmation="wrong.target",
        )
    assert "Target confirmation mismatch" in str(exc.value)

    # 3. Matching target confirmation succeeds
    decided = ApprovalService.decide_request(
        mock_db,
        approval_id=appr_id,
        approver="admin_user",
        approved=True,
        typed_target_confirmation="10.10.20.5",
        outcome_notes="Authorized for lab execution.",
    )
    assert decided["status"] == "approved"
    assert decided["approver"] == "admin_user"

    # Verify audit trail
    cur = mock_db.execute("SELECT * FROM audit_logs WHERE event = 'APPROVAL_APPROVED'")
    row = cur.fetchone()
    assert row is not None
    assert row["actor"] == "admin_user"

