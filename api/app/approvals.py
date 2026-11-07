"""Dual Human Approval Gates (Actions & Reports).

Non-Negotiable Rule 3:
Active exploitation / offensive validation (Metasploit, Burp active attacks, ZAP active scan
with attack payloads, any PoC) requires explicit human approval recorded with:
approver identity, timestamp, exact command/module/parameters, target, justification, outcome.
Lab-only flag must be checked too.
Approval tokens expire automatically.
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any, Dict, List, Optional

from .audit import AuditService


class ApprovalService:
    @staticmethod
    def create_request(
        db,
        assessment_id: str,
        request_type: str,  # 'action' or 'report'
        requester: str,
        target: str,
        tool: str = "",
        command: str = "",
        params: Optional[Dict[str, Any]] = None,
        justification: str = "",
        lab_confirmed: bool = False,
        ttl_minutes: int = 120,
    ) -> Dict[str, Any]:
        """Create an approval request in pending state."""
        appr_id = f"appr-{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(minutes=ttl_minutes)).isoformat()
        params_json = json.dumps(params or {}, sort_keys=True)

        db.execute(
            """
            INSERT INTO approvals (
                id, assessment_id, request_type, requester, approver,
                status, target, tool, command, params_json, justification,
                lab_confirmed, created_at, expires_at, decided_at, outcome_notes
            )
            VALUES (?, ?, ?, ?, '', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, '', '')
            """,
            (
                appr_id,
                assessment_id,
                request_type,
                requester,
                target,
                tool,
                command,
                params_json,
                justification,
                1 if lab_confirmed else 0,
                now.isoformat(),
                expires_at,
            ),
        )

        AuditService.record(
            db,
            action="APPROVAL_REQUESTED",
            assessment_id=assessment_id,
            actor=requester,
            target=target,
            detail={
                "approval_id": appr_id,
                "request_type": request_type,
                "tool": tool,
                "command": command,
                "justification": justification,
                "lab_confirmed": lab_confirmed,
                "expires_at": expires_at,
            },
        )
        db.commit()

        return {
            "id": appr_id,
            "assessment_id": assessment_id,
            "request_type": request_type,
            "status": "pending",
            "target": target,
            "tool": tool,
            "command": command,
            "params": params or {},
            "justification": justification,
            "lab_confirmed": lab_confirmed,
            "expires_at": expires_at,
        }

    @staticmethod
    def decide_request(
        db,
        approval_id: str,
        approver: str,
        approved: bool,
        typed_target_confirmation: str,
        outcome_notes: str = "",
    ) -> Dict[str, Any]:
        """Decide an approval request (Approve or Deny). Enforces target confirmation typing."""
        cur = db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Approval request '{approval_id}' not found.")

        r = dict(row)
        if r["status"] != "pending":
            raise ValueError(f"Approval request '{approval_id}' is already {r['status']}.")

        # Check expiration
        now = datetime.datetime.now(datetime.timezone.utc)
        exp_dt = datetime.datetime.fromisoformat(r["expires_at"])
        if now > exp_dt:
            db.execute("UPDATE approvals SET status = 'expired' WHERE id = ?", (approval_id,))
            db.commit()
            raise ValueError(f"Approval request '{approval_id}' expired at {r['expires_at']}.")

        # Safety Check: Target Confirmation Typing
        # Operator must re-type the target to prevent accidental clicks
        expected_target = r["target"].strip().lower()
        confirmed_target = (typed_target_confirmation or "").strip().lower()
        if confirmed_target != expected_target:
            raise ValueError(
                f"Target confirmation mismatch: Expected '{expected_target}', received '{confirmed_target}'."
            )

        new_status = "approved" if approved else "denied"
        decided_at = now.isoformat()

        db.execute(
            """
            UPDATE approvals
            SET status = ?, approver = ?, decided_at = ?, outcome_notes = ?
            WHERE id = ?
            """,
            (new_status, approver, decided_at, outcome_notes or "", approval_id),
        )

        AuditService.record(
            db,
            action=f"APPROVAL_{new_status.upper()}",
            assessment_id=r["assessment_id"],
            actor=approver,
            target=r["target"],
            detail={
                "approval_id": approval_id,
                "status": new_status,
                "tool": r["tool"],
                "command": r["command"],
                "notes": outcome_notes,
            },
        )
        db.commit()

        r["status"] = new_status
        r["approver"] = approver
        r["decided_at"] = decided_at
        r["outcome_notes"] = outcome_notes
        return r

    @staticmethod
    def get_approval(db, approval_id: str) -> Optional[Dict[str, Any]]:
        cur = db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    @staticmethod
    def list_approvals(db, assessment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if assessment_id:
            cur = db.execute("SELECT * FROM approvals WHERE assessment_id = ? ORDER BY created_at DESC", (assessment_id,))
        else:
            cur = db.execute("SELECT * FROM approvals ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

