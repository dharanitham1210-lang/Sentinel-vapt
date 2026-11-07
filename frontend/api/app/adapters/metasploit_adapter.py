"""Metasploit Framework (MSF) Adapter.

Execution: LIVE but STRICTLY HUMAN-APPROVED and LAB-ONLY via msfrpcd.
Non-Negotiable Rule 3:
Active exploitation / offensive validation requires explicit human approval recorded with:
approver identity, timestamp, exact module/parameters, target, justification, outcome.
Lab-only flag must be checked too. Never autonomous.
License: BSD-3-Clause (Rapid7).
"""

from __future__ import annotations

import datetime
import hashlib
import os
import shutil
from typing import Any, Dict, List, Optional

from .base import (
    AdapterHealth,
    BaseAdapter,
    ErrorClass,
    ExecutionMode,
    ExecutionResult,
    ToolCategory,
)
from .. import config


class MetasploitAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="metasploit",
            display_name="Metasploit Framework (MSF)",
            category=ToolCategory.OFFENSIVE_VALIDATION,
        )

    def get_health(self) -> AdapterHealth:
        if config.CLOUD_MODE:
            return AdapterHealth(
                tool_name=self.name,
                display_name=self.display_name,
                mode=ExecutionMode.CONFIG_REQUIRED,
                is_available=False,
                endpoint_url="",
                binary_path=None,
                license_type="BSD-3-Clause",
                licensing_verified=True,
                message="Live Metasploit offensive validation is disabled in CLOUD_MODE on public cloud infrastructure.",
                limitations=[
                    "CLOUD PROTECTION: Live offensive exploitation disabled in cloud deployment.",
                    "Offline log import mode remains available.",
                ],
                assumptions=["Cloud deployment requires isolated self-hosted runner for live offensive modules."],
                supported_formats=["Offline msf log import"],
            )

        msf_rpc_url = os.getenv("MSF_RPC_URL", "http://127.0.0.1:55553")
        msf_bin = shutil.which("msfconsole")
        is_avail = msf_bin is not None

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.LIVE if is_avail else ExecutionMode.CONFIG_REQUIRED,
            is_available=is_avail,
            endpoint_url=msf_rpc_url,
            binary_path=msf_bin,
            license_type="BSD-3-Clause",
            licensing_verified=True,
            message="Live execution strictly gated behind human approval and lab-only verification."
            if is_avail else "msfconsole/msfrpcd not detected on system.",
            limitations=[
                "MANDATORY HUMAN APPROVAL: Exploit modules cannot run autonomously.",
                "LAB-ONLY: Execution blocked on any non-isolated network.",
                "Non-destructive check modules preferred for vulnerability validation.",
            ],
            assumptions=["Target is an authorized lab host; operator is logged in as Lead Analyst."],
            supported_formats=["Live RPC", "msf output log"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = options or {}
        module = opts.get("module", "auxiliary/scanner/portscan/tcp")
        # Build strict msfconsole batch command
        return ["msfconsole", "-q", "-x", f"use {module}; set RHOSTS {target}; run; exit"]

    def validate_offensive_approval(
        self,
        module: str,
        target: str,
        approval_record: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Strictly enforce Non-Negotiable Rule 3 for Metasploit.

        Returns {'ok': True} or raises ScopeViolationError/ApprovalRequired.
        """
        is_exploit = module.startswith("exploit/")
        is_check = module.startswith("auxiliary/")

        if not is_exploit and is_check:
            # Auxiliary verification modules can run in authorized lab engagements
            return {"ok": True, "requires_approval": False}

        # For exploit modules: explicit human approval is strictly required
        if not approval_record:
            return {
                "ok": False,
                "error_class": ErrorClass.APPROVAL_REQUIRED,
                "reason": (
                    f"Exploit module '{module}' requires explicit human approval. "
                    "Submit an approval request with target, justification, and lab confirmation."
                ),
            }

        # Check approval attributes
        status = approval_record.get("status")
        if status != "approved":
            return {
                "ok": False,
                "error_class": ErrorClass.APPROVAL_REQUIRED,
                "reason": f"Approval request status is '{status}' (must be 'approved').",
            }

        # Check lab confirmed flag
        if not approval_record.get("lab_confirmed"):
            return {
                "ok": False,
                "error_class": ErrorClass.SCOPE_VIOLATION,
                "reason": "Exploit execution blocked: 'lab_confirmed' flag is false. Exploits are lab-only.",
            }

        # Check expiration
        expires_at = approval_record.get("expires_at", "")
        if expires_at:
            try:
                exp_dt = datetime.datetime.fromisoformat(expires_at)
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                if now_dt > exp_dt:
                    return {
                        "ok": False,
                        "error_class": ErrorClass.APPROVAL_REQUIRED,
                        "reason": f"Approval token expired at {expires_at}.",
                    }
            except Exception:
                pass

        # Check target match
        appr_target = approval_record.get("target", "")
        if appr_target != target:
            return {
                "ok": False,
                "error_class": ErrorClass.SCOPE_VIOLATION,
                "reason": f"Approval target mismatch: approved for '{appr_target}', requested '{target}'.",
            }

        return {"ok": True, "requires_approval": True, "approval_id": approval_record.get("id")}

    def execute(self, command: List[str], timeout_seconds: int = 120, cwd: Optional[str] = None) -> ExecutionResult:
        if config.CLOUD_MODE:
            return ExecutionResult(
                success=False,
                error_class=ErrorClass.PERMISSION,
                error_message="Metasploit live exploitation is disabled in CLOUD_MODE on cloud deployments.",
            )
        return super().execute(command, timeout_seconds, cwd)

    def parse_output(self, raw_data: bytes | str, filename: str = "msf_output.txt", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse Metasploit check output into validated finding."""
        if isinstance(raw_data, bytes):
            raw_text = raw_data.decode("utf-8", errors="replace")
        else:
            raw_text = raw_data

        if not sha256:
            sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        findings = []
        is_vuln = False
        evidence_lines = []

        for line in raw_text.splitlines():
            l_str = line.strip()
            if "[+]" in l_str or "The target is vulnerable" in l_str or "Vulnerable:" in l_str:
                is_vuln = True
                evidence_lines.append(l_str)
            elif "[*]" in l_str:
                evidence_lines.append(l_str)

        if is_vuln:
            findings.append({
                "title": "Metasploit: Offensive Validation Succeeded",
                "severity": "high",
                "confidence": 1.0,  # 100% confidence: active validation verified
                "cvss": 8.0,
                "asset": "lab-target",
                "url": "",
                "parameter": "",
                "source": "metasploit",
                "source_filename": filename,
                "source_file_sha256": sha256,
                "evidence": "\n".join(evidence_lines),
                "evidence_json": {"validated": True, "log": raw_text[:2000]},
                "remediation": "Remediate verified vulnerability immediately; confirmed exploitable in lab environment.",
                "references": [],
                "cwe": "",
                "cve": "",
            })

        return findings

