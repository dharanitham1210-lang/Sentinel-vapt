"""PortSwigger Burp Suite Scanner Adapter.

Execution: IMPORT-ONLY (Burp Suite XML/JSON issue export).
Integration Transparency: Live scanning requires Burp Suite Enterprise / Pro REST API
and active user licenses. It is presented truthfully as IMPORT-ONLY by default.
License: Commercial / Proprietary (User-Supplied Export).
"""

from __future__ import annotations

import base64
import hashlib
import os
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .base import (
    AdapterHealth,
    BaseAdapter,
    ErrorClass,
    ExecutionMode,
    ExecutionResult,
    ToolCategory,
)


class BurpAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="burp",
            display_name="PortSwigger Burp Suite",
            category=ToolCategory.WEB_APP_SCANNER,
        )

    def get_health(self) -> AdapterHealth:
        burp_api = os.getenv("BURP_ENTERPRISE_API_URL")
        if burp_api:
            return AdapterHealth(
                tool_name=self.name,
                display_name=self.display_name,
                mode=ExecutionMode.CONFIG_REQUIRED,
                is_available=False,
                endpoint_url=burp_api,
                license_type="Commercial (User-Supplied)",
                licensing_verified=False,
                message="Burp Enterprise REST endpoint configured; API token handshake pending.",
                limitations=["Burp Suite Pro/Enterprise commercial license required."],
                assumptions=["Target web application reachable by Burp agent."],
                supported_formats=[".xml", ".json"],
            )

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.IMPORT_ONLY,
            is_available=True,
            license_type="Commercial (Import-Only Parser)",
            licensing_verified=True,
            message="Import-only: Upload Burp Suite XML issue exports. Live scans require Burp Enterprise API.",
            limitations=["Live execution disabled; respects PortSwigger commercial licensing terms."],
            assumptions=["XML report exported from Burp Suite Scanner ('Save issues' as XML)."],
            supported_formats=[".xml", ".json"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        raise NotImplementedError("Live execution for Burp Suite is disabled without enterprise license.")

    def parse_output(self, raw_data: bytes | str, filename: str = "burp_issues.xml", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse Burp Suite XML issues export into normalized findings."""
        if isinstance(raw_data, bytes):
            raw_text = raw_data.decode("utf-8", errors="replace")
        else:
            raw_text = raw_data

        if not sha256:
            sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        findings = []
        if not raw_text.strip().startswith("<"):
            return findings

        try:
            root = ET.fromstring(raw_text)
        except Exception:
            return findings

        sev_map = {
            "high": "high", "medium": "medium", "low": "low", "information": "info", "info": "info"
        }
        conf_map = {
            "certain": 0.95, "firm": 0.80, "tentative": 0.50
        }
        cvss_defaults = {"high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

        for issue in root.findall(".//issue"):
            name = issue.findtext("name", "Burp Finding")
            raw_sev = (issue.findtext("severity", "Information")).lower()
            severity = sev_map.get(raw_sev, "info")

            raw_conf = (issue.findtext("confidence", "Firm")).lower()
            confidence = conf_map.get(raw_conf, 0.75)

            host = issue.findtext("host", "web-host")
            path = issue.findtext("path", "/")
            location = issue.findtext("location", path)

            issue_bg = issue.findtext("issueBackground", "")
            issue_detail = issue.findtext("issueDetail", "")
            remediation_detail = issue.findtext("remediationDetail", "")
            remediation_bg = issue.findtext("remediationBackground", "")

            evidence = issue_detail or issue_bg or f"Detected at location: {location}"

            findings.append({
                "title": f"Burp: {name}",
                "severity": severity,
                "confidence": confidence,
                "cvss": cvss_defaults.get(severity, 0.0),
                "asset": host,
                "url": f"{host}{path}",
                "parameter": location if location != path else "",
                "source": "burp",
                "source_filename": filename,
                "source_file_sha256": sha256,
                "evidence": evidence.strip(),
                "evidence_json": {
                    "type": issue.findtext("type", ""),
                    "location": location,
                },
                "remediation": (remediation_detail or remediation_bg or "Remediate according to OWASP guidelines.").strip(),
                "references": [],
                "cwe": "",
                "cve": "",
            })

        return findings

