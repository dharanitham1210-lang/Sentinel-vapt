"""Tenable Nessus Scanner Adapter.

Execution: IMPORT-ONLY (.nessus v2 XML parser).
Integration Transparency: Live API requires an active commercial Tenable Nessus / Tenable.io license
and configured API access keys. It is truthfully presented as IMPORT-ONLY by default.
License: Commercial / Proprietary (User-Supplied Export).
"""

from __future__ import annotations

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


class NessusAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="nessus",
            display_name="Tenable Nessus",
            category=ToolCategory.INFRASTRUCTURE_VULN,
        )

    def get_health(self) -> AdapterHealth:
        # Check if user explicitly configured a live Tenable Nessus API key & URL
        nessus_url = os.getenv("NESSUS_API_URL")
        nessus_key = os.getenv("NESSUS_API_KEY")

        if nessus_url and nessus_key:
            return AdapterHealth(
                tool_name=self.name,
                display_name=self.display_name,
                mode=ExecutionMode.CONFIG_REQUIRED,
                is_available=False,
                endpoint_url=nessus_url,
                license_type="Commercial (User-Supplied)",
                licensing_verified=False,
                message="Nessus credentials detected; enterprise REST connection requires live token verification.",
                limitations=["Commercial license required; rate limits apply."],
                assumptions=["Tenable Nessus Professional or Manager instance."],
                supported_formats=[".nessus"],
            )

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.IMPORT_ONLY,
            is_available=True,  # Parser is 100% available and verified
            license_type="Commercial (Import-Only Parser)",
            licensing_verified=True,
            message="Import-only: Upload verified .nessus (v2 XML) export files. Live scanning requires commercial license.",
            limitations=["Live execution disabled to respect Tenable commercial licensing."],
            assumptions=["Export is in standard Nessus v2 XML format."],
            supported_formats=[".nessus", ".xml"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        raise NotImplementedError("Live execution for Nessus is disabled. Upload .nessus report file instead.")

    def parse_output(self, raw_data: bytes | str, filename: str = "scan.nessus", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse standard .nessus v2 XML export into normalized findings."""
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
            "4": "critical",
            "3": "high",
            "2": "medium",
            "1": "low",
            "0": "info",
        }

        for report_host in root.findall(".//ReportHost"):
            host_name = report_host.get("name", "unknown-host")

            for item in report_host.findall("ReportItem"):
                raw_sev = item.get("severity", "0")
                severity = sev_map.get(raw_sev, "info")

                plugin_name = item.get("pluginName") or "Nessus Finding"
                plugin_id = item.get("pluginID", "")
                port = item.get("port", "0")
                proto = item.get("protocol", "tcp")
                svc_name = item.get("svc_name", "")

                synopsis = item.findtext("synopsis", "")
                desc = item.findtext("description", "")
                solution = item.findtext("solution", "")
                plugin_out = item.findtext("plugin_output", "")

                cvss = 0.0
                cvss3_elem = item.findtext("cvss3_base_score")
                cvss2_elem = item.findtext("cvss_base_score")
                if cvss3_elem:
                    try:
                        cvss = float(cvss3_elem)
                    except ValueError:
                        pass
                elif cvss2_elem:
                    try:
                        cvss = float(cvss2_elem)
                    except ValueError:
                        pass

                cve = item.findtext("cve", "")
                cwe = item.findtext("cwe", "")
                if cwe and not cwe.startswith("CWE-"):
                    cwe = f"CWE-{cwe}"

                evidence = plugin_out or desc or synopsis or "Nessus vulnerability detection."

                refs = []
                see_also = item.findtext("see_also", "")
                if see_also:
                    refs.extend(see_also.splitlines())

                findings.append({
                    "title": f"Nessus: {plugin_name}",
                    "severity": severity,
                    "confidence": 0.85,
                    "cvss": cvss,
                    "asset": host_name,
                    "url": f"{host_name}:{port}" if port != "0" else host_name,
                    "parameter": f"{port}/{proto}" if port != "0" else "",
                    "source": "nessus",
                    "source_filename": filename,
                    "source_file_sha256": sha256,
                    "evidence": evidence.strip(),
                    "evidence_json": {
                        "plugin_id": plugin_id,
                        "plugin_family": item.get("pluginFamily", ""),
                        "svc_name": svc_name,
                        "port": port,
                        "protocol": proto,
                        "cvss3_vector": item.findtext("cvss3_vector", ""),
                    },
                    "remediation": solution or "Apply manufacturer patches or configuration guidance.",
                    "references": [r.strip() for r in refs if r.strip()],
                    "cwe": cwe,
                    "cve": cve,
                })

        return findings

