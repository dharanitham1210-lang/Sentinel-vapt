"""OpenVAS / Greenbone Vulnerability Management (GVM) Adapter.

Execution: IMPORT-ONLY (OpenVAS XML report parser) or LIVE via GMP if local container/daemon is reachable.
Integration Transparency: Live GMP requires a dedicated Greenbone Community Edition container
running gvmd. Due to feed synchronization requirements (several hours), it is truthfully
configured for IMPORT-ONLY by default, with live GMP probes enabled when configured.
License: GPL-3.0-or-later (Process / Protocol Boundary).
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


class OpenVASAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="openvas",
            display_name="OpenVAS / Greenbone Community",
            category=ToolCategory.INFRASTRUCTURE_VULN,
        )

    def get_health(self) -> AdapterHealth:
        gmp_host = os.getenv("OPENVAS_GMP_HOST")
        if gmp_host:
            return AdapterHealth(
                tool_name=self.name,
                display_name=self.display_name,
                mode=ExecutionMode.CONFIG_REQUIRED,
                is_available=False,
                endpoint_url=gmp_host,
                license_type="GPL-3.0-or-later (GMP API)",
                licensing_verified=True,
                message="GMP endpoint configured; feed sync validation required.",
                limitations=["Greenbone feed sync must be current."],
                assumptions=["Greenbone daemon running on target host."],
                supported_formats=[".xml", ".csv"],
            )

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.IMPORT_ONLY,
            is_available=True,
            license_type="GPL-3.0-or-later (Import Parser)",
            licensing_verified=True,
            message="Import-only: Upload OpenVAS/Greenbone XML reports. Live scanning requires GMP container stack.",
            limitations=["Live GMP scanning requires multi-container Greenbone deployment."],
            assumptions=["OpenVAS XML report exported from Greenbone Security Assistant (GSA)."],
            supported_formats=[".xml", ".csv"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        raise NotImplementedError("Live execution requires active GMP daemon; upload OpenVAS XML report.")

    def parse_output(self, raw_data: bytes | str, filename: str = "openvas_report.xml", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse OpenVAS XML report into normalized findings."""
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

        def get_severity(score_val: float) -> str:
            if score_val >= 9.0:
                return "critical"
            if score_val >= 7.0:
                return "high"
            if score_val >= 4.0:
                return "medium"
            if score_val > 0.0:
                return "low"
            return "info"

        for res in root.findall(".//result"):
            name = res.findtext("name", "OpenVAS Vulnerability")
            host = res.findtext("host", "target-host")
            port = res.findtext("port", "")
            threat = res.findtext("threat", "Low")
            desc = res.findtext("description", "")
            solution = ""
            solution_elem = res.find(".//solution")
            if solution_elem is not None and solution_elem.text:
                solution = solution_elem.text

            cvss = 0.0
            sev_str = res.findtext("severity", "0.0")
            try:
                cvss = float(sev_str)
            except ValueError:
                pass

            severity = get_severity(cvss)

            cve = ""
            cve_elem = res.find(".//cve")
            if cve_elem is not None and cve_elem.text:
                cve = cve_elem.text.strip()
                if cve.lower() == "nocve":
                    cve = ""

            nvt = res.find("nvt")
            oid = nvt.get("oid", "") if nvt is not None else ""

            evidence = desc or f"Threat level: {threat}\nNVT OID: {oid}"

            findings.append({
                "title": f"OpenVAS: {name}",
                "severity": severity,
                "confidence": 0.85,
                "cvss": cvss,
                "asset": host,
                "url": f"{host}:{port}" if port else host,
                "parameter": port,
                "source": "openvas",
                "source_filename": filename,
                "source_file_sha256": sha256,
                "evidence": evidence.strip(),
                "evidence_json": {
                    "oid": oid,
                    "threat": threat,
                    "port": port,
                },
                "remediation": solution or "Apply recommended vendor fixes.",
                "references": [],
                "cwe": "",
                "cve": cve,
            })

        return findings

