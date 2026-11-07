"""Nuclei Template-Based Vulnerability Scanner Adapter.

Execution: LIVE (CLI subprocess) or IMPORT-ONLY (JSONL report).
License: MIT (ProjectDiscovery).
"""

from __future__ import annotations

import hashlib
import json
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


class NucleiAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="nuclei",
            display_name="ProjectDiscovery Nuclei",
            category=ToolCategory.WEB_APP_SCANNER,
        )

    def get_health(self) -> AdapterHealth:
        bin_path = shutil.which("nuclei")
        is_avail = bin_path is not None
        version = None
        if is_avail:
            try:
                ok, stdout, _, _, _, _ = self.run_subprocess(["nuclei", "-version"], timeout=5)
                if ok and stdout:
                    version = stdout.strip().splitlines()[0]
            except Exception:
                pass

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.LIVE if is_avail else ExecutionMode.IMPORT_ONLY,
            is_available=is_avail,
            version=version or ("Available" if is_avail else "Not installed"),
            binary_path=bin_path,
            license_type="MIT",
            licensing_verified=True,
            message="Ready for fast template-based vulnerability assessment" if is_avail else "Binary not on PATH. JSONL export supported for import.",
            limitations=["Requires downloaded community templates."],
            assumptions=["Target accepts HTTP/TCP traffic."],
            supported_formats=[".json", ".jsonl"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = options or {}
        tags = opts.get("tags", "cve,misconfig,exposure")
        return ["nuclei", "-u", target, "-jsonl", "-silent", "-tags", tags]

    def parse_output(self, raw_data: bytes | str, filename: str = "nuclei.jsonl", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse Nuclei JSON-lines output stream into normalized findings."""
        if isinstance(raw_data, bytes):
            raw_text = raw_data.decode("utf-8", errors="replace")
        else:
            raw_text = raw_data

        if not sha256:
            sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        findings = []
        for line in raw_text.splitlines():
            line_str = line.strip()
            if not line_str.startswith("{"):
                continue

            try:
                item = json.loads(line_str)
            except Exception:
                continue

            info = item.get("info", {})
            title = info.get("name") or item.get("template-id", "Nuclei Finding")
            severity = (info.get("severity") or "info").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "info"

            cvss = 0.0
            classification = info.get("classification", {})
            if classification.get("cvss-score"):
                try:
                    cvss = float(classification["cvss-score"])
                except (ValueError, TypeError):
                    pass

            cve = ""
            cve_list = classification.get("cve-id", [])
            if isinstance(cve_list, list) and cve_list:
                cve = cve_list[0].upper()
            elif isinstance(cve_list, str) and cve_list:
                cve = cve_list.upper()

            cwe = ""
            cwe_list = classification.get("cwe-id", [])
            if isinstance(cwe_list, list) and cwe_list:
                cwe = cwe_list[0].upper()
            elif isinstance(cwe_list, str) and cwe_list:
                cwe = cwe_list.upper()

            host = item.get("host") or item.get("matched-at") or "target"
            matched_at = item.get("matched-at", "")
            curl_cmd = item.get("curl-command", "")
            extracted = item.get("extracted-results", [])

            evidence = f"Matched at: {matched_at}\nTemplate ID: {item.get('template-id')}"
            if extracted:
                evidence += f"\nExtracted: {extracted}"
            if curl_cmd:
                evidence += f"\nPoC Command: {curl_cmd}"

            findings.append({
                "title": f"Nuclei: {title}",
                "severity": severity,
                "confidence": 0.90,  # High confidence due to explicit matcher rule
                "cvss": cvss,
                "asset": host,
                "url": matched_at,
                "parameter": "",
                "source": "nuclei",
                "source_filename": filename,
                "source_file_sha256": sha256,
                "evidence": evidence,
                "evidence_json": {
                    "template_id": item.get("template-id"),
                    "matcher_name": item.get("matcher-name"),
                    "type": item.get("type"),
                },
                "remediation": info.get("remediation") or "Address template findings as described in references.",
                "references": info.get("reference") or [],
                "cwe": cwe,
                "cve": cve,
            })

        return findings

