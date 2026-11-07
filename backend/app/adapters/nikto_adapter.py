"""Nikto Web Server Scanner Adapter.

Execution: LIVE (CLI subprocess) or IMPORT-ONLY (text/XML log file).
License: GPL-2.0 (Process Boundary).
"""

from __future__ import annotations

import hashlib
import re
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


class NiktoAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="nikto",
            display_name="Nikto Web Server Scanner",
            category=ToolCategory.WEB_APP_SCANNER,
        )

    def get_health(self) -> AdapterHealth:
        bin_path = shutil.which("nikto")
        is_avail = bin_path is not None
        version = None
        if is_avail:
            try:
                ok, stdout, _, _, _, _ = self.run_subprocess(["nikto", "-Version"], timeout=5)
                if ok and stdout:
                    for line in stdout.splitlines():
                        if "Nikto" in line:
                            version = line.strip()
                            break
            except Exception:
                pass

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.LIVE if is_avail else ExecutionMode.IMPORT_ONLY,
            is_available=is_avail,
            version=version or ("Available" if is_avail else "Not installed"),
            binary_path=bin_path,
            license_type="GPL-2.0 (Process Boundary)",
            licensing_verified=True,
            message="Ready for web server scanning" if is_avail else "Binary not on PATH. Upload Nikto log for import mode.",
            limitations=["Can produce noisy web traffic; non-stealthy by design."],
            assumptions=["Target host has HTTP/HTTPS listener active."],
            supported_formats=[".txt", ".json", ".xml"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        # Normalizes target URL
        url = target if "://" in target else f"http://{target}"
        return ["nikto", "-host", url, "-ask", "no", "-output", "-", "-Format", "txt"]

    def parse_output(self, raw_data: bytes | str, filename: str = "nikto.txt", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse Nikto stdout or text file into normalized findings."""
        if isinstance(raw_data, bytes):
            raw_text = raw_data.decode("utf-8", errors="replace")
        else:
            raw_text = raw_data

        if not sha256:
            sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        findings = []
        target_host = "web-host"

        for line in raw_text.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("---") or line_str.startswith("#"):
                continue

            if "Target Host:" in line_str or "Target IP:" in line_str:
                parts = line_str.split(":", 1)
                if len(parts) > 1:
                    target_host = parts[1].strip()
                continue

            if not line_str.startswith("+"):
                continue

            content = line_str.lstrip("+").strip()
            # Ignore banner and informational setup lines
            if any(ign in content for line_sub in ["Start Time", "End Time", "Scan is complete", "items checked"] for ign in [line_sub]):
                continue

            # Classify severity based on standard Nikto keywords
            severity = "info"
            cvss = 0.0
            confidence = 0.70

            c_lower = content.lower()
            if any(w in c_lower for w in ["vulnerable", "remote code", "sql injection", "command execution"]):
                severity = "high"
                cvss = 7.5
                confidence = 0.85
            elif any(w in c_lower for w in ["directory indexing", "x-frame-options", "cross site", "credentials", "outdated"]):
                severity = "medium"
                cvss = 5.0
                confidence = 0.75
            elif any(w in c_lower for w in ["header missing", "uncommon header", "cookie without"]):
                severity = "low"
                cvss = 2.5
                confidence = 0.80

            # Title extraction: first sentence or 80 chars
            title_candidate = content.split(":")[0] if ":" in content else content
            if len(title_candidate) > 90:
                title_candidate = title_candidate[:87] + "..."

            # Check for OSVDB or CVE references
            cve = ""
            m_cve = re.search(r"CVE-\d{4}-\d{4,7}", content, re.IGNORECASE)
            if m_cve:
                cve = m_cve.group(0).upper()

            findings.append({
                "title": f"Nikto: {title_candidate}",
                "severity": severity,
                "confidence": confidence,
                "cvss": cvss,
                "asset": target_host,
                "url": f"http://{target_host}",
                "parameter": "",
                "source": "nikto",
                "source_filename": filename,
                "source_file_sha256": sha256,
                "evidence": content,
                "evidence_json": {"raw_line": line_str},
                "remediation": "Investigate identified configuration or vulnerability on the web server.",
                "references": [],
                "cwe": "CWE-16" if severity in ("low", "medium") else "",
                "cve": cve,
            })

        return findings

