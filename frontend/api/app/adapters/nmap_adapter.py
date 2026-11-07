"""Nmap Scanner Adapter.

Execution: LIVE (CLI with XML streaming) or IMPORT-ONLY (Nmap XML/JSON file).
License: Free / Open Source (GPL-2.0 via process boundary).
"""

from __future__ import annotations

import hashlib
import shutil
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


class NmapAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="nmap",
            display_name="Network Mapper (Nmap)",
            category=ToolCategory.NETWORK_DISCOVERY,
        )

    def get_health(self) -> AdapterHealth:
        bin_path = shutil.which("nmap")
        is_avail = bin_path is not None
        version = None
        if is_avail:
            try:
                ok, stdout, _, _, _, _ = self.run_subprocess(["nmap", "--version"], timeout=5)
                if ok and stdout:
                    first_line = stdout.strip().splitlines()[0]
                    version = first_line.replace("Nmap version ", "").split(" ")[0]
            except Exception:
                pass

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.LIVE if is_avail else ExecutionMode.IMPORT_ONLY,
            is_available=is_avail,
            version=version or ("Available" if is_avail else "Not installed"),
            binary_path=bin_path,
            license_type="NPSL / GPL-2.0 (Process Boundary)",
            licensing_verified=True,
            message="Ready for live scanning" if is_avail else "Binary not on PATH. Upload Nmap XML for import mode.",
            limitations=["Raw packet generation requires elevated root/admin privileges for SYN scans (-sS)."],
            assumptions=["Target host is reachable over network; non-ping scanning (-Pn) used by default."],
            supported_formats=[".xml", ".json", "raw stdout"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = options or {}
        top_ports = min(int(opts.get("top_ports", 100)), 1000)
        # In CLOUD_MODE or non-root user, use -sT (TCP connect scan) and --unprivileged (no raw sockets)
        from .. import config
        is_unprivileged = getattr(os, "geteuid", lambda: 1000)() != 0 or config.CLOUD_MODE
        cmd = ["nmap"]
        if is_unprivileged:
            cmd.extend(["-sT", "--unprivileged"])
        cmd.extend(["-sV", "-Pn", "--top-ports", str(top_ports), "-oX", "-", target])
        return cmd

    def parse_output(self, raw_data: bytes | str, filename: str = "nmap.xml", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse Nmap XML output into standardized findings."""
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

        for host in root.findall(".//host"):
            status_elem = host.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue

            addr_elem = host.find("address")
            ip = addr_elem.get("addr", "") if addr_elem is not None else ""

            hostnames = [hn.get("name") for hn in host.findall(".//hostname") if hn.get("name")]
            primary_host = hostnames[0] if hostnames else ip

            for port in host.findall(".//port"):
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_id = port.get("portid", "")
                proto = port.get("protocol", "tcp")
                service_elem = port.find("service")

                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""
                extrainfo = service_elem.get("extrainfo", "") if service_elem is not None else ""

                version_banner = " ".join(filter(None, [product, version, extrainfo])).strip()

                evidence = f"Port {port_id}/{proto} open ({service_name})"
                if version_banner:
                    evidence += f" - {version_banner}"

                # Check for NSE script outputs
                scripts = []
                for s in port.findall("script"):
                    s_id = s.get("id", "")
                    s_out = s.get("output", "")
                    if s_id and s_out:
                        scripts.append(f"[{s_id}]: {s_out}")

                if scripts:
                    evidence += "\nNSE Scripts:\n" + "\n".join(scripts)

                severity = "info"
                cvss = 0.0
                confidence = 1.0

                # If dangerous or plaintext protocol
                if service_name in ("telnet", "rlogin", "ftp"):
                    severity = "low"
                    cvss = 3.5
                    confidence = 0.9

                finding = {
                    "title": f"Open port {port_id}/{proto}: {service_name}",
                    "severity": severity,
                    "confidence": confidence,
                    "cvss": cvss,
                    "asset": ip or primary_host,
                    "url": f"{primary_host}:{port_id}",
                    "parameter": f"{port_id}/{proto}",
                    "source": "nmap",
                    "source_filename": filename,
                    "source_file_sha256": sha256,
                    "evidence": evidence,
                    "evidence_json": {
                        "port": port_id,
                        "protocol": proto,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "scripts": scripts,
                    },
                    "remediation": f"Ensure {service_name} on port {port_id} is necessary; restrict access via host or network firewall.",
                    "references": [],
                    "cwe": "CWE-200" if severity != "info" else "",
                    "cve": "",
                }
                findings.append(finding)

        return findings

