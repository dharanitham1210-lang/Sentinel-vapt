"""OWASP ZAP (Zed Attack Proxy) Adapter.

Execution: LIVE (via ZAP REST API) or IMPORT-ONLY (ZAP JSON/XML report).
Safety: Active attacks require explicit Human Approval. Passive spidering/inspection is permitted.
License: Apache-2.0.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

import httpx

from ..config import ZAP_API_KEY, ZAP_API_URL
from .base import (
    AdapterHealth,
    BaseAdapter,
    ErrorClass,
    ExecutionMode,
    ExecutionResult,
    ToolCategory,
)


class ZapAdapter(BaseAdapter):
    def __init__(self):
        super().__init__(
            name="zap",
            display_name="OWASP Zed Attack Proxy (ZAP)",
            category=ToolCategory.WEB_APP_SCANNER,
        )

    def get_health(self) -> AdapterHealth:
        try:
            r = httpx.get(
                ZAP_API_URL.rstrip("/") + "/JSON/core/view/version/",
                params={"apikey": ZAP_API_KEY},
                timeout=0.6,
                trust_env=False,
            )
            if r.status_code == 200:
                v = r.json().get("version", "Live")
                return AdapterHealth(
                    tool_name=self.name,
                    display_name=self.display_name,
                    mode=ExecutionMode.LIVE,
                    is_available=True,
                    version=v,
                    endpoint_url=ZAP_API_URL,
                    license_type="Apache-2.0",
                    licensing_verified=True,
                    message="ZAP API connected and responsive.",
                    limitations=["Active attack modules require recorded human approval."],
                    assumptions=["Target application accepts HTTP traffic."],
                    supported_formats=[".json", ".xml", "Live API"],
                )
        except Exception:
            pass

        return AdapterHealth(
            tool_name=self.name,
            display_name=self.display_name,
            mode=ExecutionMode.IMPORT_ONLY,
            is_available=False,
            endpoint_url=ZAP_API_URL,
            license_type="Apache-2.0",
            licensing_verified=True,
            message="ZAP daemon not reachable on configured port. Import mode active.",
            limitations=["Live scanning unavailable without active local ZAP daemon."],
            assumptions=["User provides standard ZAP JSON alerts export."],
            supported_formats=[".json", ".xml"],
        )

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        # ZAP uses REST API rather than direct CLI process invocation
        return ["curl", f"{ZAP_API_URL}/JSON/ascan/action/scan/", f"url={target}"]

    def parse_output(self, raw_data: bytes | str, filename: str = "zap.json", sha256: str = "") -> List[Dict[str, Any]]:
        """Parse ZAP JSON alerts export into standardized findings."""
        if isinstance(raw_data, bytes):
            raw_text = raw_data.decode("utf-8", errors="replace")
        else:
            raw_text = raw_data

        if not sha256:
            sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        findings = []
        try:
            data = json.loads(raw_text)
        except Exception:
            return findings

        alerts = []
        if isinstance(data, dict):
            if "site" in data:
                sites = data["site"] if isinstance(data["site"], list) else [data["site"]]
                for s in sites:
                    alerts.extend(s.get("alerts", []))
            elif "alerts" in data:
                alerts.extend(data.get("alerts", []))
            elif "alert" in data:
                alerts.append(data)
        elif isinstance(data, list):
            alerts = data

        sev_map = {
            "3": "high", "High": "high", "high": "high",
            "2": "medium", "Medium": "medium", "medium": "medium",
            "1": "low", "Low": "low", "low": "low",
            "0": "info", "Informational": "info", "info": "info",
        }
        conf_map = {
            "3": 0.95, "High": 0.95, "high": 0.95,
            "2": 0.80, "Medium": 0.80, "medium": 0.80,
            "1": 0.60, "Low": 0.60, "low": 0.60,
            "0": 0.40, "False Positive": 0.10,
        }
        cvss_defaults = {"high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

        for a in alerts:
            title = a.get("alert") or a.get("name") or a.get("title")
            if not title:
                continue

            raw_sev = str(a.get("risk") or a.get("riskcode") or "info")
            severity = sev_map.get(raw_sev, "info")

            raw_conf = str(a.get("confidence") or "medium")
            confidence = conf_map.get(raw_conf, 0.75)

            url = a.get("url", "")
            param = a.get("param", "")
            desc = a.get("desc") or a.get("description", "")
            evidence = a.get("evidence") or a.get("attack") or desc or "Observed in ZAP analysis."
            solution = a.get("solution") or "Review affected endpoint and apply secure coding controls."
            cwe = str(a.get("cweid") or "")
            if cwe and not cwe.startswith("CWE-") and cwe != "0":
                cwe = f"CWE-{cwe}"

            asset = url.split("://")[-1].split("/")[0] if url else "web-host"

            findings.append({
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "cvss": cvss_defaults.get(severity, 0.0),
                "asset": asset,
                "url": url,
                "parameter": param,
                "source": "zap",
                "source_filename": filename,
                "source_file_sha256": sha256,
                "evidence": evidence,
                "evidence_json": {
                    "attack": a.get("attack", ""),
                    "param": param,
                    "method": a.get("method", "GET"),
                    "cwe": cwe,
                    "wasc": a.get("wascid", ""),
                },
                "remediation": solution,
                "references": [a.get("reference")] if a.get("reference") else [],
                "cwe": cwe if cwe != "0" else "",
                "cve": "",
            })

        return findings
