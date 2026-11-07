"""Adaptive Assessment State Machine and Memory Loop.

Agent loop: Plan -> Act -> Observe -> Reflect -> Replan.
Maintains structured engagement state:
- assets: hosts, IPs, OS fingerprints
- services: open ports, protocols, banners
- technologies: identified web servers, frameworks, CMS
- findings: normalized findings
- executed_actions: hash set H(tool, target, params) preventing duplicate scans
- pending_proposals: next-step proposals with 'Why this scan now' referencing Evidence IDs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


def hash_action(tool: str, target: str, params: Dict[str, Any]) -> str:
    serialized = json.dumps({"tool": tool.lower(), "target": target.lower(), "params": params}, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


@dataclass
class AdaptiveProposal:
    proposal_id: str
    tool: str
    target: str
    parameters: Dict[str, Any]
    rationale: str
    why_now: str
    triggering_evidence_id: str
    risk_class: str  # passive, intrusive, active
    requires_approval: bool
    status: str = "pending"  # pending, approved, executed, dismissed


class AssessmentStateMachine:
    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.services: List[Dict[str, Any]] = []
        self.technologies: Set[str] = set()
        self.findings: List[Dict[str, Any]] = []
        self.executed_action_hashes: Set[str] = set()
        self.proposals: List[AdaptiveProposal] = []

    def record_executed_action(self, tool: str, target: str, params: Dict[str, Any]):
        h = hash_action(tool, target, params)
        self.executed_action_hashes.add(h)

    def is_action_already_executed(self, tool: str, target: str, params: Dict[str, Any]) -> bool:
        h = hash_action(tool, target, params)
        return h in self.executed_action_hashes

    def ingest_findings(self, new_findings: List[Dict[str, Any]], triggering_artifact_id: str = ""):
        """Observe: Ingest latest tool results and update internal model."""
        self.findings.extend(new_findings)

        for f in new_findings:
            asset = f.get("asset") or "target"
            if asset not in self.assets:
                self.assets[asset] = {"host": asset, "ports": [], "technologies": []}

            param = str(f.get("parameter") or "")
            if "/" in param:
                port_str = param.split("/")[0]
                if port_str.isdigit() and int(port_str) not in self.assets[asset]["ports"]:
                    self.assets[asset]["ports"].append(int(port_str))

            evidence_str = str(f.get("evidence", "")).lower()
            # Technology fingerprinting heuristics
            tech_patterns = {
                "apache": "Apache HTTP Server",
                "nginx": "Nginx Web Server",
                "wordpress": "WordPress CMS",
                "drupal": "Drupal CMS",
                "tomcat": "Apache Tomcat",
                "openssh": "OpenSSH",
                "log4j": "Apache Log4j",
                "spring": "Spring Framework",
            }
            for pattern, tech_label in tech_patterns.items():
                if pattern in evidence_str or pattern in f.get("title", "").lower():
                    self.technologies.add(tech_label)
                    if tech_label not in self.assets[asset]["technologies"]:
                        self.assets[asset]["technologies"].append(tech_label)

        # Reflect & Replan: Generate next-step proposals
        self.reflect_and_replan(triggering_artifact_id)

    def reflect_and_replan(self, evidence_id: str):
        """Generate targeted, non-repetitive next steps based on discovered assets and technologies."""
        new_proposals = []

        for asset_host, asset_info in self.assets.items():
            ports = asset_info.get("ports", [])
            techs = asset_info.get("technologies", [])

            # Heuristic 1: If HTTP/HTTPS port discovered (80, 443, 8080, 3000), schedule ZAP & Nikto
            web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000)]
            for wp in web_ports:
                target_url = f"http://{asset_host}:{wp}"

                # Check Nikto proposal
                nikto_params = {"port": wp}
                if not self.is_action_already_executed("nikto", target_url, nikto_params):
                    new_proposals.append(AdaptiveProposal(
                        proposal_id=f"prop-nikto-{asset_host}-{wp}",
                        tool="nikto",
                        target=target_url,
                        parameters=nikto_params,
                        rationale=f"Web service detected on port {wp}. Perform web server hardening checks.",
                        why_now=f"Open port {wp} discovered on {asset_host}.",
                        triggering_evidence_id=evidence_id or "EVID-RECON-PORT",
                        risk_class="intrusive",
                        requires_approval=False,
                    ))

                # Check ZAP baseline proposal
                zap_params = {"port": wp, "mode": "baseline"}
                if not self.is_action_already_executed("zap", target_url, zap_params):
                    new_proposals.append(AdaptiveProposal(
                        proposal_id=f"prop-zap-{asset_host}-{wp}",
                        tool="zap",
                        target=target_url,
                        parameters=zap_params,
                        rationale=f"Perform OWASP Top 10 web application baseline inspection on {target_url}.",
                        why_now=f"Active HTTP listener confirmed on port {wp}.",
                        triggering_evidence_id=evidence_id or "EVID-RECON-PORT",
                        risk_class="intrusive",
                        requires_approval=False,
                    ))

            # Heuristic 2: If Critical/High vulnerability found with CVE, propose validation
            for f in self.findings:
                cve = f.get("cve", "")
                sev = f.get("severity", "info")
                if cve and sev in ("critical", "high"):
                    msf_params = {"cve": cve, "module": "auxiliary/check"}
                    if not self.is_action_already_executed("metasploit", asset_host, msf_params):
                        new_proposals.append(AdaptiveProposal(
                            proposal_id=f"prop-msf-{cve}",
                            tool="metasploit",
                            target=asset_host,
                            parameters=msf_params,
                            rationale=f"Vulnerability {cve} flagged with {sev.upper()} severity. Propose non-destructive check module verification.",
                            why_now=f"{sev.upper()} vulnerability {cve} detected in scan output.",
                            triggering_evidence_id=f.get("source_file_sha256") or evidence_id or "EVID-VULN",
                            risk_class="active",
                            requires_approval=True,  # Mandatory human approval for MSF validation
                        ))

        # Deduplicate proposals against existing pending ones
        existing_prop_ids = {p.proposal_id for p in self.proposals}
        for np in new_proposals:
            if np.proposal_id not in existing_prop_ids:
                self.proposals.append(np)

    def get_structured_state(self) -> Dict[str, Any]:
        """Return comprehensive serializable state snapshot."""
        return {
            "assessment_id": self.assessment_id,
            "assets": self.assets,
            "technologies": sorted(list(self.technologies)),
            "finding_count": len(self.findings),
            "executed_actions_count": len(self.executed_action_hashes),
            "pending_proposals": [p.__dict__ for p in self.proposals if p.status == "pending"],
        }

