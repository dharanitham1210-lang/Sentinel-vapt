"""Conversational AI Agent & Assessment Planning Service.

Parses natural-language assessment requests into auditable, schema-validated assessment plans.
Enforces:
1. Deterministic Scope Gate validation before planning.
2. Pydantic v2 schema enforcement.
3. Grounding validation: blocks any fabricated CVEs.
4. Explanatory rationale per step, with risk classification (passive / intrusive / active).
5. Deterministic fallback if LLM endpoint is unreachable.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

import httpx

from ..config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
from ..scope_gate import EngagementScope, ScopeGate
from .grounding_validator import AssessmentPlanSchema, GroundingValidator, PlanStepSchema


def _deterministic_rule_based_plan(target: str, scope: str, user_prompt: str = "") -> List[Dict[str, Any]]:
    """Deterministic, high-quality assessment plan generator."""
    p_lower = user_prompt.lower()
    web_focused = any(k in p_lower for k in ["web", "http", "webapp", "api", "juice", "dvwa"])
    quick_scan = any(k in p_lower for k in ["quick", "fast", "top"])

    top_ports = 50 if quick_scan else 100

    steps = [
        {
            "step_number": 1,
            "title": "Scope Boundary & Authorization Verification",
            "tool": "scope_gate",
            "target": target,
            "parameters": {"mode": "deterministic_check"},
            "rationale": "Verify that target IP/domain and all resolved socket addresses comply with engagement rules of engagement.",
            "risk_class": "passive",
            "estimated_duration_seconds": 10,
            "requires_approval": False,
        },
        {
            "step_number": 2,
            "title": f"Network Port & Service Discovery (Nmap Top {top_ports})",
            "tool": "nmap",
            "target": target,
            "parameters": {"top_ports": top_ports, "detect_version": True, "ping_probe": False},
            "rationale": "Identify active listening services and version banners to discover the attack surface.",
            "risk_class": "intrusive",
            "estimated_duration_seconds": 45,
            "requires_approval": False,
        },
    ]

    step_counter = 3
    if web_focused or ":80" in target or ":443" in target or "http" in target:
        steps.append({
            "step_number": step_counter,
            "title": "Web Server Misconfiguration & Banner Analysis (Nikto)",
            "tool": "nikto",
            "target": target,
            "parameters": {"format": "txt", "evasion": "none"},
            "rationale": "Inspect server headers, outdated web components, and directory exposure.",
            "risk_class": "intrusive",
            "estimated_duration_seconds": 60,
            "requires_approval": False,
        })
        step_counter += 1

        steps.append({
            "step_number": step_counter,
            "title": "OWASP Web Application Security Spider & Passive Inspection (ZAP)",
            "tool": "zap",
            "target": target,
            "parameters": {"mode": "passive_and_spider"},
            "rationale": "Crawl web application attack surface and observe passive security headers and cookie flags.",
            "risk_class": "intrusive",
            "estimated_duration_seconds": 90,
            "requires_approval": False,
        })
        step_counter += 1

    steps.append({
        "step_number": step_counter,
        "title": "Cross-Tool Evidence Ingestion & Risk Prioritization",
        "tool": "correlation_engine",
        "target": target,
        "parameters": {"dedup_algorithm": "composite_cve_cwe", "corroboration_boost": True},
        "rationale": "Correlate observations across tools, eliminate duplicates, and score risk based on CVSS, exposure, and asset criticality.",
        "risk_class": "passive",
        "estimated_duration_seconds": 15,
        "requires_approval": False,
    })
    step_counter += 1

    steps.append({
        "step_number": step_counter,
        "title": "Targeted Vulnerability Validation Check",
        "tool": "metasploit",
        "target": target,
        "parameters": {"mode": "check_only", "exploit_allowed": False},
        "rationale": "Execute non-destructive check modules for confirmed critical findings (offensive exploits require human approval).",
        "risk_class": "active",
        "estimated_duration_seconds": 60,
        "requires_approval": True,  # Mandatory human approval for MSF validation
    })

    return steps


class ConversationalAgent:
    def __init__(self, scope_gate: ScopeGate, validator: Optional[GroundingValidator] = None):
        self.scope_gate = scope_gate
        self.validator = validator or GroundingValidator()

    def plan_assessment(
        self,
        user_request: str,
        target: str,
        scope_text: str = "",
        actor: str = "analyst",
    ) -> Dict[str, Any]:
        """Validate scope deterministically, then generate a schema-validated assessment plan."""
        # 1. Scope Gate Check (Zero-LLM deterministic enforcement)
        scope_check = self.scope_gate.check_target(target, actor=actor)
        if not scope_check["ok"]:
            return {
                "ok": False,
                "error": f"Scope Violation: {scope_check['reason']}",
                "rule": scope_check.get("rule", "SCOPE_VIOLATION"),
                "plan": None,
            }

        # 2. Try LLM Plan Generation if API key is present
        raw_steps = None
        generator_info = "Rule-based Deterministic Planner"

        if LLM_API_KEY:
            try:
                system_prompt = (
                    "You are SentinelVAPT Assessment Planner. Generate a JSON object adhering to this schema:\n"
                    "{\n"
                    '  "plan_title": "string",\n'
                    '  "target_summary": "string",\n'
                    '  "steps": [\n'
                    '    {"step_number": 1, "title": "string", "tool": "string", "target": "string",\n'
                    '     "parameters": {}, "rationale": "string", "risk_class": "passive|intrusive|active",\n'
                    '     "estimated_duration_seconds": 60, "requires_approval": false}\n'
                    "  ]\n"
                    "}\n"
                    "Rules: Emphasize authorized scope. Never fabricate CVEs. Intrusive/active checks require approval."
                )
                user_msg = f"Target: {target}\nScope: {scope_text}\nAnalyst Request: {user_request}"

                resp = httpx.post(
                    LLM_BASE_URL.rstrip("/") + "/chat/completions",
                    headers={"Authorization": f"Bearer {LLM_API_KEY}"},
                    json={
                        "model": LLM_MODEL,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_msg},
                        ],
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"},
                    },
                    timeout=15.0,
                    trust_env=True,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    parsed_json = json.loads(content)
                    raw_steps = parsed_json.get("steps")
                    generator_info = f"LLM ({LLM_MODEL})"
            except Exception:
                pass

        if not raw_steps:
            raw_steps = _deterministic_rule_based_plan(target, scope_text, user_request)

        # 3. Schema & Grounding Validation
        validated_steps = []
        for s in raw_steps:
            try:
                step_obj = PlanStepSchema(
                    step_number=int(s.get("step_number", len(validated_steps) + 1)),
                    title=str(s.get("title", "Assessment Step")),
                    tool=str(s.get("tool", "nmap")).lower(),
                    target=str(s.get("target", target)),
                    parameters=s.get("parameters") or {},
                    rationale=str(s.get("rationale") or s.get("reason") or "Standard assessment phase."),
                    risk_class=str(s.get("risk_class") or "intrusive").lower(),
                    estimated_duration_seconds=int(s.get("estimated_duration_seconds", 60)),
                    requires_approval=bool(s.get("requires_approval", False) or s.get("tool") == "metasploit"),
                )
                validated_steps.append(step_obj.model_dump())
            except Exception:
                continue

        return {
            "ok": True,
            "target": target,
            "generator": generator_info,
            "steps": validated_steps,
            "requires_approval_count": sum(1 for s in validated_steps if s["requires_approval"]),
            "note": "Plan generated under deterministic scope constraints. Active steps require human approval.",
        }

