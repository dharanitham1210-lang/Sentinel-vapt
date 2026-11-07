"""AI-generated assessment plan (optional LLM; rule-based fallback otherwise).

The plan is always *explanatory* — reasons describe why each step matters.
It never fabricates scanner evidence. When no API key is configured the
fallback planner produces the same schema deterministically.
"""
import json
import os

import httpx

from .config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL


def _fallback_plan(target: str, scope: str, allowed_targets: list[str]) -> list[dict]:
    host = allowed_targets[0] if allowed_targets else target
    steps = [
        {"step": 1, "title": "Passive reconnaissance & scope confirmation",
         "action": f"Confirm target {host} is within authorized scope; review DNS and scope document.",
         "reason": "Ensures no out-of-scope scanning occurs and all rules of engagement are respected.",
         "tool": "manual", "kind": "explanation", "active": False},
        {"step": 2, "title": "Network port & service discovery (Nmap)",
         "action": f"Nmap scan of {host} (service/OS detection, low rate; e.g. -sV --top-ports 100).",
         "reason": "Identifies exposed services to prioritise; required input for later checks.",
         "tool": "nmap", "kind": "scanner", "active": True},
        {"step": 3, "title": "Web server hardening checks (Nikto)",
         "action": f"Nikto scan against http(s)://{host} for outdated/misconfigured components.",
         "reason": "Detects known-vulnerable packages and server misconfigurations.",
         "tool": "nikto", "kind": "scanner", "active": True},
        {"step": 4, "title": "Web application baseline (OWASP ZAP)",
         "action": f"ZAP API/spider + active rules only after human approval, against {host}.",
         "reason": "Finds header, injection and configuration issues that port scans miss.",
         "tool": "zap", "kind": "scanner", "active": True},
        {"step": 5, "title": "Deduplicate, score & prioritise",
         "action": "Normalize all scanner output into the common finding format, deduplicate, and compute risk = CVSS × confidence.",
         "reason": "Transparent, auditable prioritisation for patching.",
         "tool": "vulnpilot", "kind": "analysis", "active": False},
        {"step": 6, "title": "Remediation & retest guidance",
         "action": "Present evidence, affected assets and remediation per finding; generate PDF VAPT report.",
         "reason": "Deliver actionable, evidence-backed fixes per VAPT process.",
         "tool": "vulnpilot", "kind": "reporting", "active": False},
    ]
    return steps


def generate_plan(target: str, scope: str, allowed_targets: list[str]) -> dict:
    fallback = _fallback_plan(target, scope, allowed_targets)
    if not LLM_API_KEY:
        return {"steps": fallback, "generator": "rule-based fallback (no LLM_API_KEY configured)",
                "is_ai": False, "note": "Plan text is explanatory only and contains no scanner evidence."}
    try:
        prompt = (
            "You are a VAPT assessment planner. Produce a concise plan as JSON array "
            "with keys step,title,action,reason,tool,kind,active. "
            f"Target: {target}. Scope: {scope}. Allowed targets: {allowed_targets}. "
            "Emphasize scope safety; no exploitation. Return ONLY JSON."
        )
        resp = httpx.post(
            LLM_BASE_URL.rstrip("/") + "/chat/completions",
            headers={"Authorization": f"Bearer {LLM_API_KEY}"},
            json={"model": LLM_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
            timeout=20,
            trust_env=True,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        steps = json.loads(content)
        if isinstance(steps, dict):
            steps = steps.get("steps", [])
        return {"steps": steps, "generator": f"LLM ({LLM_MODEL})", "is_ai": True,
                "note": "AI text is explanatory; all findings must come from real scanner evidence."}
    except Exception as e:
        return {"steps": fallback, "generator": "rule-based fallback (LLM call failed)",
                "is_ai": False, "note": f"LLM error: {e}. Falling back to deterministic planner."}
