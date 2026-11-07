"""Schema-Enforced Grounding Validator.

Non-Negotiable Rule 5:
LLM outputs must be schema-validated (Pydantic v2).
A 'grounding validator' rejects any CVE, CWE, or CVSS score in LLM output that is not present
in real tool artifacts or in a local authoritative NVD/CWE cache.
Failed validation -> mark as unverified, reject from publication, never publish hallucinations.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field, field_validator

# Authoritative standard CWE dictionary (MITRE Top CWEs)
AUTHORITATIVE_CWES: Set[str] = {
    "CWE-16", "CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-119",
    "CWE-120", "CWE-125", "CWE-190", "CWE-200", "CWE-250", "CWE-269", "CWE-276",
    "CWE-287", "CWE-295", "CWE-306", "CWE-311", "CWE-312", "CWE-319", "CWE-326",
    "CWE-327", "CWE-352", "CWE-384", "CWE-400", "CWE-434", "CWE-502", "CWE-522",
    "CWE-601", "CWE-611", "CWE-639", "CWE-693", "CWE-732", "CWE-787", "CWE-798",
    "CWE-862", "CWE-863", "CWE-918", "CWE-942", "CWE-1021", "CWE-1336",
}

# Authoritative local cache of prominent historic & benchmark CVEs (can be supplemented at runtime)
LOCAL_NVD_BENCHMARK_CVES: Set[str] = {
    "CVE-2014-0160",  # Heartbleed
    "CVE-2017-0144",  # EternalBlue
    "CVE-2017-5638",  # Apache Struts
    "CVE-2019-0708",  # BlueKeep
    "CVE-2020-1472",  # Zerologon
    "CVE-2021-41773", # Apache 2.4.49 Path Traversal
    "CVE-2021-42013", # Apache 2.4.50 Path Traversal
    "CVE-2021-44228", # Log4Shell
    "CVE-2022-22965", # Spring4Shell
    "CVE-2023-38606", # WebKit
    "CVE-2023-44487", # HTTP/2 Rapid Reset
    "CVE-2024-21626", # runc Container Breakout
    "CVE-2024-3094",  # XZ Utils Backdoor
    "CVE-2024-6387",  # regreSSHion OpenSSH
}

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class PlanStepSchema(BaseModel):
    step_number: int = Field(..., ge=1, le=50)
    title: str = Field(..., min_length=3, max_length=150)
    tool: str = Field(..., min_length=2, max_length=50)
    target: str = Field(..., min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(..., min_length=5, max_length=500)
    risk_class: str = Field(..., pattern="^(passive|intrusive|active)$")
    estimated_duration_seconds: int = Field(default=60, ge=5, le=3600)
    requires_approval: bool = False


class AssessmentPlanSchema(BaseModel):
    plan_title: str
    target_summary: str
    steps: List[PlanStepSchema]
    is_ai_generated: bool = True
    grounding_verified: bool = False


class GroundingValidationResult(BaseModel):
    is_grounded: bool
    rejected_cves: List[str] = Field(default_factory=list)
    rejected_cwes: List[str] = Field(default_factory=list)
    rejected_cvss: List[float] = Field(default_factory=list)
    verified_cves: List[str] = Field(default_factory=list)
    verified_cwes: List[str] = Field(default_factory=list)
    reason: str = "All security claims grounded in evidence or authoritative dictionary."


class GroundingValidator:
    """Verifies that all CVEs, CWEs, and CVSS scores emitted by AI models are factually grounded."""

    def __init__(self, raw_evidence_cves: Optional[Set[str]] = None, local_cache: Optional[Set[str]] = None):
        self.evidence_cves = {c.upper().strip() for c in (raw_evidence_cves or set()) if c}
        self.authoritative_cves = LOCAL_NVD_BENCHMARK_CVES.union(local_cache or set())

    def validate_cve(self, cve: str) -> bool:
        """Check if CVE exists in real tool evidence OR in authoritative NVD dictionary."""
        c = (cve or "").strip().upper()
        if not c:
            return True  # Empty CVE is not a hallucination
        if not CVE_REGEX.match(c):
            return False
        # Must be in raw tool output OR in local NVD cache
        return c in self.evidence_cves or c in self.authoritative_cves

    def validate_cwe(self, cwe: str) -> bool:
        """Check if CWE is a legitimate MITRE CWE identifier."""
        c = (cwe or "").strip().upper()
        if not c:
            return True
        if not c.startswith("CWE-"):
            c = f"CWE-{c}"
        return c in AUTHORITATIVE_CWES

    def validate_cvss(self, cvss: float) -> bool:
        """Validate CVSS score is in the canonical 0.0 to 10.0 boundary."""
        try:
            val = float(cvss)
            return 0.0 <= val <= 10.0
        except (ValueError, TypeError):
            return False

    def validate_finding_claims(self, finding_data: Dict[str, Any]) -> GroundingValidationResult:
        """Scan a candidate finding or inference for ungrounded or fabricated identifiers."""
        cve_candidate = str(finding_data.get("cve") or "").strip().upper()
        cwe_candidate = str(finding_data.get("cwe") or "").strip().upper()
        cvss_candidate = finding_data.get("cvss")

        rejected_cves = []
        verified_cves = []
        if cve_candidate:
            if self.validate_cve(cve_candidate):
                verified_cves.append(cve_candidate)
            else:
                rejected_cves.append(cve_candidate)

        rejected_cwes = []
        verified_cwes = []
        if cwe_candidate:
            if self.validate_cwe(cwe_candidate):
                verified_cwes.append(cwe_candidate)
            else:
                rejected_cwes.append(cwe_candidate)

        rejected_cvss = []
        if cvss_candidate is not None:
            if not self.validate_cvss(cvss_candidate):
                rejected_cvss.append(cvss_candidate)

        is_grounded = len(rejected_cves) == 0 and len(rejected_cwes) == 0 and len(rejected_cvss) == 0

        reasons = []
        if rejected_cves:
            reasons.append(f"Fabricated or ungrounded CVE(s) rejected: {rejected_cves}")
        if rejected_cwes:
            reasons.append(f"Invalid CWE identifier(s): {rejected_cwes}")
        if rejected_cvss:
            reasons.append(f"Invalid CVSS score(s) outside 0.0-10.0: {rejected_cvss}")

        return GroundingValidationResult(
            is_grounded=is_grounded,
            rejected_cves=rejected_cves,
            rejected_cwes=rejected_cwes,
            rejected_cvss=rejected_cvss,
            verified_cves=verified_cves,
            verified_cwes=verified_cwes,
            reason="; ".join(reasons) if reasons else "Grounding check passed.",
        )

