"""Transparent Risk Prioritization Engine.

Non-Negotiable Rule 1 & 6:
Never fabricate scanner output, CVEs, CVSS scores, evidence, or risk scores.
Every score must be mathematically transparent and explainable.
If exploit intelligence (CISA KEV / EPSS) data is missing, explicitly report "Not available"
instead of inventing or assuming values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class RiskBreakdown:
    final_score: float
    cvss_base: float
    cvss_source: str
    exposure_factor: float
    exposure_label: str
    exploitability_factor: float
    exploitability_label: str
    exploit_intel_source: str
    criticality_factor: float
    criticality_label: str
    confidence: float
    confidence_label: str
    reason_formula: str


def calculate_risk(
    cvss: float,
    severity: str = "info",
    is_public_exposed: bool = False,
    is_authenticated: bool = False,
    known_exploited_cisa: Optional[bool] = None,
    epss_score: Optional[float] = None,
    asset_criticality: str = "medium",  # critical, high, medium, low
    confidence: float = 0.80,
    source: str = "scanner",
) -> RiskBreakdown:
    """Calculate transparent risk score:

    Risk = min(10.0, CVSS * Exposure * Exploitability * Criticality * Confidence)
    """
    base_cvss = max(0.0, min(10.0, float(cvss or 0.0)))
    if base_cvss == 0.0:
        sev_defaults = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        base_cvss = sev_defaults.get(severity.lower(), 0.0)
        cvss_source = f"Estimated from severity ({severity.upper()})"
    else:
        cvss_source = f"Authoritative scanner/NVD CVSS: {base_cvss}"

    # 1. Exposure Factor
    if is_authenticated:
        exposure_factor = 0.75
        exposure_label = "Requires Authentication (Factor 0.75)"
    elif is_public_exposed:
        exposure_factor = 1.0
        exposure_label = "Internet-facing (Factor 1.00)"
    else:
        exposure_factor = 1.0
        exposure_label = "Standard Exposure (Factor 1.00)"

    # 2. Exploitability (CISA KEV / EPSS)
    if known_exploited_cisa is True:
        exploit_factor = 1.25
        exploit_label = "Active In-The-Wild Exploitation (CISA KEV Listed)"
        exploit_source = "CISA Known Exploited Vulnerabilities Catalog"
    elif epss_score is not None:
        if epss_score >= 0.5:
            exploit_factor = 1.15
            exploit_label = f"High EPSS Probability ({epss_score * 100:.1f}%)"
            exploit_source = "FIRST EPSS Feed"
        elif epss_score >= 0.1:
            exploit_factor = 1.05
            exploit_label = f"Moderate EPSS Probability ({epss_score * 100:.1f}%)"
            exploit_source = "FIRST EPSS Feed"
        else:
            exploit_factor = 1.00
            exploit_label = f"Low EPSS Probability ({epss_score * 100:.1f}%)"
            exploit_source = "FIRST EPSS Feed"
    else:
        exploit_factor = 1.00
        exploit_label = "Standard theoretical exploitability"
        exploit_source = "Not available (no live CISA/EPSS match; factor default 1.00)"

    # 3. Asset Criticality
    crit_map = {
        "critical": (1.20, "Mission-Critical / Core Infrastructure (Factor 1.20)"),
        "high": (1.10, "High Business Value / Production Application (Factor 1.10)"),
        "medium": (1.00, "Standard Asset / Internal Workstation (Factor 1.00)"),
        "low": (0.80, "Isolated Lab / Development / Staging (Factor 0.80)"),
    }
    crit_factor, crit_label = crit_map.get(asset_criticality.lower(), crit_map["medium"])

    # 4. Confidence Calibration
    conf = max(0.1, min(1.0, float(confidence or 0.80)))
    if conf >= 0.90:
        conf_label = f"High Confidence ({int(conf * 100)}%) - Verified by active tool check or multi-tool corroboration"
    elif conf >= 0.70:
        conf_label = f"Medium Confidence ({int(conf * 100)}%) - Standard tool heuristic detection"
    else:
        conf_label = f"Low Confidence ({int(conf * 100)}%) - Unverified banner or single-source inference"

    raw_score = base_cvss * exposure_factor * exploit_factor * crit_factor * conf
    final_score = round(min(10.0, max(0.0, raw_score)), 2)

    formula = (
        f"Score {final_score:.2f} = CVSS {base_cvss:.1f} × Exposure {exposure_factor:.2f} × "
        f"Exploit {exploit_factor:.2f} × Criticality {crit_factor:.2f} × Confidence {conf:.2f}"
    )

    return RiskBreakdown(
        final_score=final_score,
        cvss_base=base_cvss,
        cvss_source=cvss_source,
        exposure_factor=exposure_factor,
        exposure_label=exposure_label,
        exploitability_factor=exploit_factor,
        exploitability_label=exploit_label,
        exploit_intel_source=exploit_source,
        criticality_factor=crit_factor,
        criticality_label=crit_label,
        confidence=conf,
        confidence_label=conf_label,
        reason_formula=formula,
    )
