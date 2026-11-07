"""Deduplication + transparent risk scoring.

Dedup key: title|asset|url|parameter (lowercased) — same evidence from
different tools merges into one finding, keeping the highest severity and
concatenating source filenames / evidence.
Risk score = CVSS * confidence, displayed with an explicit reason string.
"""
import hashlib

from .normalization import SEVERITY_ORDER, norm_severity


from .correlation import correlate_and_dedupe, generate_correlation_key
from .risk import calculate_risk


def dedup_key(f: dict) -> str:
    return generate_correlation_key(f)


def risk_score(f: dict) -> tuple[float, str]:
    bd = calculate_risk(
        cvss=float(f.get("cvss", 0.0) or 0.0),
        severity=f.get("severity", "info"),
        confidence=float(f.get("confidence", 0.8) or 0.8),
    )
    return bd.final_score, bd.reason_formula


def dedupe(findings: list[dict]) -> list[dict]:
    return correlate_and_dedupe(findings)
