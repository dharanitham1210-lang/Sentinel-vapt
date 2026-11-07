"""Genuine OWASP ZAP API integration + supported JSON import.

Live mode requires ZAP running with API enabled (default http://127.0.0.1:8090).
Import mode always works: upload a ZAP JSON export.
"""
import httpx

from ..config import ZAP_API_KEY, ZAP_API_URL
from ..scope import parse_target


def status() -> dict:
    """Probe ZAP API availability (localhost only; never via proxy)."""
    try:
        r = httpx.get(ZAP_API_URL.rstrip("/") + "/JSON/core/view/version/", params={"apikey": ZAP_API_KEY}, timeout=3, trust_env=False)
        r.raise_for_status()
        return {"ok": True, "version": r.json().get("version", ""), "url": ZAP_API_URL, "mode": "live"}
    except Exception as e:
        return {"ok": False, "error": str(e), "url": ZAP_API_URL, "mode": "import-only"}


def fetch_alerts(alerts_view: str = "alerts") -> dict:
    """Fetch alerts from a running ZAP instance."""
    try:
        r = httpx.get(ZAP_API_URL.rstrip("/") + f"/JSON/core/view/{alerts_view}/",
                      params={"apikey": ZAP_API_KEY, "start": 0, "count": 5000}, timeout=30, trust_env=False)
        r.raise_for_status()
        return {"ok": True, "data": r.json(), "error": ""}
    except Exception as e:
        return {"ok": False, "data": None, "error": str(e)}


def import_json(data, filename: str, sha: str) -> list[dict]:
    from ..normalization import parse_zap_json
    return parse_zap_json(data, filename, sha)
