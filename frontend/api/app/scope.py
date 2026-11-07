"""Scope validation — enforces authorized-target-only scanning.

Allowed:
  - localhost literals / names (localhost, *.local, *.lan, *.home, *.internal,
    *.intranet, *.lab, *.test, *.example.*)
  - Private ranges: 10/8, 172.16/12, 192.168/16, 127/8, link-local 169.254/16
  - IPv6 loopback ::1 and ULA fc00::/7
  - Explicitly authorized lab hostnames ending .corp / .local etc. are covered
    by the suffix rules; any other hostname is rejected.

Rejected: any public IP or public DNS name (e.g. google.com, 93.184.x.x).
Scanning additionally requires explicit authorization confirmation stored
on the assessment.
"""
import ipaddress
import re
import socket

ALLOWED_SUFFIXES = (".local", ".lan", ".home", ".internal", ".intranet", ".lab", ".test", ".corp")
ALLOWED_NAMES = {"localhost", "host.docker.internal", "host.containers.internal"}

_HOST_RE = re.compile(r"^[a-z0-9._-]+$", re.IGNORECASE)


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_private:
        return True
    return False


def parse_target(raw: str) -> str:
    """Strip scheme/port/path, return bare host (IP or hostname)."""
    t = (raw or "").strip()
    if not t:
        raise ValueError("Target is empty.")
    t = re.sub(r"^\w+://", "", t)
    t = t.split("/")[0].split("?")[0].split("#")[0]
    if t.startswith("[") and "]" in t:  # IPv6 literal
        t = t.split("]")[0].lstrip("[")
    else:
        t = t.split(":")[0]
    return t.strip().rstrip(".").lower()


def validate_host(raw: str) -> dict:
    """Validate a single host against authorized-target policy."""
    host = parse_target(raw)
    if not host or len(host) > 253:
        return {"host": host, "ok": False, "reason": "Invalid host length"}
    if not _HOST_RE.match(host) and ":" not in host:
        return {"host": host, "ok": False, "reason": "Invalid hostname characters"}

    # IP literal?
    try:
        ipaddress.ip_address(host)
        ok = _is_private_ip(host)
        return {
            "host": host,
            "ok": ok,
            "reason": "Private/lab IP (authorized range)" if ok else "Public IP — scanning blocked. Use localhost or a private lab address.",
        }
    except ValueError:
        pass

    if host in ALLOWED_NAMES:
        return {"host": host, "ok": True, "reason": "Localhost alias (authorized)"}

    if host.endswith(ALLOWED_SUFFIXES):
        return {"host": host, "ok": True, "reason": "Authorized lab suffix (authorized)"}

    # DNS resolution fallback — only private results allowed. If blocked we reject.
    try:
        infos = socket.getaddrinfo(host, None)
        resolved = sorted({info[4][0] for info in infos})
        if resolved and all(_is_private_ip(a) for a in resolved):
            return {"host": host, "ok": True, "reason": f"Resolves to private/lab addresses {resolved} (authorized)"}
        return {"host": host, "ok": False, "reason": "Hostname resolves to public addresses — scanning blocked."}
    except Exception:
        return {
            "host": host,
            "ok": False,
            "reason": "Hostname does not resolve to a private/lab address — scanning blocked. Use localhost or a lab hostname ending in .local/.lab/.test.",
        }


def validate_scope(scope_text: str, allowed_targets: list[str] | None = None) -> dict:
    """Validate scope description + allowed targets list.

    Returns dict with `ok`, per-host `checks`, and normalised targets.
    Rules:
      - At least one allowed target must be listed.
      - Every allowed target must pass validate_host.
      - Scope text must mention the primary target or be non-empty.
    """
    scope_text = (scope_text or "").strip()
    targets = [t.strip() for t in (allowed_targets or []) if str(t).strip()]
    checks = []
    if not targets:
        # Try to extract a target from scope text (first token that looks like host)
        m = re.search(r"(?:https?://)?([a-zA-Z0-9._-]+)(?::\d+)?(?:/|$)", scope_text)
        if m:
            targets = [m.group(1)]
    for t in targets:
        checks.append(validate_host(t))
    ok = bool(targets) and bool(scope_text) and all(c["ok"] for c in checks)
    reasons = [c["reason"] for c in checks if not c["ok"]]
    if not targets:
        reasons.append("At least one allowed target is required.")
    if not scope_text:
        reasons.append("Scope description is required.")
    return {"ok": ok, "targets": targets, "checks": checks, "reasons": reasons}
