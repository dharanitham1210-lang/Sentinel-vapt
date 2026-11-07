"""Normalize scanner outputs (nmap XML/JSON, ZAP JSON, Nikto text) into the
common finding format. Every normalized finding preserves its source file,
sha256, and raw evidence — nothing is invented.
"""
import hashlib
import json
import re
import xml.etree.ElementTree as ET

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"info": 0.0, "low": 2.5, "medium": 5.0, "high": 7.5, "critical": 10.0}


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def file_sha256(path_or_bytes) -> str:
    if isinstance(path_or_bytes, (bytes, bytearray)):
        return sha256_bytes(bytes(path_or_bytes))
    import hashlib as _h
    h = _h.sha256()
    with open(path_or_bytes, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_severity(raw: str) -> str:
    s = (raw or "").strip().lower()
    mapping = {
        "critical": "critical", "crit": "critical", "high": "high", "h": "high",
        "medium": "medium", "med": "medium", "m": "medium", "moderate": "medium",
        "low": "low", "l": "low", "info": "info", "informational": "info",
    }
    return mapping.get(s, "info")


def make_finding(**kw) -> dict:
    f = {
        "id": kw.get("id", ""),
        "title": kw.get("title", "Untitled finding"),
        "severity": norm_severity(kw.get("severity", "info")),
        "confidence": float(kw.get("confidence", 0.5)),
        "cvss": float(kw.get("cvss", 0.0) or 0.0),
        "asset": kw.get("asset", ""),
        "url": kw.get("url", ""),
        "parameter": kw.get("parameter", ""),
        "source": kw.get("source", "import"),
        "source_filename": kw.get("source_filename", ""),
        "source_file_sha256": kw.get("source_file_sha256", ""),
        "evidence": kw.get("evidence", ""),
        "evidence_json": kw.get("evidence_json", {}),
        "remediation": kw.get("remediation", ""),
        "references": kw.get("references", []),
        "cwe": kw.get("cwe", ""),
        "cve": kw.get("cve", ""),
    }
    if not f["cvss"]:
        f["cvss"] = SEVERITY_SCORE[f["severity"]]
    return f


def parse_nmap_xml(xml_text: str, filename: str, sha: str) -> list[dict]:
    out = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out
    for host in root.iter("host"):
        addr = host.find(".//address")
        ip = addr.get("addr", "") if addr is not None else ""
        for port in host.iter("port"):
            pid = port.get("portid", "")
            svc = port.find("service")
            sname = svc.get("name", "") if svc is not None else ""
            state = port.find("state")
            st = state.get("state", "") if state is not None else ""
            if st != "open":
                continue  # only genuine open ports become findings
            ev = f"port {pid} state={st} service={sname}"
            out.append(make_finding(
                title=f"Open port {pid}/{sname}".strip(),
                severity="info", confidence=1.0,
                asset=ip, url=f"{ip}:{pid}" if ip else f":{pid}",
                source="nmap", source_filename=filename, source_file_sha256=sha,
                evidence=ev, evidence_json={"port": pid, "service": sname, "state": st},
                remediation="Review exposure; close unnecessary ports; apply firewall rules.",
            ))
            for script in port.iter("script"):
                sid = script.get("id", "")
                so = script.get("output", "")
                if not so:
                    continue  # empty script output is not a finding
                out.append(make_finding(
                    title=f"Nmap script {sid}" if sid else "Nmap script output",
                    severity="low", confidence=0.8,
                    asset=ip, url=f"{ip}:{pid}" if ip else "",
                    source="nmap", source_filename=filename, source_file_sha256=sha,
                    evidence=so[:2000], evidence_json={"script": sid},
                    remediation="Evaluate script output in context; patch the underlying service.",
                ))
    return out


def parse_nmap_json(data, filename: str, sha: str) -> list[dict]:
    out = []
    if isinstance(data, dict):
        hosts = data.get("hosts", [])
    else:
        hosts = data if isinstance(data, list) else []
    for h in hosts:
        ip = h.get("address", "") if isinstance(h, dict) else ""
        for p in h.get("ports", []) if isinstance(h, dict) else []:
            pid = str(p.get("port", ""))
            svc = p.get("service", "")
            st = p.get("state", "")
            if st != "open" and st != "":
                continue  # only genuine open ports become findings
            out.append(make_finding(
                title=f"Open port {pid}/{svc}".strip(),
                severity="info", confidence=1.0, asset=ip, url=f"{ip}:{pid}",
                source="nmap", source_filename=filename, source_file_sha256=sha,
                evidence=f"port {pid} state={st} service={svc}",
                evidence_json={"port": pid, "service": svc, "state": st},
                remediation="Review exposure; close unnecessary ports.",
            ))
    return out[:_MAX_FINDINGS_PER_FILE]
    return out


def parse_zap_json(data, filename: str, sha: str) -> list[dict]:
    alerts = data.get("alerts", []) if isinstance(data, dict) else data
    if not isinstance(alerts, list):
        return []
    out = []
    for a in alerts:
        if not isinstance(a, dict):
            continue
        risk = a.get("risk", "") or a.get("severity", "")
        refs = a.get("reference", "") or a.get("references", "")
        if isinstance(refs, str):
            refs = [refs] if refs else []
        title = str(a.get("alert", "") or a.get("name", "") or "").strip()
        url = str(a.get("url", "") or "")
        evidence = (str(a.get("evidence", "") or "") or str(a.get("description", "") or ""))[:2000]
        if not title:
            continue  # no real title in the export ⇒ not a finding
        if not url and not evidence:
            continue  # title alone with zero evidence is not actionable
        out.append(make_finding(
            title=title[:200],
            severity=norm_severity(risk),
            confidence=0.9, asset=url.split("/")[0] if url else "",
            url=url,
            parameter=str(a.get("param", "") or a.get("parameter", "")),
            source="zap", source_filename=filename, source_file_sha256=sha,
            evidence=evidence,
            evidence_json={"cwesid": a.get("cwesid"), "risk": risk, "pluginId": a.get("pluginId")},
            remediation=str(a.get("solution", "")) or "Review ZAP alert details and remediate per vendor guidance.",
            references=refs,
            cwe=f"CWE-{a.get('cwesid')}" if a.get("cwesid") else "",
        ))
    return out[:_MAX_FINDINGS_PER_FILE]


# --- strict content/format guards -------------------------------------------
_UNSUPPORTED_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".tar", ".gz",
                   ".exe", ".dll", ".bin", ".so", ".dylib", ".class", ".docx", ".xlsx", ".pptx"}
_MAX_FINDINGS_PER_FILE = 1000

_NIKTO_HEADER_PREFIXES = (
    "target", "server:", "starting", "end time", "checks:", "requests:", "- nikto", "nikto",
    "ssl info", "start time", "port:", "banner:", "hostname:", "ip address", "load file",
    "site:", "404", "output", "tuning", "authentication",
)
# PDF / binary-structure line shapes — never Nikto findings
_PDF_LINE_RE = re.compile(r"^\s*(%PDF|%[A-Za-z]|/[A-Za-z]|>>|<<|stream|endstream|endobj|obj\b|trailer|xref|startxref|\d{9,}\s+\d{5}\s+[nf]\b)")


def looks_like_text(raw: bytes) -> bool:
    """True if bytes are plausibly text. Binary scans (PDF, images, zips) fail."""
    if b"\x00" in raw:
        return False
    nontext = sum(1 for b in raw[:4096] if b < 9 or (13 < b < 32))
    return (nontext / max(1, min(len(raw), 4096))) < 0.3


def _nikto_severity(body: str) -> str:
    """Nikto text output carries no severity; be conservative and disclose it."""
    bl = body.lower()
    if any(k in bl for k in ["rce", "remote code", "remote command", "critical"]):
        return "high"
    if any(k in bl for k in ["sqli", "sql injection", "xss", "code injection", "prototype pollution"]):
        return "medium"
    return "info"


def parse_nikto_text(text: str, filename: str, sha: str) -> list[dict]:
    """Strict Nikto text parser.

    Genuine Nikto .txt output lists each check on its own line prefixed with
    ``+ ``. Anything else (headers, blanks, PDF/binary structure learned from
    mis-imports, arbitrary prose) is ignored — never turned into a finding.
    """
    out = []
    name_lower = (filename or "").lower()
    if name_lower.endswith(".pdf") or _PDF_LINE_RE.search(text):
        return out
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _PDF_LINE_RE.match(line):
            continue
        m = re.match(r"\+ (.+)", line)
        if not m:
            continue  # only real Nikto lines start with "+ "
        body = m.group(1).strip()
        if not body:
            continue
        bl = body.lower()
        if bl.startswith(_NIKTO_HEADER_PREFIXES):
            continue
        if len(body) < 15:
            continue
        # binary-ish junk: too few alphanumerics ⇒ not a human-readable finding
        alnum = sum(1 for c in body if c.isalnum() or c in " /-._:()")
        if alnum / max(1, len(body)) < 0.5:
            continue
        out.append(make_finding(
            title=body[:120],
            severity=_nikto_severity(body),
            confidence=0.6,
            asset="", url="", source="nikto",
            source_filename=filename, source_file_sha256=sha,
            evidence=line[:2000],
            evidence_json={"raw": line,
                           "severity_source": "estimated from keywords; Nikto text output carries no severity"},
            remediation="Review Nikto output; patch/upgrade the identified component.",
        ))
        if len(out) >= _MAX_FINDINGS_PER_FILE:
            break
    return out


def parse_generic_json(data, filename: str, sha: str) -> list[dict]:
    """Best-effort fallback: accept common finding-like JSON shapes."""
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "alerts", "results", "issues"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title") or it.get("name") or it.get("id") or "").strip()
        if not title:
            continue  # never invent a title for a finding
        evidence = str(it.get("evidence", ""))[:2000]
        url = str(it.get("url", ""))
        asset = str(it.get("asset", ""))
        if not evidence and not url and not asset:
            continue  # a bare title with no evidence/asset is not a finding
        out.append(make_finding(
            title=title[:200],
            severity=norm_severity(str(it.get("severity", "info"))),
            confidence=float(it.get("confidence", 0.6) or 0.6),
            asset=asset,
            url=url,
            parameter=str(it.get("parameter", "")),
            source="import", source_filename=filename, source_file_sha256=sha,
            evidence=evidence,
            evidence_json=it,
            remediation=str(it.get("remediation", "")),
        ))
    return out[:_MAX_FINDINGS_PER_FILE]


def detect_and_parse(raw_bytes: bytes, filename: str) -> list[dict]:
    """Detect file type and normalize.

    Raises ValueError for binary/unsupported content (so the API can return a
    clear 400 instead of inventing findings). Returns [] when the format is
    recognized but contains no findings — never falls back to re-reading
    arbitrary text (e.g. a PDF) as "Nikto findings".
    """
    name = (filename or "").lower()
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in _UNSUPPORTED_EXT:
        raise ValueError(
            f"Unsupported file type '{ext}'. Uploaded content must be text-based "
            f"scanner output (Nmap XML/JSON, OWASP ZAP JSON, Nikto text or findings JSON)."
        )
    if not looks_like_text(raw_bytes):
        raise ValueError(
            "Uploaded content looks binary, not text. Only text-based scanner output "
            "is accepted (Nmap XML/JSON, ZAP JSON, Nikto text, findings JSON)."
        )
    sha = sha256_bytes(raw_bytes)
    text = raw_bytes.decode("utf-8", errors="ignore")

    # Nessus v2 XML
    if name.endswith(".nessus") or "<NessusClientData_v2" in text[:1000]:
        from .adapters.nessus_adapter import NessusAdapter
        return NessusAdapter().parse_output(raw_bytes, filename, sha)[:_MAX_FINDINGS_PER_FILE]

    # Burp Suite XML issue export
    if "<issues" in text[:1000] and "<issue>" in text:
        from .adapters.burp_adapter import BurpAdapter
        return BurpAdapter().parse_output(raw_bytes, filename, sha)[:_MAX_FINDINGS_PER_FILE]

    # OpenVAS XML report
    if "<report" in text[:1000] and ("<results>" in text or "<report_format" in text):
        from .adapters.openvas_adapter import OpenVASAdapter
        return OpenVASAdapter().parse_output(raw_bytes, filename, sha)[:_MAX_FINDINGS_PER_FILE]

    # XML (nmap)
    if name.endswith(".xml") or text.lstrip().startswith("<?xml"):
        from .adapters.nmap_adapter import NmapAdapter
        nmap_res = NmapAdapter().parse_output(raw_bytes, filename, sha)
        if nmap_res:
            return nmap_res[:_MAX_FINDINGS_PER_FILE]
        res = parse_nmap_xml(text, filename, sha)
        return res  # recognized format: return even if empty, never reinterpret

    # Nuclei JSONL or ZAP/Nmap JSON
    if name.endswith(".jsonl") or (text.lstrip().startswith("{") and "\n{" in text):
        from .adapters.nuclei_adapter import NucleiAdapter
        nuclei_res = NucleiAdapter().parse_output(raw_bytes, filename, sha)
        if nuclei_res:
            return nuclei_res[:_MAX_FINDINGS_PER_FILE]

    # JSON family: if it *is* JSON, never reinterpret as text either
    is_json_candidate = name.endswith(".json") or text.lstrip()[:1] in ("{", "[")
    if is_json_candidate:
        try:
            data = json.loads(text)
        except Exception:
            if name.endswith(".json"):
                return []
            data = None
        if data is not None:
            for fn in (parse_zap_json, parse_nmap_json, parse_generic_json):
                try:
                    res = fn(data, filename, sha)  # type: ignore
                except Exception:
                    res = []
                if res:
                    return res[:_MAX_FINDINGS_PER_FILE]
            return []

    # Plain text family: only genuine Nikto-style output yields findings
    return parse_nikto_text(text, filename, sha)
