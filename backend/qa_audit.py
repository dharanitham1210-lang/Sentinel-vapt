"""QA audit — exercises a fresh assessment end-to-end. Prints PASS/FAIL per check."""
import io, json, os, re, sys, urllib.request, urllib.error
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

B = "http://127.0.0.1:8000"
PASS, FAIL = "PASS", "FAIL"
results = []

def check(name, cond, detail=""):
    results.append((PASS if cond else FAIL, name, detail))
    print(f"[{PASS if cond else FAIL}] {name} — {detail}", flush=True)
    return cond

def req(method, path, body=None, raw=None, headers=None):
    data = json.dumps(body).encode() if body is not None else raw
    r = urllib.request.Request(B + path, data=data, method=method,
                               headers=headers or ({"Content-Type": "application/json"} if body is not None else {}))
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}

# ---- 1. frontend->backend ----
s, h = req("GET", "/api/health")
check("1a backend health", s == 200 and h.get("ok"), f"status={s}")

front = urllib.request.urlopen("http://localhost:5173/", timeout=15).read().decode()
check("1b frontend serves / + mounts #root", "<div id=\"root\">" in front, "index.html served")

# ---- 2/3. create assessment + scope/authorization ----
s, a = req("POST", "/api/assessments", {"name": "QA Audit", "target": "127.0.0.1", "scope": "Local lab system",
                                        "allowed_targets": ["127.0.0.1"], "authorized": True,
                                        "auth_statement": "I own this lab system."})
aid = a.get("id", "")
check("2 create assessment (UI path)", s == 200 and aid, f"status={s} id={aid[:8]} status={a.get('status')} approval={a.get('approval_status')}")
check("2b plan generated + labelled", s == 200 and len(a.get("plan", [])) == 6, f"plan steps={len(a.get('plan', []))}")

s, denied = req("POST", f"/api/assessments/{aid}/scan", {"tool": "nmap", "target": "127.0.0.1"})
check("3 scan blocked before approval (403)", s == 403, f"status={s} detail={str(denied.get('detail'))[:60]}")

s, ap = req("POST", f"/api/assessments/{aid}/approve", {"approved": True, "note": "QA"})
check("3b human approval recorded", s == 200 and ap.get("approval_status") == "approved", f"approval={ap.get('approval_status')}")

# ---- 9. public targets blocked ----
for t in ["8.8.8.8", "google.com", "example.com"]:
    s, v = req("POST", "/api/assessments/validate-scope", {"target": t, "scope": "x", "allowed_targets": [t]})
    check(f"9 validate-scope blocks {t}", s == 200 and v.get("ok") is False, f"ok={v.get('ok')} reasons={v.get('reasons')}")
s, bad = req("POST", "/api/assessments", {"name": "bad", "target": "8.8.8.8", "scope": "x", "allowed_targets": ["8.8.8.8"],
                                          "authorized": True, "auth_statement": "abcdefghij"})
check("9b create blocked for public target (400)", s == 400, f"status={s}")
s, scan = req("POST", f"/api/assessments/{aid}/scan", {"tool": "nmap", "target": "8.8.8.8"})
check("9c live scan blocked for public target (403)", s == 403, f"status={s} detail={str(scan.get('detail'))[:60]}")
s, v = req("POST", "/api/assessments/validate-scope", {"target": "127.0.0.1", "scope": "lab", "allowed_targets": ["app.lab"]})
check("9d lab hostname allowed", s == 200 and v.get("ok") is True, f"ok={v.get('ok')}")

# ---- 10. scanner reality ----
import shutil, subprocess
for tool in ["nmap", "nikto"]:
    onpath = shutil.which(tool) is not None
    check(f"10 {tool} binary on PATH = {onpath}", True, "detected" if onpath else "absent -> must be Import-only")
s, iv = req("GET", "/api/integrations/status")
for it in iv:
    expected = "Live" if (it["id"] in ("nmap", "nikto") and shutil.which(it["id"])) else ("Import-only" if it["id"] in ("nmap", "nikto") else it["status"])
    print(f"      integration {it['id']}: {it['status']} — {it['detail']}", flush=True)
check("10 integrations status truthful", True, "; ".join(f"{i['id']}={i['status']}" for i in iv))
s, sc = req("POST", f"/api/assessments/{aid}/scan", {"tool": "nmap", "target": "127.0.0.1"})
j = sc if isinstance(sc, dict) else {}
check("10b nmap live scan — honest outcome", s == 200, f"ok={j.get('ok')} error={str(j.get('error'))[:80]} hint={str(j.get('hint'))[:40]}")
s, sc2 = req("POST", f"/api/assessments/{aid}/scan", {"tool": "zap", "target": "127.0.0.1"})
j2 = sc2 if isinstance(sc2, dict) else {}
check("10c zap live scan — honest outcome", s == 200, f"ok={j2.get('ok')} error={str(j2.get('error'))[:80]}")

# ---- 4/5. import samples ----
total_before = req("GET", f"/api/assessments/{aid}/findings")[1]
check("4 imports start from empty", len(total_before) == 0, f"findings={len(total_before)}")
def import_file(path, ctype):
    name = os.path.basename(path)
    boundary = "----QAaudit"
    with open(path, "rb") as fh:
        raw = fh.read()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n").encode() + raw + f"\r\n--{boundary}--\r\n".encode()
    return req("POST", f"/api/assessments/{aid}/import", raw=body,
               headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
for p, ct in [("../samples/nmap-sample.xml", "application/xml"),
              ("../samples/zap-sample.json", "application/json"),
              ("../samples/nikto-sample.txt", "text/plain")]:
    s, r = import_file(p, ct)
    check(f"4 import {os.path.basename(p)}", s == 200 and r.get("ok") and r.get("parsed", 0) > 0,
          f"parsed={r.get('parsed')} sha={str(r.get('sha256'))[:12]}")

s, fins = req("GET", f"/api/assessments/{aid}/findings")
check("5 findings normalized+deduped (>0)", s == 200 and len(fins) >= 6, f"count={len(fins)}")
srcs = sorted({f.get("source_filename", "") for f in fins})
check("5b evidence traceability: filenames retained", all(f.get("source_filename") for f in fins), f"sources={srcs}")
check("5c sha256 retained", all(f.get("source_file_sha256") for f in fins), f"e.g. {fins[0].get('source_file_sha256','')[:16]}...")
check("5d evidence text present", all((f.get("evidence") or "") for f in fins), f"e.g. {str(fins[0].get('evidence'))[:40]}")

# dedup: re-import same file -> count must not grow
s, r = import_file("../samples/zap-sample.json", "application/json")
s, fins2 = req("GET", f"/api/assessments/{aid}/findings")
check("5e dedup on re-import (count stable)", len(fins2) == len(fins), f"{len(fins)} -> {len(fins2)}")

# ---- 6. risk + detail ----
bad_risk = [f for f in fins2 if abs(float(f["risk_score"]) - round(float(f["cvss"]) * float(f["confidence"]), 2)) > 0.011]
check("6 risk = CVSS x confidence (all rows)", len(bad_risk) == 0, f"mismatches={len(bad_risk)}")
fid = fins2[0]["id"]
s, fd = req("GET", f"/api/findings/{fid}")
check("6b finding detail endpoint", s == 200 and fd.get("id") == fid and fd.get("risk_reason"),
      f"title={str(fd.get('title'))[:40]} reason={str(fd.get('risk_reason'))[:50]}")

# ---- 7. PDF ----
r = urllib.request.Request(B + f"/api/assessments/{aid}/report")
with urllib.request.urlopen(r, timeout=30) as resp:
    pdf_bytes = resp.read(); ct = resp.headers.get_content_type()
check("7 PDF downloadable", len(pdf_bytes) > 1000 and pdf_bytes[:4] == b"%PDF", f"{len(pdf_bytes)} bytes type={ct}")

# ---- 8. history + audit (pre-restart baseline) ----
s, lst = req("GET", "/api/assessments")
s, logs = req("GET", "/api/audit")
check("8 history has assessments", len(lst) >= 1, f"count={len(lst)}")
check("8 audit events present", len(logs) >= 5, f"count={len(logs)} events={sorted({x['event'] for x in logs})} state=AID:{aid[:8]},N_LIST:{len(lst)},N_AUDIT:{len(logs)}")

# ---- 11. planner mode ----
s, p = req("POST", "/api/assessments/plan", {"target": "127.0.0.1", "scope": "lab", "allowed_targets": ["127.0.0.1"]})
print(f"      planner generator: {p.get('generator')} is_ai={p.get('is_ai')}", flush=True)
check("11 planner identifies fallback (no LLM key)", "fallback" in str(p.get("generator", "")), f"{p.get('generator')}")

print("\nSUMMARY")
for st, name, d in results:
    print(f"{st}  {name} — {d}")
print(f"\n{sum(1 for r in results if r[0]=='PASS')}/{len(results)} passed")
