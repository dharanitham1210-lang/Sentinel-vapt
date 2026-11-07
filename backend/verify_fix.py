"""Live-API verification of the parser fix + audited cleanup."""
import json, urllib.request, urllib.error

B = "http://127.0.0.1:8000"


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


lst = req("GET", "/api/assessments")[1]
target_a = [a for a in lst if a["name"] == "VulnPilot Local Security Audit"][0]
aid = target_a["id"]
pdf_name = "VulnPilot_VulnPilot_Local_Security_Audit_a5afe6d7.pdf"

before = req("GET", f"/api/assessments/{aid}/findings")[1]
print("before:", len(before), "findings")

# 1) PDFs are now rejected at import with a clear 400
bd = "----QA"
raw = (f"--{bd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{pdf_name}\"\r\n"
       "Content-Type: application/pdf\r\n\r\n").encode() + b"%PDF-1.4 fake-id-regression" + f"\r\n--{bd}--\r\n".encode()
s, r = req("POST", f"/api/assessments/{aid}/import", raw=raw,
           headers={"Content-Type": f"multipart/form-data; boundary={bd}"})
print("PDF import ->", s, str(r.get("detail"))[:100])
assert s == 400, "PDF must be rejected"

# 2) audit-logged purge of the junk rows
s, p = req("POST", f"/api/assessments/{aid}/purge",
           {"source_filename": pdf_name, "reason": "PDF metadata mis-parsed as Nikto findings (fixed parser); see QUALITY_AUDIT.md"})
print("purge ->", s, p)
assert p.get("removed") == 26, p

after = req("GET", f"/api/assessments/{aid}/findings")[1]
print("after:", len(after), "findings:", [(f["title"][:30], f["source_filename"]) for f in after])
assert len(after) == 2
assert all(f["source_filename"] == "nmap-sample.xml.xml" for f in after)

# 3) valid sample re-import still works after the fix
demo = [a for a in req("GET", "/api/assessments")[1] if a["name"] == "[DEMO DATA] Juice Shop Lab"][0]
import os, glob
for pth in sorted(glob.glob("../samples/*")):
    name = os.path.basename(pth)
    with open(pth, "rb") as fh:
        raw2 = fh.read()
    body = (f"--{bd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + raw2 + f"\r\n--{bd}--\r\n".encode()
    s, r = req("POST", f"/api/assessments/{demo['id']}/import", raw=body,
               headers={"Content-Type": f"multipart/form-data; boundary={bd}"})
    print("import", name, "->", s, r)
    assert s == 200 and r.get("parsed") == 2, (name, s, r)

print("LIVE VERIFICATION OK")
