"""Final E2E: fresh assessment, 3 imports, detail, audit, PDF content check."""
import io, json, os, urllib.request, urllib.error

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


# create + approve
s, a = req("POST", "/api/assessments", {"name": "Final E2E", "target": "127.0.0.1", "scope": "Local lab",
                                        "allowed_targets": ["127.0.0.1"], "authorized": True,
                                        "auth_statement": "I own this lab system."})
aid = a["id"]
print("created:", s, a["status"], a["approval_status"], "| plan steps:", len(a["plan"]))
s, a2 = req("POST", f"/api/assessments/{aid}/approve", {"approved": True, "note": "E2E"})
print("approved:", s, a2["approval_status"])

# import all three samples
bd = "----E2E"
for p in sorted(os.listdir("../samples")):
    with open("../samples/" + p, "rb") as fh:
        raw = fh.read()
    body = (f"--{bd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{p}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + raw + f"\r\n--{bd}--\r\n".encode()
    s, r = req("POST", f"/api/assessments/{aid}/import", raw=body,
               headers={"Content-Type": f"multipart/form-data; boundary={bd}"})
    print("import", p, "->", s, r.get("parsed"), "parsed, unique:", r.get("unique_findings"))

s, fins = req("GET", f"/api/assessments/{aid}/findings")
print("findings:", len(fins))
from collections import Counter
print(Counter((f["source"], f["severity"]) for f in fins))

# detail
fid = fins[0]["id"]
s, fd = req("GET", f"/api/findings/{fid}")
print("detail:", s, fd["title"][:50], "| risk:", fd["risk_score"], "| reason:", fd["risk_reason"][:40])

# audit
logs = req("GET", f"/api/audit?assessment_id={aid}")[1]
print("audit trail:", [x["event"] for x in logs])

# negative: PDF still rejected
raw = (f"--{bd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\n"
       "Content-Type: application/pdf\r\n\r\n").encode() + b"%PDF-1.4 fake-id-e2e" + f"\r\n--{bd}--\r\n".encode()
s, r = req("POST", f"/api/assessments/{aid}/import", raw=raw,
           headers={"Content-Type": f"multipart/form-data; boundary={bd}"})
print("PDF rejected:", s, str(r.get("detail"))[:60])

# PDF content accuracy
r = urllib.request.Request(B + f"/api/assessments/{aid}/report")
with urllib.request.urlopen(r, timeout=30) as resp:
    pdf = resp.read()
print("PDF bytes:", len(pdf), "header:", pdf[:8])

import pypdf
tr = pypdf.PdfReader(io.BytesIO(pdf))
text = "".join(p.extract_text() or "" for p in tr.pages)
missing = [f["title"][:30] for f in fins if f["title"][:25] not in text]
print("PDF pages:", len(tr.pages), "| findings missing from text:", missing)
print("E2E DONE", aid)
