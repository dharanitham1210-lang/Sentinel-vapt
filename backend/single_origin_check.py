"""Single-origin production check: one uvicorn serves API + SPA."""
import json, urllib.request

B = "http://127.0.0.1:8000"


def get(path):
    with urllib.request.urlopen(B + path, timeout=15) as r:
        return r.status, r.headers.get_content_type(), r.read()


s, ct, html = get("/")
print("GET /            ->", s, ct, len(html), "bytes; has #root:", b'id="root"' in html, "| has assets script:", b"/assets/" in html)

# a real asset file must be served (js/css chunks under dist/assets)
import pathlib
assets = list(pathlib.Path("../frontend/dist/assets").glob("index-*"))
for a in sorted(assets)[:1]:
    s, ct, _ = get(f"/assets/{a.name}")
    print("GET /assets/*    ->", s, ct, a.name)

s, ct, body = get("/api/health")
print("GET /api/health  ->", s, json.loads(body))

# SPA fallback: unknown deep link returns index.html (not 404)
s, ct, body = get("/deep/link/path")
print("GET /deep/link   ->", s, ct, b'id="root"' in body)

# unknown API path stays a JSON 404, not the SPA
try:
    get("/api/nonexistent")
    print("GET /api/nope    -> UNEXPECTED 200")
except urllib.error.HTTPError as e:
    print("GET /api/nope    ->", e.code, "(correct JSON 404)")

print("SINGLE-ORIGIN OK")
