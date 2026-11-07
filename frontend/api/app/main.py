import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, storage
from .config import REPORTS_DIR, UPLOAD_DIR
from .database import get_conn, init_db, log_audit, row_to_dict
from .dedup import dedupe
from .diff import compute_assessment_diff
from .mitre import generate_mitre_matrix, generate_navigator_layer
from .normalization import detect_and_parse, file_sha256
from .planner import generate_plan
from .report import generate_pdf
from .agent.conversational import ConversationalAgent
from .agent.grounding_validator import GroundingValidator
from .agent.state_machine import AssessmentStateMachine
from .approvals import ApprovalService
from .audit import AuditService
from .auth import (
    Role,
    UserProfile,
    create_token,
    get_current_user,
    require_role,
    verify_password,
)
from .scope_gate import EngagementScope, ScopeGate, ScopeViolationError
from .scanners import nmap as nmap_scanner
from .scanners import nikto as nikto_scanner
from .scanners import zap as zap_scanner

ALLOWED_TOOLS = {"nmap", "nikto", "zap"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def uid():
    return uuid.uuid4().hex


app = FastAPI(title="SentinelVAPT", version="1.0.0")

# CORS: strictly adhere to ALLOWED_ORIGINS
_cors_origins = config.ALLOWED_ORIGINS
_cors_kwargs = {
    "allow_methods": ["*"],
    "allow_headers": ["*"],
    "allow_credentials": True if _cors_origins != ["*"] else False,
}
if _cors_origins == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, **_cors_kwargs)


# Realtime Event Broadcasting (SSE behind Render proxy)
_event_subscribers: list[asyncio.Queue] = []

def broadcast_event(event_type: str, data: dict):
    """Broadcast an event to all connected realtime clients."""
    for q in list(_event_subscribers):
        try:
            q.put_nowait({"type": event_type, "data": data, "timestamp": now()})
        except Exception:
            pass


@app.on_event("startup")
def boot():
    init_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    seed_demo()


# Ensure DB exists even when the app is exercised without a server startup
# event (e.g. in-process tests). Safe + idempotent.
try:
    init_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
except Exception:
    pass


# ---------- demo seed ----------
def seed_demo():
    conn = get_conn()
    try:
        n = conn.execute("SELECT COUNT(*) c FROM assessments WHERE demo=1").fetchone()["c"]
        if n:
            return
        aid = uid()
        conn.execute(
            "INSERT INTO assessments (id,name,target,scope,allowed_targets,authorized,auth_statement,status,plan_json,approval_status,demo) VALUES (?,?,?,?,?,?,?,?,?,?,1)",
            (aid, "[DEMO DATA] Juice Shop Lab", "127.0.0.1", "Local Juice Shop training app on localhost",
             json.dumps(["127.0.0.1"]), 1, "I own / am authorized to test this lab system.", "approved",
             json.dumps(generate_plan("127.0.0.1", "Local Juice Shop lab", ["127.0.0.1"])["steps"]), "approved"),
        )
        demo_findings = [
            {"title": "Missing security headers (demo)", "severity": "low", "confidence": 0.85, "cvss": 2.5,
             "asset": "127.0.0.1", "url": "http://127.0.0.1:3000", "parameter": "",
             "source": "demo", "source_filename": "DEMO_DATA_zap-export.json", "source_file_sha256": "demo",
             "evidence": "X-Content-Type-Options header not set (DEMO DATA — not a real scan result).",
             "evidence_json": {"demo": True}, "remediation": "Add Content-Security-Policy and related headers.",
             "references": [], "cwe": "CWE-693", "cve": ""},
            {"title": "Open port 3000 (demo)", "severity": "info", "confidence": 1.0, "cvss": 0.0,
             "asset": "127.0.0.1", "url": "127.0.0.1:3000", "parameter": "",
             "source": "demo", "source_filename": "DEMO_DATA_nmap.xml", "source_file_sha256": "demo",
             "evidence": "port 3000 open (DEMO DATA — not a real scan result).",
             "evidence_json": {"demo": True}, "remediation": "Review port exposure; restrict via firewall.",
             "references": [], "cwe": "", "cve": ""},
        ]
        for f in dedupe(demo_findings):
            conn.execute(
                """INSERT INTO findings (id,assessment_id,title,severity,confidence,cvss,asset,url,parameter,
                   source,source_filename,source_file_sha256,evidence,evidence_json,remediation,"references",cwe,cve,dedup_key,risk_score,risk_reason,is_demo)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (uid(), aid, f["title"], f["severity"], f["confidence"], f["cvss"], f["asset"], f["url"],
                 f["parameter"], f["source"], f["source_filename"], f["source_file_sha256"], f["evidence"],
                 json.dumps(f["evidence_json"]), f["remediation"], json.dumps(f["references"]), f["cwe"], f["cve"],
                 f["dedup_key"], f["risk_score"], f["risk_reason"]),
            )
        log_audit(conn, aid, "seed_demo", "Seeded DEMO DATA assessment.")
        conn.commit()
    finally:
        conn.close()


# ---------- models ----------
class AssessmentCreate(BaseModel):
    name: str
    target: str
    scope: str
    allowed_targets: list[str] = []
    authorized: bool = False
    auth_statement: str = ""


class PlanRequest(BaseModel):
    target: str
    scope: str
    allowed_targets: list[str] = []


class ApprovalRequest(BaseModel):
    approved: bool
    note: str = ""


class ScanRequest(BaseModel):
    tool: str
    target: str = ""


# ---------- health / integrations ----------
@app.get("/health")
def root_health():
    """Render health check endpoint verifying status, version, and cloud mode."""
    from . import database
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": "SentinelVAPT",
        "cloud_mode": config.CLOUD_MODE,
        "storage_backend": config.STORAGE_BACKEND,
        "database": "postgres" if database.IS_POSTGRES else "sqlite",
        "time": now(),
    }


@app.get("/api/health")
def api_health():
    from . import database
    return {
        "ok": True,
        "status": "healthy",
        "version": "1.0.0",
        "service": "SentinelVAPT",
        "cloud_mode": config.CLOUD_MODE,
        "storage_backend": config.STORAGE_BACKEND,
        "database": "postgres" if database.IS_POSTGRES else "sqlite",
        "time": now(),
    }


@app.get("/api/realtime/events")
async def realtime_events():
    """Server-Sent Events endpoint with 15-second keepalive pings for Render reverse proxy."""
    queue = asyncio.Queue()
    _event_subscribers.append(queue)

    async def event_generator():
        try:
            yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'time': now()})}\n\n"
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=15.0)
                    event_type = item.get("type", "message")
                    yield f"event: {event_type}\ndata: {json.dumps(item)}\n\n"
                except asyncio.TimeoutError:
                    # Keepalive comment ping prevents proxy termination
                    yield f": keepalive-ping {now()}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in _event_subscribers:
                _event_subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/integrations/status")
@app.get("/api/integrations/matrix")
def integration_status():
    from .adapters.registry import registry
    matrix = registry.get_integration_matrix()
    out = []
    for item in matrix:
        status_label = item["mode"].replace("_", " ").title()
        if item["is_available"] and item["mode"] == "live":
            status_label = "Live"
        elif item["mode"] == "import_only":
            status_label = "Import-only"

        out.append({
            "id": item["tool_name"],
            "name": item["display_name"],
            "category": item["category"],
            "mode": item["mode"],
            "status": status_label,
            "is_available": item["is_available"],
            "version": item["version"] or "",
            "detail": item["message"],
            "license_type": item["license_type"],
            "licensing_verified": item["licensing_verified"],
            "limitations": item["limitations"],
            "assumptions": item["assumptions"],
            "supported_formats": item["supported_formats"],
            "endpoint_url": item.get("endpoint_url"),
            "binary_path": item.get("binary_path"),
            "checked_at": item["checked_at"],
        })
    return out


@app.get("/api/artifacts/{artifact_id}")
def get_artifact(artifact_id: str):
    conn = get_conn()
    try:
        art = storage.get_raw_artifact_content(artifact_id, db=conn)
        if not art:
            raise HTTPException(404, f"Artifact '{artifact_id}' not found.")
        return art
    finally:
        conn.close()


class LoginRequest(BaseModel):
    username: str
    password: str


class ScopeGateCheckRequest(BaseModel):
    target: str
    port: int | None = None
    tool: str | None = None
    allowed_cidrs: list[str] = []
    allowed_hostnames: list[str] = []
    exclusions: list[str] = []
    allowed_ports: list[int] = []
    allowed_tools: list[str] = []
    allow_public_ips: bool = False


# ---------- Auth Endpoints ----------
@app.post("/api/auth/login")
def login(req: LoginRequest):
    conn = get_conn()
    try:
        cur = conn.execute("SELECT id, username, password_hash, salt, role, is_active FROM users WHERE username = ?", (req.username.strip(),))
        user = cur.fetchone()
        if not user:
            raise HTTPException(401, "Invalid username or password")
        u = row_to_dict(user)
        if not u["is_active"]:
            raise HTTPException(403, "Account is disabled")
        if not verify_password(req.password, u["password_hash"], u["salt"]):
            raise HTTPException(401, "Invalid username or password")

        token = create_token(u["id"], u["username"], u["role"])
        return {
            "token": token,
            "token_type": "bearer",
            "user": {
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
            },
        }
    finally:
        conn.close()


@app.get("/api/auth/me")
def me(current_user: UserProfile = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
    }


# ---------- Audit Integrity Endpoint ----------
@app.get("/api/audit/integrity")
def audit_integrity():
    conn = get_conn()
    try:
        return AuditService.verify_integrity(conn)
    finally:
        conn.close()


# ---------- Scope Gate Check Endpoint ----------
@app.post("/api/scope/gate-check")
def scope_gate_check(req: ScopeGateCheckRequest, current_user: UserProfile = Depends(get_current_user)):
    conn = get_conn()
    try:
        scope = EngagementScope(
            allowed_cidrs=req.allowed_cidrs,
            allowed_hostnames=req.allowed_hostnames,
            exclusions=req.exclusions,
            allowed_ports=req.allowed_ports,
            allowed_tools=req.allowed_tools,
            allow_public_ips=req.allow_public_ips,
        )
        gate = ScopeGate(scope, audit_logger=AuditService, db=conn, assessment_id="system")
        t_check = gate.check_target(req.target, port=req.port, actor=current_user.username)
        if not t_check["ok"]:
            return t_check

        if req.tool:
            tool_check = gate.check_tool(req.tool, actor=current_user.username)
            if not tool_check["ok"]:
                return tool_check

        return t_check
    finally:
        conn.close()


@app.get("/api/audit")
def audit_logs(assessment_id: str | None = None, limit: int = 200):
    conn = get_conn()
    try:
        if assessment_id:
            rows = conn.execute("SELECT * FROM audit_logs WHERE assessment_id=? ORDER BY id DESC LIMIT ?",
                                (assessment_id, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [row_to_dict(r) for r in rows]
    finally:
        conn.close()


# ---------- scope validation & plan ----------
@app.post("/api/assessments/validate-scope")
def validate(req: PlanRequest):
    v = validate_scope(req.scope, req.allowed_targets or ([req.target] if req.target else []))
    return {**v, "scan_allowed": v["ok"], "message": "Scope OK. Authorization confirmation still required before any active scan."
            if v["ok"] else "Scope REJECTED: " + " ".join(v["reasons"])}


@app.post("/api/assessments/plan")
def plan(req: PlanRequest):
    v = validate_scope(req.scope, req.allowed_targets or ([req.target] if req.target else []))
    if not v["ok"]:
        raise HTTPException(400, "Scope validation failed: " + " ".join(v["reasons"]))
    return generate_plan(req.target, req.scope, v["targets"])


# ---------- assessments ----------
@app.get("/api/assessments")
def list_assessments():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM assessments ORDER BY created_at DESC").fetchall()
        out = []
        for r in rows:
            d = row_to_dict(r)
            d["finding_count"] = conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE assessment_id=?", (d["id"],)).fetchone()["c"]
            out.append(d)
        return out
    finally:
        conn.close()


@app.post("/api/assessments")
def create_assessment(req: AssessmentCreate):
    targets = req.allowed_targets or ([req.target] if req.target else [])
    v = validate_scope(req.scope, targets)
    if not v["ok"]:
        raise HTTPException(400, "Scope validation failed: " + " ".join(v["reasons"]))
    if not req.name.strip():
        raise HTTPException(400, "Name is required.")
    if not req.authorized or len(req.auth_statement or "") < 10:
        raise HTTPException(400, "Explicit authorization confirmation is required (statement of at least 10 characters).")
    aid = uid()
    plan_data = generate_plan(req.target, req.scope, v["targets"])
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO assessments (id,name,target,scope,allowed_targets,authorized,auth_statement,status,plan_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (aid, req.name.strip(), req.target, req.scope, json.dumps(v["targets"]), 1,
             req.auth_statement.strip(), "planned", json.dumps(plan_data["steps"])),
        )
        log_audit(conn, aid, "assessment_created", f"Target={req.target}  plan_generator={plan_data['generator']}")
        conn.commit()
    finally:
        conn.close()
    return get_assessment(aid)


@app.get("/api/assessments/{aid}")
def get_assessment(aid: str):
    conn = get_conn()
    try:
        r = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not r:
            raise HTTPException(404, "Assessment not found.")
        d = row_to_dict(r)
        d["plan"] = json.loads(d["plan_json"] or "[]")
        d["allowed_targets_list"] = json.loads(d["allowed_targets"] or "[]")
        d["finding_count"] = conn.execute(
            "SELECT COUNT(*) c FROM findings WHERE assessment_id=?", (aid,)).fetchone()["c"]
        return d
    finally:
        conn.close()


class ApprovalCreateRequest(BaseModel):
    assessment_id: str
    request_type: str = "action"  # 'action' or 'report'
    target: str
    tool: str = ""
    command: str = ""
    params: dict = {}
    justification: str
    lab_confirmed: bool = False
    ttl_minutes: int = 120


class ApprovalDecideRequest(BaseModel):
    approved: bool
    typed_target_confirmation: str
    outcome_notes: str = ""


class AgentChatRequest(BaseModel):
    message: str
    target: str = ""


# ---------- Approvals Center Endpoints ----------
@app.post("/api/approvals")
def create_approval(req: ApprovalCreateRequest, current_user: UserProfile = Depends(get_current_user)):
    conn = get_conn()
    try:
        res = ApprovalService.create_request(
            conn,
            assessment_id=req.assessment_id,
            request_type=req.request_type,
            requester=current_user.username,
            target=req.target,
            tool=req.tool,
            command=req.command,
            params=req.params,
            justification=req.justification,
            lab_confirmed=req.lab_confirmed,
            ttl_minutes=req.ttl_minutes,
        )
        return res
    finally:
        conn.close()


@app.get("/api/approvals")
def list_approvals(assessment_id: str | None = None):
    conn = get_conn()
    try:
        return ApprovalService.list_approvals(conn, assessment_id=assessment_id)
    finally:
        conn.close()


@app.post("/api/approvals/{approval_id}/decide")
def decide_approval(
    approval_id: str,
    req: ApprovalDecideRequest,
    current_user: UserProfile = Depends(require_role(Role.LEAD_ANALYST)),
):
    conn = get_conn()
    try:
        return ApprovalService.decide_request(
            conn,
            approval_id=approval_id,
            approver=current_user.username,
            approved=req.approved,
            typed_target_confirmation=req.typed_target_confirmation,
            outcome_notes=req.outcome_notes,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    finally:
        conn.close()


# ---------- Agent Chat & State Endpoints ----------
@app.post("/api/assessments/{aid}/chat")
def agent_chat(aid: str, req: AgentChatRequest, current_user: UserProfile = Depends(get_current_user)):
    conn = get_conn()
    try:
        a = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not a:
            raise HTTPException(404, "Assessment not found.")
        ad = row_to_dict(a)

        allowed_targets = json.loads(ad.get("allowed_targets") or "[]")
        allowed_cidrs = json.loads(ad.get("allowed_cidrs") or "[]")
        allowed_hostnames = json.loads(ad.get("allowed_hostnames") or "[]")
        exclusions = json.loads(ad.get("exclusions") or "[]")
        allowed_tools = json.loads(ad.get("allowed_tools") or "[]")

        scope_obj = EngagementScope(
            allowed_cidrs=allowed_cidrs or ([ad["target"]] if "/" in ad["target"] else []),
            allowed_hostnames=allowed_hostnames or ([ad["target"]] if not "/" in ad["target"] and not ad["target"].replace(".", "").isdigit() else []),
            exclusions=exclusions,
            allowed_tools=allowed_tools,
        )
        gate = ScopeGate(scope_obj, audit_logger=AuditService, db=conn, assessment_id=aid)
        agent = ConversationalAgent(gate)

        target_to_use = req.target or ad["target"]
        plan_res = agent.plan_assessment(
            user_request=req.message,
            target=target_to_use,
            scope_text=ad.get("scope", ""),
            actor=current_user.username,
        )

        if plan_res["ok"]:
            # Update assessment plan in database
            conn.execute(
                "UPDATE assessments SET plan_json=?, updated_at=? WHERE id=?",
                (json.dumps(plan_res["steps"]), now(), aid),
            )
            log_audit(conn, aid, "AGENT_REPLAN", f"Replanned by agent: {req.message[:100]}", actor=current_user.username)
            conn.commit()

        return plan_res
    finally:
        conn.close()


@app.get("/api/assessments/{aid}/state")
def assessment_state(aid: str):
    conn = get_conn()
    try:
        findings_rows = conn.execute("SELECT * FROM findings WHERE assessment_id=?", (aid,)).fetchall()
        findings = [row_to_dict(r) for r in findings_rows]
        sm = AssessmentStateMachine(assessment_id=aid)
        sm.ingest_findings(findings)
        return sm.get_structured_state()
    finally:
        conn.close()


@app.post("/api/assessments/{aid}/approve")
def approve_assessment(aid: str, req: ApprovalRequest):
    conn = get_conn()
    try:
        r = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not r:
            raise HTTPException(404, "Assessment not found.")
        status = "approved" if req.approved else "changes_requested"
        conn.execute("UPDATE assessments SET approval_status=?, status=?, updated_at=? WHERE id=?",
                     (status, "approved" if req.approved else "planned", now(), aid))
        log_audit(conn, aid, "approval", f"approved={req.approved} note={req.note}")
        conn.commit()
    finally:
        conn.close()
    return get_assessment(aid)


# ---------- imports ----------
@app.post("/api/assessments/{aid}/import")
async def import_scan(aid: str, file: UploadFile = File(...)):
    conn = get_conn()
    try:
        a = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not a:
            raise HTTPException(404, "Assessment not found.")
        raw = await file.read()
        fname = file.filename or "upload"
        sha = hashlib.sha256(raw).hexdigest()
        stored_name = f"{aid}_{uid()}_{fname}"
        try:
            storage_ref = await storage.save_upload(stored_name, raw)
        except Exception as e:
            log_audit(conn, aid, "import_rejected", f"file={fname} sha256={sha} reason=storage_error:{e}")
            conn.commit()
            raise HTTPException(502, f"Failed to store uploaded evidence: {e}")
        try:
            findings = detect_and_parse(raw, fname)
        except ValueError as e:
            log_audit(conn, aid, "import_rejected", f"file={fname} sha256={sha} reason={e}")
            conn.commit()
            raise HTTPException(400, str(e))

        # Save into content-addressed immutable artifact store
        tool_src = findings[0]["source"] if findings else "import"
        storage.save_raw_artifact(aid, tool_src, fname, raw, db=conn)
        findings = dedupe(findings)
        # keep existing findings and re-dedupe across the whole assessment so
        # importing the same file twice doesn't duplicate rows
        existing = conn.execute('SELECT evidence, source_filename, title, severity, confidence, cvss, asset, url, parameter, source, source_file_sha256, evidence_json, remediation, "references" FROM findings WHERE assessment_id=?', (aid,)).fetchall()
        all_f = [
            {"title": r["title"], "severity": r["severity"], "confidence": r["confidence"], "cvss": r["cvss"],
             "asset": r["asset"], "url": r["url"], "parameter": r["parameter"], "source": r["source"],
             "source_filename": r["source_filename"], "source_file_sha256": r["source_file_sha256"],
             "evidence": r["evidence"], "evidence_json": json.loads(r["evidence_json"] or "{}"),
             "remediation": r["remediation"], "references": json.loads(r["references"] or "[]"), "cwe": "", "cve": ""}
            for r in existing
        ]
        merged = dedupe(all_f + findings)
        conn.execute("DELETE FROM findings WHERE assessment_id=?", (aid,))
        for f in merged:
            conn.execute(
                """INSERT INTO findings (id,assessment_id,title,severity,confidence,cvss,asset,url,parameter,
                   source,source_filename,source_file_sha256,evidence,evidence_json,remediation,"references",cwe,cve,dedup_key,risk_score,risk_reason)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid(), aid, f["title"], f["severity"], f["confidence"], f["cvss"], f["asset"], f["url"],
                 f["parameter"], f["source"], f["source_filename"], f["source_file_sha256"], f["evidence"],
                 json.dumps(f["evidence_json"]), f["remediation"], json.dumps(f["references"]), f["cwe"], f["cve"],
                 f["dedup_key"], f["risk_score"], f["risk_reason"]),
            )
        log_audit(conn, aid, "import", f"file={fname} sha256={sha} storage={storage_ref} parsed={len(findings)} unique_now={len(merged)}")
        conn.commit()
        return {"ok": True, "filename": fname, "sha256": sha, "parsed": len(findings), "unique_findings": len(merged)}
    finally:
        conn.close()


class PurgeRequest(BaseModel):
    source_filename: str
    reason: str = ""


@app.post("/api/assessments/{aid}/purge")
def purge_findings(aid: str, req: PurgeRequest):
    """Remove findings from a specific import (e.g. a mis-imported PDF).

    Safe by design: only rows matching the exact source filename are deleted,
    the original uploaded file is untouched, and a `purge_findings` audit event
    records what was removed, when and why — history is never rewritten.
    """
    conn = get_conn()
    try:
        a = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not a:
            raise HTTPException(404, "Assessment not found.")
        fn = (req.source_filename or "").strip()
        if not fn:
            raise HTTPException(400, "source_filename is required.")
        # match exact first; also match merged sets joined with "; "
        rows = conn.execute(
            "SELECT id, title FROM findings WHERE assessment_id=? AND "
            "(source_filename = ? OR source_filename LIKE ? OR source_filename LIKE ?)",
            (aid, fn, f"%{fn}%;%", f"%{fn}"),
        ).fetchall()
        removed = [row_to_dict(r) for r in rows]
        for r in removed:
            conn.execute("DELETE FROM findings WHERE id=?", (r["id"],))
        log_audit(conn, aid, "purge_findings",
                  f"removed={len(removed)} source_filename={fn} reason={req.reason} titles={[r['title'][:40] for r in removed[:8]]}")
        conn.commit()
        return {"ok": True, "removed": len(removed), "source_filename": fn}
    finally:
        conn.close()


# ---------- scan runs ----------
def _load_assessment(aid: str):
    conn = get_conn()
    try:
        r = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not r:
            raise HTTPException(404, "Assessment not found.")
        return row_to_dict(r)
    finally:
        conn.close()


def _check_can_scan(a: dict, tool: str, target: str):
    if a.get("approval_status") != "approved":
        raise HTTPException(403, "Human approval required before active validation. Approve this assessment first.")
    if not a.get("authorized"):
        raise HTTPException(403, "Explicit authorization confirmation is missing.")
    scope_v = validate_scope(a.get("scope", ""), json.loads(a.get("allowed_targets") or "[]"))
    if not scope_v["ok"]:
        raise HTTPException(403, "Scope validation failed: " + " ".join(scope_v["reasons"]))
    t = target or a.get("target", "")
    if t:
        from .scope import validate_host
        vh = validate_host(t)
        if not vh["ok"]:
            raise HTTPException(403, f"Target blocked: {vh['reason']}")


@app.post("/api/assessments/{aid}/scan")
def run_scan(aid: str, req: ScanRequest):
    tool = (req.tool or "").lower()
    if tool not in ALLOWED_TOOLS:
        raise HTTPException(400, "Tool must be one of: nmap, nikto, zap.")
    a = _load_assessment(aid)
    _check_can_scan(a, tool, req.target)
    target_ref = req.target or a.get("target", "")
    run_id = uid()
    conn = get_conn()
    try:
        conn.execute("INSERT INTO scan_runs (id,assessment_id,tool,target,status) VALUES (?,?,?,?, 'queued')",
                     (run_id, aid, tool, target_ref))
        log_audit(conn, aid, "scan_started", f"tool={tool} target={target_ref}")
        conn.commit()
    finally:
        conn.close()

    result = {"ok": False, "error": "", "command": "", "stdout": "", "stderr": ""}
    if tool == "nmap":
        result = nmap_scanner.run(target_ref)
    elif tool == "nikto":
        result = nikto_scanner.run(target_ref)
    elif tool == "zap":
        st = zap_scanner.status()
        if not st.get("ok"):
            result = {"ok": False, "error": "ZAP API unreachable: " + st.get("error", ""), "command": "", "stdout": "", "stderr": ""}
        else:
            f = zap_scanner.fetch_alerts()
            result = {"ok": f["ok"], "error": f.get("error", ""), "command": f"GET {config.ZAP_API_URL}/JSON/core/view/alerts/",
                      "stdout": json.dumps(f.get("data", {}))[:20000], "stderr": ""}

    imported = 0
    # If live output present, normalize + store as evidence-backed findings
    raw_text = result.get("stdout", "") or ""
    if result.get("ok") and raw_text.strip():
        fname = f"live_{tool}_{run_id}.out"
        try:
            if tool == "zap":
                findings = detect_and_parse(raw_text.encode(), fname)
            elif tool == "nmap":
                findings = detect_and_parse(raw_text.encode(), fname + ".xml")
            else:
                findings = detect_and_parse(raw_text.encode(), fname + ".txt")
        except ValueError:
            findings = []
        findings = dedupe(findings)
        conn = get_conn()
        try:
            for f in findings:
                conn.execute(
                    """INSERT INTO findings (id,assessment_id,title,severity,confidence,cvss,asset,url,parameter,
                       source,source_filename,source_file_sha256,evidence,evidence_json,remediation,"references",cwe,cve,dedup_key,risk_score,risk_reason)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (uid(), aid, f["title"], f["severity"], f["confidence"], f["cvss"], f["asset"], f["url"],
                     f["parameter"], f["source"], f["source_filename"], f["source_file_sha256"], f["evidence"],
                     json.dumps(f["evidence_json"]), f["remediation"], json.dumps(f["references"]), f["cwe"], f["cve"],
                     f["dedup_key"], f["risk_score"], f["risk_reason"]),
                )
            imported = len(findings)
            conn.execute("UPDATE scan_runs SET status=?, command=?, stdout=?, stderr=?, findings_imported=? WHERE id=?",
                         ("completed" if result["ok"] else "failed", result.get("command", ""),
                          raw_text[:50000], result.get("stderr", "")[:20000], imported, run_id))
            log_audit(conn, aid, "scan_completed", f"tool={tool} imported={imported}")
            conn.commit()
        finally:
            conn.close()
    else:
        conn = get_conn()
        try:
            conn.execute("UPDATE scan_runs SET status='failed', command=?, stdout=?, stderr=? WHERE id=?",
                         (result.get("command", ""), raw_text[:50000], (result.get("stderr", "") + " " + result.get("error", ""))[:20000], run_id))
            log_audit(conn, aid, "scan_failed", f"tool={tool} error={result.get('error','')}")
            conn.commit()
        finally:
            conn.close()
    return {"ok": result.get("ok", False), "error": result.get("error", ""), "run_id": run_id,
            "command": result.get("command", ""), "findings_imported": imported,
            "hint": "Scanners not installed? Use Dashboard → Import to upload nmap XML / ZAP JSON / Nikto text outputs." if not result.get("ok") else ""}


@app.get("/api/assessments/{aid}/scans")
def list_scans(aid: str):
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM scan_runs WHERE assessment_id=? ORDER BY created_at DESC", (aid,)).fetchall()
        return [row_to_dict(r) for r in rows]
    finally:
        conn.close()


# ---------- findings ----------
@app.get("/api/assessments/{aid}/findings")
def list_findings(aid: str, severity: str | None = None):
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM findings WHERE assessment_id=? ORDER BY risk_score DESC", (aid,)).fetchall()
        out = [row_to_dict(r) for r in rows]
        for f in out:
            f["evidence_decoded"] = f.pop("evidence_json", "{}")
        if severity:
            out = [f for f in out if f.get("severity") == severity.lower()]
        return out
    finally:
        conn.close()


@app.get("/api/findings/{fid}")
def get_finding(fid: str):
    conn = get_conn()
    try:
        r = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not r:
            raise HTTPException(404, "Finding not found.")
        return row_to_dict(r)
    finally:
        conn.close()


# ---------- MITRE ATT&CK & Retest Diff Endpoints ----------
@app.get("/api/assessments/{aid}/mitre")
def get_assessment_mitre(aid: str):
    conn = get_conn()
    try:
        a = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not a:
            raise HTTPException(404, "Assessment not found.")
        findings_rows = conn.execute("SELECT * FROM findings WHERE assessment_id=?", (aid,)).fetchall()
        findings = [row_to_dict(r) for r in findings_rows]
        return generate_mitre_matrix(findings)
    finally:
        conn.close()


@app.get("/api/assessments/{aid}/mitre/navigator")
def get_mitre_navigator_layer(aid: str):
    conn = get_conn()
    try:
        a = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not a:
            raise HTTPException(404, "Assessment not found.")
        ad = row_to_dict(a)
        findings_rows = conn.execute("SELECT * FROM findings WHERE assessment_id=?", (aid,)).fetchall()
        findings = [row_to_dict(r) for r in findings_rows]
        return generate_navigator_layer(ad.get("name", "Assessment"), findings)
    finally:
        conn.close()


@app.get("/api/assessments/{aid}/diff/{prior_aid}")
def get_assessment_diff(aid: str, prior_aid: str):
    conn = get_conn()
    try:
        a_curr = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        a_prior = conn.execute("SELECT * FROM assessments WHERE id=?", (prior_aid,)).fetchone()
        if not a_curr or not a_prior:
            raise HTTPException(404, "One or both assessments not found.")
        curr_dict = row_to_dict(a_curr)
        prior_dict = row_to_dict(a_prior)

        curr_findings = [row_to_dict(r) for r in conn.execute("SELECT * FROM findings WHERE assessment_id=?", (aid,)).fetchall()]
        prior_findings = [row_to_dict(r) for r in conn.execute("SELECT * FROM findings WHERE assessment_id=?", (prior_aid,)).fetchall()]

        return compute_assessment_diff(curr_dict, prior_dict, curr_findings, prior_findings)
    finally:
        conn.close()


# ---------- dashboard stats ----------
@app.get("/api/dashboard/stats")
def dashboard_stats():
    conn = get_conn()
    try:
        apps = conn.execute("SELECT COUNT(*) c FROM assessments").fetchone()["c"]
        fins = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
        sev_rows = conn.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity").fetchall()
        src_rows = conn.execute("SELECT source, COUNT(*) c FROM findings GROUP BY source").fetchall()
        recent = conn.execute("SELECT * FROM assessments ORDER BY created_at DESC LIMIT 5").fetchall()
        return {
            "assessments": apps,
            "findings": fins,
            "by_severity": {r["severity"]: r["c"] for r in sev_rows},
            "by_source": {r["source"]: r["c"] for r in src_rows},
            "recent": [row_to_dict(r) for r in recent],
        }
    finally:
        conn.close()


# ---------- report ----------
@app.get("/api/assessments/{aid}/report")
async def download_report(aid: str):
    conn = get_conn()
    try:
        a = conn.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not a:
            raise HTTPException(404, "Assessment not found.")
        ad = row_to_dict(a)
        findings = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM findings WHERE assessment_id=? ORDER BY risk_score DESC", (aid,)).fetchall()]
        audit = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM audit_logs WHERE assessment_id=? ORDER BY id", (aid,)).fetchall()]
        approvals_list = [row_to_dict(r) for r in conn.execute(
            "SELECT * FROM approvals WHERE assessment_id=? ORDER BY created_at DESC", (aid,)).fetchall()]
        audit_integrity = AuditService.verify_integrity(conn)
    finally:
        conn.close()
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in ad.get("name", "assessment"))
    filename = f"SentinelVAPT_{safe}_{aid[:8]}.pdf"
    tmp = os.path.join(REPORTS_DIR, f"_tmp_{uid()}_{filename}")
    os.makedirs(os.path.dirname(tmp), exist_ok=True)
    try:
        generate_pdf(ad, findings, audit, tmp, approvals=approvals_list, audit_integrity_result=audit_integrity)
        data = Path(tmp).read_bytes()
        try:
            ref = await storage.save_report(filename, data)
        except Exception as e:
            # Local fallback: keep serving bytes; log storage issue.
            ref = f"local-bytes:{filename} ({e})"
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
    _c = get_conn()
    try:
        log_audit(_c, aid, "report_generated", f"findings={len(findings)} storage={ref}")
        _c.commit()
    finally:
        _c.close()
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------- single-origin production serving ----------
# When frontend/dist exists (run `npm run build` in frontend/), FastAPI also
# serves the SPA, so one uvicorn process is the whole "website" — no separate
# dev server, no CORS, no proxy needed. Local dev (npm run dev on :5173) is
# untouched; the React app calls /api on the same origin either way.
_FRONTEND_DIST = Path(config.BASE_DIR).parent / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse as _FR

    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIST / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    def _index():
        return _FR(str(_FRONTEND_DIST / "index.html"), media_type="text/html")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa(full_path: str):
        from fastapi.responses import JSONResponse
        if full_path.startswith(("api/", "docs", "openapi")):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        candidate = _FRONTEND_DIST / full_path
        if candidate.is_file():
            return _FR(str(candidate))
        return _FR(str(_FRONTEND_DIST / "index.html"), media_type="text/html")
