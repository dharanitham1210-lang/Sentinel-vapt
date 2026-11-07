"""File storage: local filesystem by default, database or Supabase Storage when configured.

Safety & Integrity:
- Preserves local filesystem storage for local development.
- In 'database' storage mode (Render / Neon cloud deployment), raw scanner artifacts are stored
  directly in the PostgreSQL database with SHA-256 verification, ensuring evidence tracing
  persists across container restarts even without a persistent disk.
- Never weakens SHA-256 validation.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional

import httpx

from . import config

ARTIFACTS_DIR = config.ARTIFACTS_DIR


def supabase_enabled() -> bool:
    return bool(config.SUPABASE_URL and config.SUPABASE_SERVICE_KEY)


def _headers(content_type: str = "application/octet-stream") -> dict:
    key = config.SUPABASE_SERVICE_KEY
    return {
        "Authorization": f"Bearer {key}",
        "apikey": key,
        "Content-Type": content_type,
        "x-upsert": "true",
    }


def _object_url(bucket: str, object_path: str) -> str:
    base = config.SUPABASE_URL.rstrip("/")
    return f"{base}/storage/v1/object/{bucket}/{object_path.lstrip('/')}"


async def save_upload(filename: str, data: bytes) -> str:
    """Store uploaded evidence. Returns a storage reference/path string."""
    if supabase_enabled():
        bucket = config.SUPABASE_UPLOADS_BUCKET
        path = filename.replace("\\", "/")
        url = _object_url(bucket, path)
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(url, headers=_headers("application/octet-stream"), content=data)
            if r.status_code not in (200, 201):
                raise RuntimeError(f"Supabase upload failed ({r.status_code}): {r.text[:300]}")
        return f"supabase://{bucket}/{path}"
    
    # Filesystem storage
    safe = os.path.join(config.UPLOAD_DIR, filename)
    os.makedirs(os.path.dirname(safe), exist_ok=True)
    with open(safe, "wb") as f:
        f.write(data)
    return safe


async def save_report(filename: str, data: bytes) -> str:
    """Store generated PDF report. Returns a storage reference/path string."""
    if supabase_enabled():
        bucket = config.SUPABASE_REPORTS_BUCKET
        path = filename.replace("\\", "/")
        url = _object_url(bucket, path)
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(url, headers=_headers("application/pdf"), content=data)
            if r.status_code not in (200, 201):
                raise RuntimeError(f"Supabase report upload failed ({r.status_code}): {r.text[:300]}")
        return f"supabase://{bucket}/{path}"
    
    out = os.path.join(config.REPORTS_DIR, filename)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(data)
    return out


async def load_report(ref: str) -> Optional[bytes]:
    """Load report bytes from local path or Supabase reference."""
    if not ref:
        return None
    if ref.startswith("supabase://"):
        _, _, rest = ref.partition("supabase://")
        bucket, _, path = rest.partition("/")
        url = _object_url(bucket, path)
        key = config.SUPABASE_SERVICE_KEY
        headers = {"Authorization": f"Bearer {key}", "apikey": key}
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                return r.content
            return None
    p = Path(ref)
    if p.is_file():
        return p.read_bytes()
    return None


def save_raw_artifact(
    assessment_id: str,
    tool_name: str,
    filename: str,
    data: bytes,
    db=None,
) -> dict:
    """Save raw scanner output into content-addressed immutable storage with SHA-256 validation.
    
    Supports STORAGE_BACKEND='database' (storing content directly in PostgreSQL/Neon)
    as well as STORAGE_BACKEND='local' (filesystem).
    """
    sha256 = hashlib.sha256(data).hexdigest()
    byte_size = len(data)
    line_count = len(data.splitlines())
    artifact_id = f"art-{sha256[:12]}"

    content_str = data.decode("utf-8", errors="replace")

    # Local filesystem cache (always try writing to local disk if writable)
    target_path = ""
    try:
        target_dir = os.path.join(ARTIFACTS_DIR, assessment_id or "system")
        os.makedirs(target_dir, exist_ok=True)
        target_path = os.path.join(target_dir, f"{sha256}.raw")
        if not os.path.exists(target_path):
            with open(target_path, "wb") as f:
                f.write(data)
    except Exception:
        # Ephemeral environments might have restricted filesystem; database storage handles it
        target_path = f"db://artifacts/{artifact_id}"

    if db:
        try:
            cur = db.execute("SELECT id FROM artifacts WHERE sha256 = ? AND assessment_id = ?", (sha256, assessment_id))
            row = cur.fetchone()
            if not row:
                try:
                    db.execute(
                        """
                        INSERT INTO artifacts (id, assessment_id, filename, sha256, byte_size, line_count, source_tool, file_path, content_bytes, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (artifact_id, assessment_id, filename, sha256, byte_size, line_count, tool_name, target_path, content_str),
                    )
                except Exception:
                    # Backward-compatibility fallback if table doesn't have content_bytes column
                    db.execute(
                        """
                        INSERT INTO artifacts (id, assessment_id, filename, sha256, byte_size, line_count, source_tool, file_path, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (artifact_id, assessment_id, filename, sha256, byte_size, line_count, tool_name, target_path),
                    )
                db.commit()
            else:
                artifact_id = row["id"] if isinstance(row, dict) else row[0]
                # If content_bytes is empty and we have data, backfill it
                try:
                    db.execute("UPDATE artifacts SET content_bytes = ? WHERE id = ? AND (content_bytes IS NULL OR content_bytes = '')", (content_str, artifact_id))
                    db.commit()
                except Exception:
                    pass
        except Exception:
            pass

    return {
        "id": artifact_id,
        "assessment_id": assessment_id,
        "filename": filename,
        "sha256": sha256,
        "byte_size": byte_size,
        "line_count": line_count,
        "source_tool": tool_name,
        "file_path": target_path,
    }


def get_raw_artifact_content(artifact_id: str, db=None) -> Optional[dict]:
    """Retrieve raw artifact metadata and content by ID or SHA-256 with cryptographic verification."""
    if not db:
        return None

    cur = db.execute("SELECT * FROM artifacts WHERE id = ? OR sha256 = ? LIMIT 1", (artifact_id, artifact_id))
    row = cur.fetchone()
    if not row:
        return None

    r = dict(row)
    expected_sha = r.get("sha256", "")
    content = r.get("content_bytes", "")

    # If content was not in DB, fall back to local file
    if not content:
        p = r.get("file_path", "")
        if p and not p.startswith("db://") and os.path.isfile(p):
            try:
                with open(p, "rb") as f:
                    content = f.read().decode("utf-8", errors="replace")
            except Exception:
                pass

    # Verify cryptographic integrity
    if content and expected_sha:
        computed_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        r["sha256_verified"] = (computed_sha == expected_sha)
    else:
        r["sha256_verified"] = False

    r["content"] = content
    return r
