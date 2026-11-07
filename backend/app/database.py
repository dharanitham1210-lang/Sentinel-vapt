"""Database layer: SQLite by default (local), PostgreSQL when DATABASE_URL is postgres* (production).

Safety & Integrity:
- Default/local path remains SQLite (backend/vulnpilot.db via VULNPILOT_DB/config).
- Full PostgreSQL / Neon compatibility with connection retry and pre-ping (scale-to-zero cold-start handling).
- Cryptographically chained audit logging (SHA-256 links).
- RBAC users and explicit human approvals tables.
- Idempotent schema evolution: adds missing columns without dropping tables or losing data.
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

from .config import DATABASE_URL

logger = logging.getLogger("sentinel.database")


def _is_postgres(url: str) -> bool:
    u = (url or "").strip().lower()
    return u.startswith("postgresql://") or u.startswith("postgres://")


IS_POSTGRES = _is_postgres(DATABASE_URL)

_db_path = DATABASE_URL
if not IS_POSTGRES and not os.path.isabs(_db_path):
    _db_path = str(Path(__file__).resolve().parent.parent / _db_path)


def _prepare_postgres_dsn(url: str) -> str:
    """Ensure Neon / remote Postgres connections enforce sslmode=require."""
    u = url.strip()
    # Neon and most cloud providers require sslmode
    if "sslmode=" not in u.lower() and "localhost" not in u and "127.0.0.1" not in u:
        separator = "&" if "?" in u else "?"
        u = f"{u}{separator}sslmode=require"
    return u


class _CompatCursor:
    """Cursor wrapper to accept sqlite-style '?' placeholders for PostgreSQL."""

    def __init__(self, cur, is_postgres: bool):
        self._cur = cur
        self._pg = is_postgres

    def _sql(self, sql):
        if self._pg and "?" in sql:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql, params=()):
        return self._cur.execute(self._sql(sql), params)

    def executemany(self, sql, seq_of_params):
        return self._cur.executemany(self._sql(sql), seq_of_params)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __getattr__(self, name):
        return getattr(self._cur, name)


class _CompatConn:
    def __init__(self, conn, is_postgres: bool):
        self._conn = conn
        self._pg = is_postgres

    def execute(self, sql, params=()):
        cur = self._conn.execute(self._sql(sql), params)
        return _CompatCursor(cur, self._pg)

    def _sql(self, sql):
        if self._pg and "?" in sql:
            return sql.replace("?", "%s")
        return sql

    def executescript(self, script):
        if self._pg:
            cur = self._conn.cursor()
            try:
                for stmt in (s.strip() for s in script.split(";")):
                    if stmt:
                        cur.execute(stmt)
            finally:
                cur.close()
        else:
            self._conn.executescript(script)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def cursor(self):
        return _CompatCursor(self._conn.cursor(), self._pg)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _connect_postgres_with_retry(dsn: str, max_retries: int = 4, base_delay: float = 1.0):
    """Handle Neon scale-to-zero cold starts with exponential backoff and connection pre-ping."""
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as e:
        raise RuntimeError(
            "PostgreSQL DATABASE_URL configured but psycopg is not installed. "
            "Install backend requirements (psycopg[binary]) or use local SQLite."
        ) from e

    dsn_prepared = _prepare_postgres_dsn(dsn)
    last_err = None

    for attempt in range(1, max_retries + 1):
        try:
            conn = psycopg.connect(dsn_prepared, row_factory=dict_row, autocommit=False)
            # Pre-ping to verify connection is ready
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            return conn
        except Exception as err:
            last_err = err
            if attempt < max_retries:
                wait_time = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    f"PostgreSQL connection attempt {attempt} failed (possible Neon cold start). "
                    f"Retrying in {wait_time:.1f}s... Error: {err}"
                )
                time.sleep(wait_time)
            else:
                logger.error(f"PostgreSQL connection failed after {max_retries} attempts: {err}")
                raise last_err


def get_conn():
    if IS_POSTGRES:
        conn = _connect_postgres_with_retry(DATABASE_URL)
        return _CompatConn(conn, True)

    conn = sqlite3.connect(_db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return _CompatConn(conn, False)


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT NOT NULL,
    allowed_targets TEXT NOT NULL DEFAULT '[]',
    allowed_cidrs TEXT NOT NULL DEFAULT '[]',
    allowed_hostnames TEXT NOT NULL DEFAULT '[]',
    exclusions TEXT NOT NULL DEFAULT '[]',
    allowed_ports TEXT NOT NULL DEFAULT '[]',
    allowed_tools TEXT NOT NULL DEFAULT '[]',
    rate_limit_rps REAL DEFAULT NULL,
    time_window_start TEXT DEFAULT NULL,
    time_window_end TEXT DEFAULT NULL,
    rules_of_engagement TEXT NOT NULL DEFAULT '',
    auth_doc_hash TEXT NOT NULL DEFAULT '',
    authorized INTEGER NOT NULL DEFAULT 0,
    auth_statement TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    plan_json TEXT NOT NULL DEFAULT '[]',
    approval_status TEXT NOT NULL DEFAULT 'not_requested',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    demo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    cvss REAL NOT NULL DEFAULT 0.0,
    asset TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    parameter TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'import',
    source_filename TEXT NOT NULL DEFAULT '',
    source_file_sha256 TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    remediation TEXT NOT NULL DEFAULT '',
    "references" TEXT NOT NULL DEFAULT '[]',
    cwe TEXT NOT NULL DEFAULT '',
    cve TEXT NOT NULL DEFAULT '',
    dedup_key TEXT NOT NULL DEFAULT '',
    risk_score REAL NOT NULL DEFAULT 0.0,
    risk_reason TEXT NOT NULL DEFAULT '',
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT DEFAULT 'system',
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT 'system',
    target TEXT NOT NULL DEFAULT '',
    payload_hash TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    command TEXT NOT NULL DEFAULT '',
    stdout TEXT NOT NULL DEFAULT '',
    stderr TEXT NOT NULL DEFAULT '',
    findings_imported INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    request_type TEXT NOT NULL DEFAULT 'action',
    requester TEXT NOT NULL,
    approver TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    target TEXT NOT NULL,
    tool TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL DEFAULT '',
    params_json TEXT NOT NULL DEFAULT '{}',
    justification TEXT NOT NULL DEFAULT '',
    lab_confirmed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    decided_at TEXT DEFAULT '',
    outcome_notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL DEFAULT 0,
    line_count INTEGER NOT NULL DEFAULT 0,
    source_tool TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    content_bytes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

POSTGRES_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS assessments (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target TEXT NOT NULL,
        scope TEXT NOT NULL,
        allowed_targets TEXT NOT NULL DEFAULT '[]',
        allowed_cidrs TEXT NOT NULL DEFAULT '[]',
        allowed_hostnames TEXT NOT NULL DEFAULT '[]',
        exclusions TEXT NOT NULL DEFAULT '[]',
        allowed_ports TEXT NOT NULL DEFAULT '[]',
        allowed_tools TEXT NOT NULL DEFAULT '[]',
        rate_limit_rps REAL DEFAULT NULL,
        time_window_start TEXT DEFAULT NULL,
        time_window_end TEXT DEFAULT NULL,
        rules_of_engagement TEXT NOT NULL DEFAULT '',
        auth_doc_hash TEXT NOT NULL DEFAULT '',
        authorized INTEGER NOT NULL DEFAULT 0,
        auth_statement TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'draft',
        plan_json TEXT NOT NULL DEFAULT '[]',
        approval_status TEXT NOT NULL DEFAULT 'not_requested',
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        demo INTEGER NOT NULL DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL DEFAULT 0.5,
        cvss REAL NOT NULL DEFAULT 0.0,
        asset TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        parameter TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'import',
        source_filename TEXT NOT NULL DEFAULT '',
        source_file_sha256 TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '{}',
        remediation TEXT NOT NULL DEFAULT '',
        "references" TEXT NOT NULL DEFAULT '[]',
        cwe TEXT NOT NULL DEFAULT '',
        cve TEXT NOT NULL DEFAULT '',
        dedup_key TEXT NOT NULL DEFAULT '',
        risk_score REAL NOT NULL DEFAULT 0.0,
        risk_reason TEXT NOT NULL DEFAULT '',
        is_demo INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        assessment_id TEXT DEFAULT 'system',
        event TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        actor TEXT NOT NULL DEFAULT 'system',
        target TEXT NOT NULL DEFAULT '',
        payload_hash TEXT NOT NULL DEFAULT '',
        prev_hash TEXT NOT NULL DEFAULT '',
        entry_hash TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_runs (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        tool TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        command TEXT NOT NULL DEFAULT '',
        stdout TEXT NOT NULL DEFAULT '',
        stderr TEXT NOT NULL DEFAULT '',
        findings_imported INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TEXT DEFAULT ''
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        request_type TEXT NOT NULL DEFAULT 'action',
        requester TEXT NOT NULL,
        approver TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        target TEXT NOT NULL,
        tool TEXT NOT NULL DEFAULT '',
        command TEXT NOT NULL DEFAULT '',
        params_json TEXT NOT NULL DEFAULT '{}',
        justification TEXT NOT NULL DEFAULT '',
        lab_confirmed INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        decided_at TEXT DEFAULT '',
        outcome_notes TEXT DEFAULT ''
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        byte_size INTEGER NOT NULL DEFAULT 0,
        line_count INTEGER NOT NULL DEFAULT 0,
        source_tool TEXT NOT NULL DEFAULT '',
        file_path TEXT NOT NULL DEFAULT '',
        content_bytes TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
]


def _ensure_sqlite_columns(conn):
    """Idempotently add any newly declared columns to SQLite tables if upgrading existing DB."""
    cur = conn.cursor()
    # Check audit_logs columns
    cur.execute("PRAGMA table_info(audit_logs)")
    existing_audit_cols = {row[1] for row in cur.fetchall()}
    audit_cols_to_add = [
        ("actor", "TEXT NOT NULL DEFAULT 'system'"),
        ("target", "TEXT NOT NULL DEFAULT ''"),
        ("payload_hash", "TEXT NOT NULL DEFAULT ''"),
        ("prev_hash", "TEXT NOT NULL DEFAULT ''"),
        ("entry_hash", "TEXT NOT NULL DEFAULT ''"),
    ]
    for col_name, col_def in audit_cols_to_add:
        if col_name not in existing_audit_cols:
            try:
                conn.execute(f"ALTER TABLE audit_logs ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass

    # Check artifacts columns
    cur.execute("PRAGMA table_info(artifacts)")
    existing_artifact_cols = {row[1] for row in cur.fetchall()}
    if "content_bytes" not in existing_artifact_cols:
        try:
            conn.execute("ALTER TABLE artifacts ADD COLUMN content_bytes TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

    # Check assessments columns
    cur.execute("PRAGMA table_info(assessments)")
    existing_assessment_cols = {row[1] for row in cur.fetchall()}
    assessment_cols_to_add = [
        ("allowed_cidrs", "TEXT NOT NULL DEFAULT '[]'"),
        ("allowed_hostnames", "TEXT NOT NULL DEFAULT '[]'"),
        ("exclusions", "TEXT NOT NULL DEFAULT '[]'"),
        ("allowed_ports", "TEXT NOT NULL DEFAULT '[]'"),
        ("allowed_tools", "TEXT NOT NULL DEFAULT '[]'"),
        ("rate_limit_rps", "REAL DEFAULT NULL"),
        ("time_window_start", "TEXT DEFAULT NULL"),
        ("time_window_end", "TEXT DEFAULT NULL"),
        ("rules_of_engagement", "TEXT NOT NULL DEFAULT ''"),
        ("auth_doc_hash", "TEXT NOT NULL DEFAULT ''"),
    ]
    for col_name, col_def in assessment_cols_to_add:
        if col_name not in existing_assessment_cols:
            try:
                conn.execute(f"ALTER TABLE assessments ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass


def _ensure_postgres_columns(conn):
    """Idempotently verify columns exist in PostgreSQL tables."""
    try:
        conn.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS content_bytes TEXT NOT NULL DEFAULT ''")
        conn.commit()
    except Exception:
        pass


def init_db():
    conn = get_conn()
    try:
        if not IS_POSTGRES:
            conn.executescript(SQLITE_SCHEMA)
            _ensure_sqlite_columns(conn)
            conn.commit()

            # Initialize default users & audit chain
            from .auth import init_default_users
            from .audit import AuditService
            init_default_users(conn)
            AuditService.backfill_legacy_if_needed(conn)
        else:
            # PostgreSQL creation
            for stmt in POSTGRES_SCHEMA:
                s = stmt.strip()
                if s:
                    try:
                        conn.execute(s)
                        conn.commit()
                    except Exception as e:
                        logger.warning(f"Error applying Postgres schema statement: {e}")

            _ensure_postgres_columns(conn)

            # Initialize default users & audit chain
            from .auth import init_default_users
            from .audit import AuditService
            init_default_users(conn)
            AuditService.backfill_legacy_if_needed(conn)
    finally:
        conn.close()


def log_audit(conn, assessment_id, event, detail="", actor="system", target=""):
    """Record an audit log entry via AuditService (cryptographically chained)."""
    from .audit import AuditService
    return AuditService.record(
        conn,
        action=event,
        assessment_id=assessment_id or "system",
        actor=actor or "system",
        target=target or "",
        detail=detail,
        commit=True,
    )


def row_to_dict(r):
    if r is None:
        return None
    if isinstance(r, dict):
        return dict(r)
    return dict(r)
