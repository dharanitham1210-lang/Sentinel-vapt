"""Cryptographically Chained Audit Log Service.

Every action in SentinelVAPT is recorded in an append-only, hash-chained ledger.
Each record stores:
- id: Sequential integer identifier
- assessment_id: Associated assessment or 'system'
- timestamp: ISO 8601 UTC timestamp
- actor: User or automated subsystem that performed the action
- action: Standardized action verb (e.g., 'SCOPE_REJECT', 'APPROVE_ACTION', 'RUN_SCAN')
- target: Target asset, host, or artifact ID
- payload_hash: SHA-256 hash of the JSON-serialized payload/details
- prev_hash: SHA-256 hash of the immediate predecessor record (or 64 zeros for genesis)
- entry_hash: SHA-256(f"{id}|{timestamp}|{assessment_id}|{actor}|{action}|{target}|{payload_hash}|{prev_hash}")

Provides a deterministic verify_audit_integrity() function that traverses the chain,
recalculates hashes, and pinpoints any modification, deletion, or insertion.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

GENESIS_PREV_HASH = "0" * 64


def compute_payload_hash(payload: Any) -> str:
    """Compute SHA-256 hash of an arbitrary payload formatted as deterministic JSON."""
    if payload is None:
        payload = {}
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
            raw = json.dumps(parsed, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        except Exception:
            raw = payload.encode("utf-8")
    else:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def compute_entry_hash(
    record_id: int,
    timestamp: str,
    assessment_id: str,
    actor: str,
    action: str,
    target: str,
    payload_hash: str,
    prev_hash: str,
) -> str:
    """Compute SHA-256 hash chaining all record fields."""
    content = f"{record_id}|{timestamp}|{assessment_id}|{actor}|{action}|{target}|{payload_hash}|{prev_hash}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class AuditService:
    @staticmethod
    def backfill_legacy_if_needed(db):
        """Idempotently chain any legacy records that were inserted without hash links."""
        cur = db.execute("SELECT id, entry_hash FROM audit_logs WHERE entry_hash = '' OR entry_hash IS NULL ORDER BY id ASC")
        unhashed = cur.fetchall()
        if not unhashed:
            return

        cur_all = db.execute(
            "SELECT id, assessment_id, event, detail, actor, target, payload_hash, prev_hash, entry_hash, created_at "
            "FROM audit_logs ORDER BY id ASC"
        )
        rows = cur_all.fetchall()
        prev = GENESIS_PREV_HASH
        for r in rows:
            rid = r["id"] if isinstance(r, dict) else r[0]
            aid = (r["assessment_id"] if isinstance(r, dict) else r[1]) or "system"
            ev = r["event"] if isinstance(r, dict) else r[2]
            detail = (r["detail"] if isinstance(r, dict) else r[3]) or ""
            actor = (r["actor"] if isinstance(r, dict) else r[4]) or "system"
            tgt = (r["target"] if isinstance(r, dict) else r[5]) or ""
            ts = (r["created_at"] if isinstance(r, dict) else r[9]) or datetime.datetime.now(datetime.timezone.utc).isoformat()

            ph = compute_payload_hash(detail)
            eh = compute_entry_hash(rid, ts, aid, actor, ev, tgt, ph, prev)
            db.execute(
                "UPDATE audit_logs SET actor=?, target=?, payload_hash=?, prev_hash=?, entry_hash=? WHERE id=?",
                (actor, tgt, ph, prev, eh, rid),
            )
            prev = eh
        db.commit()

    @staticmethod
    def get_latest_hash(db) -> str:
        """Fetch the entry_hash of the most recent audit record, or GENESIS_PREV_HASH if empty."""
        cur = db.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if row:
            if isinstance(row, dict):
                h = row.get("entry_hash")
            else:
                h = row[0]
            if h and len(h) == 64:
                return h
        return GENESIS_PREV_HASH

    @classmethod
    def record(
        cls,
        db,
        action: str,
        assessment_id: str = "system",
        actor: str = "system",
        target: str = "",
        detail: Any = None,
        commit: bool = True,
    ) -> Dict[str, Any]:
        """Record an immutable, hash-chained audit log entry."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload_hash = compute_payload_hash(detail)
        prev_hash = cls.get_latest_hash(db)

        if not isinstance(detail, str):
            detail_str = json.dumps(detail, sort_keys=True, separators=(",", ":"), default=str)
        else:
            detail_str = detail

        # Insert record with placeholder entry_hash to obtain row id
        cur = db.execute(
            """
            INSERT INTO audit_logs (
                assessment_id, event, detail, actor, target,
                payload_hash, prev_hash, entry_hash, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id or "system",
                action,
                detail_str or "",
                actor or "system",
                target or "",
                payload_hash,
                prev_hash,
                "PENDING",
                timestamp,
            ),
        )

        record_id = cur.lastrowid
        # In case driver does not populate lastrowid (e.g. some Postgres wrappers)
        if not record_id:
            cur2 = db.execute("SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1")
            r2 = cur2.fetchone()
            record_id = r2["id"] if isinstance(r2, dict) else r2[0]

        entry_hash = compute_entry_hash(
            record_id=int(record_id),
            timestamp=timestamp,
            assessment_id=assessment_id or "system",
            actor=actor or "system",
            action=action,
            target=target or "",
            payload_hash=payload_hash,
            prev_hash=prev_hash,
        )

        db.execute(
            "UPDATE audit_logs SET entry_hash = ? WHERE id = ?",
            (entry_hash, record_id),
        )

        if commit:
            db.commit()

        return {
            "id": record_id,
            "assessment_id": assessment_id,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "target": target,
            "payload_hash": payload_hash,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }

    @staticmethod
    def verify_integrity(db) -> Dict[str, Any]:
        """Verify the cryptographic integrity of the entire audit log chain.

        Returns:
            {
                "valid": bool,
                "total_records": int,
                "broken_at_id": Optional[int],
                "error_reason": Optional[str],
                "verified_at": str
            }
        """
        cur = db.execute(
            """
            SELECT id, assessment_id, event, detail, actor, target,
                   payload_hash, prev_hash, entry_hash, created_at
            FROM audit_logs
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
        total = len(rows)

        if total == 0:
            return {
                "valid": True,
                "total_records": 0,
                "broken_at_id": None,
                "error_reason": None,
                "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

        expected_prev_hash = GENESIS_PREV_HASH

        for idx, row in enumerate(rows):
            if isinstance(row, dict):
                r = row
            else:
                r = {
                    "id": row[0],
                    "assessment_id": row[1],
                    "event": row[2],
                    "detail": row[3],
                    "actor": row[4],
                    "target": row[5],
                    "payload_hash": row[6],
                    "prev_hash": row[7],
                    "entry_hash": row[8],
                    "created_at": row[9],
                }

            row_id = r["id"]
            row_prev_hash = r.get("prev_hash") or ""
            row_entry_hash = r.get("entry_hash") or ""
            row_payload_hash = r.get("payload_hash") or ""
            row_detail = r.get("detail") or ""

            # Check 1: prev_hash must link to preceding record's entry_hash
            if row_prev_hash != expected_prev_hash:
                return {
                    "valid": False,
                    "total_records": total,
                    "broken_at_id": row_id,
                    "error_reason": f"Broken chain link at ID {row_id}: expected prev_hash {expected_prev_hash}, found {row_prev_hash}",
                    "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }

            # Check 2: recalculate payload hash from detail string
            computed_ph = compute_payload_hash(row_detail)
            if row_payload_hash and computed_ph != row_payload_hash:
                return {
                    "valid": False,
                    "total_records": total,
                    "broken_at_id": row_id,
                    "error_reason": f"Tampered payload at ID {row_id}: computed payload_hash {computed_ph} != recorded {row_payload_hash}",
                    "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }

            # Check 3: recalculate entry hash
            computed_eh = compute_entry_hash(
                record_id=row_id,
                timestamp=r["created_at"],
                assessment_id=r.get("assessment_id") or "system",
                actor=r.get("actor") or "system",
                action=r["event"],
                target=r.get("target") or "",
                payload_hash=row_payload_hash or computed_ph,
                prev_hash=row_prev_hash,
            )

            if computed_eh != row_entry_hash:
                return {
                    "valid": False,
                    "total_records": total,
                    "broken_at_id": row_id,
                    "error_reason": f"Invalid entry hash at ID {row_id}: computed {computed_eh} != recorded {row_entry_hash}",
                    "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }

            expected_prev_hash = row_entry_hash

        return {
            "valid": True,
            "total_records": total,
            "broken_at_id": None,
            "error_reason": None,
            "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
