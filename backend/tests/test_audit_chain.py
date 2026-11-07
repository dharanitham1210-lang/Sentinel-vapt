import sqlite3
import pytest
from app.audit import AuditService, GENESIS_PREV_HASH, compute_entry_hash, compute_payload_hash


@pytest.fixture
def memory_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id TEXT DEFAULT 'system',
            event TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT 'system',
            target TEXT NOT NULL DEFAULT '',
            payload_hash TEXT NOT NULL DEFAULT '',
            prev_hash TEXT NOT NULL DEFAULT '',
            entry_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    yield conn
    conn.close()


def test_empty_audit_log_integrity(memory_db):
    result = AuditService.verify_integrity(memory_db)
    assert result["valid"] is True
    assert result["total_records"] == 0
    assert result["broken_at_id"] is None


def test_sequential_hash_chaining(memory_db):
    # Record 3 events
    e1 = AuditService.record(memory_db, action="CREATE_ENGAGEMENT", actor="analyst_1", target="192.168.1.10", detail={"name": "Test Lab"})
    assert e1["id"] == 1
    assert e1["prev_hash"] == GENESIS_PREV_HASH
    assert len(e1["entry_hash"]) == 64

    e2 = AuditService.record(memory_db, action="RUN_NMAP", actor="analyst_1", target="192.168.1.10", detail={"ports": [80, 443]})
    assert e2["id"] == 2
    assert e2["prev_hash"] == e1["entry_hash"]
    assert len(e2["entry_hash"]) == 64

    e3 = AuditService.record(memory_db, action="SCOPE_REJECT", actor="agent", target="8.8.8.8", detail={"reason": "Public IP"})
    assert e3["id"] == 3
    assert e3["prev_hash"] == e2["entry_hash"]

    # Verify entire chain passes
    verify_result = AuditService.verify_integrity(memory_db)
    assert verify_result["valid"] is True
    assert verify_result["total_records"] == 3
    assert verify_result["broken_at_id"] is None


def test_tamper_detection_in_payload(memory_db):
    AuditService.record(memory_db, action="TEST_ACTION_1", detail="Original detail 1")
    AuditService.record(memory_db, action="TEST_ACTION_2", detail="Original detail 2")
    AuditService.record(memory_db, action="TEST_ACTION_3", detail="Original detail 3")

    # Verify it was valid
    assert AuditService.verify_integrity(memory_db)["valid"] is True

    # Tamper with detail of record 2
    memory_db.execute("UPDATE audit_logs SET detail = 'Tampered detail 2' WHERE id = 2")
    memory_db.commit()

    tampered_result = AuditService.verify_integrity(memory_db)
    assert tampered_result["valid"] is False
    assert tampered_result["broken_at_id"] == 2
    assert "Tampered payload" in tampered_result["error_reason"]


def test_tamper_detection_in_entry_hash(memory_db):
    AuditService.record(memory_db, action="TEST_ACTION_A", detail="A")
    AuditService.record(memory_db, action="TEST_ACTION_B", detail="B")

    # Manually overwrite entry_hash
    memory_db.execute("UPDATE audit_logs SET entry_hash = 'badhash' WHERE id = 2")
    memory_db.commit()

    result = AuditService.verify_integrity(memory_db)
    assert result["valid"] is False
    assert result["broken_at_id"] == 2
    assert "Invalid entry hash" in result["error_reason"]


def test_tamper_detection_broken_chain_link(memory_db):
    AuditService.record(memory_db, action="EVENT_1", detail="1")
    AuditService.record(memory_db, action="EVENT_2", detail="2")
    AuditService.record(memory_db, action="EVENT_3", detail="3")

    # Alter prev_hash of record 3
    memory_db.execute("UPDATE audit_logs SET prev_hash = '0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff' WHERE id = 3")
    memory_db.commit()

    result = AuditService.verify_integrity(memory_db)
    assert result["valid"] is False
    assert result["broken_at_id"] == 3
    assert "Broken chain link" in result["error_reason"]

