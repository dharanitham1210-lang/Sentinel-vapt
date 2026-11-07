import sqlite3
import pytest
from fastapi import HTTPException

from app.auth import (
    Role,
    ROLE_HIERARCHY,
    create_token,
    hash_password,
    init_default_users,
    require_role,
    verify_password,
    verify_token,
    UserProfile,
)


def test_password_hashing_and_verification():
    pw = "SuperSecretPentest2026!"
    h_hex, s_hex = hash_password(pw)
    assert len(h_hex) == 128  # 64-byte scrypt output in hex
    assert len(s_hex) == 32   # 16-byte salt in hex

    # Correct password succeeds
    assert verify_password(pw, h_hex, s_hex) is True

    # Incorrect password fails
    assert verify_password("WrongPassword123", h_hex, s_hex) is False

    # Different salts yield different hashes
    h2_hex, s2_hex = hash_password(pw)
    assert s_hex != s2_hex
    assert h_hex != h2_hex
    assert verify_password(pw, h2_hex, s2_hex) is True


def test_token_creation_and_tamper_detection():
    token = create_token("usr-123", "alice_lead", Role.LEAD_ANALYST.value)
    payload = verify_token(token)
    assert payload["uid"] == "usr-123"
    assert payload["sub"] == "alice_lead"
    assert payload["role"] == "lead_analyst"

    # Tampered token payload
    parts = token.split(".")
    tampered_token = f"dGFtcGVyZWQ.{parts[1]}"
    with pytest.raises(HTTPException) as exc:
        verify_token(tampered_token)
    assert exc.value.status_code == 401


def test_role_hierarchy_permissions():
    assert ROLE_HIERARCHY[Role.ADMIN] > ROLE_HIERARCHY[Role.LEAD_ANALYST]
    assert ROLE_HIERARCHY[Role.LEAD_ANALYST] > ROLE_HIERARCHY[Role.ANALYST]
    assert ROLE_HIERARCHY[Role.ANALYST] > ROLE_HIERARCHY[Role.VIEWER]

    admin_user = UserProfile(id="1", username="admin", role=Role.ADMIN, is_active=True)
    analyst_user = UserProfile(id="2", username="analyst", role=Role.ANALYST, is_active=True)
    viewer_user = UserProfile(id="3", username="viewer", role=Role.VIEWER, is_active=True)

    # Lead analyst check
    lead_dep = require_role(Role.LEAD_ANALYST)
    assert lead_dep(admin_user) == admin_user

    with pytest.raises(HTTPException) as exc1:
        lead_dep(analyst_user)
    assert exc1.value.status_code == 403

    with pytest.raises(HTTPException) as exc2:
        lead_dep(viewer_user)
    assert exc2.value.status_code == 403


def test_default_users_seeded():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    init_default_users(conn)

    cur = conn.execute("SELECT username, role, password_hash, salt FROM users ORDER BY username ASC")
    users = {r["username"]: r for r in cur.fetchall()}
    assert "admin" in users
    assert users["admin"]["role"] == "admin"
    assert verify_password("Admin123!Sentinel", users["admin"]["password_hash"], users["admin"]["salt"]) is True

    assert "lead_analyst" in users
    assert users["lead_analyst"]["role"] == "lead_analyst"
    conn.close()

