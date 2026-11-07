# ADR 0003: Authentication, RBAC, and Memory-Hard Password Security

## Status
Accepted

## Context
A production security platform requires strict role-based access control (Admin, Lead Analyst, Analyst, Viewer) to prevent unauthorized execution of network scanners or modification of engagement boundaries. Furthermore, credentials must be protected against brute-force and hardware acceleration attacks using memory-hard hashing.

## Decision
We implemented `auth.py` (`backend/app/auth.py`) with:
1. **Memory-Hard Hashing:** Standard library `hashlib.scrypt` with $N=16384, r=8, p=1$ and 16-byte cryptographically random salt per user. Password verification uses `hmac.compare_digest` to defend against timing side-channel attacks.
2. **Role Hierarchy:**
   - `ADMIN` (Level 40): System configuration, secrets, integrations, platform audit.
   - `LEAD_ANALYST` (Level 30): Engagement creation, scope modifications, action approvals, report publication sign-off.
   - `ANALYST` (Level 20): Scan orchestration, finding triage, requesting human approvals, evidence note taking.
   - `VIEWER` (Level 10): Read-only access to dashboards, verified findings, approved reports, and audit logs.
3. **Session Tokens:** HMAC-SHA256 signed bearer tokens containing user ID, username, role, timestamp, expiration, and random nonce.
4. **FastAPI Dependency Injection:** `require_role(min_role)` decorators cleanly enforce endpoint-level RBAC.

## Consequences
- Defends against offline cracking via high memory cost.
- Clean separation of duties aligned with enterprise consulting practices.

