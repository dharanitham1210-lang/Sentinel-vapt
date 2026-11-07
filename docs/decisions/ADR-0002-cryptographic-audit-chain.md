# ADR 0002: Cryptographically Chained Audit Log Architecture

## Status
Accepted

## Context
Non-negotiable rule 8 mandates that every action within SentinelVAPT be attributable via an append-only, hash-chained audit log where each entry cryptographically commits to the SHA-256 hash of its immediate predecessor. The system must also provide an automated, tamper-detecting `verify_audit_integrity()` function.

## Decision
We implemented `AuditService` (`backend/app/audit.py`) with the following characteristics:
1. **Ledger Schema:** Each audit record contains:
   - `id`: Monotonically increasing primary key
   - `assessment_id`: Associated assessment or `system`
   - `timestamp`: UTC ISO-8601 timestamp
   - `actor`: User profile identifier or automated subsystem (`system`, `agent`)
   - `action`: Standardized audit verb (e.g. `SCOPE_REJECT`, `RUN_SCAN`, `APPROVE_ACTION`)
   - `target`: Scoped IP, hostname, or artifact reference
   - `payload_hash`: Deterministic SHA-256 of sorted-key JSON payload
   - `prev_hash`: SHA-256 hash of record $N-1$ (or 64 zeros for genesis)
   - `entry_hash`: $\text{SHA-256}(id \parallel timestamp \parallel assessment\_id \parallel actor \parallel action \parallel target \parallel payload\_hash \parallel prev\_hash)$
2. **Integrity Verifier:** The `verify_integrity()` algorithm iterates sequentially over all rows in $O(N)$ time, recomputing each payload hash, confirming pointer alignment (`prev_hash` $\equiv entry\_hash_{N-1}$), and re-evaluating `entry_hash`. Any modification to an old payload or sequence instantly invalidates all downstream hashes and reports `broken_at_id`.
3. **Idempotent Migration:** `backfill_legacy_if_needed()` ensures existing records in previously unhashed databases are upgraded without data loss.

## Consequences
- Immutable, tamper-evident audit trail suitable for regulatory and legal VAPT evidentiary standards.
- Zero external cryptographic dependencies (built on standard library `hashlib`).

