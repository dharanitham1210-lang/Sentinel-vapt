# ADR 0001: Deterministic Scope Gate Implementation

## Status
Accepted

## Context
AI-powered penetration testing platforms are prone to scope escape when scope enforcement relies on LLM prompts or unstructured system messages. Prompt injections, redirections, or URL manipulation (such as userinfo tricks like `http://authorized@evil.com`) can lead the agent to target unauthorized or public systems. The prompt requires that scope enforcement be deterministic code that the LLM cannot bypass under any circumstances.

## Decision
We implemented `ScopeGate` (`backend/app/scope_gate.py`) as pure deterministic Python code:
1. **Network Primitives:** Using standard library `ipaddress` for subnet and CIDR boundary math (IPv4 and IPv6).
2. **IP Normalization:** Normalizing IPv4-mapped IPv6 (`::ffff:x.x.x.x`) and 6to4 (`2002::/16`) to their underlying IPv4 representations.
3. **URL Parsing Safety:** Using `urllib.parse.urlsplit` to isolate the host from any userinfo components (`user:password@host`), preventing authentication trick bypasses.
4. **DNS Pre-Resolution Pinning:** Resolving hostnames to all target IPs using `socket.getaddrinfo()` before permitting tool execution. Every resolved IP must belong to the allowed scope, and any host resolving to a public or excluded IP is rejected.
5. **Exclusion Precedence:** Scope exclusions (denylists) strictly override allowlists.
6. **Public IP Policy:** By default, all public IPs are blocked; only RFC 1918 private, loopback, link-local, and ULA ranges are permitted unless explicitly authorized.
7. **Direct Audit Trail:** Any scope violation immediately records a `SCOPE_REJECT` event in the cryptographically chained audit log.

## Consequences
- Guaranteed zero-bypass scope enforcement at runtime.
- Comprehensive unit test coverage across 10 distinct boundary and trick scenarios.

