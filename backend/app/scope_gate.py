"""Scope Gate — Deterministic, Zero-LLM Scope Enforcement Engine.

Non-Negotiable Rule:
Scope enforcement is DETERMINISTIC CODE, not an LLM decision.
Every tool invocation, URL fetch, or target registration passes through this Scope Gate.
Out-of-scope = hard reject + audit log entry. The LLM can never bypass it.

Protections:
1. IP literals and CIDRs (IPv4 and IPv6) with strict boundary containment
2. IPv4-mapped IPv6 (::ffff:x.x.x.x) and tunneling normalization
3. URL userinfo trick protection (http://user:pass@host)
4. DNS rebinding protection (pre-resolution of all hostnames to IPs before check)
5. Exclusion lists (denylist takes precedence over allowlist)
6. Default public IP blocking (only RFC 1918, RFC 4193, loopback permitted unless lab override)
7. Tool, port, rate limit, and time window validation
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import config

# Standard private and lab ranges
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]
LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]
ULA_NETWORKS = [
    ipaddress.ip_network("fc00::/7"),
]

ALLOWED_LAB_SUFFIXES = (
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".intranet",
    ".lab",
    ".test",
    ".corp",
    ".example",
    ".invalid",
)
ALLOWED_LOCAL_HOSTNAMES = {
    "localhost",
    "host.docker.internal",
    "host.containers.internal",
}

HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-_]{1,63}(?<!-)(\.[A-Za-z0-9-_]{1,63})*\.?$"
)


class ScopeViolationError(ValueError):
    """Raised when a target or action violates engagement scope rules."""

    def __init__(self, message: str, rule: str = "SCOPE_VIOLATION", target: str = ""):
        super().__init__(message)
        self.message = message
        self.rule = rule
        self.target = target


def normalize_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1) to pure IPv4."""
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None:
            return ip_obj.ipv4_mapped
        # Check 6to4 (2002::/16)
        if ip_obj in ipaddress.ip_network("2002::/16"):
            # Extract 32 bits after prefix
            ipv4_int = (int(ip_obj) >> 80) & 0xFFFFFFFF
            return ipaddress.IPv4Address(ipv4_int)
    return ip_obj


def is_private_ip(ip_str_or_obj: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Determine whether an IP address belongs to RFC 1918, Loopback, Link-Local, or ULA."""
    try:
        if isinstance(ip_str_or_obj, str):
            ip = ipaddress.ip_address(ip_str_or_obj.strip())
        else:
            ip = ip_str_or_obj
    except ValueError:
        return False

    ip = normalize_ip(ip)

    if ip.is_loopback or ip.is_link_local or ip.is_private:
        return True

    # Explicit check against ULA and RFC 1918
    for net in RFC1918_NETWORKS + LOOPBACK_NETWORKS + LINK_LOCAL_NETWORKS + ULA_NETWORKS:
        if ip in net:
            return True

    return False


def extract_host_and_port(raw: str) -> Tuple[str, Optional[int]]:
    """Cleanly parse URL or host:port string without vulnerability to userinfo or path confusion.

    Examples:
    - '192.168.1.1' -> ('192.168.1.1', None)
    - '192.168.1.1:8080' -> ('192.168.1.1', 8080)
    - 'http://user:pass@192.168.1.1:8080/test' -> ('192.168.1.1', 8080)
    - 'http://evil.com@192.168.1.1' -> hostname is 192.168.1.1, userinfo is evil.com
    - '[::1]:8443' -> ('::1', 8443)
    """
    raw = (raw or "").strip()
    if not raw:
        raise ScopeViolationError("Target string cannot be empty", rule="EMPTY_TARGET")

    # If scheme missing, prepend placeholder to allow standard URL parsing
    url_to_parse = raw if "://" in raw else f"tcp://{raw}"

    try:
        parsed = urllib.parse.urlsplit(url_to_parse)
    except Exception as e:
        raise ScopeViolationError(f"Malformed target URL/host: {e}", rule="MALFORMED_URL", target=raw)

    hostname = parsed.hostname
    port = parsed.port

    if not hostname:
        # Fallback for bare IPv6 or tricky strings
        h = raw.split("/")[0].split("?")[0].split("#")[0]
        if "@" in h:
            h = h.split("@")[-1]
        if h.startswith("[") and "]" in h:
            hostname = h.split("]")[0].lstrip("[")
        else:
            hostname = h.split(":")[0]

    if not hostname:
        raise ScopeViolationError("Could not resolve valid host from target", rule="INVALID_HOST", target=raw)

    return hostname.strip().rstrip(".").lower(), port


@dataclass
class EngagementScope:
    """Deterministic Scope Specification for an Engagement."""
    allowed_cidrs: List[str] = field(default_factory=list)
    allowed_hostnames: List[str] = field(default_factory=list)
    allowed_urls: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)  # Denylist (IPs, CIDRs, hostnames)
    allowed_ports: List[int] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    rate_limit_rps: Optional[float] = None
    time_window_start: Optional[datetime.time] = None
    time_window_end: Optional[datetime.time] = None
    allow_public_ips: bool = False  # Strict default: public internet IPs are forbidden

    # Parsed internal structures
    _parsed_allowed_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list, init=False, repr=False
    )
    _parsed_excluded_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list, init=False, repr=False
    )
    _parsed_excluded_ips: Set[str] = field(default_factory=set, init=False, repr=False)
    _parsed_excluded_hosts: Set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self):
        self._parsed_allowed_networks = []
        for cidr in self.allowed_cidrs:
            c = cidr.strip()
            if c:
                try:
                    self._parsed_allowed_networks.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass

        self._parsed_excluded_networks = []
        self._parsed_excluded_ips = set()
        self._parsed_excluded_hosts = set()

        for exc in self.exclusions:
            e = exc.strip().lower()
            if not e:
                continue
            if "/" in e:
                try:
                    self._parsed_excluded_networks.append(ipaddress.ip_network(e, strict=False))
                    continue
                except ValueError:
                    pass
            try:
                ip_obj = ipaddress.ip_address(e)
                norm = normalize_ip(ip_obj)
                self._parsed_excluded_ips.add(str(norm))
            except ValueError:
                self._parsed_excluded_hosts.add(e)


class ScopeGate:
    """Enforces deterministic scope boundaries before any tool execution or target ingestion."""

    def __init__(self, scope: EngagementScope, audit_logger=None, db=None, assessment_id: str = "system"):
        self.scope = scope
        self.audit_logger = audit_logger
        self.db = db
        self.assessment_id = assessment_id

    def _log_violation(self, target: str, reason: str, rule: str, actor: str = "system"):
        """Record scope rejection directly to the audit log."""
        if self.audit_logger and self.db:
            try:
                self.audit_logger.record(
                    self.db,
                    action="SCOPE_REJECT",
                    assessment_id=self.assessment_id,
                    actor=actor,
                    target=target,
                    detail={"reason": reason, "rule": rule},
                )
            except Exception:
                pass

    def check_target(self, raw_target: str, port: Optional[int] = None, actor: str = "system") -> Dict[str, Any]:
        """Validate target against scope rules.

        Returns:
            {"ok": True, "target": host, "port": port, "reason": "Target in scope"}
            OR raises ScopeViolationError (or returns dict with ok=False).
        """
        try:
            host, extracted_port = extract_host_and_port(raw_target)
        except ScopeViolationError as sve:
            self._log_violation(raw_target, sve.message, sve.rule, actor=actor)
            return {"ok": False, "target": raw_target, "reason": sve.message, "rule": sve.rule}

        effective_port = port if port is not None else extracted_port

        # 1. Check Port Allowlist if specified
        if effective_port is not None and self.scope.allowed_ports:
            if effective_port not in self.scope.allowed_ports:
                msg = f"Port {effective_port} is not permitted by engagement scope (allowed: {self.scope.allowed_ports})"
                self._log_violation(f"{host}:{effective_port}", msg, "PORT_OUT_OF_SCOPE", actor=actor)
                return {"ok": False, "target": f"{host}:{effective_port}", "reason": msg, "rule": "PORT_OUT_OF_SCOPE"}

        # 2. Check Exclusions by Hostname
        if host in self.scope._parsed_excluded_hosts:
            msg = f"Hostname {host} is explicitly excluded in scope denylist."
            self._log_violation(host, msg, "EXCLUDED_HOST", actor=actor)
            return {"ok": False, "target": host, "reason": msg, "rule": "EXCLUDED_HOST"}

        # 3. Check if target is an IP literal
        ip_obj = None
        try:
            raw_ip = ipaddress.ip_address(host)
            ip_obj = normalize_ip(raw_ip)
        except ValueError:
            pass

        if ip_obj is not None:
            norm_ip_str = str(ip_obj)

            # 3a. Check IP Exclusions
            if norm_ip_str in self.scope._parsed_excluded_ips:
                msg = f"IP address {norm_ip_str} is explicitly in scope exclusion list."
                self._log_violation(norm_ip_str, msg, "EXCLUDED_IP", actor=actor)
                return {"ok": False, "target": norm_ip_str, "reason": msg, "rule": "EXCLUDED_IP"}

            for exc_net in self.scope._parsed_excluded_networks:
                if ip_obj in exc_net:
                    msg = f"IP {norm_ip_str} belongs to excluded CIDR {exc_net}."
                    self._log_violation(norm_ip_str, msg, "EXCLUDED_CIDR", actor=actor)
                    return {"ok": False, "target": norm_ip_str, "reason": msg, "rule": "EXCLUDED_CIDR"}

            # 3b. Check Public IP Policy
            is_priv = is_private_ip(ip_obj)
            if not is_priv and not self.scope.allow_public_ips:
                msg = f"Public IP {norm_ip_str} blocked: Public target scanning is forbidden by default."
                self._log_violation(norm_ip_str, msg, "PUBLIC_IP_BLOCKED", actor=actor)
                return {"ok": False, "target": norm_ip_str, "reason": msg, "rule": "PUBLIC_IP_BLOCKED"}

            # In CLOUD_MODE, private/loopback targets must be explicitly allowlisted
            if config.CLOUD_MODE and is_priv:
                has_explicit_cidr = self.scope._parsed_allowed_networks and any(ip_obj in net for net in self.scope._parsed_allowed_networks)
                has_explicit_host = norm_ip_str in self.scope.allowed_hostnames
                if not has_explicit_cidr and not has_explicit_host:
                    msg = (
                        f"Private/loopback target {norm_ip_str} blocked: In CLOUD_MODE, private targets must be "
                        "explicitly allowlisted in engagement scope. Note: 127.0.0.1 in cloud refers to the backend container itself."
                    )
                    self._log_violation(norm_ip_str, msg, "CLOUD_PRIVATE_NOT_ALLOWLISTED", actor=actor)
                    return {"ok": False, "target": norm_ip_str, "reason": msg, "rule": "CLOUD_PRIVATE_NOT_ALLOWLISTED"}

            # 3c. Check Allowed CIDRs
            if self.scope._parsed_allowed_networks:
                in_allowed = any(ip_obj in net for net in self.scope._parsed_allowed_networks)
                if not in_allowed:
                    msg = f"IP {norm_ip_str} is not inside any allowed engagement CIDRs."
                    self._log_violation(norm_ip_str, msg, "CIDR_OUT_OF_SCOPE", actor=actor)
                    return {"ok": False, "target": norm_ip_str, "reason": msg, "rule": "CIDR_OUT_OF_SCOPE"}

            return {"ok": True, "target": norm_ip_str, "port": effective_port, "reason": "Authorized IP in scope"}

        # 4. Hostname evaluation
        # Check Allowed Localhost Names
        is_local_name = host in ALLOWED_LOCAL_HOSTNAMES
        has_lab_suffix = any(host.endswith(sfx) for sfx in ALLOWED_LAB_SUFFIXES)

        # Explicit allowed hostnames
        in_allowed_hosts = False
        for allowed in self.scope.allowed_hostnames:
            al = allowed.strip().lower()
            if al.startswith("*."):
                domain_part = al[2:]
                if host == domain_part or host.endswith("." + domain_part):
                    in_allowed_hosts = True
                    break
            elif host == al:
                in_allowed_hosts = True
                break

        if config.CLOUD_MODE and is_local_name and not in_allowed_hosts:
            msg = f"Localhost '{host}' blocked: In CLOUD_MODE, localhost must be explicitly allowlisted in engagement scope."
            self._log_violation(host, msg, "CLOUD_LOCALHOST_NOT_ALLOWLISTED", actor=actor)
            return {"ok": False, "target": host, "reason": msg, "rule": "CLOUD_LOCALHOST_NOT_ALLOWLISTED"}

        # 5. DNS Pre-Resolution & Rebinding Protection
        # Always resolve the hostname to verify every resolved IP falls in-scope
        try:
            addr_infos = socket.getaddrinfo(host, None)
            resolved_ips = {info[4][0] for info in addr_infos}
        except socket.gaierror as e:
            # If it's a lab suffix/name that might only resolve in lab docker network
            if self.scope.allowed_hostnames:
                if in_allowed_hosts or is_local_name:
                    return {
                        "ok": True,
                        "target": host,
                        "port": effective_port,
                        "reason": "Authorized lab hostname (unresolved on host DNS)",
                    }
            elif is_local_name or has_lab_suffix:
                return {
                    "ok": True,
                    "target": host,
                    "port": effective_port,
                    "reason": "Authorized lab hostname (unresolved on host DNS)",
                }
            msg = f"Hostname {host} DNS lookup failed: {e}"
            self._log_violation(host, msg, "DNS_RESOLUTION_FAILED", actor=actor)
            return {"ok": False, "target": host, "reason": msg, "rule": "DNS_RESOLUTION_FAILED"}

        # Check every resolved IP address against exclusions and public IP policy
        for rip_str in resolved_ips:
            try:
                rip = normalize_ip(ipaddress.ip_address(rip_str))
            except ValueError:
                continue

            # Check exclusions
            if str(rip) in self.scope._parsed_excluded_ips:
                msg = f"Hostname {host} resolves to excluded IP {rip}."
                self._log_violation(host, msg, "DNS_RESOLVES_TO_EXCLUDED", actor=actor)
                return {"ok": False, "target": host, "reason": msg, "rule": "DNS_RESOLVES_TO_EXCLUDED"}

            for exc_net in self.scope._parsed_excluded_networks:
                if rip in exc_net:
                    msg = f"Hostname {host} resolves to IP {rip} in excluded CIDR {exc_net}."
                    self._log_violation(host, msg, "DNS_RESOLVES_TO_EXCLUDED_CIDR", actor=actor)
                    return {"ok": False, "target": host, "reason": msg, "rule": "DNS_RESOLVES_TO_EXCLUDED_CIDR"}

            # Check public policy
            if not is_private_ip(rip) and not self.scope.allow_public_ips:
                msg = f"Hostname {host} resolves to public IP {rip} (Public targets blocked)."
                self._log_violation(host, msg, "DNS_RESOLVES_TO_PUBLIC", actor=actor)
                return {"ok": False, "target": host, "reason": msg, "rule": "DNS_RESOLVES_TO_PUBLIC"}

            # Check CIDR match if CIDRs specified
            if self.scope._parsed_allowed_networks:
                in_net = any(rip in net for net in self.scope._parsed_allowed_networks)
                if not in_net and not (in_allowed_hosts or is_local_name or has_lab_suffix):
                    msg = f"Hostname {host} resolves to IP {rip} which is outside allowed CIDRs."
                    self._log_violation(host, msg, "DNS_OUT_OF_CIDR", actor=actor)
                    return {"ok": False, "target": host, "reason": msg, "rule": "DNS_OUT_OF_CIDR"}

        # When explicit allowed_hostnames are configured, the target MUST match them
        if self.scope.allowed_hostnames:
            if in_allowed_hosts or is_local_name:
                return {"ok": True, "target": host, "port": effective_port, "reason": "Authorized hostname in scope"}
            msg = f"Hostname {host} is not in authorized hostnames list."
            self._log_violation(host, msg, "HOSTNAME_NOT_ALLOWED", actor=actor)
            return {"ok": False, "target": host, "reason": msg, "rule": "HOSTNAME_NOT_ALLOWED"}

        # If no explicit hostnames given, fall back to lab suffixes / localhost
        if is_local_name or has_lab_suffix:
            return {"ok": True, "target": host, "port": effective_port, "reason": "Authorized lab hostname in scope"}

        msg = f"Hostname {host} is not an authorized lab hostname."
        self._log_violation(host, msg, "HOSTNAME_NOT_ALLOWED", actor=actor)
        return {"ok": False, "target": host, "reason": msg, "rule": "HOSTNAME_NOT_ALLOWED"}

    def check_tool(self, tool_name: str, actor: str = "system") -> Dict[str, Any]:
        """Verify whether a tool is permitted in the engagement."""
        tool = (tool_name or "").strip().lower()
        if self.scope.allowed_tools and tool not in [t.lower() for t in self.scope.allowed_tools]:
            msg = f"Tool '{tool}' is not permitted by engagement scope (allowed: {self.scope.allowed_tools})"
            self._log_violation(tool, msg, "TOOL_NOT_PERMITTED", actor=actor)
            return {"ok": False, "tool": tool, "reason": msg, "rule": "TOOL_NOT_PERMITTED"}
        return {"ok": True, "tool": tool, "reason": "Tool permitted"}

    def check_time_window(self, actor: str = "system") -> Dict[str, Any]:
        """Verify whether current execution time falls within allowed time window."""
        if not self.scope.time_window_start or not self.scope.time_window_end:
            return {"ok": True, "reason": "No time window restriction configured"}

        now_utc = datetime.datetime.now(datetime.timezone.utc).time()
        start = self.scope.time_window_start
        end = self.scope.time_window_end

        if start <= end:
            in_window = start <= now_utc <= end
        else:  # Overnight window
            in_window = now_utc >= start or now_utc <= end

        if not in_window:
            msg = f"Current UTC time {now_utc.strftime('%H:%M:%S')} is outside allowed window ({start.strftime('%H:%M:%S')} - {end.strftime('%H:%M:%S')})"
            self._log_violation("time_window", msg, "TIME_WINDOW_VIOLATION", actor=actor)
            return {"ok": False, "reason": msg, "rule": "TIME_WINDOW_VIOLATION"}

        return {"ok": True, "reason": "Within allowed time window"}

    def enforce_or_raise(self, target: str, port: Optional[int] = None, tool: Optional[str] = None, actor: str = "system"):
        """Convenience method that checks target, tool, and time window; raises ScopeViolationError on failure."""
        t_check = self.check_target(target, port=port, actor=actor)
        if not t_check["ok"]:
            raise ScopeViolationError(t_check["reason"], rule=t_check.get("rule", "SCOPE_VIOLATION"), target=target)

        if tool:
            tool_check = self.check_tool(tool, actor=actor)
            if not tool_check["ok"]:
                raise ScopeViolationError(tool_check["reason"], rule=tool_check.get("rule", "TOOL_VIOLATION"), target=tool)

        time_check = self.check_time_window(actor=actor)
        if not time_check["ok"]:
            raise ScopeViolationError(time_check["reason"], rule=time_check.get("rule", "TIME_VIOLATION"), target="time_window")
