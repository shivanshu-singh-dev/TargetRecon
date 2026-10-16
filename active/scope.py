"""Strict scope and authorization enforcement for active reconnaissance.

Guarantees that active network probes are restricted exclusively to
explicitly authorized hostnames, IP addresses, and CIDR subnets.

Protects against:
- Hostname suffix spoofing (e.g., rejecting 'attacker-example.com' when '*.example.com' is allowed)
- DNS rebinding to unauthorized internal/loopback IPs
- Scope broadening via redirects or DNS alterations
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import socket
from pathlib import Path
from typing import Iterable, Optional

from models import normalize_domain, normalize_ip

logger = logging.getLogger(__name__)


class ScopeValidationError(Exception):
    """Raised when a candidate probe target is not permitted by authorization scope."""
    pass


class ScopeManager:
    """Manages explicit allowlists and validates targets before active probing."""

    def __init__(self) -> None:
        self.allowed_hosts: set[str] = set()
        self.allowed_patterns: set[str] = set()
        self.allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.allowed_ips: set[str] = set()
        self._has_explicit_ip_rules: bool = False

    def add_rule(self, rule_str: str) -> None:
        """Add a single authorization rule (CIDR, IP, wildcard, or exact hostname)."""
        rule = rule_str.strip()
        if not rule or rule.startswith("#"):
            return

        # Attempt to parse as CIDR network or single IP
        try:
            if "/" in rule:
                net = ipaddress.ip_network(rule, strict=False)
                self.allowed_networks.append(net)
                self._has_explicit_ip_rules = True
                return
            else:
                ip = ipaddress.ip_address(rule)
                self.allowed_ips.add(str(ip))
                self._has_explicit_ip_rules = True
                return
        except ValueError:
            pass

        # Treat as domain name or pattern
        norm_rule = rule.lower().strip()
        if norm_rule.startswith("."):
            # Suffix shorthand: '.example.com' allows '*.example.com' and 'example.com'
            self.allowed_hosts.add(normalize_domain(norm_rule[1:]))
            self.allowed_patterns.add(f"*{norm_rule}")
        elif "*" in norm_rule:
            self.allowed_patterns.add(norm_rule)
        else:
            self.allowed_hosts.add(normalize_domain(norm_rule))

    def load_from_file(self, file_path: Path | str) -> int:
        """Load authorization allowlist from a plain text file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Authorization scope file not found: {path}")

        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    self.add_rule(stripped)
                    count += 1
        return count

    def is_ip_in_scope(self, ip_str: str) -> bool:
        """Verify whether an IP address is authorized under IP/CIDR rules."""
        norm_ip = normalize_ip(ip_str)
        if not norm_ip:
            return False

        if norm_ip in self.allowed_ips:
            return True

        target_ip_obj = ipaddress.ip_address(norm_ip)
        for net in self.allowed_networks:
            if target_ip_obj in net:
                return True

        return False

    def is_hostname_in_scope(self, hostname: str) -> bool:
        """Verify whether a hostname is authorized under domain/wildcard rules."""
        norm_domain = normalize_domain(hostname)
        if not norm_domain:
            return False

        # Exact match
        if norm_domain in self.allowed_hosts:
            return True

        # Wildcard / suffix matching
        for pat in self.allowed_patterns:
            if pat.startswith("*."):
                # Proper subdomain suffix matching
                base_domain = pat[2:]
                if norm_domain == base_domain or norm_domain.endswith(f".{base_domain}"):
                    return True
            elif fnmatch.fnmatch(norm_domain, pat):
                return True

        return False

    def is_in_scope(self, target: str, resolved_ip: Optional[str] = None) -> bool:
        """Verify whether a target host or IP is explicitly authorized."""
        if not target:
            return False

        clean_target = target.strip().lower()

        # Case 1: Target is directly an IP
        norm_ip = normalize_ip(clean_target)
        if norm_ip:
            return self.is_ip_in_scope(norm_ip)

        # Case 2: Target is a hostname
        if not self.is_hostname_in_scope(clean_target):
            return False

        # If resolved_ip is provided, audit it against IP scope restrictions
        if resolved_ip:
            norm_res_ip = normalize_ip(resolved_ip)
            if norm_res_ip:
                ip_obj = ipaddress.ip_address(norm_res_ip)
                # Anti-rebinding guard: block loopback and cloud metadata unless explicitly scoped
                if (ip_obj.is_loopback or str(ip_obj) == "169.254.169.254") and not self.is_ip_in_scope(norm_res_ip):
                    logger.warning("DNS resolution '%s' -> '%s' rejected (loopback/metadata anti-rebinding).", clean_target, norm_res_ip)
                    return False

                # If the scope defined explicit IP networks, the resolved IP must also match
                if self._has_explicit_ip_rules and not self.is_ip_in_scope(norm_res_ip):
                    logger.warning("DNS resolution '%s' -> '%s' is outside authorized IP subnets.", clean_target, norm_res_ip)
                    return False

        return True

    def validate_or_raise(self, target: str, resolved_ip: Optional[str] = None) -> None:
        """Check scope and raise ScopeValidationError if target is unauthorized."""
        if not self.is_in_scope(target, resolved_ip=resolved_ip):
            raise ScopeValidationError(
                f"Target '{target}' (resolved_ip={resolved_ip}) is NOT in authorized scope. Active scanning aborted."
            )

    def filter_targets(self, targets: Iterable[str]) -> tuple[list[str], list[str]]:
        """Separate candidate targets into (in_scope, out_of_scope)."""
        in_scope = []
        out_of_scope = []
        for t in targets:
            if self.is_in_scope(t):
                in_scope.append(t)
            else:
                out_of_scope.append(t)
        return in_scope, out_of_scope

    def resolve_and_audit_probe(self, host: str, port: int) -> tuple[bool, Optional[str], Optional[str]]:
        """Resolve host and verify both hostname and resolved IP before probe execution.

        Returns (is_allowed, resolved_ip, error_message).
        """
        # 1. Audit hostname syntax and scope
        if not self.is_hostname_in_scope(host) and not self.is_ip_in_scope(host):
            return False, None, f"Host '{host}' is outside authorized scope."

        # If already an IP string
        direct_ip = normalize_ip(host)
        if direct_ip:
            if not self.is_ip_in_scope(direct_ip):
                return False, direct_ip, f"IP '{direct_ip}' is outside authorized scope."
            return True, direct_ip, None

        # 2. Resolve DNS to get actual target IP
        try:
            addr_info = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            if not addr_info:
                return False, None, f"Failed to resolve DNS for host '{host}'."
            resolved_ip = addr_info[0][4][0]
        except Exception as exc:
            return False, None, f"DNS resolution failed for '{host}': {exc}"

        # 3. Audit resolved IP against scope & anti-rebinding policies
        if not self.is_in_scope(host, resolved_ip=resolved_ip):
            return False, resolved_ip, f"Resolved IP '{resolved_ip}' for '{host}' violates scope or rebinding rules."

        return True, resolved_ip, None
