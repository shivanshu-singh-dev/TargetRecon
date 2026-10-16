"""Strict scope and authorization enforcement for active reconnaissance.

Guarantees that active network probes are restricted exclusively to
explicitly authorized hostnames, IP addresses, and CIDR subnets.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
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
                return
            else:
                ip = ipaddress.ip_address(rule)
                self.allowed_ips.add(str(ip))
                return
        except ValueError:
            pass

        # Treat as domain name or pattern
        norm_rule = rule.lower().strip(".")
        if "*" in norm_rule:
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

    def is_in_scope(self, target: str) -> bool:
        """Verify whether a target host or IP is explicitly authorized."""
        if not target:
            return False

        clean_target = target.strip().lower()

        # Check if target is an IP
        norm_ip = normalize_ip(clean_target)
        if norm_ip:
            if norm_ip in self.allowed_ips:
                return True
            target_ip_obj = ipaddress.ip_address(norm_ip)
            for net in self.allowed_networks:
                if target_ip_obj in net:
                    return True
            # IP was not explicitly in scope
            return False

        # Target is a domain/hostname
        norm_domain = normalize_domain(clean_target)
        if norm_domain in self.allowed_hosts:
            return True

        for pat in self.allowed_patterns:
            if fnmatch.fnmatch(norm_domain, pat):
                return True

        return False

    def validate_or_raise(self, target: str) -> None:
        """Check scope and raise ScopeValidationError if target is unauthorized."""
        if not self.is_in_scope(target):
            raise ScopeValidationError(
                f"Target '{target}' is NOT in authorized scope. Active scanning aborted."
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
