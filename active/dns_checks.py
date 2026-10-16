"""Active DNS verification and explicit Zone-Transfer (AXFR) testing.

Enforces strict safety boundaries:
- Standard resolution comparison verifies current state against historical records.
- Zone-Transfer (AXFR) attempts are disabled by default.
- AXFR requires explicit --enable-zone-transfer flag AND authorization check.
"""

from __future__ import annotations

import logging
from typing import Optional
import dns.exception
import dns.query
import dns.resolver
import dns.zone

from config import config
from models import (
    CollectionMethod,
    DNSRecord,
    DiscoveredAssetInventory,
    Observation,
    normalize_domain,
    normalize_ip,
)
from active.scope import ScopeManager

logger = logging.getLogger(__name__)


def verify_active_dns_records(
    target_host: str,
    scope_manager: ScopeManager,
    inventory: DiscoveredAssetInventory,
    timeout: Optional[float] = None,
) -> dict[str, list[str]]:
    """Actively verify current DNS records against historical/passive observations."""
    clean_host = normalize_domain(target_host)
    scope_manager.validate_or_raise(clean_host)

    timeout_val = timeout or config.NETWORK_TIMEOUT
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout_val
    resolver.lifetime = timeout_val

    verified: dict[str, list[str]] = {}

    for r_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(clean_host, r_type)
            values = []
            for rdata in answers:
                val = str(rdata).strip().strip('"')
                if r_type == "MX":
                    parts = val.split()
                    if len(parts) >= 2:
                        val = parts[1].rstrip(".")
                elif r_type == "NS":
                    val = val.rstrip(".")

                values.append(val)
                rec = DNSRecord(
                    record_type=r_type,
                    host=clean_host,
                    value=val,
                    source="active_dns_verify",
                    ttl=getattr(answers, "ttl", None),
                )
                inventory.add_dns_record(rec)

                if r_type in ("A", "AAAA"):
                    ip_norm = normalize_ip(val)
                    if ip_norm:
                        inventory.add_ip(ip_norm, source="active_dns_verify", method=CollectionMethod.ACTIVE)

            verified[r_type] = values

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            verified[r_type] = []
        except Exception as exc:
            logger.debug("Active DNS check error for %s (%s): %s", clean_host, r_type, exc)

    return verified


def test_zone_transfer(
    domain: str,
    nameserver: str,
    scope_manager: ScopeManager,
    inventory: DiscoveredAssetInventory,
    enable_zone_transfer: bool = False,
    timeout: Optional[float] = None,
) -> list[str]:
    """Perform DNS Zone Transfer (AXFR) only when explicitly enabled and authorized.

    Safety:
    AXFR queries can request the entire DNS zone file. This check is strictly
    disabled by default and will raise an error or abort unless explicitly
    authorized by the user.
    """
    clean_domain = normalize_domain(domain)
    clean_ns = normalize_domain(nameserver)

    if not enable_zone_transfer:
        msg = "Zone transfer (AXFR) test is disabled by default. Pass --enable-zone-transfer to permit."
        logger.info(msg)
        return []

    # Enforce scope check on both domain and nameserver
    scope_manager.validate_or_raise(clean_domain)
    scope_manager.validate_or_raise(clean_ns)

    timeout_val = timeout or config.NETWORK_TIMEOUT
    transferred_names: list[str] = []

    try:
        # Resolve nameserver IP
        ns_answers = dns.resolver.resolve(clean_ns, "A")
        ns_ip = str(ns_answers[0])

        xfr = dns.query.xfr(ns_ip, clean_domain, timeout=timeout_val)
        zone = dns.zone.from_xfr(xfr)

        for name, node in zone.nodes.items():
            record_name = f"{name}.{clean_domain}".strip(".")
            norm_name = normalize_domain(record_name)
            if norm_name:
                transferred_names.append(norm_name)
                inventory.add_subdomain(norm_name, source=f"axfr_{clean_ns}", method=CollectionMethod.ACTIVE)

        logger.info("Zone transfer succeeded on %s for %s (%d records).", clean_ns, clean_domain, len(transferred_names))

    except Exception as exc:
        msg = f"Zone transfer rejected or failed on nameserver {clean_ns}: {exc}"
        logger.debug(msg)
        inventory.add_error("axfr", msg)

    return transferred_names
