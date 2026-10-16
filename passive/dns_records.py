"""Passive DNS record enumeration using standard DNS resolver queries.

Queries public or system configured DNS recursive resolvers for:
- A (IPv4 Addresses)
- AAAA (IPv6 Addresses)
- MX (Mail Exchangers)
- NS (Authoritative Name Servers)
- TXT (Text Records / SPF / Verification Tokens)

Technical Distinction:
These queries query designated DNS infrastructure resolvers and do not send
network packets directly to the target web or application services.
"""

from __future__ import annotations

import logging
from typing import Optional
import dns.exception
import dns.resolver

from config import config
from models import (
    CollectionMethod,
    DNSRecord,
    DiscoveredAssetInventory,
    normalize_domain,
    normalize_ip,
)

logger = logging.getLogger(__name__)


def query_dns_records(
    target_host: str,
    inventory: DiscoveredAssetInventory,
    record_types: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT"),
    timeout: Optional[float] = None,
) -> list[DNSRecord]:
    """Query standard DNS record types for a given host or domain name.

    Returns list of discovered DNSRecord models and adds discovered IPs
    and records to the central inventory.
    """
    clean_host = normalize_domain(target_host)
    if not clean_host:
        return []

    timeout_val = timeout or config.NETWORK_TIMEOUT
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout_val
    resolver.lifetime = timeout_val

    results: list[DNSRecord] = []

    for r_type in record_types:
        try:
            answers = resolver.resolve(clean_host, r_type)
            for rdata in answers:
                val = str(rdata).strip().strip('"')

                # Clean MX priorities (e.g. '10 mail.example.com.' -> 'mail.example.com')
                if r_type == "MX":
                    parts = val.split()
                    if len(parts) >= 2:
                        val = parts[1].rstrip(".")

                # Clean NS trailing dot
                if r_type == "NS":
                    val = val.rstrip(".")

                record = DNSRecord(
                    record_type=r_type,
                    host=clean_host,
                    value=val,
                    source="dns_resolver",
                    ttl=getattr(answers, "ttl", None),
                )
                results.append(record)
                inventory.add_dns_record(record)

                # Add resolved IPs to inventory
                if r_type in ("A", "AAAA"):
                    ip_norm = normalize_ip(val)
                    if ip_norm:
                        inventory.add_ip(ip_norm, source="dns_resolver", method=CollectionMethod.PASSIVE)

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Normal DNS scenario: record type or host does not exist
            pass
        except dns.exception.Timeout:
            msg = f"DNS query timeout for {clean_host} ({r_type}) after {timeout_val}s."
            logger.debug(msg)
            inventory.add_error("dns_resolver", msg)
        except Exception as exc:
            msg = f"DNS query error for {clean_host} ({r_type}): {exc}"
            logger.debug(msg)
            inventory.add_error("dns_resolver", msg)

    return results
