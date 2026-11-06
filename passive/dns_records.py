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
    record_types: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"),
    timeout: Optional[float] = None,
) -> list[DNSRecord]:
    """Query comprehensive DNS record types for a given host or domain name.

    Returns list of discovered DNSRecord models, captures MX preferences,
    audits DMARC email policies, and updates the central inventory.
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
                priority = None

                # Capture MX priorities (e.g. '10 mail.example.com.' -> priority 10, target 'mail.example.com')
                if r_type == "MX":
                    parts = val.split()
                    if len(parts) >= 2:
                        try:
                            priority = int(parts[0])
                        except ValueError:
                            pass
                        val = parts[1].rstrip(".")

                # Clean trailing dots
                if r_type in ("NS", "CNAME", "SOA"):
                    val = val.rstrip(".")

                record = DNSRecord(
                    record_type=r_type,
                    host=clean_host,
                    value=val,
                    source="dns_resolver",
                    ttl=getattr(answers, "ttl", None),
                    priority=priority,
                )
                results.append(record)
                inventory.add_dns_record(record)

                # Add resolved IPs to inventory
                if r_type in ("A", "AAAA"):
                    ip_norm = normalize_ip(val)
                    if ip_norm:
                        inventory.add_ip(ip_norm, source="dns_resolver", method=CollectionMethod.PASSIVE)

                # Add CNAME target to inventory if it shares domain suffix
                if r_type == "CNAME":
                    clean_cname = normalize_domain(val)
                    if clean_cname and clean_cname.endswith(clean_host):
                        inventory.add_subdomain(clean_cname, source="dns_resolver", method=CollectionMethod.PASSIVE)

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.Timeout:
            msg = f"DNS query timeout for {clean_host} ({r_type}) after {timeout_val}s."
            logger.debug(msg)
            inventory.add_error("dns_resolver", msg)
        except Exception as exc:
            msg = f"DNS query error for {clean_host} ({r_type}): {exc}"
            logger.debug(msg)
            inventory.add_error("dns_resolver", msg)

    # Query DMARC policy under _dmarc.<target_host>
    dmarc_host = f"_dmarc.{clean_host}"
    try:
        dmarc_answers = resolver.resolve(dmarc_host, "TXT")
        for rdata in dmarc_answers:
            val = str(rdata).strip().strip('"')
            if "v=dmarc" in val.lower():
                record = DNSRecord(
                    record_type="TXT",
                    host=dmarc_host,
                    value=val,
                    source="dns_resolver",
                    ttl=getattr(dmarc_answers, "ttl", None),
                )
                results.append(record)
                inventory.add_dns_record(record)
    except Exception:
        pass  # DMARC missing is common, silent fallback

    return results
