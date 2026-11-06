"""Certificate Transparency reconnaissance using crt.sh public log database.

Extracts historical and current TLS certificate SAN (Subject Alternative Names)
and Common Names associated with the target domain.
"""

from __future__ import annotations

import logging
import time
from typing import Optional
import requests
import dns.resolver

from config import config
from models import CollectionMethod, DiscoveredAssetInventory, normalize_domain

logger = logging.getLogger(__name__)


def query_crtsh(
    domain: str,
    inventory: DiscoveredAssetInventory,
    timeout: Optional[float] = None,
    max_retries: int = 2,
    fallback_dns: bool = False,
) -> set[str]:
    """Query crt.sh for public certificate transparency logs with retry and fallback.

    Extracts, normalizes, and deduplicates subdomain records while recording provenance.
    Gracefully handles rate limits (HTTP 429), timeouts, and malformed responses.
    If crt.sh is temporarily unavailable or times out, falls back to passive DNS resolution
    of common standard prefixes so reconnaissance coverage is never blocked.
    """
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        return set()

    # crt.sh backend postgres queries are often slow; use min 10s
    timeout_val = max(10.0, timeout or config.NETWORK_TIMEOUT)
    url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DAA-TargetRecon-Auditor/1.0"
    }

    discovered: set[str] = set()
    succeeded = False

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout_val)
            if response.status_code == 429:
                msg = f"crt.sh returned HTTP 429 (Rate Limited) on attempt {attempt}/{max_retries}."
                logger.warning(msg)
                if attempt < max_retries:
                    time.sleep(1.5)
                    continue
                inventory.add_error("crt.sh", msg)
                break

            if response.status_code != 200:
                msg = f"crt.sh returned unexpected HTTP status {response.status_code}."
                logger.warning(msg)
                inventory.add_error("crt.sh", msg)
                break

            records = response.json()
            for entry in records:
                names = []
                if "common_name" in entry and entry["common_name"]:
                    names.append(entry["common_name"])
                if "name_value" in entry and entry["name_value"]:
                    names.extend(entry["name_value"].split("\n"))

                for raw_name in names:
                    normalized = normalize_domain(raw_name)
                    if normalized and (normalized == clean_domain or normalized.endswith(f".{clean_domain}")):
                        discovered.add(normalized)
                        inventory.add_subdomain(normalized, source="crt.sh", method=CollectionMethod.PASSIVE)

            succeeded = True
            break

        except requests.exceptions.Timeout:
            if attempt < max_retries:
                time.sleep(1.0)
                continue
            msg = f"Connection to crt.sh timed out after {timeout_val} seconds (attempt {attempt}/{max_retries})."
            logger.warning(msg)
            inventory.add_error("crt.sh", msg)
        except requests.exceptions.RequestException as exc:
            msg = f"Network exception communicating with crt.sh: {exc}"
            logger.warning(msg)
            inventory.add_error("crt.sh", msg)
            break
        except Exception as exc:
            msg = f"Unexpected error querying crt.sh: {exc}"
            logger.error(msg)
            inventory.add_error("crt.sh", msg)
            break

    # Resilient Subdomain Discovery Fallback:
    # If crt.sh was unreachable or timed out, query standard common infrastructure prefixes
    if fallback_dns and not discovered:
        logger.info("crt.sh yielded 0 subdomains; checking common infrastructure prefixes via DNS resolver...")
        common_prefixes = (
            "www", "mail", "api", "app", "dev", "admin", "portal",
            "staging", "m", "vpn", "auth", "status", "test", "web"
        )
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        for prefix in common_prefixes:
            candidate = f"{prefix}.{clean_domain}"
            try:
                resolver.resolve(candidate, "A")
                discovered.add(candidate)
                inventory.add_subdomain(candidate, source="dns_resolver", method=CollectionMethod.PASSIVE)
            except Exception:
                pass

    return discovered

    return discovered
