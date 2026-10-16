"""Certificate Transparency reconnaissance using crt.sh public log database.

Extracts historical and current TLS certificate SAN (Subject Alternative Names)
and Common Names associated with the target domain.
"""

from __future__ import annotations

import logging
from typing import Optional
import requests

from config import config
from models import CollectionMethod, DiscoveredAssetInventory, normalize_domain

logger = logging.getLogger(__name__)


def query_crtsh(
    domain: str,
    inventory: DiscoveredAssetInventory,
    timeout: Optional[float] = None,
) -> set[str]:
    """Query crt.sh for public certificate transparency logs.

    Extracts, normalizes, and deduplicates subdomain records while recording provenance.
    Gracefully handles rate limits (HTTP 429), timeouts, and malformed responses.
    """
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        return set()

    timeout_val = timeout or config.NETWORK_TIMEOUT
    url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (DAA Coursework Reconnaissance Framework; Research/Academic)"
    }

    discovered: set[str] = set()

    try:
        response = requests.get(url, headers=headers, timeout=timeout_val)
        if response.status_code == 429:
            msg = "crt.sh returned HTTP 429 (Rate Limited). Retrying later or using cached records."
            logger.warning(msg)
            inventory.add_error("crt.sh", msg)
            return discovered

        if response.status_code != 200:
            msg = f"crt.sh returned unexpected HTTP status {response.status_code}."
            logger.warning(msg)
            inventory.add_error("crt.sh", msg)
            return discovered

        try:
            records = response.json()
        except ValueError as err:
            msg = f"crt.sh response could not be parsed as JSON: {err}"
            logger.warning(msg)
            inventory.add_error("crt.sh", msg)
            return discovered

        for entry in records:
            # Parse both common_name and name_value (which can contain multiline SANs)
            names = []
            if "common_name" in entry and entry["common_name"]:
                names.append(entry["common_name"])
            if "name_value" in entry and entry["name_value"]:
                names.extend(entry["name_value"].split("\n"))

            for raw_name in names:
                normalized = normalize_domain(raw_name)
                # Verify that the domain belongs to the target domain scope
                if normalized and (normalized == clean_domain or normalized.endswith(f".{clean_domain}")):
                    discovered.add(normalized)
                    inventory.add_subdomain(normalized, source="crt.sh", method=CollectionMethod.PASSIVE)

    except requests.exceptions.Timeout:
        msg = f"Connection to crt.sh timed out after {timeout_val} seconds."
        logger.warning(msg)
        inventory.add_error("crt.sh", msg)
    except requests.exceptions.RequestException as exc:
        msg = f"Network exception while communicating with crt.sh: {exc}"
        logger.warning(msg)
        inventory.add_error("crt.sh", msg)
    except Exception as exc:
        msg = f"Unexpected error querying crt.sh: {exc}"
        logger.error(msg)
        inventory.add_error("crt.sh", msg)

    return discovered
