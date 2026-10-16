"""Adapters for indexed internet exposure search engines (Shodan and Censys).

Retrieves historical and indexed port/service observations without directly
connecting to target endpoints.

Authenticates via environment variables:
- SHODAN_API_KEY
- CENSYS_API_ID / CENSYS_API_SECRET

Security and Integrity:
- If API keys are not provided, gracefully reports that the service is unconfigured.
- Never prints or hardcodes secrets.
- Does not fabricate data when credentials are absent.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
import requests

from config import config
from models import (
    CollectionMethod,
    DiscoveredAssetInventory,
    Observation,
    ServiceEndpoint,
    normalize_domain,
    normalize_ip,
)

logger = logging.getLogger(__name__)


def query_shodan_subdomains(
    domain: str,
    inventory: DiscoveredAssetInventory,
    api_key: Optional[str] = None,
    timeout: Optional[float] = None,
) -> set[str]:
    """Query Shodan DNS domain information endpoint if API key is provided."""
    clean_domain = normalize_domain(domain)
    key = api_key or config.SHODAN_API_KEY

    if not key:
        msg = "Shodan API key not configured (SHODAN_API_KEY). Skipping Shodan passive lookup."
        logger.info(msg)
        inventory.add_error("shodan", msg)
        return set()

    timeout_val = timeout or config.NETWORK_TIMEOUT
    url = f"https://api.shodan.io/dns/domain/{clean_domain}?key={key}"
    discovered: set[str] = set()

    try:
        resp = requests.get(url, timeout=timeout_val)
        if resp.status_code == 401:
            msg = "Shodan API key invalid or unauthorized."
            inventory.add_error("shodan", msg)
            return discovered
        if resp.status_code != 200:
            msg = f"Shodan API returned HTTP status {resp.status_code}."
            inventory.add_error("shodan", msg)
            return discovered

        data = resp.json()
        subdomains = data.get("subdomains", [])
        for sub in subdomains:
            full_sub = normalize_domain(f"{sub}.{clean_domain}")
            if full_sub:
                discovered.add(full_sub)
                inventory.add_subdomain(full_sub, source="shodan", method=CollectionMethod.PASSIVE)

    except requests.exceptions.Timeout:
        inventory.add_error("shodan", f"Shodan API timed out after {timeout_val}s.")
    except Exception as exc:
        inventory.add_error("shodan", f"Shodan API query error: {exc}")

    return discovered


def query_shodan_host(
    ip_str: str,
    inventory: DiscoveredAssetInventory,
    api_key: Optional[str] = None,
    timeout: Optional[float] = None,
) -> list[ServiceEndpoint]:
    """Query Shodan host intelligence for open ports and services on a known IP."""
    norm_ip = normalize_ip(ip_str)
    key = api_key or config.SHODAN_API_KEY

    if not norm_ip or not key:
        return []

    timeout_val = timeout or config.NETWORK_TIMEOUT
    url = f"https://api.shodan.io/shodan/host/{norm_ip}?key={key}"
    services: list[ServiceEndpoint] = []

    try:
        resp = requests.get(url, timeout=timeout_val)
        if resp.status_code != 200:
            return services

        data = resp.json()
        for item in data.get("data", []):
            port = item.get("port")
            if not port:
                continue
            svc = ServiceEndpoint(
                host=norm_ip,
                port=port,
                protocol=item.get("transport", "tcp"),
                service_name=item.get("_shodan", {}).get("module", item.get("product")),
                product=item.get("product"),
                version=item.get("version"),
                banner=item.get("data"),
                confidence=0.85,
                source="shodan_indexed",
            )
            services.append(svc)
            inventory.add_service(svc)

    except Exception as exc:
        logger.debug("Shodan host lookup failed for %s: %s", norm_ip, exc)

    return services


def query_censys_hosts(
    domain: str,
    inventory: DiscoveredAssetInventory,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    timeout: Optional[float] = None,
) -> list[str]:
    """Query Censys Search API v2 for hosts associated with target domain."""
    aid = api_id or config.CENSYS_API_ID
    asec = api_secret or config.CENSYS_API_SECRET

    if not aid or not asec:
        msg = "Censys API credentials not configured (CENSYS_API_ID/CENSYS_API_SECRET). Skipping Censys lookup."
        logger.info(msg)
        inventory.add_error("censys", msg)
        return []

    timeout_val = timeout or config.NETWORK_TIMEOUT
    url = "https://search.censys.io/api/v2/hosts/search"
    params = {"q": domain, "per_page": 25}
    discovered_ips: list[str] = []

    try:
        resp = requests.get(url, params=params, auth=(aid, asec), timeout=timeout_val)
        if resp.status_code != 200:
            inventory.add_error("censys", f"Censys API returned HTTP {resp.status_code}")
            return discovered_ips

        data = resp.json()
        results = data.get("result", {}).get("hits", [])
        for hit in results:
            ip_val = normalize_ip(hit.get("ip"))
            if ip_val:
                discovered_ips.append(ip_val)
                inventory.add_ip(ip_val, source="censys_indexed", method=CollectionMethod.PASSIVE)

    except Exception as exc:
        inventory.add_error("censys", f"Censys API error: {exc}")

    return discovered_ips
