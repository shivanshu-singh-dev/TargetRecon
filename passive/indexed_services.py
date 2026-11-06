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
                confidence=0.75,
                source="shodan_indexed",
                method=CollectionMethod.PASSIVE,
                verified_live=False,
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
    api_key: Optional[str] = None,
    timeout: Optional[float] = None,
) -> list[str]:
    """Query Censys API (Platform v3 PAT or legacy v2 Basic Auth) for hosts associated with target domain."""
    aid = api_id or config.CENSYS_API_ID
    asec = api_secret or config.CENSYS_API_SECRET
    token = api_key or config.CENSYS_API_KEY or asec or aid

    if not token and not (aid and asec):
        msg = "Censys API credentials not configured (CENSYS_API_KEY / CENSYS_API_ID / CENSYS_API_SECRET). Skipping Censys lookup."
        logger.info(msg)
        inventory.add_error("censys", msg)
        return []

    timeout_val = timeout or config.NETWORK_TIMEOUT
    discovered_ips: list[str] = []

    # 1. Modern Censys Platform API (Bearer Token authentication)
    if token and (str(token).startswith("censys_") or not (aid and asec)):
        org_id = config.CENSYS_ORGANIZATION_ID
        url_v3 = (
            f"https://api.platform.censys.io/v3/global/search/query?organization_id={org_id}"
            if org_id
            else "https://api.platform.censys.io/v3/global/search/query"
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "DAA-TargetRecon/1.0",
        }
        payload = {"query": domain}
        try:
            resp = requests.post(url_v3, headers=headers, json=payload, timeout=timeout_val)
            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("result", {}).get("hits", [])
                for hit in hits:
                    ip_val = normalize_ip(hit.get("ip") or hit.get("resource", {}).get("ip"))
                    if ip_val:
                        discovered_ips.append(ip_val)
                        inventory.add_ip(ip_val, source="censys_indexed", method=CollectionMethod.PASSIVE)
                return discovered_ips
            elif resp.status_code == 403:
                err_detail = "Censys API key verified. (Global domain search requires an Organization ID on Censys Platform; host-level intelligence will be retrieved directly per IP)."
                try:
                    detail = resp.json().get("detail")
                    if detail and "organization ID" in detail:
                        err_detail = "Censys API key verified. (Global domain search requires an Organization ID on Censys Platform; host-level intelligence will be retrieved directly per IP)."
                    elif detail:
                        err_detail = f"Censys API: {detail}"
                except Exception:
                    pass
                logger.info(err_detail)
                inventory.add_error("censys", err_detail)
                return discovered_ips
            else:
                inventory.add_error("censys", f"Censys Platform API returned HTTP {resp.status_code}")
                return discovered_ips
        except Exception as exc:
            inventory.add_error("censys", f"Censys Platform API query error: {exc}")
            return discovered_ips

    # 2. Legacy v2 Basic Auth fallback
    if aid and asec:
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"q": domain, "per_page": 25}
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


def query_censys_host(
    ip_str: str,
    inventory: DiscoveredAssetInventory,
    target_domain: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: Optional[float] = None,
) -> list[ServiceEndpoint]:
    """Query Censys Platform v3 for host intelligence on a specific IP."""
    norm_ip = normalize_ip(ip_str)
    token = api_key or config.CENSYS_API_KEY or config.CENSYS_API_SECRET or config.CENSYS_API_ID
    if not norm_ip or not token:
        return []

    timeout_val = timeout or config.NETWORK_TIMEOUT
    url = f"https://api.platform.censys.io/v3/global/asset/host/{norm_ip}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "DAA-TargetRecon/1.0",
    }
    services: list[ServiceEndpoint] = []

    try:
        resp = requests.get(url, headers=headers, timeout=timeout_val)
        if resp.status_code != 200:
            return services

        res = resp.json().get("result", {}).get("resource", {})

        # 1. Ingest discovered services and ports
        for s in res.get("services", []):
            port = s.get("port")
            if not port:
                continue
            proto = (s.get("transport_protocol") or "tcp").lower()
            prod = None
            for item in (s.get("software") or []):
                if item.get("product"):
                    prod = item.get("product")
                    break

            svc = ServiceEndpoint(
                host=norm_ip,
                port=port,
                protocol=proto,
                service_name=s.get("service_name") or prod or "unknown",
                product=prod,
                confidence=0.75,
                source="censys_indexed",
                method=CollectionMethod.PASSIVE,
                verified_live=False,
            )
            services.append(svc)
            inventory.add_service(svc)

        # 2. Ingest matching subdomains/hostnames from reverse and forward DNS
        dns_data = res.get("dns", {})
        all_names = list(dns_data.get("names", [])) + list(dns_data.get("reverse_dns", {}).get("names", []))
        clean_target = normalize_domain(target_domain) if target_domain else None

        for name in all_names:
            clean_name = normalize_domain(name)
            if clean_name:
                if clean_target and clean_name.endswith(clean_target):
                    inventory.add_subdomain(clean_name, source="censys_indexed", method=CollectionMethod.PASSIVE)
                elif not clean_target:
                    inventory.add_subdomain(clean_name, source="censys_indexed", method=CollectionMethod.PASSIVE)

        # 3. Ingest Autonomous System and Geo metadata
        as_info = res.get("autonomous_system", {})
        if as_info.get("asn"):
            inventory.add_observation(
                asset_id=norm_ip,
                source="censys_indexed",
                method=CollectionMethod.PASSIVE,
                raw_value=f"AS{as_info.get('asn')} ({as_info.get('name', 'Unknown')})",
                confidence=0.9,
            )

    except Exception as exc:
        logger.debug("Censys host query failed for %s: %s", norm_ip, exc)

    return services
