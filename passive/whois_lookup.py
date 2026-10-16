"""WHOIS registration data retrieval.

Integrates with system WHOIS CLI tool if available, or falls back to standard
direct port 43 WHOIS socket protocol queries. Handles privacy-redacted and
unavailable fields gracefully without halting the pipeline.
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
from typing import Any, Optional

from config import config
from models import CollectionMethod, DiscoveredAssetInventory, Observation, normalize_domain

logger = logging.getLogger(__name__)


def query_whois_socket(domain: str, server: str = "whois.iana.org", timeout: float = 4.0) -> str:
    """Perform a direct RFC 3912 WHOIS query over TCP port 43 with timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    response_data = b""
    try:
        sock.connect((server, 43))
        sock.sendall(f"{domain}\r\n".encode("utf-8"))
        while True:
            chunk = sock.recv(2048)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 32768:
                break
    finally:
        sock.close()

    text = response_data.decode("utf-8", errors="replace")

    # If IANA points to a specific TLD WHOIS server, query that server
    refer_match = re.search(r"refer:\s*([^\s]+)", text, re.IGNORECASE)
    if refer_match and server == "whois.iana.org":
        sub_server = refer_match.group(1).strip()
        try:
            return query_whois_socket(domain, server=sub_server, timeout=timeout)
        except Exception:
            pass

    return text


def parse_whois_text(raw_text: str) -> dict[str, str]:
    """Parse key WHOIS fields while identifying privacy-redacted entries."""
    parsed: dict[str, str] = {}
    if not raw_text:
        return parsed

    fields_to_find = {
        "registrar": [r"Registrar:\s*(.+)", r"registrar-name:\s*(.+)"],
        "creation_date": [r"Creation Date:\s*(.+)", r"created:\s*(.+)"],
        "expiry_date": [r"Registry Expiry Date:\s*(.+)", r"paid-till:\s*(.+)"],
        "organization": [r"Registrant Organization:\s*(.+)", r"org:\s*(.+)"],
        "country": [r"Registrant Country:\s*(.+)", r"country:\s*(.+)"],
        "name_servers": [r"Name Server:\s*(.+)", r"nserver:\s*(.+)"],
    }

    for key, patterns in fields_to_find.items():
        for pat in patterns:
            match = re.search(pat, raw_text, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                if any(redacted in val.lower() for redacted in ["redacted", "privacy", "gdpr", "withheld"]):
                    val = "[REDACTED FOR PRIVACY]"
                parsed[key] = val
                break

    return parsed


def query_whois(
    domain: str,
    inventory: DiscoveredAssetInventory,
    timeout: Optional[float] = None,
) -> dict[str, str]:
    """Retrieve WHOIS registration data using available CLI or socket integration."""
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        return {}

    timeout_val = timeout or config.NETWORK_TIMEOUT
    raw_output = ""

    # Strategy 1: Check if system whois binary exists
    if config.is_tool_available("whois"):
        try:
            cmd = ["whois", clean_domain]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_val, shell=False)
            if proc.returncode == 0:
                raw_output = proc.stdout
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as exc:
            logger.debug("System whois CLI failed or timed out: %s", exc)

    # Strategy 2: Fall back to direct socket query
    if not raw_output:
        try:
            raw_output = query_whois_socket(clean_domain, timeout=timeout_val)
        except Exception as exc:
            msg = f"WHOIS socket query unavailable: {exc}"
            logger.debug(msg)
            inventory.add_error("whois", msg)

    if not raw_output:
        return {}

    parsed = parse_whois_text(raw_output)

    # Store in inventory as observation
    for field_name, value in parsed.items():
        inventory.observations.append(
            Observation(
                asset_id=f"{clean_domain}:WHOIS:{field_name}",
                source="whois",
                method=CollectionMethod.PASSIVE,
                raw_value=value,
                normalized_value=value,
                confidence=0.9 if value != "[REDACTED FOR PRIVACY]" else 0.5,
            )
        )

    return parsed
