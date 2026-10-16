"""Optional adapter for theHarvester OSINT reconnaissance tool.

Detects if theHarvester CLI binary is available on system PATH.
If installed, invokes it via safe subprocess (shell=False) and extracts
discovered subdomains and hosts. If absent, logs a clear notice and skips
cleanly without impacting the reconnaissance pipeline.
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Optional

from config import config
from models import CollectionMethod, DiscoveredAssetInventory, normalize_domain

logger = logging.getLogger(__name__)


def run_theharvester(
    domain: str,
    inventory: DiscoveredAssetInventory,
    timeout: Optional[float] = None,
) -> set[str]:
    """Execute theHarvester CLI if installed and parse discovered subdomains."""
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        return set()

    if not config.is_tool_available("theHarvester"):
        msg = "theHarvester is not installed on PATH. Skipping theHarvester passive collection."
        logger.info(msg)
        inventory.add_error("theHarvester", msg)
        return set()

    timeout_val = timeout or 30.0
    discovered: set[str] = set()

    cmd = ["theHarvester", "-d", clean_domain, "-b", "bing,duckduckgo", "-l", "100"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_val,
            shell=False,
        )

        output = proc.stdout + "\n" + proc.stderr
        # Parse hosts from output
        # theHarvester prints hosts in a [*] Hosts found: section
        subdomain_regex = rf"([a-zA-Z0-9_\-\.]+\.{re.escape(clean_domain)})"
        for match in re.finditer(subdomain_regex, output, re.IGNORECASE):
            sub = normalize_domain(match.group(1))
            if sub and sub != clean_domain:
                discovered.add(sub)
                inventory.add_subdomain(sub, source="theHarvester", method=CollectionMethod.PASSIVE)

    except subprocess.TimeoutExpired:
        msg = f"theHarvester execution timed out after {timeout_val} seconds."
        logger.warning(msg)
        inventory.add_error("theHarvester", msg)
    except Exception as exc:
        msg = f"Error running theHarvester: {exc}"
        logger.warning(msg)
        inventory.add_error("theHarvester", msg)

    return discovered
