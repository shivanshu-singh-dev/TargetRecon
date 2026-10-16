"""Conservative Nmap active scanning adapter and XML parser.

Enforces:
- Scope check prior to execution
- Safe subprocess invocation with shell=False and argument arrays
- Conservative port lists and timeouts
- No vulnerability exploitation or intrusive scripts
- Robust XML parsing of open ports, products, and software versions
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Sequence

from config import config
from models import (
    CollectionMethod,
    DiscoveredAssetInventory,
    Observation,
    ServiceEndpoint,
    normalize_domain,
    normalize_ip,
)
from active.scope import ScopeManager, ScopeValidationError

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_content: str, source: str = "nmap") -> list[ServiceEndpoint]:
    """Parse Nmap XML output into normalized ServiceEndpoint instances.

    Works identically on live scan output and stored offline test fixtures.
    """
    endpoints: list[ServiceEndpoint] = []
    if not xml_content or not xml_content.strip():
        return endpoints

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as err:
        logger.warning("Failed to parse Nmap XML content: %s", err)
        return endpoints

    # Iterate over <host> elements
    for host_elem in root.findall("host"):
        # Check host status
        status_elem = host_elem.find("status")
        if status_elem is not None and status_elem.get("state") != "up":
            continue

        # Extract primary address
        host_address = None
        for addr_elem in host_elem.findall("address"):
            addr_type = addr_elem.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6"):
                host_address = normalize_ip(addr_elem.get("addr", ""))
                break

        # Fallback to hostnames
        if not host_address:
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                for hn in hostnames.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        host_address = normalize_domain(name)
                        break

        if not host_address:
            continue

        # Extract open ports and services
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            try:
                port_num = int(port_elem.get("portid", "0"))
            except ValueError:
                continue

            protocol = port_elem.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            service_name = None
            product = None
            version = None

            if service_elem is not None:
                service_name = service_elem.get("name")
                product = service_elem.get("product")
                version = service_elem.get("version")

            endpoint = ServiceEndpoint(
                host=host_address,
                port=port_num,
                protocol=protocol,
                service_name=service_name,
                product=product,
                version=version,
                confidence=0.95,
                source=source,
            )
            endpoints.append(endpoint)

    return endpoints


def run_nmap_scan(
    target: str,
    scope_manager: ScopeManager,
    inventory: DiscoveredAssetInventory,
    ports: Optional[Sequence[int]] = None,
    timeout: Optional[float] = None,
) -> list[ServiceEndpoint]:
    """Execute conservative Nmap port and service scan on an authorized target."""
    # 1. Enforce strict scope validation
    scope_manager.validate_or_raise(target)

    # 2. Check if nmap binary is available
    if not config.is_tool_available("nmap"):
        msg = "Nmap executable not found on system PATH. Install Nmap to enable active scanning."
        logger.warning(msg)
        inventory.add_error("nmap", msg)
        return []

    scan_ports = ports or config.DEFAULT_ACTIVE_PORTS
    ports_arg = ",".join(str(p) for p in scan_ports)
    timeout_val = timeout or 60.0

    # Write output to temporary XML file
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp_file:
        tmp_xml_path = tmp_file.name

    # Safe conservative Nmap arguments (No scripts, no aggressive timing)
    cmd = [
        "nmap",
        "-sT",              # Unprivileged TCP connect scan
        "-sV",              # Service and version detection
        "--version-light",  # Light intensity (reduces probe count)
        "-p", ports_arg,
        "--max-retries", "1",
        "--host-timeout", f"{int(timeout_val)}s",
        "-oX", tmp_xml_path,
        target,
    ]

    endpoints: list[ServiceEndpoint] = []
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_val,
            shell=False,
        )

        if proc.returncode != 0 and proc.returncode != 1:
            msg = f"Nmap returned nonzero exit code {proc.returncode}: {proc.stderr.strip()}"
            logger.warning(msg)
            inventory.add_error("nmap", msg)

        # Read and parse generated XML
        xml_path = Path(tmp_xml_path)
        if xml_path.is_file():
            content = xml_path.read_text(encoding="utf-8", errors="replace")
            endpoints = parse_nmap_xml(content, source="nmap")

            for ep in endpoints:
                inventory.add_service(ep)

    except subprocess.TimeoutExpired:
        msg = f"Nmap scan for {target} timed out after {timeout_val} seconds."
        logger.warning(msg)
        inventory.add_error("nmap", msg)
    except Exception as exc:
        msg = f"Error during Nmap execution: {exc}"
        logger.error(msg)
        inventory.add_error("nmap", msg)
    finally:
        # Cleanup temporary XML file
        try:
            Path(tmp_xml_path).unlink(missing_ok=True)
        except OSError:
            pass

    return endpoints
