"""Controlled socket-based banner collection for authorized endpoints.

Safety principles:
- Conservative read timeouts and strict response size caps (e.g. 2048 bytes).
- Standard protocol greetings only (HTTP HEAD, SMTP EHLO/HELO, SSH version exchange).
- Strict non-exploitation: no credential testing, no brute force, no destructive commands.
- Guaranteed socket termination in finally blocks.
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Optional

from config import config
from models import ServiceEndpoint, normalize_ip
from banner.matcher import (
    AhoCorasick,
    Signature,
    extract_software_version,
    load_signatures_from_file,
)

logger = logging.getLogger(__name__)


def grab_banner(
    host: str,
    port: int,
    timeout: Optional[float] = None,
    max_bytes: Optional[int] = None,
) -> Optional[str]:
    """Retrieve service greeting banner from target port using conservative socket IO."""
    timeout_val = timeout or config.NETWORK_TIMEOUT
    max_size = max_bytes or config.MAX_BANNER_BYTES

    # Determine probe payload by standard port convention
    probe_payload = b""
    is_tls = False

    if port in (80, 8080):
        # Conservative HTTP HEAD request
        probe_payload = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: DAA-Recon-Auditor\r\n\r\n".encode("utf-8")
    elif port in (443, 8443):
        is_tls = True
        probe_payload = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: DAA-Recon-Auditor\r\n\r\n".encode("utf-8")
    elif port == 25:
        # SMTP greeting or EHLO
        probe_payload = b"EHLO recon.local\r\n"
    elif port == 21:
        # FTP sends banner on connect; no payload required
        probe_payload = b""
    elif port == 22:
        # SSH sends protocol version exchange automatically
        probe_payload = b""

    raw_response = b""

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout_val)

        if is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sock.connect((host, port))

        # For protocols that do not send banner automatically, transmit initial handshake probe
        if probe_payload:
            sock.sendall(probe_payload)

        # Read greeting
        raw_response = sock.recv(max_size)

    except (socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError) as exc:
        logger.debug("Banner grab failed for %s:%d: %s", host, port, exc)
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if not raw_response:
        return None

    return raw_response.decode("utf-8", errors="replace").strip()


def identify_service(
    host: str,
    port: int,
    banner: str,
    matcher: Optional[AhoCorasick] = None,
) -> ServiceEndpoint:
    """Analyze collected banner using Aho-Corasick matching and version extraction."""
    if matcher is None:
        matcher = AhoCorasick(case_sensitive=False)
        sigs = load_signatures_from_file(config.SIGNATURES_FILE)
        for s in sigs:
            matcher.add_signature(s)
        matcher.build()

    matches = matcher.search(banner)

    detected_product = None
    detected_protocol = "tcp"
    service_name = "unknown"

    if matches:
        # Select best / primary match
        primary_match = matches[0]
        detected_product = primary_match.product
        detected_protocol = primary_match.protocol.lower()
        service_name = primary_match.pattern_id.split("-")[0]

    # Decoupled version extraction
    detected_version = None
    if detected_product:
        detected_version = extract_software_version(banner, detected_product)

    return ServiceEndpoint(
        host=host,
        port=port,
        protocol="tcp",
        service_name=service_name,
        product=detected_product,
        version=detected_version,
        banner=banner,
        confidence=0.9 if detected_product else 0.5,
        source="banner_grabber",
    )
