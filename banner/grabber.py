"""Controlled socket-based banner collection for authorized endpoints.

Safety principles:
- Conservative read timeouts and strict response size caps (e.g. 2048 bytes).
- Standard protocol greetings only (HTTP HEAD, SMTP EHLO/HELO, SSH version exchange).
- Strict non-exploitation: no credential testing, no brute force, no destructive commands.
- Guaranteed socket termination in finally blocks.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from typing import Any, Optional

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


def audit_http_headers(raw_banner: str) -> Optional[dict[str, Any]]:
    """Parse HTTP headers to audit security headers and detect web technologies."""
    if not raw_banner or not raw_banner.startswith("HTTP/"):
        return None

    headers: dict[str, str] = {}
    for line in raw_banner.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.strip().lower()] = v.strip()

    sec_headers = {
        "Strict-Transport-Security": "strict-transport-security" in headers,
        "Content-Security-Policy": "content-security-policy" in headers,
        "X-Frame-Options": "x-frame-options" in headers,
        "X-Content-Type-Options": "x-content-type-options" in headers,
        "Referrer-Policy": "referrer-policy" in headers,
    }

    present_count = sum(1 for v in sec_headers.values() if v)
    if present_count == 5:
        score = "Grade A+"
    elif present_count == 4:
        score = "Grade A"
    elif present_count == 3:
        score = "Grade B"
    elif present_count == 2:
        score = "Grade C"
    elif present_count == 1:
        score = "Grade D"
    else:
        score = "Grade F"

    frameworks: list[str] = []
    if "x-powered-by" in headers:
        xpb = headers["x-powered-by"]
        frameworks.append(xpb)
        if "php" in xpb.lower():
            frameworks.append("PHP")
        elif "express" in xpb.lower():
            frameworks.append("Express.js")
        elif "asp.net" in xpb.lower():
            frameworks.append("ASP.NET")

    if "set-cookie" in headers:
        sc = headers["set-cookie"].lower()
        if "phpsessid" in sc:
            frameworks.append("PHP")
        if "laravel" in sc:
            frameworks.append("Laravel")
        if "csrftoken" in sc or "sessionid" in sc:
            frameworks.append("Django")
        if "connect.sid" in sc:
            frameworks.append("Express.js")
        if "jsessionid" in sc:
            frameworks.append("Java/Spring")
        if "wp-" in sc or "wordpress" in sc:
            frameworks.append("WordPress")
        if "__cf_bm" in sc or "_cfduid" in sc:
            frameworks.append("Cloudflare")

    if "server" in headers:
        srv = headers["server"]
        if "cloudflare" in srv.lower():
            frameworks.append("Cloudflare CDN/WAF")
        elif "nginx" in srv.lower():
            frameworks.append("Nginx")
        elif "apache" in srv.lower():
            frameworks.append("Apache")
        elif "caddy" in srv.lower():
            frameworks.append("Caddy")

    unique_frameworks = sorted(list(set(frameworks)))

    return {
        "security_headers": sec_headers,
        "security_score": score,
        "detected_frameworks": unique_frameworks,
    }


def inspect_tls_certificate(host: str, port: int = 443, timeout: float = 4.0) -> Optional[dict[str, Any]]:
    """Retrieve and parse X.509 TLS certificate directly over socket."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False

    cert: Optional[dict[str, Any]] = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError:
        try:
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    return {
                        "issuer": "Self-Signed / Untrusted Authority",
                        "subject": host,
                        "valid_from": "Unknown",
                        "valid_until": "Unknown",
                        "days_remaining": 0,
                        "is_expired": False,
                        "sans": [host],
                    }
        except Exception:
            return None
    except Exception as exc:
        logger.debug("TLS certificate extraction failed for %s:%d: %s", host, port, exc)
        return None

    if not cert:
        return None

    issuer_name = "Unknown Issuer"
    for item in cert.get("issuer", ()):
        for k, v in item:
            if k == "organizationName":
                issuer_name = v
                break
            elif k == "commonName":
                issuer_name = v

    subject_cn = host
    for item in cert.get("subject", ()):
        for k, v in item:
            if k == "commonName":
                subject_cn = v

    not_after_str = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")
    days_remaining = 0
    is_expired = False

    if not_after_str:
        try:
            exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            delta = exp_date - now
            days_remaining = max(0, delta.days)
            is_expired = delta.total_seconds() < 0
        except Exception:
            pass

    sans: list[str] = []
    for item in cert.get("subjectAltName", ()):
        if len(item) == 2 and item[0] == "DNS":
            sans.append(item[1])

    return {
        "issuer": issuer_name,
        "subject": subject_cn,
        "valid_from": not_before_str,
        "valid_until": not_after_str,
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "sans": sorted(list(set(sans))),
    }


def identify_service(
    host: str,
    port: int,
    banner: str,
    matcher: Optional[AhoCorasick] = None,
    tls_cert_info: Optional[dict[str, Any]] = None,
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
        primary_match = matches[0]
        detected_product = primary_match.product
        detected_protocol = primary_match.protocol.lower()
        service_name = primary_match.pattern_id.split("-")[0]

    detected_version = None
    if detected_product:
        detected_version = extract_software_version(banner, detected_product)

    # Perform HTTP header & framework audit
    header_audit = audit_http_headers(banner)
    security_headers = header_audit.get("security_headers") if header_audit else None
    security_score = header_audit.get("security_score") if header_audit else None
    detected_frameworks = header_audit.get("detected_frameworks") if header_audit else []

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
        security_headers=security_headers,
        detected_frameworks=detected_frameworks,
        security_score=security_score,
        tls_cert_info=tls_cert_info,
    )
