"""Controlled socket-based banner collection for authorized endpoints.

Safety principles:
- Conservative read timeouts and strict response size caps (e.g. 2048 bytes).
- Standard protocol greetings only (HTTP HEAD, SMTP EHLO/HELO, SSH version exchange).
- Strict non-exploitation: no credential testing, no brute force, no destructive commands.
- Guaranteed socket termination in finally blocks.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import socket
import ssl
from typing import Any, Optional

from config import config
from models import CollectionMethod, ServiceEndpoint, normalize_ip
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
    """Parse HTTP headers with weighted scoring and redirect-aware policy evaluation."""
    if not raw_banner or not raw_banner.startswith("HTTP/"):
        return None

    lines = raw_banner.splitlines()
    status_line = lines[0] if lines else ""
    status_code = None
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status_code = int(parts[1])

    is_redirect = status_code in (301, 302, 303, 307, 308)

    headers: dict[str, str] = {}
    for line in lines[1:]:
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
        elif "next.js" in xpb.lower():
            frameworks.append("Next.js")

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

    srv = headers.get("server")
    if srv:
        if "cloudflare" in srv.lower():
            frameworks.append("Cloudflare CDN/WAF")
        elif "nginx" in srv.lower():
            frameworks.append("Nginx")
        elif "apache" in srv.lower():
            frameworks.append("Apache")
        elif "caddy" in srv.lower():
            frameworks.append("Caddy")
        elif "railway" in srv.lower():
            frameworks.append("Railway Edge")

    unique_frameworks = sorted(list(set(frameworks)))

    # Header Scoring Logic
    if is_redirect:
        target_loc = headers.get("location", "")
        if target_loc.startswith("https://"):
            score = "Grade A (Secure HTTPS Redirect)"
            evaluation_note = "Valid HTTP->HTTPS redirect. Per RFC 6797 §7.2, HSTS is prohibited on plain HTTP and evaluated on the target HTTPS endpoint."
        else:
            score = "Grade C (Insecure Redirect)"
            evaluation_note = f"Redirect target is not HTTPS: '{target_loc}'."
    else:
        # Weighted Scoring Model for Application Endpoints (Total = 100)
        # Content-Security-Policy: 30 pts (primary defense against XSS)
        # Strict-Transport-Security: 25 pts (prevents MITM downgrade)
        # X-Frame-Options: 15 pts (clickjacking protection)
        # X-Content-Type-Options: 15 pts (MIME-sniffing protection)
        # Referrer-Policy: 15 pts (privacy preservation)
        points = 0
        if sec_headers["Content-Security-Policy"]:
            points += 30
        if sec_headers["Strict-Transport-Security"]:
            points += 25
        if sec_headers["X-Frame-Options"]:
            points += 15
        if sec_headers["X-Content-Type-Options"]:
            points += 15
        if sec_headers["Referrer-Policy"]:
            points += 15

        if points >= 95:
            score = "Grade A+"
        elif points >= 85:
            score = "Grade A"
        elif points >= 70:
            score = "Grade B (Hardening Opportunity: Missing CSP)" if not sec_headers["Content-Security-Policy"] else "Grade B"
        elif points >= 50:
            score = "Grade C"
        elif points >= 30:
            score = "Grade D"
        else:
            score = "Grade F"
        evaluation_note = f"Weighted header score: {points}/100. CSP={'present' if sec_headers['Content-Security-Policy'] else 'missing'}."

    return {
        "status_code": status_code,
        "is_redirect": is_redirect,
        "location": headers.get("location"),
        "server_header": srv,
        "security_headers": sec_headers,
        "security_score": score,
        "evaluation_note": evaluation_note,
        "detected_frameworks": unique_frameworks,
    }


def inspect_tls_certificate(host: str, port: int = 443, timeout: float = 4.0) -> Optional[dict[str, Any]]:
    """Retrieve and thoroughly parse X.509 TLS certificate directly over socket."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    cert: Optional[dict[str, Any]] = None
    raw_der: Optional[bytes] = None
    cipher_suite: Optional[str] = None
    tls_version: Optional[str] = None

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                raw_der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    cipher_suite = cipher_tuple[0]
    except Exception as exc:
        logger.debug("TLS certificate extraction failed for %s:%d: %s", host, port, exc)
        return None

    if not cert:
        return None

    issuer_name = "Unknown Issuer"
    issuer_dict = {}
    for item in cert.get("issuer", ()):
        for k, v in item:
            issuer_dict[k] = v
            if k == "organizationName":
                issuer_name = v
            elif k == "commonName" and issuer_name == "Unknown Issuer":
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

    fp_sha256 = hashlib.sha256(raw_der).hexdigest() if raw_der else None
    serial_hex = hex(cert.get("serialNumber", 0)) if "serialNumber" in cert else None

    # Determine certificate status
    if is_expired:
        cert_status = "EXPIRED"
    elif days_remaining <= 14:
        cert_status = "EXPIRING_SOON"
    else:
        cert_status = "VALID"

    return {
        "issuer": issuer_name,
        "issuer_details": issuer_dict,
        "subject": subject_cn,
        "valid_from": not_before_str,
        "valid_until": not_after_str,
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "status": cert_status,
        "sans": sorted(list(set(sans))),
        "serial_number": serial_hex,
        "fingerprint_sha256": fp_sha256,
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
    }


def identify_service(
    host: str,
    port: int,
    banner: str,
    matcher: Optional[AhoCorasick] = None,
    tls_cert_info: Optional[dict[str, Any]] = None,
) -> ServiceEndpoint:
    """Analyze collected banner using Aho-Corasick matching, version extraction, and HTTP headers."""
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
    server_header = header_audit.get("server_header") if header_audit else None
    http_status = header_audit.get("status_code") if header_audit else None
    is_redirect = header_audit.get("is_redirect", False) if header_audit else False

    # Fallback to extracted HTTP technologies if Aho-Corasick has no signature
    if not detected_product:
        if detected_frameworks:
            detected_product = detected_frameworks[0]
        elif server_header:
            detected_product = server_header

    if service_name == "unknown":
        if port in (443, 8443) or tls_cert_info:
            service_name = "https"
        elif port in (80, 8080):
            service_name = "http"
        elif port == 22:
            service_name = "ssh"
        elif port == 21:
            service_name = "ftp"
        elif port == 25:
            service_name = "smtp"
        elif port == 3306:
            service_name = "mysql"

    # Documented Confidence Model:
    # 0.95: Direct live socket connect + valid banner + version or header proof
    # 0.90: Direct banner grabbed with valid HTTP response
    # 0.85: Valid TLS handshake confirmed
    # 0.70: Basic port open response
    if detected_product and detected_version:
        conf = 0.95
    elif detected_product or detected_frameworks:
        conf = 0.90
    elif tls_cert_info:
        conf = 0.85
    else:
        conf = 0.70

    return ServiceEndpoint(
        host=host,
        port=port,
        protocol=detected_protocol,
        service_name=service_name,
        product=detected_product,
        version=detected_version,
        banner=banner,
        confidence=conf,
        source="banner_grabber",
        method=CollectionMethod.ACTIVE,
        security_headers=security_headers,
        detected_frameworks=detected_frameworks,
        security_score=security_score,
        tls_cert_info=tls_cert_info,
        server_header=server_header,
        http_status=http_status,
        is_redirect=is_redirect,
        verified_live=True,
    )
