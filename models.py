"""Data models and normalization utilities for reconnaissance assets and observations.

Maintains provenance, confidence, normalization, and deduplication logic.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class CollectionMethod(str, Enum):
    """Method used to gather reconnaissance data."""
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"
    SIMULATED = "SIMULATED"


class RelationshipType(str, Enum):
    """Types of edges connecting entities in the asset graph."""
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    EXPOSES_PORT = "EXPOSES_PORT"
    RUNS_SERVICE = "RUNS_SERVICE"
    OBSERVED_BY = "OBSERVED_BY"


class DiscrepancyType(str, Enum):
    """Types of evidence discrepancies detected during correlation."""
    UNRESOLVED_SUBDOMAIN = "UNRESOLVED_SUBDOMAIN"
    INDEXED_SERVICE_UNCONFIRMED = "INDEXED_SERVICE_UNCONFIRMED"
    FINGERPRINT_DISAGREEMENT = "FINGERPRINT_DISAGREEMENT"
    CONFLICTING_OBSERVATIONS = "CONFLICTING_OBSERVATIONS"


def normalize_domain(domain: str) -> str:
    """Normalize a domain or subdomain string.

    Lowercases, removes whitespace, strips leading/trailing dots,
    and removes wildcards (e.g., *.example.com -> example.com).
    """
    if not domain:
        return ""
    clean = domain.strip().lower()
    if clean.startswith("*."):
        clean = clean[2:]
    clean = clean.strip(".")
    # Validate against basic domain character set (alphanumeric, dots, hyphens)
    clean = re.sub(r"[^\w\.\-]", "", clean)
    return clean


def normalize_ip(ip_str: str) -> Optional[str]:
    """Canonicalize an IPv4 or IPv6 string representation.

    Returns normalized string or None if invalid.
    """
    if not ip_str:
        return None
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr)
    except ValueError:
        return None


def normalize_port(port: Any) -> Optional[int]:
    """Validate and convert port to an integer within 1-65535."""
    try:
        val = int(port)
        if 1 <= val <= 65535:
            return val
    except (ValueError, TypeError):
        pass
    return None


@dataclass
class Observation:
    """Individual provenance-preserving observation of an asset."""
    asset_id: str
    source: str
    method: CollectionMethod
    raw_value: Any
    normalized_value: Any
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    confidence: float = 1.0
    status: str = "SUCCESS"
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "source": self.source,
            "method": self.method.value if isinstance(self.method, CollectionMethod) else str(self.method),
            "raw_value": str(self.raw_value),
            "normalized_value": str(self.normalized_value),
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "status": self.status,
            "error_message": self.error_message,
        }


@dataclass
class DNSRecord:
    """A DNS record observation."""
    record_type: str
    host: str
    value: str
    source: str
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    ttl: Optional[int] = None
    priority: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "host": self.host,
            "value": self.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
            "priority": self.priority,
        }


@dataclass
class ServiceEndpoint:
    """Identified network service endpoint."""
    host: str
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.8
    source: str = "banner"
    method: CollectionMethod = CollectionMethod.ACTIVE
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    security_headers: Optional[dict[str, bool]] = None
    detected_frameworks: Optional[list[str]] = None
    security_score: Optional[str] = None
    tls_cert_info: Optional[dict[str, Any]] = None
    server_header: Optional[str] = None
    http_status: Optional[int] = None
    is_redirect: bool = False
    verified_live: bool = False

    @property
    def endpoint_id(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "confidence": self.confidence,
            "source": self.source,
            "method": self.method.value if isinstance(self.method, CollectionMethod) else str(self.method),
            "timestamp": self.timestamp,
            "security_headers": self.security_headers,
            "detected_frameworks": self.detected_frameworks or [],
            "security_score": self.security_score,
            "tls_cert_info": self.tls_cert_info,
            "server_header": self.server_header,
            "http_status": self.http_status,
            "is_redirect": self.is_redirect,
            "verified_live": self.verified_live,
        }


@dataclass
class ProbeResult:
    """Explicit execution outcome of an active network probe."""
    probe_id: str
    host: str
    port: int
    protocol: str = "tcp"
    cost: int = 1
    value: int = 1
    state: str = "NOT_EXECUTED"  # OPEN, CLOSED, FILTERED, TIMEOUT, FAILED, NOT_EXECUTED
    response_time_ms: float = 0.0
    banner_excerpt: Optional[str] = None
    details: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "cost": self.cost,
            "value": self.value,
            "state": self.state,
            "response_time_ms": round(self.response_time_ms, 2),
            "banner_excerpt": self.banner_excerpt,
            "details": self.details,
            "timestamp": self.timestamp,
        }


@dataclass
class ProbeCandidate:
    """A candidate active network probe for DAA scheduling."""
    probe_id: str
    host: str
    port: int
    protocol: str = "tcp"
    cost: int = 1
    value: int = 1
    reason: str = "Standard probe"
    selected: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "cost": self.cost,
            "value": self.value,
            "reason": self.reason,
            "selected": self.selected,
        }


@dataclass
class ConsistencyFinding:
    """Evidence discrepancy or inconsistency identified during graph analysis."""
    finding_type: DiscrepancyType
    asset_id: str
    description: str
    evidence_sources: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type.value if isinstance(self.finding_type, DiscrepancyType) else str(self.finding_type),
            "asset_id": self.asset_id,
            "description": self.description,
            "evidence_sources": self.evidence_sources,
            "timestamp": self.timestamp,
        }


@dataclass
class DiscoveredAssetInventory:
    """Aggregated inventory of discovered assets with multi-source provenance."""
    root_domain: str
    subdomains: set[str] = field(default_factory=set)
    ip_addresses: set[str] = field(default_factory=set)
    dns_records: list[DNSRecord] = field(default_factory=list)
    services: list[ServiceEndpoint] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    probe_executions: list[ProbeResult] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def add_subdomain(self, subdomain: str, source: str, method: CollectionMethod = CollectionMethod.PASSIVE) -> None:
        norm = normalize_domain(subdomain)
        if norm:
            self.subdomains.add(norm)
            self.observations.append(
                Observation(
                    asset_id=norm,
                    source=source,
                    method=method,
                    raw_value=subdomain,
                    normalized_value=norm,
                )
            )

    def add_ip(self, ip: str, source: str, method: CollectionMethod = CollectionMethod.PASSIVE) -> None:
        norm = normalize_ip(ip)
        if norm:
            self.ip_addresses.add(norm)
            self.observations.append(
                Observation(
                    asset_id=norm,
                    source=source,
                    method=method,
                    raw_value=ip,
                    normalized_value=norm,
                )
            )

    def add_dns_record(self, record: DNSRecord) -> None:
        self.dns_records.append(record)
        # Use specific asset_id for multi-valued record types to preserve uniqueness
        if record.record_type in ("MX", "TXT", "NS"):
            asset_key = f"{record.host}:{record.record_type}:{record.value}"
        else:
            asset_key = f"{record.host}:{record.record_type}"

        raw_display = f"{record.value} (pri={record.priority})" if record.priority is not None else record.value
        self.observations.append(
            Observation(
                asset_id=asset_key,
                source=record.source,
                method=CollectionMethod.PASSIVE,
                raw_value=raw_display,
                normalized_value=record.value,
            )
        )

    def add_service(self, service: ServiceEndpoint) -> None:
        self.services.append(service)
        # Construct meaningful, non-null raw and normalized observation values
        if service.product and service.version:
            raw_val = f"{service.product} {service.version}"
            norm_val = service.product
        elif service.product:
            raw_val = service.product
            norm_val = service.product
        elif service.server_header:
            raw_val = f"Server: {service.server_header}"
            norm_val = service.server_header
        elif service.detected_frameworks:
            raw_val = f"Framework: {', '.join(service.detected_frameworks)}"
            norm_val = service.detected_frameworks[0]
        elif service.service_name and service.service_name != "unknown":
            raw_val = service.service_name
            norm_val = service.service_name
        else:
            raw_val = f"Open Port {service.port}/{service.protocol}"
            norm_val = f"Port-{service.port}"

        self.observations.append(
            Observation(
                asset_id=service.endpoint_id,
                source=service.source,
                method=service.method,
                raw_value=raw_val,
                normalized_value=norm_val,
                confidence=service.confidence,
            )
        )

    def add_probe_execution(self, record: ProbeResult) -> None:
        self.probe_executions.append(record)

    def add_error(self, source: str, message: str) -> None:
        self.errors.append({"source": source, "message": message, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()})
