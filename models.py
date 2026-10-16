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

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "host": self.host,
            "value": self.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
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
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

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
            "banner": self.banner[:100] + "..." if self.banner and len(self.banner) > 100 else self.banner,
            "confidence": self.confidence,
            "source": self.source,
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
        self.observations.append(
            Observation(
                asset_id=f"{record.host}:{record.record_type}",
                source=record.source,
                method=CollectionMethod.PASSIVE,
                raw_value=record.value,
                normalized_value=record.value,
            )
        )

    def add_service(self, service: ServiceEndpoint) -> None:
        self.services.append(service)
        self.observations.append(
            Observation(
                asset_id=service.endpoint_id,
                source=service.source,
                method=CollectionMethod.ACTIVE,
                raw_value=f"{service.service_name} {service.version}",
                normalized_value=f"{service.product or service.service_name or 'unknown'}",
                confidence=service.confidence,
            )
        )

    def add_error(self, source: str, message: str) -> None:
        self.errors.append({"source": source, "message": message, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()})
