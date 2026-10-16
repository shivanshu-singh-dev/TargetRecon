"""Unit tests for the asset correlation graph and graph algorithms (BFS, DFS, consistency)."""

import pytest
from graph import AssetGraph
from models import (
    CollectionMethod,
    ConsistencyFinding,
    DiscrepancyType,
    DiscoveredAssetInventory,
    Observation,
    RelationshipType,
)


def build_sample_recon_graph() -> AssetGraph:
    """Build a deterministic reconnaissance graph for testing.

    Structure:
    example.com (Domain)
      -> HAS_SUBDOMAIN -> api.example.com (Subdomain)
      -> HAS_SUBDOMAIN -> mail.example.com (Subdomain)
      -> HAS_SUBDOMAIN -> dev.example.com (Subdomain, unresolved)

    api.example.com -> RESOLVES_TO -> 192.0.2.1 (IPAddress)
    mail.example.com -> RESOLVES_TO -> 192.0.2.1 (IPAddress - shared IP!)

    192.0.2.1 -> EXPOSES_PORT -> 192.0.2.1:443 (Endpoint)
    192.0.2.1:443 -> RUNS_SERVICE -> service_nginx (Service)
    """
    g = AssetGraph()
    g.add_node("example.com", "Domain", {"sources": ["input"]})
    g.add_node("api.example.com", "Subdomain", {"sources": ["crtsh"], "discovered_passively": True})
    g.add_node("mail.example.com", "Subdomain", {"sources": ["crtsh", "dns"], "discovered_passively": True})
    g.add_node("dev.example.com", "Subdomain", {"sources": ["crtsh"], "discovered_passively": True})

    g.add_node("192.0.2.1", "IPAddress")
    g.add_node("192.0.2.1:443", "Endpoint")
    g.add_node("service_nginx", "Service", {"banner_product": "nginx", "fingerprint_product": "nginx"})

    # Edges
    g.add_edge("example.com", "api.example.com", RelationshipType.HAS_SUBDOMAIN)
    g.add_edge("example.com", "mail.example.com", RelationshipType.HAS_SUBDOMAIN)
    g.add_edge("example.com", "dev.example.com", RelationshipType.HAS_SUBDOMAIN)

    g.add_edge("api.example.com", "192.0.2.1", RelationshipType.RESOLVES_TO)
    g.add_edge("mail.example.com", "192.0.2.1", RelationshipType.RESOLVES_TO)

    g.add_edge("192.0.2.1", "192.0.2.1:443", RelationshipType.EXPOSES_PORT)
    g.add_edge("192.0.2.1:443", "service_nginx", RelationshipType.RUNS_SERVICE)

    return g


def test_bfs_traversal():
    """Verify BFS explores nodes in breadth-first level order."""
    g = build_sample_recon_graph()
    traversal = g.bfs("example.com")

    assert traversal[0] == "example.com"
    # Level 1 should be the three subdomains
    level_1 = set(traversal[1:4])
    assert level_1 == {"api.example.com", "mail.example.com", "dev.example.com"}
    # Level 2 should contain 192.0.2.1
    assert "192.0.2.1" in traversal[4:]
    # Last should be the deep service
    assert traversal[-1] == "service_nginx"


def test_dfs_traversal():
    """Verify DFS explores along deep branches to leaf vertices."""
    g = build_sample_recon_graph()
    traversal = g.dfs("example.com")

    assert traversal[0] == "example.com"
    assert len(traversal) == len(g.nodes)
    assert set(traversal) == set(g.nodes.keys())


def test_path_tracing():
    """Verify finding directed paths from domain to service endpoint."""
    g = build_sample_recon_graph()
    paths = g.find_paths("example.com", "service_nginx")

    assert len(paths) == 2
    # Two valid paths: via api.example.com and via mail.example.com
    path_intermediaries = {p[1] for p in paths}
    assert path_intermediaries == {"api.example.com", "mail.example.com"}
    for p in paths:
        assert p[0] == "example.com"
        assert p[-1] == "service_nginx"
        assert "192.0.2.1" in p


def test_shared_infrastructure_detection():
    """Verify multiple subdomains pointing to the same IP are identified as shared."""
    g = build_sample_recon_graph()
    shared = g.find_shared_assets(target_node_type="IPAddress")

    assert "192.0.2.1" in shared
    assert sorted(shared["192.0.2.1"]) == ["api.example.com", "mail.example.com"]


def test_connected_components():
    """Verify connected component decomposition."""
    g = build_sample_recon_graph()
    # Add an isolated node/cluster
    g.add_node("isolated.org", "Domain")
    g.add_node("10.0.0.1", "IPAddress")
    g.add_edge("isolated.org", "10.0.0.1", RelationshipType.RESOLVES_TO)

    components = g.find_connected_components()
    assert len(components) == 2
    comp_sizes = sorted([len(c) for c in components])
    assert comp_sizes == [2, 7]


def test_consistency_unresolved_subdomain():
    """Verify detection of a passively discovered subdomain that has no resolution edge."""
    g = build_sample_recon_graph()
    findings = g.run_consistency_checks()

    unresolved_findings = [
        f for f in findings if f.finding_type == DiscrepancyType.UNRESOLVED_SUBDOMAIN
    ]
    assert len(unresolved_findings) == 1
    assert unresolved_findings[0].asset_id == "dev.example.com"


def test_consistency_fingerprint_disagreement():
    """Verify detection of discrepancy when banner and web fingerprint disagree."""
    g = AssetGraph()
    g.add_node(
        "srv1",
        "Service",
        {"banner_product": "OpenSSH", "fingerprint_product": "Apache HTTP Server"},
    )
    findings = g.run_consistency_checks()
    disagreements = [
        f for f in findings if f.finding_type == DiscrepancyType.FINGERPRINT_DISAGREEMENT
    ]
    assert len(disagreements) == 1
    assert disagreements[0].asset_id == "srv1"


def test_consistency_conflicting_observations():
    """Verify detection of conflicting values recorded for the same asset ID."""
    inv = DiscoveredAssetInventory(root_domain="example.com")
    inv.observations.append(
        Observation(
            asset_id="web.example.com:A",
            source="dns_resolver",
            method=CollectionMethod.PASSIVE,
            raw_value="192.0.2.1",
            normalized_value="192.0.2.1",
        )
    )
    inv.observations.append(
        Observation(
            asset_id="web.example.com:A",
            source="passive_history",
            method=CollectionMethod.PASSIVE,
            raw_value="198.51.100.2",
            normalized_value="198.51.100.2",
        )
    )

    g = AssetGraph()
    findings = g.run_consistency_checks(inventory=inv)
    conflict_findings = [
        f for f in findings if f.finding_type == DiscrepancyType.CONFLICTING_OBSERVATIONS
    ]
    assert len(conflict_findings) == 1
    assert conflict_findings[0].asset_id == "web.example.com:A"
