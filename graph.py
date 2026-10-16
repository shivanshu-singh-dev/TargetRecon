"""Asset correlation graph using an adjacency-list representation.

Demonstrates:
- Multi-relational asset graph representing domains, subdomains, IPs, endpoints, and services.
- From-scratch BFS and DFS traversals with O(V + E) complexity bounds.
- Path tracing between domains and services.
- Shared infrastructure discovery (e.g., subdomains sharing IP addresses).
- Connected component decomposition.
- Evidence consistency and discrepancy analysis.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from typing import Any, Optional

from models import (
    ConsistencyFinding,
    DiscrepancyType,
    DiscoveredAssetInventory,
    RelationshipType,
)


@dataclass
class GraphNode:
    """A typed vertex in the reconnaissance asset graph."""
    node_id: str
    node_type: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "properties": self.properties,
        }


@dataclass
class GraphEdge:
    """A directed, typed relationship between two asset vertices."""
    source_id: str
    target_id: str
    relationship_type: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type,
            "properties": self.properties,
        }


class AssetGraph:
    """Adjacency-list based multi-relational correlation graph.

    Data Structures:
        nodes: dict[node_id -> GraphNode]
        adj: dict[node_id -> list[GraphEdge]] (forward adjacency)
        rev_adj: dict[node_id -> list[GraphEdge]] (reverse adjacency)
    """

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.adj: dict[str, list[GraphEdge]] = collections.defaultdict(list)
        self.rev_adj: dict[str, list[GraphEdge]] = collections.defaultdict(list)

    def add_node(self, node_id: str, node_type: str, properties: Optional[dict[str, Any]] = None) -> GraphNode:
        """Add or update an asset vertex."""
        clean_id = node_id.strip()
        if clean_id not in self.nodes:
            self.nodes[clean_id] = GraphNode(node_id=clean_id, node_type=node_type, properties=properties or {})
        else:
            if properties:
                self.nodes[clean_id].properties.update(properties)
        return self.nodes[clean_id]

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship_type: RelationshipType | str,
        properties: Optional[dict[str, Any]] = None,
    ) -> GraphEdge:
        """Add a directed edge between two assets.

        Ensures both endpoints exist in the graph before connecting them.
        """
        s_id = source_id.strip()
        t_id = target_id.strip()
        rel = relationship_type.value if isinstance(relationship_type, RelationshipType) else str(relationship_type)

        if s_id not in self.nodes:
            self.add_node(s_id, "Unknown")
        if t_id not in self.nodes:
            self.add_node(t_id, "Unknown")

        # Avoid duplicate edges with identical relation
        for existing in self.adj[s_id]:
            if existing.target_id == t_id and existing.relationship_type == rel:
                if properties:
                    existing.properties.update(properties)
                return existing

        edge = GraphEdge(source_id=s_id, target_id=t_id, relationship_type=rel, properties=properties or {})
        self.adj[s_id].append(edge)
        self.rev_adj[t_id].append(edge)
        return edge

    # ========================================================================
    # Traversal Algorithms: BFS and DFS
    # ========================================================================
    def bfs(
        self,
        start_node_id: str,
        allowed_relationships: Optional[set[str]] = None,
    ) -> list[str]:
        """Breadth-First Search traversal starting from start_node_id.

        Explores vertices level-by-level using an explicit FIFO queue.
        Time Complexity:  O(V + E) where V is the number of reachable vertices
                          and E is the number of outgoing edges explored.
        Space Complexity: O(V) storing the queue and visited set.
        """
        start = start_node_id.strip()
        if start not in self.nodes:
            return []

        visited: set[str] = set()
        queue: collections.deque[str] = collections.deque([start])
        visited.add(start)
        traversal_order: list[str] = []

        while queue:
            curr = queue.popleft()
            traversal_order.append(curr)

            for edge in self.adj.get(curr, []):
                if allowed_relationships and edge.relationship_type not in allowed_relationships:
                    continue
                neighbor = edge.target_id
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        return traversal_order

    def dfs(
        self,
        start_node_id: str,
        allowed_relationships: Optional[set[str]] = None,
    ) -> list[str]:
        """Depth-First Search traversal starting from start_node_id.

        Explores as deep as possible along each branch using an explicit LIFO stack.
        Time Complexity:  O(V + E)
        Space Complexity: O(V) for the stack and visited set.
        """
        start = start_node_id.strip()
        if start not in self.nodes:
            return []

        visited: set[str] = set()
        stack: list[str] = [start]
        traversal_order: list[str] = []

        while stack:
            curr = stack.pop()
            if curr in visited:
                continue
            visited.add(curr)
            traversal_order.append(curr)

            # Push neighbors in reverse order to preserve left-to-right exploration
            edges = self.adj.get(curr, [])
            for edge in reversed(edges):
                if allowed_relationships and edge.relationship_type not in allowed_relationships:
                    continue
                neighbor = edge.target_id
                if neighbor not in visited:
                    stack.append(neighbor)

        return traversal_order

    # ========================================================================
    # Graph Analysis: Connected Components & Paths
    # ========================================================================
    def find_connected_components(self) -> list[list[str]]:
        """Decompose graph into connected components treating edges as undirected.

        Time Complexity: O(V + E) over the entire graph.
        """
        visited: set[str] = set()
        components: list[list[str]] = []

        for node_id in self.nodes:
            if node_id not in visited:
                component: list[str] = []
                queue: collections.deque[str] = collections.deque([node_id])
                visited.add(node_id)

                while queue:
                    curr = queue.popleft()
                    component.append(curr)

                    # Forward neighbors
                    for edge in self.adj.get(curr, []):
                        nxt = edge.target_id
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append(nxt)

                    # Reverse neighbors (undirected connectivity)
                    for edge in self.rev_adj.get(curr, []):
                        prev = edge.source_id
                        if prev not in visited:
                            visited.add(prev)
                            queue.append(prev)

                components.append(sorted(component))

        return components

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 8,
    ) -> list[list[str]]:
        """Find all simple directed paths between source and target using backtracking DFS.

        Returns list of paths where each path is a sequence of node IDs.
        """
        source = source_id.strip()
        target = target_id.strip()

        if source not in self.nodes or target not in self.nodes:
            return []

        paths: list[list[str]] = []

        def backtrack(curr: str, current_path: list[str], visited: set[str], depth: int) -> None:
            if curr == target:
                paths.append(list(current_path))
                return
            if depth >= max_depth:
                return

            for edge in self.adj.get(curr, []):
                nxt = edge.target_id
                if nxt not in visited:
                    visited.add(nxt)
                    current_path.append(nxt)
                    backtrack(nxt, current_path, visited, depth + 1)
                    current_path.pop()
                    visited.remove(nxt)

        backtrack(source, [source], {source}, 0)
        return paths

    def find_shared_assets(self, target_node_type: str = "IPAddress") -> dict[str, list[str]]:
        """Identify infrastructure assets shared by multiple domains or subdomains.

        Example: One IP address hosting multiple subdomains.
        """
        shared: dict[str, list[str]] = {}

        for node_id, node in self.nodes.items():
            if node.node_type == target_node_type:
                # Find all subdomains pointing to this target node
                in_sources = [
                    edge.source_id
                    for edge in self.rev_adj.get(node_id, [])
                    if edge.relationship_type in ("RESOLVES_TO", "HAS_SUBDOMAIN")
                ]
                if len(in_sources) > 1:
                    shared[node_id] = sorted(in_sources)

        return shared

    def detect_duplicates(self) -> list[dict[str, Any]]:
        """Detect potential duplicate or redundant entities due to case or formatting."""
        seen_lower: dict[str, list[str]] = collections.defaultdict(list)
        for node_id in self.nodes:
            seen_lower[node_id.lower()].append(node_id)

        duplicates = []
        for key, ids in seen_lower.items():
            if len(ids) > 1:
                duplicates.append({"normalized_key": key, "instances": ids})
        return duplicates

    # ========================================================================
    # Stage 5 Consistency & Discrepancy Checks
    # ========================================================================
    def run_consistency_checks(
        self,
        inventory: Optional[DiscoveredAssetInventory] = None,
        active_scan_performed: bool = False,
    ) -> list[ConsistencyFinding]:
        """Examine correlation graph for evidence discrepancies and inconsistencies.

        Evaluates:
        1. Passively discovered subdomain that does not currently resolve.
        2. Indexed service not observed during active scanning (when active scan was run).
        3. Disagreement between banner match and web fingerprint.
        4. Conflicting observations of the same asset with different values.
        """
        findings: list[ConsistencyFinding] = []

        # Check 1: Passively discovered subdomain that does not resolve
        for node_id, node in self.nodes.items():
            if node.node_type == "Subdomain":
                # Subdomain is considered unresolved if it has no outgoing RESOLVES_TO edge
                resolves_edges = [
                    e for e in self.adj.get(node_id, [])
                    if e.relationship_type == RelationshipType.RESOLVES_TO.value
                ]
                # Check if it was discovered passively
                is_passive = node.properties.get("discovered_passively", True)
                if is_passive and not resolves_edges:
                    findings.append(
                        ConsistencyFinding(
                            finding_type=DiscrepancyType.UNRESOLVED_SUBDOMAIN,
                            asset_id=node_id,
                            description=(
                                f"Subdomain '{node_id}' was discovered in passive reconnaissance "
                                "records but has no active DNS A/AAAA resolution."
                            ),
                            evidence_sources=node.properties.get("sources", ["passive"]),
                        )
                    )

        # Check 2: Indexed service unconfirmed during authorized active scan
        if active_scan_performed:
            for node_id, node in self.nodes.items():
                if node.node_type == "Service":
                    source = node.properties.get("source", "").lower()
                    if "shodan" in source or "censys" in source:
                        # Check if verified by active scan
                        verified = node.properties.get("verified_active", False)
                        if not verified:
                            findings.append(
                                ConsistencyFinding(
                                    finding_type=DiscrepancyType.INDEXED_SERVICE_UNCONFIRMED,
                                    asset_id=node_id,
                                    description=(
                                        f"Service '{node_id}' was present in historical indexed data ({source}) "
                                        "but was not observed during the authorized active scan."
                                    ),
                                    evidence_sources=[source],
                                )
                            )

        # Check 3: Disagreement between banner match and web fingerprint / service header
        for node_id, node in self.nodes.items():
            if node.node_type == "Service":
                banner_product = node.properties.get("banner_product")
                fingerprint_product = node.properties.get("fingerprint_product")
                if banner_product and fingerprint_product:
                    if banner_product.lower() not in fingerprint_product.lower() and fingerprint_product.lower() not in banner_product.lower():
                        findings.append(
                            ConsistencyFinding(
                                finding_type=DiscrepancyType.FINGERPRINT_DISAGREEMENT,
                                asset_id=node_id,
                                description=(
                                    f"Product identification discrepancy on {node_id}: "
                                    f"Banner match reported '{banner_product}' while fingerprint "
                                    f"reported '{fingerprint_product}'."
                                ),
                                evidence_sources=["banner_grabber", "web_fingerprint"],
                            )
                        )

        # Check 4: Conflicting observations of same asset from inventory
        if inventory:
            obs_by_asset: dict[str, list[Any]] = collections.defaultdict(list)
            for obs in inventory.observations:
                obs_by_asset[obs.asset_id].append(obs)

            for asset_id, obs_list in obs_by_asset.items():
                distinct_values = set(str(o.normalized_value) for o in obs_list if o.normalized_value)
                if len(distinct_values) > 1 and not asset_id.endswith(":NS"):
                    sources = list(set(o.source for o in obs_list))
                    findings.append(
                        ConsistencyFinding(
                            finding_type=DiscrepancyType.CONFLICTING_OBSERVATIONS,
                            asset_id=asset_id,
                            description=(
                                f"Multiple sources observed differing values for asset '{asset_id}': "
                                f"{', '.join(sorted(distinct_values))}."
                            ),
                            evidence_sources=sources,
                        )
                    )

        return findings

    def get_metrics(self) -> dict[str, Any]:
        """Compute structural graph metrics."""
        type_counts: dict[str, int] = collections.defaultdict(int)
        for node in self.nodes.values():
            type_counts[node.node_type] += 1

        rel_counts: dict[str, int] = collections.defaultdict(int)
        total_edges = 0
        for edge_list in self.adj.values():
            for edge in edge_list:
                rel_counts[edge.relationship_type] += 1
                total_edges += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": total_edges,
            "node_distribution": dict(type_counts),
            "relationship_distribution": dict(rel_counts),
            "connected_components_count": len(self.find_connected_components()),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary for JSON reports."""
        nodes_list = [n.to_dict() for n in self.nodes.values()]
        edges_list = []
        for edge_list in self.adj.values():
            for edge in edge_list:
                edges_list.append(edge.to_dict())
        return {
            "metrics": self.get_metrics(),
            "nodes": nodes_list,
            "edges": edges_list,
        }
