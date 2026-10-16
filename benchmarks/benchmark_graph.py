"""Benchmark graph construction and traversal algorithms (BFS and DFS).

Measures:
- Adjacency list construction time across varying vertex and edge densities
- BFS and DFS traversal latencies across vertex counts (50, 200, 1000, 5000)
- Traversal completeness (visited node count)
- Median filtering over multiple repetitions using time.perf_counter()
"""

from __future__ import annotations

import csv
import json
import random
import statistics
import time
from pathlib import Path
from typing import Any

from config import config
from graph import AssetGraph
from models import RelationshipType


def generate_synthetic_asset_graph(
    subdomain_count: int,
    ip_count: int,
    services_per_ip: int = 2,
    seed: int = 42,
) -> AssetGraph:
    """Construct deterministic multi-relational asset graph for scaling benchmarks."""
    rng = random.Random(seed)
    g = AssetGraph()

    root = "target-corp.com"
    g.add_node(root, "Domain")

    # Generate subdomains
    subdomains = [f"sub-{i}.target-corp.com" for i in range(subdomain_count)]
    for sub in subdomains:
        g.add_node(sub, "Subdomain")
        g.add_edge(root, sub, RelationshipType.HAS_SUBDOMAIN)

    # Generate IP pool
    ips = [f"198.51.100.{i % 250}" if i < 250 else f"203.0.113.{i % 250}" for i in range(ip_count)]
    for ip in ips:
        g.add_node(ip, "IPAddress")

    # Connect subdomains to IPs (some subdomains share IPs)
    for sub in subdomains:
        assigned_ip = rng.choice(ips)
        g.add_edge(sub, assigned_ip, RelationshipType.RESOLVES_TO)

    # Attach endpoints and services to IPs
    ports = [22, 80, 443, 8080, 3306]
    for ip in ips:
        for p in ports[:services_per_ip]:
            ep_id = f"{ip}:{p}"
            g.add_node(ep_id, "Endpoint")
            g.add_edge(ip, ep_id, RelationshipType.EXPOSES_PORT)

            svc_id = f"service_{ip}_{p}"
            g.add_node(svc_id, "Service", {"product": "TestProduct"})
            g.add_edge(ep_id, svc_id, RelationshipType.RUNS_SERVICE)

    return g


def run_graph_benchmarks(
    scales: tuple[tuple[int, int], ...] = (
        (50, 10),      # Small
        (200, 30),     # Medium
        (1000, 100),   # Large
        (3000, 250),   # Enterprise
        (6000, 500),   # Stress test
    ),
    repetitions: int = 5,
    save_results: bool = True,
) -> list[dict[str, Any]]:
    """Execute graph scaling benchmarks and measure BFS vs DFS latency."""
    results: list[dict[str, Any]] = []

    for sub_count, ip_count in scales:
        # 1. Construction Benchmark
        build_times = []
        for _ in range(repetitions):
            t0 = time.perf_counter()
            _ = generate_synthetic_asset_graph(sub_count, ip_count, seed=4000 + sub_count)
            build_times.append(time.perf_counter() - t0)

        # Baseline graph instance for traversals
        test_graph = generate_synthetic_asset_graph(sub_count, ip_count, seed=4000 + sub_count)
        v_count = len(test_graph.nodes)
        e_count = sum(len(el) for el in test_graph.adj.values())

        root_id = "target-corp.com"

        # 2. BFS Traversal Benchmark
        bfs_times = []
        bfs_visited = None
        for _ in range(repetitions):
            t0 = time.perf_counter()
            bfs_visited = test_graph.bfs(root_id)
            bfs_times.append(time.perf_counter() - t0)

        # 3. DFS Traversal Benchmark
        dfs_times = []
        dfs_visited = None
        for _ in range(repetitions):
            t0 = time.perf_counter()
            dfs_visited = test_graph.dfs(root_id)
            dfs_times.append(time.perf_counter() - t0)

        assert bfs_visited is not None and dfs_visited is not None

        row = {
            "subdomain_count": sub_count,
            "ip_count": ip_count,
            "vertex_count": v_count,
            "edge_count": e_count,
            "build_time_ms": round(statistics.median(build_times) * 1000, 4),
            "bfs_runtime_ms": round(statistics.median(bfs_times) * 1000, 4),
            "bfs_visited_count": len(bfs_visited),
            "dfs_runtime_ms": round(statistics.median(dfs_times) * 1000, 4),
            "dfs_visited_count": len(dfs_visited),
            "traversal_equivalent_coverage": len(bfs_visited) == len(dfs_visited),
        }
        results.append(row)

    if save_results:
        out_dir = config.BENCHMARKS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        json_file = out_dir / "graph_benchmark.json"
        csv_file = out_dir / "graph_benchmark.csv"

        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        if results:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)

    return results


if __name__ == "__main__":
    print("[*] Running asset correlation graph benchmarks...")
    bench_results = run_graph_benchmarks()
    print(f"[+] Completed {len(bench_results)} graph scaling experiments.")
    for res in bench_results:
        print(f"  V={res['vertex_count']}, E={res['edge_count']}: Build={res['build_time_ms']}ms, "
              f"BFS={res['bfs_runtime_ms']}ms, DFS={res['dfs_runtime_ms']}ms (Visited: {res['bfs_visited_count']})")
