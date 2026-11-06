"""Unit tests for the FastAPI backend adapter endpoints."""

import pytest
from fastapi import BackgroundTasks, HTTPException
from api_server import (
    BannerMatchRequest,
    GraphTraverseRequest,
    RunCreateRequest,
    SchedulerTestRequest,
    create_run,
    get_benchmark_results,
    get_health,
    get_run_assets,
    get_run_details,
    get_run_findings,
    get_run_graph,
    list_runs,
    api_banner_match,
    api_graph_traversal,
    api_scheduler,
)


def test_get_health():
    """Verify health endpoint reports tools and signature metrics."""
    health = get_health()
    assert health["status"] == "healthy"
    assert "version" in health
    assert "external_tools" in health
    assert health["signatures_count"] > 10


def test_list_runs_includes_historical_simulation():
    """Verify indexing of reports from disk into runs list."""
    runs = list_runs()
    assert isinstance(runs, list)
    assert any(r["run_id"] == "simulation_report" for r in runs)


def test_get_run_details_and_assets():
    """Verify retrieving complete report and assets for simulation_report."""
    details = get_run_details("simulation_report")
    assert details["run_id"] == "simulation_report"
    assert details["status"] == "completed"

    assets = get_run_assets("simulation_report")
    assert len(assets["subdomains"]) > 0
    assert len(assets["ip_addresses"]) > 0

    graph = get_run_graph("simulation_report")
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0

    findings = get_run_findings("simulation_report")
    assert isinstance(findings, list)


def test_active_run_creation_auto_scope():
    """Verify active run creation accepts requests and auto-populates scope if empty."""
    res = create_run(
        RunCreateRequest(
            target_domain="example.com",
            mode="active",
        ),
        BackgroundTasks(),
    )
    assert res["status"] == "queued"
    assert "active" in res["run_id"]


def test_live_banner_matching_endpoint():
    """Verify live Aho-Corasick matching endpoint."""
    banner_text = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2"
    res = api_banner_match(BannerMatchRequest(banner=banner_text))

    assert res["is_equivalent"] is True
    assert len(res["ac_matches"]) > 0
    assert any(m["product"] == "OpenSSH" for m in res["ac_matches"])
    assert res["extracted_versions"].get("OpenSSH") == "9.3p1"


def test_live_scheduler_endpoint():
    """Verify live probe scheduler comparison endpoint."""
    res = api_scheduler(SchedulerTestRequest(budget=20, candidate_count=15))

    assert res["budget"] == 20
    assert "knapsack_dp" in res["results"]
    assert "greedy" in res["results"]
    assert "discovery_order" in res["results"]
    assert res["results"]["knapsack_dp"]["is_optimal"] is True


def test_live_graph_traversal_endpoint():
    """Verify BFS and DFS traversal on simulation graph."""
    bfs_res = api_graph_traversal(
        GraphTraverseRequest(run_id="simulation_report", algorithm="bfs", start_node_id="example.com")
    )
    assert bfs_res["algorithm"] == "BFS"
    assert len(bfs_res["traversal_order"]) > 0
    assert bfs_res["traversal_order"][0] == "example.com"

    dfs_res = api_graph_traversal(
        GraphTraverseRequest(run_id="simulation_report", algorithm="dfs", start_node_id="example.com")
    )
    assert dfs_res["algorithm"] == "DFS"
    assert len(dfs_res["traversal_order"]) == len(bfs_res["traversal_order"])


def test_get_benchmark_results_endpoint():
    """Verify retrieving benchmark metrics."""
    res = get_benchmark_results()
    assert "scheduler" in res
    assert "matcher" in res
    assert "graph" in res
    assert len(res["scheduler"]) > 0
    assert len(res["matcher"]) > 0
    assert len(res["graph"]) > 0
