"""Unit tests for probe scheduling algorithms (Discovery, Greedy, 0/1 Knapsack DP)."""

import pytest
from models import ProbeCandidate
from scheduler import (
    compare_strategies,
    generate_candidate_probes,
    schedule_discovery_order,
    schedule_greedy,
    schedule_knapsack_dp,
)


def test_knapsack_known_optimal():
    """Verify DP yields exact mathematical optimum for a classic knapsack instance."""
    # Classic textbook instance:
    # Item 0: cost 1, value 1
    # Item 1: cost 2, value 6
    # Item 2: cost 3, value 10
    # Item 3: cost 5, value 16
    # Budget = 7
    # Optimal subset: items {1, 3} (cost 2+5=7, value 6+16=22) or items {0, 2, 3} (cost 1+3+5=9 > 7)
    # Check possible combinations under 7:
    # {1, 2} cost 5, val 16
    # {0, 1, 2} cost 6, val 17
    # {1, 3} cost 7, val 22
    # Optimum is 22.
    candidates = [
        ProbeCandidate("p0", "host.com", 80, "tcp", cost=1, value=1),
        ProbeCandidate("p1", "host.com", 443, "tcp", cost=2, value=6),
        ProbeCandidate("p2", "host.com", 22, "tcp", cost=3, value=10),
        ProbeCandidate("p3", "host.com", 8080, "tcp", cost=5, value=16),
    ]

    result = schedule_knapsack_dp(candidates, budget=7)
    assert result.total_value == 22
    assert result.total_cost == 7
    selected_ids = {p.probe_id for p in result.selected_probes}
    assert selected_ids == {"p1", "p3"}


def test_greedy_is_suboptimal():
    """Demonstrate a scenario where Greedy heuristic fails to reach the DP optimum."""
    # Instance where Greedy takes highest ratio item and blocks better combination:
    # Item A: cost 6, value 7 (ratio = 7/6 = 1.1667)
    # Item B: cost 5, value 5 (ratio = 5/5 = 1.0)
    # Item C: cost 5, value 5 (ratio = 5/5 = 1.0)
    # Budget = 10
    #
    # Greedy:
    # Ratios: A (1.1667) > B (1.0) == C (1.0)
    # Greedy picks A (cost 6, val 7). Remaining budget = 4.
    # Cannot pick B (cost 5 > 4) or C (cost 5 > 4).
    # Greedy Total Value = 7.
    #
    # 0/1 Knapsack DP:
    # Can pick B + C: cost = 5 + 5 = 10, total value = 10.
    # DP Total Value = 10 > Greedy Total Value = 7.
    candidates = [
        ProbeCandidate("itemA", "target", 80, cost=6, value=7),
        ProbeCandidate("itemB", "target", 443, cost=5, value=5),
        ProbeCandidate("itemC", "target", 22, cost=5, value=5),
    ]

    dp_res = schedule_knapsack_dp(candidates, budget=10)
    greedy_res = schedule_greedy(candidates, budget=10)

    assert dp_res.total_value == 10
    assert dp_res.total_cost == 10
    assert {p.probe_id for p in dp_res.selected_probes} == {"itemB", "itemC"}

    assert greedy_res.total_value == 7
    assert greedy_res.total_cost == 6
    assert {p.probe_id for p in greedy_res.selected_probes} == {"itemA"}

    # Assert DP strictly outperforms greedy
    assert dp_res.total_value > greedy_res.total_value


def test_discovery_order_baseline():
    """Verify discovery-order takes probes strictly in input arrival order."""
    candidates = [
        ProbeCandidate("p1", "host.com", 80, cost=3, value=10),
        ProbeCandidate("p2", "host.com", 443, cost=4, value=20),
        ProbeCandidate("p3", "host.com", 22, cost=3, value=15),
    ]
    # Budget = 6
    # p1 fits (cost 3, val 10). Remaining 3.
    # p2 does not fit (cost 4 > 3).
    # p3 fits (cost 3 <= 3). Remaining 0.
    # Discovery picks p1 and p3. Total cost 6, total value 25.
    result = schedule_discovery_order(candidates, budget=6)
    assert result.total_cost == 6
    assert result.total_value == 25
    assert [p.probe_id for p in result.selected_probes] == ["p1", "p3"]


def test_edge_cases_empty_and_zero_budget():
    """Verify safe handling of zero budget and empty candidate lists."""
    assert schedule_knapsack_dp([], 10).total_value == 0
    assert schedule_greedy([], 10).total_value == 0
    assert schedule_discovery_order([], 10).total_value == 0

    cands = [ProbeCandidate("p1", "h", 80, cost=5, value=10)]
    assert schedule_knapsack_dp(cands, 0).total_value == 0
    assert schedule_greedy(cands, 0).total_value == 0
    assert schedule_discovery_order(cands, 0).total_value == 0


def test_edge_case_all_costs_exceed_budget():
    """Verify behavior when no probe can fit in the budget."""
    cands = [
        ProbeCandidate("p1", "h", 80, cost=10, value=20),
        ProbeCandidate("p2", "h", 443, cost=15, value=30),
    ]
    assert schedule_knapsack_dp(cands, 5).selected_count == 0
    assert schedule_greedy(cands, 5).selected_count == 0
    assert schedule_discovery_order(cands, 5).selected_count == 0


def test_edge_case_equal_values_and_costs():
    """Verify behavior when all items have identical cost and value."""
    cands = [
        ProbeCandidate(f"p{i}", "h", 80 + i, cost=2, value=5)
        for i in range(5)
    ]
    # Budget = 6 allows exactly 3 items: value = 15, cost = 6
    dp_res = schedule_knapsack_dp(cands, 6)
    assert dp_res.total_value == 15
    assert dp_res.total_cost == 6
    assert dp_res.selected_count == 3


def test_compare_strategies():
    """Verify comparator execution and annotation of optimality."""
    cands = [
        ProbeCandidate("itemA", "target", 80, cost=6, value=7),
        ProbeCandidate("itemB", "target", 443, cost=5, value=5),
        ProbeCandidate("itemC", "target", 22, cost=5, value=5),
    ]
    comp = compare_strategies(cands, budget=10)
    assert comp["knapsack_dp"].is_optimal is True
    assert comp["greedy"].is_optimal is False


def test_candidate_generation():
    """Verify deterministic candidate probe generation with source-aware heuristic."""
    hosts = ["api.example.com", "example.com"]
    sources = {"api.example.com": 3, "example.com": 1}
    resolves = {"api.example.com": True, "example.com": False}

    probes = generate_candidate_probes(hosts, ports=(80, 22), source_counts=sources, resolves_map=resolves)
    assert len(probes) == 4
    # api.example.com has 3 sources and resolves: should have higher value than example.com
    api_probe = next(p for p in probes if p.host == "api.example.com" and p.port == 22)
    root_probe = next(p for p in probes if p.host == "example.com" and p.port == 22)
    assert api_probe.value > root_probe.value
