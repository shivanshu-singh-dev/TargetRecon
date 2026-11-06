"""Probe scheduling strategies using Data Structures & Algorithms concepts.

Implements three selection strategies under a finite probe budget:
1. Discovery-order baseline (First-fit in arrival sequence)
2. Greedy heuristic (Value-to-cost ratio maximization)
3. 0/1 Knapsack Dynamic Programming (Exact optimal subset selection)

Includes mathematical documentation, recurrence relations, complexity bounds,
and optimality verification.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Iterable

from models import ProbeCandidate


@dataclass
class ScheduleResult:
    """Outcome of a probe scheduling algorithm execution."""
    strategy_name: str
    selected_probes: list[ProbeCandidate]
    total_cost: int
    total_value: int
    budget: int
    candidate_count: int
    selected_count: int
    is_optimal: bool = False
    guaranteed_optimal: bool = False
    matched_optimal_value: bool = False
    approximation_ratio: float = 1.0
    budget_is_restrictive: bool = True
    all_candidates: list[dict[str, Any]] = field(default_factory=list)
    runtime_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name,
            "selected_count": self.selected_count,
            "candidate_count": self.candidate_count,
            "total_cost": self.total_cost,
            "total_value": self.total_value,
            "budget": self.budget,
            "is_optimal": self.is_optimal,
            "guaranteed_optimal": self.guaranteed_optimal,
            "matched_optimal_value": self.matched_optimal_value,
            "approximation_ratio": self.approximation_ratio,
            "budget_is_restrictive": self.budget_is_restrictive,
            "runtime_seconds": self.runtime_seconds,
            "selected_probe_ids": [p.probe_id for p in self.selected_probes],
            "all_candidates": self.all_candidates,
        }


def generate_candidate_probes(
    hosts: Iterable[str],
    ports: tuple[int, ...] = (21, 22, 25, 80, 443, 3306, 8080),
    source_counts: dict[str, int] | None = None,
    resolves_map: dict[str, bool] | None = None,
) -> list[ProbeCandidate]:
    """Derive prioritized candidate probes for discovered hosts.

    Cost model (illustrative for DAA lab coursework evaluation):
    - Standard Web ports (80, 443): Cost 2 (fast HTTP probes)
    - Interactive/Stateful ports (22, 21, 25): Cost 3 (socket handshake & banner)
    - Database/Secondary ports (3306, 8080): Cost 4 (slower response/negotiation)

    Value model (illustrative):
    - Higher value for hosts with multiple corroborating passive sources (+2 per source).
    - Higher value (+3) if active DNS confirms host resolution.
    - Base port relevance (SSH=8, HTTPS=7, HTTP=6, DB=5, others=3).
    """
    source_counts = source_counts or {}
    resolves_map = resolves_map or {}
    candidates: list[ProbeCandidate] = []

    port_costs = {80: 2, 443: 2, 22: 3, 21: 3, 25: 3, 3306: 4, 8080: 3}
    port_values = {22: 8, 443: 7, 80: 6, 3306: 5, 21: 4, 25: 4, 8080: 5}

    for host in sorted(hosts):
        sources = source_counts.get(host, 1)
        resolves = resolves_map.get(host, True)

        for port in ports:
            cost = port_costs.get(port, 3)
            base_val = port_values.get(port, 3)
            # Additive value bonuses
            value = base_val + (sources * 2) + (3 if resolves else 0)
            reason = f"Port {port} on {host} (sources={sources}, resolves={resolves})"

            candidates.append(
                ProbeCandidate(
                    probe_id=f"probe_{host}_{port}",
                    host=host,
                    port=port,
                    protocol="tcp",
                    cost=cost,
                    value=value,
                    reason=reason,
                    selected=False,
                )
            )

    return candidates


# ============================================================================
# Strategy A: Discovery-Order Baseline
# ============================================================================
def schedule_discovery_order(
    candidates: list[ProbeCandidate], budget: int
) -> ScheduleResult:
    """Strategy A: Select probes in first-fit discovery order.

    Greedily includes each probe encountered if the remaining budget permits.
    Time Complexity: O(n)
    Space Complexity: O(n) to store selected probes.
    """
    if budget <= 0 or not candidates:
        return ScheduleResult(
            strategy_name="Discovery-Order",
            selected_probes=[],
            total_cost=0,
            total_value=0,
            budget=budget,
            candidate_count=len(candidates),
            selected_count=0,
        )

    selected: list[ProbeCandidate] = []
    current_cost = 0
    current_value = 0

    for cand in candidates:
        cand_cost = max(1, cand.cost)
        if current_cost + cand_cost <= budget:
            c_copy = copy.copy(cand)
            c_copy.selected = True
            selected.append(c_copy)
            current_cost += cand_cost
            current_value += cand.value

    return ScheduleResult(
        strategy_name="Discovery-Order",
        selected_probes=selected,
        total_cost=current_cost,
        total_value=current_value,
        budget=budget,
        candidate_count=len(candidates),
        selected_count=len(selected),
    )


# ============================================================================
# Strategy B: Greedy Selection Heuristic
# ============================================================================
def schedule_greedy(
    candidates: list[ProbeCandidate], budget: int
) -> ScheduleResult:
    """Strategy B: Rank candidate probes by value-to-cost ratio.

    Sorts candidates descending by efficiency ratio (value / cost).
    Ties broken by higher absolute value, then smaller cost.
    Safely clamps invalid/zero costs to 1.

    Time Complexity: O(n log n) due to sorting.
    Space Complexity: O(n) for sorted items and selection.
    """
    if budget <= 0 or not candidates:
        return ScheduleResult(
            strategy_name="Greedy-Ratio",
            selected_probes=[],
            total_cost=0,
            total_value=0,
            budget=budget,
            candidate_count=len(candidates),
            selected_count=0,
        )

    # Sort descending by ratio, then value, then ascending cost
    def sort_key(item: ProbeCandidate) -> tuple[float, int, int]:
        eff_cost = max(1, item.cost)
        ratio = item.value / eff_cost
        return (ratio, item.value, -eff_cost)

    sorted_candidates = sorted(candidates, key=sort_key, reverse=True)

    selected: list[ProbeCandidate] = []
    current_cost = 0
    current_value = 0

    for cand in sorted_candidates:
        cand_cost = max(1, cand.cost)
        if current_cost + cand_cost <= budget:
            c_copy = copy.copy(cand)
            c_copy.selected = True
            selected.append(c_copy)
            current_cost += cand_cost
            current_value += cand.value

    return ScheduleResult(
        strategy_name="Greedy-Ratio",
        selected_probes=selected,
        total_cost=current_cost,
        total_value=current_value,
        budget=budget,
        candidate_count=len(candidates),
        selected_count=len(selected),
    )


# ============================================================================
# Strategy C: 0/1 Knapsack Dynamic Programming
# ============================================================================
def schedule_knapsack_dp(
    candidates: list[ProbeCandidate], budget: int
) -> ScheduleResult:
    """Strategy C: Exact 0/1 Knapsack Dynamic Programming.

    Problem Formulation:
        Maximize:   sum(cand.value * x_i) for i in 1..n
        Subject to: sum(cand.cost * x_i) <= budget
                    x_i in {0, 1}

    Recurrence Relation:
        Let dp[i][w] be the maximum value achievable using a subset of the
        first i candidates with total cost at most w.

        Base Cases:
            dp[0][w] = 0 for all 0 <= w <= budget
            dp[i][0] = 0 for all 0 <= i <= n

        State Transition:
            For i in 1..n:
                cost_i = max(1, candidates[i-1].cost)
                val_i  = candidates[i-1].value
                For w in 0..budget:
                    if cost_i > w:
                        dp[i][w] = dp[i-1][w]
                    else:
                        dp[i][w] = max(dp[i-1][w], dp[i-1][w - cost_i] + val_i)

    Table Reconstruction:
        Trace back from dp[n][budget]:
        If dp[i][w] != dp[i-1][w], candidate[i-1] was included;
        decrement w by cost_i and continue to i-1.

    Algorithmic Complexity:
        Time Complexity:  O(n * B) where n is candidate count, B is budget.
        Space Complexity: O(n * B) storing the full 2D matrix to permit
                          exact backtracking reconstruction.
    """
    if budget <= 0 or not candidates:
        return ScheduleResult(
            strategy_name="0/1-Knapsack-DP",
            selected_probes=[],
            total_cost=0,
            total_value=0,
            budget=budget,
            candidate_count=len(candidates),
            selected_count=0,
            is_optimal=True,
        )

    n = len(candidates)
    B = budget

    # Initialize (n+1) x (B+1) table with zeros
    dp: list[list[int]] = [[0] * (B + 1) for _ in range(n + 1)]

    # Fill DP Table
    for i in range(1, n + 1):
        cost_i = max(1, candidates[i - 1].cost)
        val_i = candidates[i - 1].value
        for w in range(B + 1):
            if cost_i > w:
                dp[i][w] = dp[i - 1][w]
            else:
                without_item = dp[i - 1][w]
                with_item = dp[i - 1][w - cost_i] + val_i
                dp[i][w] = with_item if with_item > without_item else without_item

    # Reconstruction of Selected Items
    selected: list[ProbeCandidate] = []
    w = B
    for i in range(n, 0, -1):
        cost_i = max(1, candidates[i - 1].cost)
        # If value differs from cell above, item i-1 was included
        if dp[i][w] != dp[i - 1][w]:
            c_copy = copy.copy(candidates[i - 1])
            c_copy.selected = True
            selected.append(c_copy)
            w -= cost_i

    # Reverse to preserve original candidate sequence
    selected.reverse()

    total_cost = sum(max(1, p.cost) for p in selected)
    total_value = dp[n][B]

    return ScheduleResult(
        strategy_name="0/1-Knapsack-DP",
        selected_probes=selected,
        total_cost=total_cost,
        total_value=total_value,
        budget=budget,
        candidate_count=n,
        selected_count=len(selected),
        is_optimal=True,
    )


# ============================================================================
# Strategy Comparator
# ============================================================================
def compare_strategies(
    candidates: list[ProbeCandidate], budget: int
) -> dict[str, ScheduleResult]:
    """Execute and compare all three scheduling strategies."""
    dp_res = schedule_knapsack_dp(candidates, budget)
    greedy_res = schedule_greedy(candidates, budget)
    discovery_res = schedule_discovery_order(candidates, budget)

    total_candidate_cost = sum(c.cost for c in candidates)
    is_restrictive = budget < total_candidate_cost

    cand_summaries = [
        {
            "probe_id": c.probe_id,
            "host": c.host,
            "port": c.port,
            "cost": c.cost,
            "value": c.value,
            "efficiency_ratio": round(c.value / max(1, c.cost), 3),
            "reason": c.reason,
        }
        for c in candidates
    ]

    # Knapsack DP is mathematically guaranteed optimal for 0/1 knapsack
    dp_res.guaranteed_optimal = True
    dp_res.matched_optimal_value = True
    dp_res.approximation_ratio = 1.0
    dp_res.is_optimal = True
    dp_res.budget_is_restrictive = is_restrictive
    dp_res.all_candidates = cand_summaries

    # Greedy ratio has NO mathematical guarantee for discrete 0/1 items
    greedy_res.guaranteed_optimal = False
    greedy_res.matched_optimal_value = (greedy_res.total_value == dp_res.total_value)
    greedy_res.is_optimal = greedy_res.matched_optimal_value
    greedy_res.approximation_ratio = round(greedy_res.total_value / max(1, dp_res.total_value), 4)
    greedy_res.budget_is_restrictive = is_restrictive
    greedy_res.all_candidates = cand_summaries

    # Discovery-order baseline (first-fit arrival order)
    discovery_res.guaranteed_optimal = False
    discovery_res.matched_optimal_value = (discovery_res.total_value == dp_res.total_value)
    discovery_res.is_optimal = discovery_res.matched_optimal_value
    discovery_res.approximation_ratio = round(discovery_res.total_value / max(1, dp_res.total_value), 4)
    discovery_res.budget_is_restrictive = is_restrictive
    discovery_res.all_candidates = cand_summaries

    return {
        "knapsack_dp": dp_res,
        "greedy": greedy_res,
        "discovery_order": discovery_res,
    }
