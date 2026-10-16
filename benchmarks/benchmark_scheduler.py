"""Benchmark probe scheduling algorithms: Discovery-Order vs Greedy vs 0/1 Knapsack DP.

Measures runtime (using time.perf_counter() over multiple repetitions and median filtering),
value collected, budget consumed, probe count, and optimality across synthetic datasets.
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
from models import ProbeCandidate
from scheduler import schedule_discovery_order, schedule_greedy, schedule_knapsack_dp


def generate_synthetic_probes(count: int, seed: int = 42) -> list[ProbeCandidate]:
    """Generate deterministic synthetic candidate probes."""
    rng = random.Random(seed)
    candidates: list[ProbeCandidate] = []
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443]

    for i in range(count):
        host = f"host-{i % 100}.internal"
        port = rng.choice(ports)
        cost = rng.randint(1, 10)
        value = rng.randint(2, 40)
        candidates.append(
            ProbeCandidate(
                probe_id=f"probe_{i}_{host}_{port}",
                host=host,
                port=port,
                protocol="tcp",
                cost=cost,
                value=value,
                reason=f"Synthetic probe {i}",
            )
        )
    return candidates


def run_scheduler_benchmarks(
    sizes: tuple[int, ...] = (10, 50, 100, 250, 500, 1000),
    budget_ratios: tuple[float, ...] = (0.2, 0.4),
    repetitions: int = 5,
    save_results: bool = True,
) -> list[dict[str, Any]]:
    """Execute scheduling benchmarks and collect performance statistics."""
    results: list[dict[str, Any]] = []

    for size in sizes:
        candidates = generate_synthetic_probes(size, seed=1000 + size)
        total_candidate_cost = sum(c.cost for c in candidates)

        for ratio in budget_ratios:
            budget = max(5, int(total_candidate_cost * ratio))

            # Run Discovery-Order repetitions
            disc_times = []
            disc_res = None
            for _ in range(repetitions):
                t0 = time.perf_counter()
                disc_res = schedule_discovery_order(candidates, budget)
                disc_times.append(time.perf_counter() - t0)

            # Run Greedy repetitions
            greedy_times = []
            greedy_res = None
            for _ in range(repetitions):
                t0 = time.perf_counter()
                greedy_res = schedule_greedy(candidates, budget)
                greedy_times.append(time.perf_counter() - t0)

            # Run 0/1 Knapsack DP repetitions
            dp_times = []
            dp_res = None
            for _ in range(repetitions):
                t0 = time.perf_counter()
                dp_res = schedule_knapsack_dp(candidates, budget)
                dp_times.append(time.perf_counter() - t0)

            assert disc_res and greedy_res and dp_res

            opt_val = dp_res.total_value
            row = {
                "candidate_count": size,
                "budget": budget,
                "budget_ratio": ratio,
                # Dynamic Programming
                "dp_value": dp_res.total_value,
                "dp_cost": dp_res.total_cost,
                "dp_selected_count": dp_res.selected_count,
                "dp_runtime_ms": round(statistics.median(dp_times) * 1000, 4),
                # Greedy
                "greedy_value": greedy_res.total_value,
                "greedy_cost": greedy_res.total_cost,
                "greedy_selected_count": greedy_res.selected_count,
                "greedy_runtime_ms": round(statistics.median(greedy_times) * 1000, 4),
                "greedy_optimal": greedy_res.total_value == opt_val,
                "greedy_efficiency_pct": round((greedy_res.total_value / opt_val * 100) if opt_val else 100.0, 2),
                # Discovery-Order
                "discovery_value": disc_res.total_value,
                "discovery_cost": disc_res.total_cost,
                "discovery_selected_count": disc_res.selected_count,
                "discovery_runtime_ms": round(statistics.median(disc_times) * 1000, 4),
                "discovery_optimal": disc_res.total_value == opt_val,
                "discovery_efficiency_pct": round((disc_res.total_value / opt_val * 100) if opt_val else 100.0, 2),
            }
            results.append(row)

    if save_results:
        out_dir = config.BENCHMARKS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        json_file = out_dir / "scheduler_benchmark.json"
        csv_file = out_dir / "scheduler_benchmark.csv"

        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        if results:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)

    return results


if __name__ == "__main__":
    print("[*] Running probe scheduler benchmarks...")
    bench_results = run_scheduler_benchmarks()
    print(f"[+] Completed {len(bench_results)} benchmark cases. Results saved in {config.BENCHMARKS_DIR}")
    for res in bench_results[:3]:
        print(f"  N={res['candidate_count']}, Budget={res['budget']}: DP Val={res['dp_value']} ({res['dp_runtime_ms']}ms), "
              f"Greedy Val={res['greedy_value']} (Optimal: {res['greedy_optimal']})")
