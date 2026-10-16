"""Benchmark multi-pattern matching: Aho-Corasick vs Naive baseline.

Measures:
- Preprocessing / construction time (Trie + failure links)
- Text matching time across pattern counts (10, 50, 100, 500, 1000) and varying banner lengths
- Verifies output equivalence between Aho-Corasick and NaiveMatcher
- Median filtering over multiple repetitions using time.perf_counter()
"""

from __future__ import annotations

import csv
import json
import random
import statistics
import string
import time
from pathlib import Path
from typing import Any

from config import config
from banner.matcher import AhoCorasick, NaiveMatcher, Signature


def generate_synthetic_signatures(count: int, seed: int = 42) -> list[Signature]:
    """Generate deterministic signature sets of varying lengths."""
    rng = random.Random(seed)
    signatures: list[Signature] = []
    base_words = [
        "OpenSSH", "nginx", "Apache", "Ubuntu", "Debian", "Microsoft-IIS",
        "Postfix", "vsftpd", "Pure-FTPd", "LiteSpeed", "envoy", "cloudflare",
        "CentOS", "Alpine", "RedHat", "Caddy", "ProFTPD", "Exim", "MySQL", "MariaDB"
    ]

    for i in range(count):
        word = rng.choice(base_words)
        suffix = "".join(rng.choices(string.ascii_letters + string.digits, k=rng.randint(2, 6)))
        pat = f"{word}_{suffix}"
        signatures.append(
            Signature(
                id=f"sig_{i}",
                pattern=pat,
                product=f"Product_{word}",
                protocol="TCP",
                category="Benchmark",
            )
        )
    return signatures


def generate_synthetic_text(length: int, planted_signatures: list[Signature], seed: int = 99) -> str:
    """Generate synthetic banner corpus with planted signatures."""
    rng = random.Random(seed)
    chars = string.ascii_letters + string.digits + " /.-_:\r\n"
    raw_chars = [rng.choice(chars) for _ in range(length)]

    # Plant a subset of signatures into random positions
    if planted_signatures:
        for _ in range(min(20, len(planted_signatures))):
            sig = rng.choice(planted_signatures)
            p_len = len(sig.pattern)
            if length > p_len + 5:
                pos = rng.randint(0, length - p_len - 1)
                raw_chars[pos : pos + p_len] = list(sig.pattern)

    return "".join(raw_chars)


def run_matcher_benchmarks(
    sig_counts: tuple[int, ...] = (10, 50, 100, 250, 500, 1000),
    text_lengths: tuple[int, ...] = (500, 2000, 8000),
    repetitions: int = 5,
    save_results: bool = True,
) -> list[dict[str, Any]]:
    """Execute string matching benchmarks and verify semantic equivalence."""
    results: list[dict[str, Any]] = []

    for k in sig_counts:
        signatures = generate_synthetic_signatures(k, seed=2000 + k)

        for text_len in text_lengths:
            banner_text = generate_synthetic_text(text_len, signatures, seed=3000 + text_len)

            # 1. Aho-Corasick Construction Benchmark
            ac_build_times = []
            for _ in range(repetitions):
                t0 = time.perf_counter()
                ac = AhoCorasick(case_sensitive=False)
                for s in signatures:
                    ac.add_signature(s)
                ac.build()
                ac_build_times.append(time.perf_counter() - t0)

            # Ready-to-search AC instance
            ac_instance = AhoCorasick(case_sensitive=False)
            for s in signatures:
                ac_instance.add_signature(s)
            ac_instance.build()

            # 2. Aho-Corasick Search Benchmark
            ac_search_times = []
            ac_matches = None
            for _ in range(repetitions):
                t0 = time.perf_counter()
                ac_matches = ac_instance.search(banner_text)
                ac_search_times.append(time.perf_counter() - t0)

            # 3. Naive Matcher Benchmark
            naive_instance = NaiveMatcher(case_sensitive=False)
            for s in signatures:
                naive_instance.add_signature(s)

            naive_search_times = []
            naive_matches = None
            for _ in range(repetitions):
                t0 = time.perf_counter()
                naive_matches = naive_instance.search(banner_text)
                naive_search_times.append(time.perf_counter() - t0)

            # 4. Verify semantic equivalence
            assert ac_matches is not None and naive_matches is not None
            equivalent = len(ac_matches) == len(naive_matches)
            if equivalent:
                for m1, m2 in zip(ac_matches, naive_matches):
                    if m1.pattern_id != m2.pattern_id or m1.start_pos != m2.start_pos:
                        equivalent = False
                        break

            ac_search_med = statistics.median(ac_search_times) * 1000
            naive_search_med = statistics.median(naive_search_times) * 1000
            speedup = (naive_search_med / ac_search_med) if ac_search_med > 0 else 1.0

            row = {
                "signature_count": k,
                "text_length": text_len,
                "match_count": len(ac_matches),
                "is_equivalent": equivalent,
                "ac_build_time_ms": round(statistics.median(ac_build_times) * 1000, 4),
                "ac_search_time_ms": round(ac_search_med, 4),
                "naive_search_time_ms": round(naive_search_med, 4),
                "ac_speedup_factor": round(speedup, 2),
            }
            results.append(row)

    if save_results:
        out_dir = config.BENCHMARKS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        json_file = out_dir / "matcher_benchmark.json"
        csv_file = out_dir / "matcher_benchmark.csv"

        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        if results:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)

    return results


if __name__ == "__main__":
    print("[*] Running multi-pattern matcher benchmarks...")
    bench_results = run_matcher_benchmarks()
    print(f"[+] Completed {len(bench_results)} matcher benchmark tests.")
    for res in bench_results[:4]:
        print(f"  Sigs={res['signature_count']}, TextLen={res['text_length']}: AC={res['ac_search_time_ms']}ms, "
              f"Naive={res['naive_search_time_ms']}ms, Speedup={res['ac_speedup_factor']}x (Equivalent: {res['is_equivalent']})")
