"""Command-Line Interface for Algorithm-Optimized Reconnaissance Framework.

Supports four safe execution workflows:
1. simulate: Fully offline, fixture-driven simulation; zero external network packets.
2. scan --mode passive: Collects publicly available OSINT data without probing services.
3. scan --mode active: Controlled active scanning strictly gated by allowlist and confirmation.
4. benchmark: Rigorous offline DAA performance experiments (Scheduler, Matcher, Graph).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from config import config
from models import (
    CollectionMethod,
    DiscoveredAssetInventory,
    Observation,
    RelationshipType,
    ServiceEndpoint,
    normalize_domain,
)
from scheduler import compare_strategies, generate_candidate_probes
from banner.grabber import grab_banner, identify_service, inspect_tls_certificate
from banner.matcher import (
    AhoCorasick,
    extract_software_version,
    load_signatures_from_file,
)
from graph import AssetGraph
from report import build_report_data, write_reports
from active.scope import ScopeManager, ScopeValidationError
from active.nmap_runner import parse_nmap_xml, run_nmap_scan
from active.dns_checks import verify_active_dns_records
from passive.crtsh import query_crtsh
from passive.dns_records import query_dns_records
from passive.whois_lookup import query_whois
from passive.theharvester import run_theharvester
from passive.indexed_services import (
    query_censys_hosts,
    query_censys_host,
    query_shodan_host,
    query_shodan_subdomains,
)
from benchmarks.benchmark_scheduler import run_scheduler_benchmarks
from benchmarks.benchmark_matcher import run_matcher_benchmarks
from benchmarks.benchmark_graph import run_graph_benchmarks

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger("recon_framework")


# ============================================================================
# Simulation Mode (Offline, Reproducible)
# ============================================================================
def run_simulation_mode(budget: int = 100) -> tuple[Path, Path]:
    """Execute end-to-end simulation using offline fixtures."""
    logger.info("=== Starting Offline Simulation Mode (Zero Network Traffic) ===")

    fixtures_path = config.FIXTURES_DIR / "passive_data.json"
    if not fixtures_path.is_file():
        logger.error("Simulation fixture not found: %s", fixtures_path)
        sys.exit(1)

    with open(fixtures_path, "r", encoding="utf-8") as f:
        fixture_data = json.load(f)

    target_domain = fixture_data.get("target_domain", "example.com")
    inventory = DiscoveredAssetInventory(root_domain=target_domain)

    # 1. Load Simulated Passive Subdomains
    for item in fixture_data.get("subdomains", []):
        sub = item["subdomain"]
        for src in item["sources"]:
            inventory.add_subdomain(sub, source=src, method=CollectionMethod.SIMULATED)

    # 2. Load Simulated DNS Records
    from models import DNSRecord
    for r in fixture_data.get("dns_records", []):
        rec = DNSRecord(
            record_type=r["record_type"],
            host=r["host"],
            value=r["value"],
            source=r["source"],
            ttl=r.get("ttl"),
        )
        inventory.add_dns_record(rec)
        if r["record_type"] in ("A", "AAAA"):
            inventory.add_ip(r["value"], source=r["source"], method=CollectionMethod.SIMULATED)

    # 3. Load Sample Nmap XML into Service Endpoints
    nmap_xml_path = config.FIXTURES_DIR / "nmap_sample.xml"
    if nmap_xml_path.is_file():
        xml_content = nmap_xml_path.read_text(encoding="utf-8")
        endpoints = parse_nmap_xml(xml_content, source="simulated_nmap")
        for ep in endpoints:
            inventory.add_service(ep)

    # 4. Banner Matching with Aho-Corasick on Fixture Banners
    banners_fixture_path = config.FIXTURES_DIR / "banners.json"
    matcher = AhoCorasick(case_sensitive=False)
    for sig in load_signatures_from_file(config.SIGNATURES_FILE):
        matcher.add_signature(sig)
    matcher.build()

    if banners_fixture_path.is_file():
        with open(banners_fixture_path, "r", encoding="utf-8") as f:
            banner_items = json.load(f)
        for b in banner_items:
            svc = identify_service(b["host"], b["port"], b["banner"], matcher=matcher)
            inventory.add_service(svc)

    # 5. DAA Probe Scheduling Comparison
    logger.info("Evaluating Probe Schedulers (Discovery vs Greedy vs 0/1 Knapsack DP)...")
    source_counts = {sub: len([o for o in inventory.observations if o.asset_id == sub]) for sub in inventory.subdomains}
    resolves_map = {sub: True for sub in inventory.subdomains if sub != "unresolved-legacy.example.com"}
    resolves_map["unresolved-legacy.example.com"] = False

    candidate_probes = generate_candidate_probes(
        hosts=list(inventory.subdomains) + [target_domain],
        ports=(22, 80, 443, 8080),
        source_counts=source_counts,
        resolves_map=resolves_map,
    )

    scheduler_results = compare_strategies(candidate_probes, budget=budget)
    dp_res = scheduler_results["knapsack_dp"]
    greedy_res = scheduler_results["greedy"]
    disc_res = scheduler_results["discovery_order"]

    logger.info(
        "Scheduler Results (Budget=%d): DP Value=%d (Cost=%d) | Greedy Value=%d (Cost=%d, Opt=%s) | Discovery Value=%d (Cost=%d)",
        budget,
        dp_res.total_value,
        dp_res.total_cost,
        greedy_res.total_value,
        greedy_res.total_cost,
        greedy_res.is_optimal,
        disc_res.total_value,
        disc_res.total_cost,
    )

    # 6. Build Asset Correlation Graph
    logger.info("Constructing Asset Correlation Graph...")
    graph = AssetGraph()
    graph.add_node(target_domain, "Domain", {"sources": ["input"]})

    for sub in inventory.subdomains:
        graph.add_node(sub, "Subdomain", {
            "sources": list({o.source for o in inventory.observations if o.asset_id == sub}),
            "discovered_passively": True,
        })
        graph.add_edge(target_domain, sub, RelationshipType.HAS_SUBDOMAIN)

    for rec in inventory.dns_records:
        if rec.record_type in ("A", "AAAA"):
            graph.add_node(rec.value, "IPAddress", {"source": rec.source})
            graph.add_edge(rec.host, rec.value, RelationshipType.RESOLVES_TO)

    for svc in inventory.services:
        graph.add_node(svc.host, "IPAddress")
        graph.add_node(svc.endpoint_id, "Endpoint", {"port": svc.port, "protocol": svc.protocol})
        graph.add_edge(svc.host, svc.endpoint_id, RelationshipType.EXPOSES_PORT)

        svc_node_id = f"service_{svc.endpoint_id}"
        graph.add_node(svc_node_id, "Service", {
            "service_name": svc.service_name,
            "product": svc.product,
            "version": svc.version,
            "banner_product": svc.product,
            "fingerprint_product": svc.product,
            "source": svc.source,
        })
        graph.add_edge(svc.endpoint_id, svc_node_id, RelationshipType.RUNS_SERVICE)

    # Graph Traversal Evaluations
    bfs_order = graph.bfs(target_domain)
    dfs_order = graph.dfs(target_domain)
    shared_ips = graph.find_shared_assets(target_node_type="IPAddress")
    consistency_findings = graph.run_consistency_checks(inventory=inventory, active_scan_performed=True)

    logger.info(
        "Graph Metrics: %d Vertices, %d Edges | BFS Explored: %d | Shared IPs: %d | Inconsistencies: %d",
        len(graph.nodes),
        sum(len(e) for e in graph.adj.values()),
        len(bfs_order),
        len(shared_ips),
        len(consistency_findings),
    )

    # 7. Generate Reports
    inventory_summary = {
        "subdomains": sorted(inventory.subdomains),
        "ip_addresses": sorted(inventory.ip_addresses),
        "dns_records": [r.to_dict() for r in inventory.dns_records],
        "services": [s.to_dict() for s in inventory.services],
        "observations": [o.to_dict() for o in inventory.observations],
        "errors": inventory.errors,
    }

    scheduler_summary = {k: v.to_dict() for k, v in scheduler_results.items()}
    report_dict = build_report_data(
        target_domain=target_domain,
        mode="simulation",
        inventory_data=inventory_summary,
        scheduler_comparison=scheduler_summary,
        graph_data=graph.to_dict(),
        consistency_findings=[f.to_dict() for f in consistency_findings],
        scope_rules=["*.example.com", "93.184.216.0/24 (simulated scope)"],
    )

    json_path, md_path = write_reports(report_dict, base_name="simulation_report")
    logger.info("Simulation reports written successfully:")
    logger.info("  JSON Report: %s", json_path)
    logger.info("  Markdown Report: %s", md_path)

    return json_path, md_path


# ============================================================================
# Passive Mode
# ============================================================================
def run_passive_mode(domain: str, budget: int = 100) -> tuple[Path, Path]:
    """Execute passive reconnaissance pipeline."""
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        logger.error("Invalid target domain: %s", domain)
        sys.exit(1)

    logger.info("=== Starting Passive Reconnaissance for '%s' ===", clean_domain)
    inventory = DiscoveredAssetInventory(root_domain=clean_domain)

    # 1. Certificate Transparency
    logger.info("[1/4] Querying Certificate Transparency (crt.sh)...")
    query_crtsh(clean_domain, inventory)

    # 2. DNS Records
    logger.info("[2/4] Querying DNS Resolver (A, AAAA, MX, NS, TXT)...")
    query_dns_records(clean_domain, inventory)
    for sub in list(inventory.subdomains):
        query_dns_records(sub, inventory, record_types=("A", "AAAA"))

    # 3. WHOIS
    logger.info("[3/4] Retrieving WHOIS registration details...")
    query_whois(clean_domain, inventory)

    # 4. theHarvester and Indexed APIs (optional)
    logger.info("[4/4] Checking optional OSINT sources...")
    run_theharvester(clean_domain, inventory)
    query_shodan_subdomains(clean_domain, inventory)
    query_censys_hosts(clean_domain, inventory)
    for ip in list(inventory.ip_addresses)[:5]:
        query_shodan_host(ip, inventory)
        query_censys_host(ip, inventory, target_domain=clean_domain)

    # DAA Scheduler Comparison
    candidate_probes = generate_candidate_probes(
        hosts=list(inventory.subdomains) + [clean_domain],
        ports=(22, 80, 443, 8080),
    )
    scheduler_results = compare_strategies(candidate_probes, budget=budget)

    # Asset Correlation Graph
    graph = AssetGraph()
    graph.add_node(clean_domain, "Domain", {"sources": ["input"]})

    for sub in inventory.subdomains:
        graph.add_node(sub, "Subdomain", {"discovered_passively": True})
        graph.add_edge(clean_domain, sub, RelationshipType.HAS_SUBDOMAIN)

    for rec in inventory.dns_records:
        if rec.record_type in ("A", "AAAA"):
            graph.add_node(rec.value, "IPAddress")
            graph.add_edge(rec.host, rec.value, RelationshipType.RESOLVES_TO)

    consistency_findings = graph.run_consistency_checks(inventory=inventory, active_scan_performed=False)

    inventory_summary = {
        "subdomains": sorted(inventory.subdomains),
        "ip_addresses": sorted(inventory.ip_addresses),
        "dns_records": [r.to_dict() for r in inventory.dns_records],
        "services": [s.to_dict() for s in inventory.services],
        "observations": [o.to_dict() for o in inventory.observations],
        "errors": inventory.errors,
    }

    report_dict = build_report_data(
        target_domain=clean_domain,
        mode="passive",
        inventory_data=inventory_summary,
        scheduler_comparison={k: v.to_dict() for k, v in scheduler_results.items()},
        graph_data=graph.to_dict(),
        consistency_findings=[f.to_dict() for f in consistency_findings],
    )

    json_path, md_path = write_reports(report_dict, base_name=f"passive_{clean_domain}")
    logger.info("Passive reports written successfully:")
    logger.info("  JSON Report: %s", json_path)
    logger.info("  Markdown Report: %s", md_path)

    return json_path, md_path


# ============================================================================
# Active Mode
# ============================================================================
def run_active_mode(
    domain: str,
    scope_file: Path | str | None = None,
    confirm_active: bool = True,
    budget: int = 100,
    enable_zone_transfer: bool = False,
) -> tuple[Path, Path]:
    """Execute active reconnaissance on target services."""
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        logger.error("Invalid target domain: %s", domain)
        sys.exit(1)

    # Initialize Scope
    scope_mgr = ScopeManager()
    if scope_file:
        try:
            rule_count = scope_mgr.load_from_file(scope_file)
            logger.info("Loaded %d scope rules from %s", rule_count, scope_file)
        except Exception as exc:
            logger.warning("Could not load scope file: %s. Defaulting scope to %s", exc, clean_domain)
            scope_mgr.add_rule(clean_domain)
            scope_mgr.add_rule(f"*.{clean_domain}")
    else:
        scope_mgr.add_rule(clean_domain)
        scope_mgr.add_rule(f"*.{clean_domain}")

    logger.info("=== Starting Active Reconnaissance for '%s' ===", clean_domain)
    inventory = DiscoveredAssetInventory(root_domain=clean_domain)

    # 3. Gather initial passive infrastructure for candidate selection
    query_dns_records(clean_domain, inventory)
    query_crtsh(clean_domain, inventory)
    query_shodan_subdomains(clean_domain, inventory)
    query_censys_hosts(clean_domain, inventory)
    for ip in list(inventory.ip_addresses)[:5]:
        query_shodan_host(ip, inventory)
        query_censys_host(ip, inventory, target_domain=clean_domain)

    # Filter discovered hosts against scope allowlist
    in_scope_subdomains, out_of_scope_subdomains = scope_mgr.filter_targets(inventory.subdomains)
    logger.info(
        "Scope filter: %d targets authorized, %d targets rejected as out-of-scope.",
        len(in_scope_subdomains),
        len(out_of_scope_subdomains),
    )

    # 4. Generate Candidate Probes & Schedule with 0/1 Knapsack DP
    active_ports = (80, 443, 8080, 22, 21, 25, 3306, 8443)
    candidate_probes = generate_candidate_probes(
        hosts=[clean_domain] + in_scope_subdomains,
        ports=active_ports,
    )
    scheduler_results = compare_strategies(candidate_probes, budget=budget)
    selected_probes = scheduler_results["knapsack_dp"].selected_probes

    logger.info(
        "0/1 Knapsack DP selected %d active probes out of %d candidates (Budget=%d, Cost=%d, Value=%d)",
        len(selected_probes),
        len(candidate_probes),
        budget,
        scheduler_results["knapsack_dp"].total_cost,
        scheduler_results["knapsack_dp"].total_value,
    )

    # 5. Execute Probes strictly on authorized selections
    matcher = AhoCorasick(case_sensitive=False)
    for sig in load_signatures_from_file(config.SIGNATURES_FILE):
        matcher.add_signature(sig)
    matcher.build()

    for probe in selected_probes:
        # Re-verify scope and resolve IP before every active probe to prevent DNS rebinding
        is_allowed, resolved_ip, err_msg = scope_mgr.resolve_and_audit_probe(probe.host, probe.port)
        if not is_allowed:
            logger.warning("Skipping unauthorized probe target: %s (Reason: %s)", probe.host, err_msg)
            continue

        logger.info("Executing probe: %s:%d (%s) [Resolved IP: %s]", probe.host, probe.port, probe.reason, resolved_ip)
        
        # Enforce configurable rate limit politeness delay
        if config.RATE_LIMIT_DELAY > 0:
            time.sleep(config.RATE_LIMIT_DELAY)

        # Attempt TLS certificate inspection and SAN discovery on TLS ports
        tls_cert = None
        if probe.port in (443, 8443):
            tls_cert = inspect_tls_certificate(probe.host, probe.port)
            if tls_cert and tls_cert.get("sans"):
                for san in tls_cert["sans"]:
                    clean_san = san.lstrip("*.")
                    if clean_san.endswith(clean_domain) and clean_san not in inventory.subdomains:
                        inventory.add_subdomain(clean_san, source="tls_certificate")

        # Attempt socket banner grab subject to configured network timeout
        banner_text = grab_banner(probe.host, probe.port, timeout=config.NETWORK_TIMEOUT)
        if banner_text:
            svc = identify_service(probe.host, probe.port, banner_text, matcher=matcher, tls_cert_info=tls_cert)
            inventory.add_service(svc)
        elif tls_cert:
            svc = identify_service(
                probe.host,
                probe.port,
                f"TLS Handshake Successful ({tls_cert.get('issuer', 'Unknown')})",
                matcher=matcher,
                tls_cert_info=tls_cert,
            )
            inventory.add_service(svc)

    # 6. Execute Nmap on primary target if Nmap is installed
    if config.is_tool_available("nmap"):
        logger.info("Executing conservative Nmap scan on %s...", clean_domain)
        run_nmap_scan(clean_domain, scope_mgr, inventory, ports=(22, 80, 443))

    # 7. Build Graph and Correlation
    graph = AssetGraph()
    graph.add_node(clean_domain, "Domain")
    for sub in in_scope_subdomains:
        graph.add_node(sub, "Subdomain")
        graph.add_edge(clean_domain, sub, RelationshipType.HAS_SUBDOMAIN)

    for rec in inventory.dns_records:
        if rec.record_type in ("A", "AAAA"):
            graph.add_node(rec.value, "IPAddress")
            graph.add_edge(rec.host, rec.value, RelationshipType.RESOLVES_TO)

    for svc in inventory.services:
        graph.add_node(svc.host, "IPAddress")
        graph.add_node(svc.endpoint_id, "Endpoint", {"port": svc.port})
        graph.add_edge(svc.host, svc.endpoint_id, RelationshipType.EXPOSES_PORT)

        svc_node_id = f"service_{svc.endpoint_id}"
        graph.add_node(svc_node_id, "Service", {
            "product": svc.product,
            "version": svc.version,
            "banner_product": svc.product,
            "fingerprint_product": svc.product,
            "source": svc.source,
        })
        graph.add_edge(svc.endpoint_id, svc_node_id, RelationshipType.RUNS_SERVICE)

    consistency_findings = graph.run_consistency_checks(inventory=inventory, active_scan_performed=True)

    inventory_summary = {
        "subdomains": sorted(inventory.subdomains),
        "ip_addresses": sorted(inventory.ip_addresses),
        "dns_records": [r.to_dict() for r in inventory.dns_records],
        "services": [s.to_dict() for s in inventory.services],
        "observations": [o.to_dict() for o in inventory.observations],
        "errors": inventory.errors,
    }

    report_dict = build_report_data(
        target_domain=clean_domain,
        mode="active",
        inventory_data=inventory_summary,
        scheduler_comparison={k: v.to_dict() for k, v in scheduler_results.items()},
        graph_data=graph.to_dict(),
        consistency_findings=[f.to_dict() for f in consistency_findings],
        scope_rules=list(scope_mgr.allowed_hosts | scope_mgr.allowed_patterns | scope_mgr.allowed_ips),
    )

    json_path, md_path = write_reports(report_dict, base_name=f"active_{clean_domain}")
    logger.info("Active scan reports written successfully:")
    logger.info("  JSON Report: %s", json_path)
    logger.info("  Markdown Report: %s", md_path)

    return json_path, md_path


# ============================================================================
# Benchmark Mode
# ============================================================================
def run_benchmarks(target: str = "all") -> None:
    """Execute standalone DAA benchmark experiments."""
    logger.info("=== Running Standalone DAA Coursework Benchmarks ===")

    if target in ("all", "scheduler"):
        logger.info("\n[1/3] Benchmarking Probe Scheduler Algorithms...")
        sched_res = run_scheduler_benchmarks()
        logger.info("Completed %d scheduler scenarios.", len(sched_res))

    if target in ("all", "matcher"):
        logger.info("\n[2/3] Benchmarking Multi-Pattern Matcher (Aho-Corasick vs Naive)...")
        match_res = run_matcher_benchmarks()
        logger.info("Completed %d matcher scenarios.", len(match_res))

    if target in ("all", "graph"):
        logger.info("\n[3/3] Benchmarking Asset Graph Scaling (BFS vs DFS)...")
        graph_res = run_graph_benchmarks()
        logger.info("Completed %d graph scaling scenarios.", len(graph_res))

    logger.info("\n[+] All benchmark results saved in: %s", config.BENCHMARKS_DIR)


# ============================================================================
# Main Entry Point
# ============================================================================
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Algorithm-Optimized Reconnaissance Framework (DAA Coursework)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Execution mode")

    # Simulation subcommand
    simulate_parser = subparsers.add_parser("simulate", help="Run offline simulation using test fixtures")
    simulate_parser.add_argument("--budget", type=int, default=100, help="Probe scheduling budget (default: 100)")

    # Scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Execute reconnaissance scan")
    scan_parser.add_argument("--domain", required=True, help="Target domain (e.g. example.com)")
    scan_parser.add_argument("--mode", choices=["passive", "active"], default="passive", help="Scan mode")
    scan_parser.add_argument("--scope-file", help="Optional path to scope allowlist file")
    scan_parser.add_argument("--budget", type=int, default=100, help="Knapsack probe budget (default: 100)")
    scan_parser.add_argument("--confirm-active", action="store_true", default=True, help="Active scanning flag")
    scan_parser.add_argument("--enable-zone-transfer", action="store_true", help="Enable DNS zone transfer test (AXFR)")

    # Benchmark subcommand
    bench_parser = subparsers.add_parser("benchmark", help="Run offline DAA algorithmic benchmarks")
    bench_parser.add_argument("--all", action="store_true", help="Run all benchmarks (scheduler, matcher, graph)")
    bench_parser.add_argument("--target", choices=["scheduler", "matcher", "graph", "all"], default="all", help="Target benchmark")

    args = parser.parse_args()

    if args.command == "simulate":
        run_simulation_mode(budget=args.budget)
    elif args.command == "scan":
        if args.mode == "passive":
            run_passive_mode(args.domain, budget=args.budget)
        elif args.mode == "active":
            run_active_mode(
                domain=args.domain,
                scope_file=args.scope_file,
                confirm_active=True,
                budget=args.budget,
                enable_zone_transfer=args.enable_zone_transfer,
            )
    elif args.command == "benchmark":
        target = "all" if args.all else args.target
        run_benchmarks(target)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
