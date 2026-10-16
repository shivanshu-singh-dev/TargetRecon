"""FastAPI backend adapter for the Algorithm-Optimized Reconnaissance Framework.

Exposes REST endpoints for:
- Run lifecycle management (demo, passive, scope-controlled active)
- Real-time job status tracking and cancellation
- Asset inventory retrieval, filtering, and export
- Graph topology and interactive BFS/DFS traversal execution
- Live DAA algorithm test benches (Knapsack DP scheduler, Aho-Corasick matching)
- Benchmark result aggregation and on-demand benchmark execution
- Report downloads (JSON and Markdown)
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config import config
from models import (
    CollectionMethod,
    DiscoveredAssetInventory,
    Observation,
    RelationshipType,
    ServiceEndpoint,
    normalize_domain,
)
from scheduler import compare_strategies, generate_candidate_probes, schedule_knapsack_dp, schedule_greedy, schedule_discovery_order
from banner.grabber import grab_banner, identify_service
from banner.matcher import (
    AhoCorasick,
    NaiveMatcher,
    Signature,
    extract_software_version,
    load_signatures_from_file,
)
from graph import AssetGraph
from report import build_report_data, generate_json_report, generate_markdown_report, write_reports
from active.scope import ScopeManager, ScopeValidationError
from active.nmap_runner import parse_nmap_xml, run_nmap_scan
from active.dns_checks import verify_active_dns_records
from passive.crtsh import query_crtsh
from passive.dns_records import query_dns_records
from passive.whois_lookup import query_whois
from passive.theharvester import run_theharvester
from passive.indexed_services import (
    query_censys_hosts,
    query_shodan_host,
    query_shodan_subdomains,
)
from benchmarks.benchmark_scheduler import run_scheduler_benchmarks
from benchmarks.benchmark_matcher import run_matcher_benchmarks
from benchmarks.benchmark_graph import run_graph_benchmarks

logger = logging.getLogger("recon_api")

app = FastAPI(
    title="Algorithm-Optimized Reconnaissance Framework API",
    version="1.0.0",
    description="REST API adapter exposing DAA reconnaissance engine, algorithms, and reporting.",
)

# CORS configuration for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# In-Memory Job & Run Store
# ============================================================================
class RunJob:
    def __init__(self, run_id: str, target_domain: str, mode: str, budget: int, scope_rules: list[str]) -> None:
        self.run_id = run_id
        self.target_domain = target_domain
        self.mode = mode
        self.budget = budget
        self.scope_rules = scope_rules
        self.status: Literal["queued", "running", "completed", "failed", "cancelled"] = "queued"
        self.start_time: str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.end_time: Optional[str] = None
        self.progress_message: str = "Job initialized"
        self.error_message: Optional[str] = None
        self.report_data: Optional[dict[str, Any]] = None
        self.cancel_requested: bool = False

RUN_STORE: dict[str, RunJob] = {}
RUN_LOCK = threading.Lock()


def load_historical_runs() -> None:
    """Index existing reports from the reports directory."""
    reports_dir = config.REPORTS_DIR
    if not reports_dir.is_dir():
        return

    for json_file in reports_dir.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            meta = data.get("metadata", {})
            run_id = json_file.stem
            target = meta.get("target_domain", "Unknown")
            mode = meta.get("mode", "Unknown")
            budget = meta.get("settings", {}).get("default_budget", 15)
            scope = data.get("authorization_scope", {}).get("scope_rules", [])

            job = RunJob(run_id=run_id, target_domain=target, mode=mode, budget=budget, scope_rules=scope)
            job.status = "completed"
            job.start_time = meta.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
            job.end_time = job.start_time
            job.progress_message = "Completed (loaded from disk report)"
            job.report_data = data

            with RUN_LOCK:
                if run_id not in RUN_STORE:
                    RUN_STORE[run_id] = job
        except Exception as exc:
            logger.debug("Could not index historical report %s: %s", json_file, exc)

# Pre-index existing reports
load_historical_runs()


# ============================================================================
# Request & Response Schemas
# ============================================================================
class RunCreateRequest(BaseModel):
    target_domain: str = Field(..., min_length=3, max_length=253)
    mode: Literal["demo", "passive", "active"]
    budget: int = Field(default=15, ge=1, le=1000)
    confirm_active: bool = False
    scope_rules: list[str] = Field(default_factory=list)
    enable_zone_transfer: bool = False


class BannerMatchRequest(BaseModel):
    banner: str = Field(..., max_length=10000)
    case_sensitive: bool = False


class SchedulerTestRequest(BaseModel):
    budget: int = Field(default=15, ge=1, le=5000)
    candidate_count: int = Field(default=20, ge=1, le=500)


class GraphTraverseRequest(BaseModel):
    run_id: str
    algorithm: Literal["bfs", "dfs"]
    start_node_id: str


# ============================================================================
# API Endpoints
# ============================================================================
@app.get("/api/health")
def get_health() -> dict[str, Any]:
    """Health check and environment status."""
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "version": "1.0.0",
        "external_tools": config.get_tool_status(),
        "signatures_count": len(load_signatures_from_file(config.SIGNATURES_FILE)),
    }


@app.get("/api/runs")
def list_runs() -> list[dict[str, Any]]:
    """List all historical and active reconnaissance runs."""
    load_historical_runs()
    with RUN_LOCK:
        runs_list = []
        for job in sorted(RUN_STORE.values(), key=lambda j: j.start_time, reverse=True):
            asset_count = 0
            error_count = 0
            if job.report_data:
                inv = job.report_data.get("inventory", {})
                asset_count = len(inv.get("subdomains", [])) + len(inv.get("ip_addresses", []))
                error_count = len(inv.get("errors", []))

            runs_list.append({
                "run_id": job.run_id,
                "target_domain": job.target_domain,
                "mode": job.mode,
                "budget": job.budget,
                "status": job.status,
                "start_time": job.start_time,
                "end_time": job.end_time,
                "progress_message": job.progress_message,
                "asset_count": asset_count,
                "error_count": error_count,
            })
        return runs_list


@app.get("/api/runs/{run_id}")
def get_run_details(run_id: str) -> dict[str, Any]:
    """Retrieve complete report data for a specific run."""
    with RUN_LOCK:
        job = RUN_STORE.get(run_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    return {
        "run_id": job.run_id,
        "target_domain": job.target_domain,
        "mode": job.mode,
        "budget": job.budget,
        "status": job.status,
        "start_time": job.start_time,
        "end_time": job.end_time,
        "progress_message": job.progress_message,
        "error_message": job.error_message,
        "report_data": job.report_data,
    }


@app.get("/api/runs/{run_id}/status")
def get_run_status(run_id: str) -> dict[str, Any]:
    """Retrieve live status of a run job."""
    with RUN_LOCK:
        job = RUN_STORE.get(run_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    return {
        "run_id": job.run_id,
        "status": job.status,
        "progress_message": job.progress_message,
        "error_message": job.error_message,
    }


@app.post("/api/runs/{run_id}/cancel")
def cancel_run(run_id: str) -> dict[str, str]:
    """Request graceful cancellation of an active run."""
    with RUN_LOCK:
        job = RUN_STORE.get(run_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    if job.status in ("queued", "running"):
        job.cancel_requested = True
        job.status = "cancelled"
        job.progress_message = "Cancelled by user"
        return {"message": "Run cancellation requested."}
    return {"message": f"Run already in terminal state: {job.status}"}


@app.get("/api/runs/{run_id}/assets")
def get_run_assets(run_id: str) -> dict[str, Any]:
    """Retrieve asset inventory for a run."""
    job_details = get_run_details(run_id)
    report = job_details.get("report_data") or {}
    return report.get("inventory", {})


@app.get("/api/runs/{run_id}/graph")
def get_run_graph(run_id: str) -> dict[str, Any]:
    """Retrieve correlated asset graph for a run."""
    job_details = get_run_details(run_id)
    report = job_details.get("report_data") or {}
    return report.get("graph", {})


@app.get("/api/runs/{run_id}/findings")
def get_run_findings(run_id: str) -> list[dict[str, Any]]:
    """Retrieve evidence discrepancy findings for a run."""
    job_details = get_run_details(run_id)
    report = job_details.get("report_data") or {}
    return report.get("consistency_findings", [])


@app.get("/api/runs/{run_id}/reports/{fmt}")
def download_run_report(run_id: str, fmt: Literal["json", "markdown"]) -> Response:
    """Download the JSON or Markdown report for a run."""
    job_details = get_run_details(run_id)
    report = job_details.get("report_data")
    if not report:
        raise HTTPException(status_code=404, detail="Report data not ready.")

    if fmt == "json":
        content = generate_json_report(report)
        return Response(content=content, media_type="application/json", headers={
            "Content-Disposition": f"attachment; filename={run_id}_report.json"
        })
    else:
        content = generate_markdown_report(report)
        return Response(content=content, media_type="text/markdown", headers={
            "Content-Disposition": f"attachment; filename={run_id}_report.md"
        })


# ============================================================================
# Run Dispatch Worker
# ============================================================================
def execute_run_task(job: RunJob) -> None:
    """Background worker executing the requested reconnaissance mode."""
    try:
        job.status = "running"
        target_domain = normalize_domain(job.target_domain)

        if job.mode == "demo":
            job.progress_message = "Executing offline simulated demo using fixtures..."
            fixtures_path = config.FIXTURES_DIR / "passive_data.json"
            with open(fixtures_path, "r", encoding="utf-8") as f:
                fixture_data = json.load(f)

            inventory = DiscoveredAssetInventory(root_domain=target_domain)
            for item in fixture_data.get("subdomains", []):
                for src in item["sources"]:
                    inventory.add_subdomain(item["subdomain"], source=src, method=CollectionMethod.SIMULATED)

            for r in fixture_data.get("dns_records", []):
                from models import DNSRecord
                rec = DNSRecord(record_type=r["record_type"], host=r["host"], value=r["value"], source=r["source"])
                inventory.add_dns_record(rec)
                if r["record_type"] in ("A", "AAAA"):
                    inventory.add_ip(r["value"], source=r["source"], method=CollectionMethod.SIMULATED)

            # Sample Nmap fixture
            nmap_xml_path = config.FIXTURES_DIR / "nmap_sample.xml"
            if nmap_xml_path.is_file():
                endpoints = parse_nmap_xml(nmap_xml_path.read_text(encoding="utf-8"), source="simulated_nmap")
                for ep in endpoints:
                    inventory.add_service(ep)

            # Banners fixture
            matcher = AhoCorasick(case_sensitive=False)
            for sig in load_signatures_from_file(config.SIGNATURES_FILE):
                matcher.add_signature(sig)
            matcher.build()

            banners_path = config.FIXTURES_DIR / "banners.json"
            if banners_path.is_file():
                with open(banners_path, "r", encoding="utf-8") as f:
                    banner_items = json.load(f)
                for b in banner_items:
                    svc = identify_service(b["host"], b["port"], b["banner"], matcher=matcher)
                    inventory.add_service(svc)

            job.progress_message = "Scheduling probes with 0/1 Knapsack DP..."
            candidate_probes = generate_candidate_probes(
                hosts=list(inventory.subdomains) + [target_domain],
                ports=(22, 80, 443, 8080),
            )
            scheduler_results = compare_strategies(candidate_probes, budget=job.budget)

            job.progress_message = "Building Asset Correlation Graph..."
            graph = AssetGraph()
            graph.add_node(target_domain, "Domain", {"sources": ["input"]})

            for sub in inventory.subdomains:
                graph.add_node(sub, "Subdomain", {"discovered_passively": True})
                graph.add_edge(target_domain, sub, RelationshipType.HAS_SUBDOMAIN)

            for rec in inventory.dns_records:
                if rec.record_type in ("A", "AAAA"):
                    graph.add_node(rec.value, "IPAddress")
                    graph.add_edge(rec.host, rec.value, RelationshipType.RESOLVES_TO)

            for svc in inventory.services:
                graph.add_node(svc.host, "IPAddress")
                graph.add_node(svc.endpoint_id, "Endpoint", {"port": svc.port, "protocol": svc.protocol})
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

            inv_summary = {
                "subdomains": sorted(inventory.subdomains),
                "ip_addresses": sorted(inventory.ip_addresses),
                "dns_records": [r.to_dict() for r in inventory.dns_records],
                "services": [s.to_dict() for s in inventory.services],
                "observations": [o.to_dict() for o in inventory.observations],
                "errors": inventory.errors,
            }

            job.report_data = build_report_data(
                target_domain=target_domain,
                mode="demo",
                inventory_data=inv_summary,
                scheduler_comparison={k: v.to_dict() for k, v in scheduler_results.items()},
                graph_data=graph.to_dict(),
                consistency_findings=[f.to_dict() for f in consistency_findings],
                scope_rules=["*.example.com (simulated demo allowlist)"],
            )

        elif job.mode == "passive":
            job.progress_message = "Gathering passive Certificate Transparency records..."
            inventory = DiscoveredAssetInventory(root_domain=target_domain)
            query_crtsh(target_domain, inventory)

            job.progress_message = "Querying DNS resolvers for A, AAAA, MX, NS, TXT..."
            query_dns_records(target_domain, inventory)
            for sub in list(inventory.subdomains)[:10]:
                query_dns_records(sub, inventory, record_types=("A", "AAAA"))

            job.progress_message = "Retrieving WHOIS registration records..."
            query_whois(target_domain, inventory)

            run_theharvester(target_domain, inventory)
            query_shodan_subdomains(target_domain, inventory)

            job.progress_message = "Analyzing probe candidates and graph relationships..."
            candidate_probes = generate_candidate_probes(
                hosts=list(inventory.subdomains) + [target_domain],
                ports=(22, 80, 443, 8080),
            )
            scheduler_results = compare_strategies(candidate_probes, budget=job.budget)

            graph = AssetGraph()
            graph.add_node(target_domain, "Domain")
            for sub in inventory.subdomains:
                graph.add_node(sub, "Subdomain", {"discovered_passively": True})
                graph.add_edge(target_domain, sub, RelationshipType.HAS_SUBDOMAIN)

            for rec in inventory.dns_records:
                if rec.record_type in ("A", "AAAA"):
                    graph.add_node(rec.value, "IPAddress")
                    graph.add_edge(rec.host, rec.value, RelationshipType.RESOLVES_TO)

            consistency_findings = graph.run_consistency_checks(inventory=inventory, active_scan_performed=False)

            inv_summary = {
                "subdomains": sorted(inventory.subdomains),
                "ip_addresses": sorted(inventory.ip_addresses),
                "dns_records": [r.to_dict() for r in inventory.dns_records],
                "services": [s.to_dict() for s in inventory.services],
                "observations": [o.to_dict() for o in inventory.observations],
                "errors": inventory.errors,
            }

            job.report_data = build_report_data(
                target_domain=target_domain,
                mode="passive",
                inventory_data=inv_summary,
                scheduler_comparison={k: v.to_dict() for k, v in scheduler_results.items()},
                graph_data=graph.to_dict(),
                consistency_findings=[f.to_dict() for f in consistency_findings],
            )

        elif job.mode == "active":
            # Active Mode: server-side scope enforcement
            scope_mgr = ScopeManager()
            for r in job.scope_rules:
                scope_mgr.add_rule(r)

            if not scope_mgr.is_in_scope(target_domain):
                raise ScopeValidationError(f"Target domain '{target_domain}' is not permitted by authorization scope.")

            job.progress_message = "Gathering initial infrastructure..."
            inventory = DiscoveredAssetInventory(root_domain=target_domain)
            query_dns_records(target_domain, inventory)
            query_crtsh(target_domain, inventory)

            in_scope_subs, _ = scope_mgr.filter_targets(inventory.subdomains)

            candidate_probes = generate_candidate_probes(
                hosts=[target_domain] + in_scope_subs,
                ports=config.DEFAULT_ACTIVE_PORTS[:5],
            )
            scheduler_results = compare_strategies(candidate_probes, budget=job.budget)
            selected_probes = scheduler_results["knapsack_dp"].selected_probes

            matcher = AhoCorasick(case_sensitive=False)
            for sig in load_signatures_from_file(config.SIGNATURES_FILE):
                matcher.add_signature(sig)
            matcher.build()

            for idx, probe in enumerate(selected_probes):
                if job.cancel_requested:
                    break
                job.progress_message = f"Probing {probe.host}:{probe.port} ({idx + 1}/{len(selected_probes)})..."
                allowed, resolved_ip, err = scope_mgr.resolve_and_audit_probe(probe.host, probe.port)
                if allowed:
                    banner = grab_banner(probe.host, probe.port, timeout=config.NETWORK_TIMEOUT)
                    if banner:
                        svc = identify_service(probe.host, probe.port, banner, matcher=matcher)
                        inventory.add_service(svc)

            if config.is_tool_available("nmap") and not job.cancel_requested:
                job.progress_message = f"Running Nmap scan on {target_domain}..."
                run_nmap_scan(target_domain, scope_mgr, inventory, ports=(22, 80, 443))

            graph = AssetGraph()
            graph.add_node(target_domain, "Domain")
            for sub in in_scope_subs:
                graph.add_node(sub, "Subdomain")
                graph.add_edge(target_domain, sub, RelationshipType.HAS_SUBDOMAIN)

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

            inv_summary = {
                "subdomains": sorted(inventory.subdomains),
                "ip_addresses": sorted(inventory.ip_addresses),
                "dns_records": [r.to_dict() for r in inventory.dns_records],
                "services": [s.to_dict() for s in inventory.services],
                "observations": [o.to_dict() for o in inventory.observations],
                "errors": inventory.errors,
            }

            job.report_data = build_report_data(
                target_domain=target_domain,
                mode="active",
                inventory_data=inv_summary,
                scheduler_comparison={k: v.to_dict() for k, v in scheduler_results.items()},
                graph_data=graph.to_dict(),
                consistency_findings=[f.to_dict() for f in consistency_findings],
                scope_rules=job.scope_rules,
            )

        # Write reports to disk
        write_reports(job.report_data, base_name=job.run_id)
        job.status = "completed"
        job.progress_message = "Scan completed successfully."
        job.end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    except Exception as exc:
        logger.exception("Error executing run %s: %s", job.run_id, exc)
        job.status = "failed"
        job.error_message = str(exc)
        job.progress_message = f"Failed: {exc}"
        job.end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()


@app.post("/api/runs")
def create_run(req: RunCreateRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Dispatch a new reconnaissance job with strict server-side scope validation."""
    clean_domain = normalize_domain(req.target_domain)
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Invalid target domain string.")

    # Server-Side Safety Validation
    if req.mode == "active":
        if not req.confirm_active:
            raise HTTPException(
                status_code=400,
                detail="Active scanning requires explicit confirmation flag 'confirm_active=True'."
            )
        if not req.scope_rules:
            raise HTTPException(
                status_code=400,
                detail="Active scanning requires at least one explicit scope allowlist rule."
            )
        # Verify target domain is in scope rules
        temp_mgr = ScopeManager()
        for r in req.scope_rules:
            temp_mgr.add_rule(r)
        if not temp_mgr.is_in_scope(clean_domain):
            raise HTTPException(
                status_code=400,
                detail=f"Target domain '{clean_domain}' is not authorized by the provided scope rules."
            )

    run_id = f"{req.mode}_{clean_domain.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    job = RunJob(
        run_id=run_id,
        target_domain=clean_domain,
        mode=req.mode,
        budget=req.budget,
        scope_rules=req.scope_rules,
    )

    with RUN_LOCK:
        RUN_STORE[run_id] = job

    # Run in background
    background_tasks.add_task(execute_run_task, job)

    return {
        "run_id": run_id,
        "target_domain": clean_domain,
        "mode": req.mode,
        "status": "queued",
        "message": "Reconnaissance run dispatched successfully.",
    }


# ============================================================================
# Live DAA Algorithm Endpoints
# ============================================================================
@app.post("/api/algorithms/match-banner")
def api_banner_match(req: BannerMatchRequest) -> dict[str, Any]:
    """Live Aho-Corasick and Naive matcher execution on user-provided banner text."""
    signatures = load_signatures_from_file(config.SIGNATURES_FILE)

    # 1. Aho-Corasick
    ac = AhoCorasick(case_sensitive=req.case_sensitive)
    for s in signatures:
        ac.add_signature(s)
    ac.build()
    ac_matches = ac.search(req.banner)

    # 2. Naive Matcher
    naive = NaiveMatcher(case_sensitive=req.case_sensitive)
    for s in signatures:
        naive.add_signature(s)
    naive_matches = naive.search(req.banner)

    # Version extraction heuristics
    extracted_versions: dict[str, Optional[str]] = {}
    for m in ac_matches:
        if m.product not in extracted_versions:
            extracted_versions[m.product] = extract_software_version(req.banner, m.product)

    return {
        "banner_length": len(req.banner),
        "signature_count": len(signatures),
        "ac_matches": [m.to_dict() for m in ac_matches],
        "naive_matches_count": len(naive_matches),
        "is_equivalent": len(ac_matches) == len(naive_matches),
        "extracted_versions": extracted_versions,
    }


@app.post("/api/algorithms/schedule")
def api_scheduler(req: SchedulerTestRequest) -> dict[str, Any]:
    """Run DAA probe scheduling comparison across a synthetic candidate set."""
    from benchmarks.benchmark_scheduler import generate_synthetic_probes
    candidates = generate_synthetic_probes(req.candidate_count, seed=42)

    comp = compare_strategies(candidates, budget=req.budget)
    return {
        "budget": req.budget,
        "candidate_count": req.candidate_count,
        "candidates": [c.to_dict() for c in candidates[:15]],  # Sample of candidates
        "results": {k: v.to_dict() for k, v in comp.items()},
    }


@app.post("/api/algorithms/graph-traverse")
def api_graph_traversal(req: GraphTraverseRequest) -> dict[str, Any]:
    """Execute BFS or DFS traversal on a run's asset graph and return visit sequence."""
    job_details = get_run_details(req.run_id)
    report = job_details.get("report_data") or {}
    graph_dict = report.get("graph") or {}

    g = AssetGraph()
    for n in graph_dict.get("nodes", []):
        g.add_node(n["node_id"], n["node_type"], n.get("properties"))
    for e in graph_dict.get("edges", []):
        g.add_edge(e["source_id"], e["target_id"], e["relationship_type"], e.get("properties"))

    start = req.start_node_id.strip()
    if start not in g.nodes:
        # Default to first available node
        if g.nodes:
            start = next(iter(g.nodes.keys()))
        else:
            return {"traversal_order": [], "visited_count": 0}

    if req.algorithm == "bfs":
        traversal = g.bfs(start)
    else:
        traversal = g.dfs(start)

    return {
        "algorithm": req.algorithm.upper(),
        "start_node_id": start,
        "traversal_order": traversal,
        "visited_count": len(traversal),
        "total_graph_nodes": len(g.nodes),
    }


# ============================================================================
# Benchmark API Endpoints
# ============================================================================
@app.get("/api/benchmarks/results")
def get_benchmark_results() -> dict[str, Any]:
    """Return historical offline benchmark JSON outputs."""
    benchmarks_dir = config.BENCHMARKS_DIR
    res: dict[str, Any] = {"scheduler": [], "matcher": [], "graph": []}

    sched_file = benchmarks_dir / "scheduler_benchmark.json"
    if sched_file.is_file():
        with open(sched_file, "r", encoding="utf-8") as f:
            res["scheduler"] = json.load(f)

    match_file = benchmarks_dir / "matcher_benchmark.json"
    if match_file.is_file():
        with open(match_file, "r", encoding="utf-8") as f:
            res["matcher"] = json.load(f)

    graph_file = benchmarks_dir / "graph_benchmark.json"
    if graph_file.is_file():
        with open(graph_file, "r", encoding="utf-8") as f:
            res["graph"] = json.load(f)

    return res


@app.post("/api/benchmarks/{target}")
def trigger_benchmark(target: Literal["scheduler", "matcher", "graph", "all"]) -> dict[str, str]:
    """Execute benchmark suite and update disk cache."""
    if target in ("scheduler", "all"):
        run_scheduler_benchmarks()
    if target in ("matcher", "all"):
        run_matcher_benchmarks()
    if target in ("graph", "all"):
        run_graph_benchmarks()

    return {"message": f"Benchmark for '{target}' completed successfully."}


# Mount built frontend static files if present (allows 1-command startup)
from fastapi.staticfiles import StaticFiles

frontend_dist = Path(__file__).resolve().parent / "frontend" / "dist"
if frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting TargetRecon Dashboard API Server at http://127.0.0.1:8000")
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)

