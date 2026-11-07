"""Comprehensive deep feature test script for TargetRecon API and algorithms."""

import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"


def api_get(endpoint: str):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"User-Agent": "DeepCheck/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_post(endpoint: str, payload: dict):
    url = f"{BASE_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "DeepCheck/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def poll_run(run_id: str, timeout: int = 45):
    start = time.time()
    while time.time() - start < timeout:
        status_data = api_get(f"/api/runs/{run_id}/status")
        status = status_data.get("status")
        msg = status_data.get("progress_message", "")
        print(f"   [{run_id[:8]}] Status: {status} | Progress: {msg}")
        if status in ("completed", "failed", "cancelled"):
            return status
        time.sleep(1.5)
    raise TimeoutError(f"Run {run_id} did not finish within {timeout}s")


def main():
    print("=" * 70)
    print(" TARGETRECON DEEP FEATURE VERIFICATION")
    print("=" * 70)

    # 1. Health Endpoint
    print("\n[1] Testing GET /api/health...")
    health = api_get("/api/health")
    assert health["status"] == "healthy", f"Health check failed: {health}"
    print(f"    Status: {health['status']} | Signatures: {health['signatures_count']} | Tools: {health['external_tools']}")

    # 2. List Runs
    print("\n[2] Testing GET /api/runs...")
    runs = api_get("/api/runs")
    print(f"    Retrieved {len(runs)} existing runs.")
    for r in runs[:3]:
        print(f"    - Run #{r.get('run_number')}: {r['target_domain']} ({r['mode'].upper()}) - {r['status']}")

    # 3. Test Simulation Run Creation
    print("\n[3] Testing POST /api/runs (Simulation Mode)...")
    sim_res = api_post("/api/runs", {"target_domain": "example.com", "mode": "simulation", "budget": 15})
    sim_id = sim_res["run_id"]
    print(f"    Created run {sim_id}. Polling completion...")
    sim_status = poll_run(sim_id)
    assert sim_status == "completed", f"Simulation failed with status: {sim_status}"

    # Verify Simulation Assets & Graph
    sim_assets = api_get(f"/api/runs/{sim_id}/assets")
    print(f"    Simulation Assets: {len(sim_assets.get('subdomains', []))} subdomains, {len(sim_assets.get('ip_addresses', []))} IPs, {len(sim_assets.get('services', []))} services")
    assert len(sim_assets.get("subdomains", [])) > 0
    assert len(sim_assets.get("services", [])) > 0

    sim_graph = api_get(f"/api/runs/{sim_id}/graph")
    print(f"    Simulation Graph: {sim_graph.get('metrics', {}).get('total_nodes', 0)} nodes, {sim_graph.get('metrics', {}).get('total_edges', 0)} edges")

    # 4. Test Passive Run Creation
    print("\n[4] Testing POST /api/runs (Passive Mode on example.com)...")
    pass_res = api_post("/api/runs", {"target_domain": "example.com", "mode": "passive", "budget": 10})
    pass_id = pass_res["run_id"]
    print(f"    Created passive run {pass_id}. Polling completion...")
    pass_status = poll_run(pass_id, timeout=30)
    assert pass_status == "completed", f"Passive run failed: {pass_status}"

    pass_assets = api_get(f"/api/runs/{pass_id}/assets")
    print(f"    Passive Assets: {len(pass_assets.get('subdomains', []))} subdomains, {len(pass_assets.get('ip_addresses', []))} IPs, {len(pass_assets.get('dns_records', []))} DNS records")

    # 5. Test Active Run Creation on scanme.nmap.org
    print("\n[5] Testing POST /api/runs (Active Mode on scanme.nmap.org)...")
    act_res = api_post("/api/runs", {"target_domain": "scanme.nmap.org", "mode": "active", "budget": 10})
    act_id = act_res["run_id"]
    print(f"    Created active run {act_id}. Polling completion...")
    act_status = poll_run(act_id, timeout=45)
    assert act_status == "completed", f"Active run failed: {act_status}"

    act_assets = api_get(f"/api/runs/{act_id}/assets")
    act_services = act_assets.get("services", [])
    print(f"    Active Assets: {len(act_assets.get('subdomains', []))} subdomains, {len(act_assets.get('ip_addresses', []))} IPs, {len(act_services)} services")

    # Verify Option A Fields (Security Score, Frameworks, Headers)
    print("\n[6] Verifying Option A (Security Posture & TLS Inspector) in Active Run...")
    found_score = False
    found_framework = False
    for s in act_services:
        print(f"    - Endpoint: {s.get('endpoint_id')} | Product: {s.get('product')} v{s.get('version')}")
        if s.get("security_score"):
            found_score = True
            print(f"      Security Score: {s.get('security_score')}")
        if s.get("detected_frameworks"):
            found_framework = True
            print(f"      Detected Frameworks: {s.get('detected_frameworks')}")
        if s.get("security_headers"):
            print(f"      Security Headers Checked: {list(s.get('security_headers').keys())}")
        if s.get("tls_cert_info"):
            print(f"      TLS Cert: Issuer={s['tls_cert_info'].get('issuer')} | Days Left={s['tls_cert_info'].get('days_remaining')}")

    print(f"    Option A verified: Security Score found={found_score}, Frameworks found={found_framework}")

    # 7. Test Algorithmic Endpoints
    print("\n[7] Testing DAA Algorithm Endpoints...")
    
    # 7.1 Aho-Corasick Matcher Test
    sample_banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nX-Powered-By: PHP/8.1\r\n"
    matcher_test = api_post("/api/algorithms/match-banner", {"banner": sample_banner, "case_sensitive": False})
    print(f"    Aho-Corasick matches: {len(matcher_test.get('ac_matches', []))} matches found.")
    for m in matcher_test.get("ac_matches", []):
        print(f"      - Match: {m['product']} ({m['pattern_id']}) at [{m['start_pos']}:{m['end_pos']}]")
    print(f"      Is Equivalent with Naive Matcher: {matcher_test.get('is_equivalent')}")
    print(f"      Extracted Versions: {matcher_test.get('extracted_versions')}")
    assert matcher_test.get("is_equivalent") is True
    assert "nginx" in matcher_test.get("extracted_versions", {})

    # 7.2 0/1 Knapsack Scheduler Test
    sched_test = api_post("/api/algorithms/schedule", {"budget": 15, "candidate_count": 20})
    dp_val = sched_test.get("results", {}).get("knapsack_dp", {}).get("total_value")
    greedy_val = sched_test.get("results", {}).get("greedy", {}).get("total_value")
    disc_val = sched_test.get("results", {}).get("discovery_order", {}).get("total_value")
    print(f"    Scheduler Comparison (Budget 15): DP Value={dp_val} | Greedy Value={greedy_val} | Discovery Value={disc_val}")
    assert dp_val >= greedy_val, "Knapsack DP should be >= Greedy"

    # 7.3 Graph BFS and DFS Traversals
    print("\n[8] Testing Graph BFS/DFS Traversals on Active Run...")
    bfs_res = api_post("/api/algorithms/graph-traverse", {"run_id": act_id, "algorithm": "bfs", "start_node_id": "scanme.nmap.org"})
    dfs_res = api_post("/api/algorithms/graph-traverse", {"run_id": act_id, "algorithm": "dfs", "start_node_id": "scanme.nmap.org"})
    print(f"    BFS Visited {len(bfs_res.get('traversal_order', []))} nodes: {bfs_res.get('traversal_order')}")
    print(f"    DFS Visited {len(dfs_res.get('traversal_order', []))} nodes: {dfs_res.get('traversal_order')}")
    assert len(bfs_res.get("traversal_order", [])) > 0
    assert len(dfs_res.get("traversal_order", [])) > 0

    # 8. Report Endpoints
    print("\n[9] Testing Report Download Endpoints...")
    json_report = api_get(f"/api/runs/{act_id}/reports/json")
    assert json_report.get("metadata", {}).get("target_domain") == "scanme.nmap.org"
    print("    JSON Report downloaded successfully and verified.")

    md_req = urllib.request.Request(f"{BASE_URL}/api/runs/{act_id}/reports/markdown")
    with urllib.request.urlopen(md_req) as resp:
        md_text = resp.read().decode("utf-8")
        assert "TargetRecon" in md_text
        print(f"    Markdown Report downloaded successfully ({len(md_text)} chars).")

    print("\n" + "=" * 70)
    print(" ALL DEEP CHECKS PASSED WITH 100% SUCCESS!")
    print("=" * 70)


if __name__ == "__main__":
    main()
