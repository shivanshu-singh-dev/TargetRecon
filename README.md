# TargetRecon — Advanced Cyber Reconnaissance & OSINT Platform
**Enterprise-Grade External Attack Surface Management (EASM), Multi-Source OSINT Aggregation & High-Performance Scanning Engine**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests Passing](https://img.shields.io/badge/pytest-49%20passed-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-OSINT%20%7C%20Active%20Fingerprinting%20%7C%20Attack%20Surface%20Mapping-orange.svg)]()
[![Dashboard](https://img.shields.io/badge/UI-FastAPI%20%2B%20React%20%2B%20Tailwind-teal.svg)]()
[![Security Policy](https://img.shields.io/badge/policy-Strict%20Non--Exploitation-lightgrey.svg)]()

---

## 1. Executive Summary & Capabilities

**TargetRecon** is a production-grade external attack surface management (EASM) and cyber reconnaissance platform. Designed for security teams, penetration testers, and threat intelligence analysts, TargetRecon automates the entire discovery lifecycle: from multi-source passive OSINT aggregation to scope-controlled active fingerprinting and graph-theoretic attack surface correlation.

Under the hood, TargetRecon replaces brute-force network scanning with an **algorithm-optimized reconnaissance engine** that guarantees mathematical rate-limit optimality, constant-time banner signature matching, and instant relationship graph traversals.

```
                           Target Domain / CIDR Input
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 ▼                                           ▼
      [Passive OSINT Ingestion]                   [Scope Boundary Control]
      • Certificate Transparency (crt.sh)         • Explicit IP/CIDR/Domain Rules
      • Comprehensive DNS (A/AAAA/MX/NS/SOA/CAA)  • Auto-Scoped Wildcard Enforcement
      • Mail Security (_dmarc / SPF / DKIM)       • Strict Target Inclusion Filter
      • WHOIS / RDAP Registration Metadata                   │
      • Threat Feeds (Censys & Shodan)                       ▼
                 │                                [Candidate Probe Generation]
                 ▼                                (Priority Value, Stealth Cost)
      [Asset Graph Ingestion]                                │
      • Multi-relational vertices & edges                    ▼
      • Correlation & shared infrastructure       [Intelligent Probe Scheduler]
      • Cross-source discrepancy audit             • Dynamic Programming Optimization
                 ▲                                 • Greedy Rate-Limiting Ratios
                 │                                 • Budget & WAF Drop Prevention
                 │                                           │
                 │                                           ▼
                 │                                [Authorized Active Probing]
                 │                                • Socket Banner Grabbing
                 └─────────────────────────────── • Deep TLS Certificate Inspector
                                                  • Web Security Header Auditor
                                                  • Framework & Version Extractor
                                                             │
                                                             ▼
                                                [Reporting & SOC Operations]
                                                • Audit JSON & Markdown Reports
                                                • Real-Time React / Tailwind GUI
                                                • RESTful API (Port 8000)
```

### Key Functional Pillars:

1. **Multi-Source Passive OSINT Gathering:**
   - **Certificate Transparency:** Queries `crt.sh` with exponential backoff retries and automatic active DNS prefix fallback.
   - **Deep DNS Enumeration:** Resolves IPv4 (`A`), IPv6 (`AAAA`), Mail Exchanges (`MX` with preference priorities), Nameservers (`NS`), Text verification records (`TXT`), Zone Authority (`SOA`), Certificate Authority Authorization (`CAA`), and DMARC policy (`_dmarc.{domain}`).
   - **Registration Intelligence:** Direct RFC 3912 socket WHOIS lookups and RDAP metadata parsing.
   - **Indexed Threat Intelligence:** Integration with Shodan and Censys APIs, strictly preserving passive provenance and historical timestamps.

2. **Scoped Active Probing & Fingerprinting:**
   - **Strict Scope Boundaries:** Enforces explicit allowed hostnames, wildcard patterns, and CIDR blocks with IPv6 safety checks.
   - **Socket Banner Grabbing:** Polished TCP handshakes retrieving protocol headers with explicit outcome telemetry (`OPEN`, `CLOSED`, `FILTERED`/`TIMEOUT`, `FAILED`).
   - **Deep TLS Analysis:** Real-time certificate inspection extracting issuer, subject, validity status, remaining days, negotiated TLS version (`TLSv1.3`), cipher suite, serial number, and SHA-256 certificate fingerprints.
   - **Web Security Posture Auditing:** Weighted scoring model (A through F) auditing Content Security Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, and Referrer-Policy, with RFC 6797 §7.2 HTTP redirect awareness.
   - **Technology Stack Identification:** Accurate extraction of server software, cloud infrastructure (`railway-hikari`, `cloudflare`, `aws`), and application frameworks (`Next.js`, `React`, `Express`).

3. **Multi-Relational Asset Correlation Graph:**
   - Adjacency-list graph correlating `Domain` $\rightarrow$ `RESOLVES_TO` $\rightarrow$ `IPAddress` $\rightarrow$ `EXPOSES_PORT` $\rightarrow$ `Endpoint` $\rightarrow$ `RUNS_SERVICE` $\rightarrow$ `Service`.
   - Automated discrepancy auditing: flags unresolved subdomains, unconfirmed historical services, and genuine evidence discrepancies across sources (while correctly handling valid multi-record DNS sets).

4. **High-Performance Core Engine:**
   - **Intelligent Probe Scheduling:** Optimal subset selection under strict probe budgets to prevent firewall IP bans, network congestion, and defensive tripwires.
   - **Aho-Corasick Multi-Pattern Matcher:** Trie-based string matching automaton inspecting network banners across hundreds of service signatures simultaneously in $\mathcal{O}(L + Z)$ time.
   - **Graph BFS / DFS Traversals:** Instant relationship path tracing and connected component analysis running in linear $\mathcal{O}(V + E)$ time.

---

## 2. Architecture & Directory Layout

```text
TargetRecon/
├── main.py                  # Unified CLI engine (simulate, scan, benchmark)
├── api_server.py            # Localhost FastAPI REST adapter & SPA static server
├── config.py                # Centralized configuration, timeouts, paths, credentials
├── models.py                # Normalized asset models, probe outcomes, and provenance tracking
├── scheduler.py             # Intelligent probe scheduler (DP optimal, Greedy, Discovery order)
├── graph.py                 # Multi-relational asset graph, BFS/DFS traversals, anomaly detection
├── report.py                # Comprehensive JSON & Markdown audit reporting engine
├── run_dashboard.bat        # Windows 1-click batch launcher for SOC dashboard
├── run_dashboard.ps1        # PowerShell launcher (production & dev modes)
├── requirements.txt         # Core dependencies (requests, dnspython, pytest, fastapi, uvicorn)
├── .env.example             # Configuration template
├── frontend/                # Professional SOC Web Dashboard
│   ├── package.json         # React 18, TypeScript, Tailwind CSS, Recharts, Lucide
│   ├── vite.config.ts       # Vite build configuration with /api proxy
│   ├── tailwind.config.js   # Dark graphite SOC styling
│   ├── dist/                # Production static assets served by FastAPI
│   └── src/
│       ├── api.ts           # Type-safe REST client for FastAPI endpoints
│       ├── types.ts         # TypeScript schema definitions matching backend models
│       ├── components/      # Sidebar, Header, KPI Cards, Status Badges
│       └── pages/           # Overview, NewRun, Inventory, Graph, Engine Lab, Findings, Reports
├── passive/
│   ├── crtsh.py             # Certificate Transparency query engine with DNS fallback
│   ├── dns_records.py       # Comprehensive passive DNS resolver (A, AAAA, MX, NS, TXT, SOA, CAA, DMARC)
│   ├── whois_lookup.py      # System whois & RFC 3912 socket fallback parser
│   ├── theharvester.py      # theHarvester OSINT tool adapter (optional)
│   └── indexed_services.py  # Censys & Shodan indexed threat intelligence adapters
├── active/
│   ├── scope.py             # Strict CIDR/host allowlist enforcement & IPv6 verification
│   ├── nmap_runner.py       # Conservative Nmap runner & offline XML parser
│   └── dns_checks.py        # Active DNS verification & gated AXFR zone transfer checks
├── banner/
│   ├── grabber.py           # Socket banner grabber, TLS inspector & security header auditor
│   ├── matcher.py           # Aho-Corasick multi-pattern automaton & version extractor
│   └── signatures.json      # Service identification signatures
├── benchmarks/
│   ├── benchmark_scheduler.py  # Scheduler scaling benchmarks
│   ├── benchmark_matcher.py    # Aho-Corasick vs Naive pattern matching benchmarks
│   ├── benchmark_graph.py      # Graph scaling benchmarks
│   └── results/                # Saved benchmark outputs (JSON/CSV)
├── fixtures/
│   ├── passive_data.json    # Deterministic offline passive dataset
│   ├── nmap_sample.xml      # Valid Nmap XML scan output
│   └── banners.json         # Real-world protocol banner fixtures
└── tests/
    ├── test_scheduler.py    # Unit tests for scheduler optimization & edge cases
    ├── test_matcher.py      # Unit tests for Aho-Corasick & version extraction
    ├── test_graph.py        # Unit tests for graph algorithms & anomaly checks
    ├── test_normalization.py# Domain, IP, and provenance normalization tests
    ├── test_scope_and_nmap.py# Scope allowlist & Nmap parser tests
    ├── test_passive_fixtures.py# Passive source handling & graceful degradation
    ├── test_reporting.py    # Audit report generation tests
    ├── test_api_server.py   # FastAPI adapter endpoint tests
    └── deep_check.py        # End-to-end integration and API verification suite
```

---

## 3. Installation & Setup

### Prerequisites
- **Python:** Version 3.11 or newer (tested on Python 3.12.4).
- **Node.js (Optional):** Version 18+ (only needed if modifying frontend source code; pre-built production assets are included).
- **Operating Systems:** Windows 10/11, Ubuntu 20.04+, Debian, macOS.

### Step-by-Step Installation

```powershell
# 1. Clone or navigate to the project directory
cd s:\TargetRecon

# 2. Create the Python virtual environment
python -m venv .venv

# 3. Activate the virtual environment
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# (If script execution is restricted: Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned)

# On Linux / macOS:
# source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify the test suite
pytest -q
```

---

## 4. Configuration & Environment Variables

Copy `.env.example` to `.env` to configure scanning parameters and optional API keys:

```bash
cp .env.example .env
```

| Parameter | Default | Description |
|:---|:---:|:---|
| `RECON_TIMEOUT_SECONDS` | `5.0` | Socket connection and HTTP response timeout (seconds) |
| `RECON_MAX_RETRIES` | `2` | Maximum retry attempts for external queries |
| `RECON_RATE_LIMIT_DELAY` | `0.5` | Politeness delay between active socket probes |
| `RECON_MAX_BANNER_BYTES` | `2048` | Maximum socket banner payload to ingest |
| `RECON_DEFAULT_BUDGET` | `100` | Default active probe allowance |
| `SHODAN_API_KEY` | *(None)* | Optional Shodan API key for indexed host queries |
| `CENSYS_API_ID` | *(None)* | Optional Censys API ID |
| `CENSYS_API_SECRET` | *(None)* | Optional Censys API Secret |

> [!NOTE]
> All core capabilities, active socket probing, DNS enumeration, TLS analysis, Certificate Transparency, and graph correlation run completely out-of-the-box with **zero API keys required**.

---

## 5. Command-Line Interface (CLI)

TargetRecon provides a command-line interface supporting four distinct operational modes:

### 1. Passive Reconnaissance Mode
Aggregates public OSINT data without transmitting direct network packets to the target's service ports:

```bash
python main.py scan --domain example.com --mode passive
```

### 2. Active Reconnaissance Mode
Performs scoped DNS verification, scheduled socket probing, TLS certificate inspection, and HTTP header auditing:

```bash
# Standard active scan with default probe allowance (100)
python main.py scan --domain example.com --mode active

# Active scan with custom probe allowance and strict scope file
python main.py scan --domain example.com --mode active --budget 25 --scope-file scope.txt

# Enable DNS Zone Transfer (AXFR) verification
python main.py scan --domain example.com --mode active --enable-zone-transfer
```

### 3. Fully Offline Simulation Mode
Executes the full pipeline against deterministic offline fixtures with zero external network traffic:

```bash
python main.py simulate --budget 20
```

### 4. Engine Performance Benchmarks
Executes performance stress tests across the scheduler, multi-pattern matcher, and graph engine:

```bash
python main.py benchmark --all
```

---

## 6. SOC Web Dashboard & REST API

TargetRecon features an interactive SOC dashboard built with **React**, **TypeScript**, **Tailwind CSS**, and **Recharts**, backed by a **FastAPI** local service.

### Launching the Dashboard

```powershell
# Option A: One-click launcher (PowerShell)
.\run_dashboard.ps1

# Option B: Direct Python execution
.venv\Scripts\python.exe api_server.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

```
┌────────────────────────────────────────────────────────────────────────┐
│  TargetRecon SOC Console                              [● Engine Active]│
│  ┌──────────────────┐ ┌──────────────────────────────────────────────┐ │
│  │ Navigation       │ │ Target: wombto18.com | Mode: ACTIVE          │ │
│  │ • Overview       │ ├──────────────────────────────────────────────┤ │
│  │ • New Recon Run  │ │ Subdomains: 1  |  IPs: 1  |  Services: 2     │ │
│  │ • Discovered Inv │ ├──────────────────────────────────────────────┤ │
│  │ • Asset Graph    │ │ [Interactive Attack Surface Topology Graph] │ │
│  │ • Engine Lab     │ │ Domain ──► IP ──► Endpoints ──► Services     │ │
│  │ • Findings       │ ├──────────────────────────────────────────────┤ │
│  │ • Reports        │ │ Security Headers: HTTPS Grade A | TLSv1.3    │ │
│  └──────────────────┘ └──────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### Core Dashboard Views:
- **Overview:** Live KPI counters, scan status, and summary telemetry.
- **New Recon Run:** Dispatch active or passive scans with configurable probe allowances and custom scope filters.
- **Asset Inventory:** Searchable, filterable tables for subdomains, IPs, DNS records, services, and TLS certificates with complete source provenance.
- **Asset Graph:** High-contrast topology visualization supporting interactive node inspection, connected components, and BFS/DFS path tracing.
- **Engine Performance:** Real-time sandboxes to test the probe scheduling optimizer, Aho-Corasick signature matcher, and graph traversal scaling.
- **Security Findings:** Automated anomaly and discrepancy alerts (e.g., unresolved subdomains, missing security headers).
- **Reports:** Single-click export of comprehensive JSON audit files and formatted Markdown reports.

### REST API Endpoints:

| Category | Endpoint | Description |
|:---|:---|:---|
| **System** | `GET /api/health` | Service health, signature database count, tool availability |
| **Scans** | `GET /api/runs` | List all historical and in-progress reconnaissance runs |
| | `POST /api/runs` | Dispatch a new scan (Simulation, Passive, Active) |
| | `GET /api/runs/{id}` | Complete scan data, KPIs, and scheduler results |
| | `GET /api/runs/{id}/status` | Lightweight status polling for live running jobs |
| | `POST /api/runs/{id}/cancel` | Cancel an active background scan |
| **Assets & Graph** | `GET /api/runs/{id}/assets` | Paginated asset inventory with source provenance |
| | `GET /api/runs/{id}/graph` | Adjacency graph nodes, edges, and cluster metrics |
| | `GET /api/runs/{id}/findings` | Consistency discrepancies and security warnings |
| **Reports** | `GET /api/runs/{id}/reports/json` | Download raw JSON audit report |
| | `GET /api/runs/{id}/reports/markdown` | Download formatted Markdown report |
| **Engine Lab** | `POST /api/algorithms/match-banner` | Real-time signature matching on custom banner text |
| | `POST /api/algorithms/schedule` | Probe scheduler comparison on custom probe sets |
| | `POST /api/algorithms/graph-traverse`| Step-by-step BFS or DFS traversal on run graph |
| **Benchmarks** | `GET /api/benchmarks/results` | Historical empirical scaling datasets |

---

## 7. High-Performance Core Engine Specifications

TargetRecon integrates three core algorithmic engines to achieve enterprise-grade scanning speed, stealth, and resilience:

### 7.1 Intelligent Probe Scheduler
When assessing extensive attack surfaces, probing every open port simultaneously triggers Web Application Firewall (WAF) rate limits, causes IP bans, and degrades target network stability. TargetRecon formulates active probe selection as a bounded-cost optimization problem.

Each candidate probe $i$ carries:
- **Estimated Resource Cost ($w_i$):** Quantifying network packets, socket negotiation time, and detection risk (e.g., standard HTTP=2, SSH/SMTP=3, Database=4).
- **Information Value ($v_i$):** Prioritizing corroborated subdomains, confirmed active DNS hosts, and high-value management interfaces (e.g., SSH=8, HTTPS=7, Database=5).

The engine evaluates three strategies:
1. **Discovery-Order:** Sequential first-fit baseline ($O(n)$).
2. **Greedy Ratio Heuristic:** Sorts candidates by value-to-cost density ($v_i / w_i$) in $O(n \log n)$. While fast, greedy selection frequently misses higher-value probe combinations when approaching budget boundaries.
3. **Dynamic Programming Optimization:** Uses exact 0/1 knapsack dynamic programming with state recurrence:
   $$dp[i][w] = \max\left(dp[i-1][w], \, dp[i-1][w - w_i] + v_i\right)$$
   Guarantees maximum intelligence yield in $\mathcal{O}(nB)$ time, reconstructed in $\mathcal{O}(n)$ via backtracking.

### 7.2 Multi-Pattern Signature Matching (Aho-Corasick)
Active banner grabbing returns unstructured text payloads. Identifying services using sequential regex or pattern-by-pattern matching requires $\mathcal{O}(K \cdot L)$ time (where $K$ is signature count and $L$ is banner length), which degrades significantly as signature databases grow.

TargetRecon implements the **Aho-Corasick Automaton**:
- **Construction:** Builds a prefix trie of all $K$ signatures with breadth-first search (BFS) failure links and dictionary output links in $\mathcal{O}(\sum |p_k|)$ time.
- **Search:** Streams banner text through state transitions in $\mathcal{O}(L + Z)$ time (where $Z$ is the count of matches), completely independent of pattern count $K$.
- **Version Heuristics:** Once a product is identified, regular expressions extract exact semver and release numbers (`1.24.0`, `OpenSSH_8.9p1`).

### 7.3 Multi-Relational Asset Graph
Attack surfaces are relational networks, not flat lists. TargetRecon represents discovered assets as an adjacency-list graph:
- **Node Types:** `Domain`, `Subdomain`, `IPAddress`, `Endpoint`, `Service`, `DNSRecord`, `TLSCertificate`.
- **Edge Types:** `HAS_SUBDOMAIN`, `RESOLVES_TO`, `EXPOSES_PORT`, `RUNS_SERVICE`, `SECURED_BY`.
- **Graph Traversal:** Implements pure-Python Breadth-First Search (BFS) for shortest relationship path discovery and Depth-First Search (DFS) for reachable component mapping in strictly linear $\mathcal{O}(V + E)$ time.
- **Automated Anomaly Audit:** Flags dangling DNS pointers, unconfirmed historical services, and discrepancies across data sources.

---

## 8. Empirical Performance Benchmarks

All benchmarks were recorded on Windows 11 with Python 3.12.4 using high-resolution hardware timers (`time.perf_counter()`):

### 8.1 Probe Scheduler Efficiency

| Candidates ($n$) | Budget ($B$) | DP Value | DP Runtime | Greedy Value | Greedy Optimal? | Greedy Efficiency | Discovery Efficiency |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **10** | 12 | 95 | 0.018 ms | 95 | ✓ Yes | 100.0% | 47.4% |
| **10** | 25 | **137** | 0.027 ms | **132** | **✗ Suboptimal** | **96.35%** | 69.3% |
| **50** | 58 | 475 | 0.239 ms | 475 | ✓ Yes | 100.0% | 51.6% |
| **100** | 115 | **1,070** | 0.923 ms | **1,063** | **✗ Suboptimal** | **99.35%** | 34.0% |
| **250** | 564 | **3,653** | 11.565 ms | **3,646** | **✗ Suboptimal** | **99.81%** | 62.1% |
| **500** | 1,076 | 7,333 | 49.978 ms | 7,333 | ✓ Yes | 100.0% | 52.8% |
| **1,000** | 2,181 | 14,863 | 207.028 ms | 14,863 | ✓ Yes | 100.0% | 57.2% |

### 8.2 Aho-Corasick Signature Matcher vs. Naive Baseline

| Signatures ($K$) | Banner Length ($L$) | AC Build Time | AC Search Time | Naive Search Time | **AC Speedup** | Output Equivalent? |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **10** | 500 bytes | 0.037 ms | 0.051 ms | 0.013 ms | 0.26x | ✓ True |
| **100** | 2,000 bytes | 0.256 ms | 0.159 ms | 0.107 ms | 0.67x | ✓ True |
| **250** | 2,000 bytes | 0.475 ms | 0.159 ms | 0.245 ms | **1.54x** | ✓ True |
| **500** | 2,000 bytes | 1.127 ms | 0.157 ms | 0.470 ms | **2.99x** | ✓ True |
| **500** | 8,000 bytes | 1.091 ms | 0.559 ms | 1.527 ms | **2.73x** | ✓ True |
| **1,000** | 500 bytes | 1.924 ms | 0.043 ms | 0.343 ms | **7.92x** | ✓ True |
| **1,000** | 8,000 bytes | 1.945 ms | 0.564 ms | 3.033 ms | **5.38x** | ✓ True |

### 8.3 Asset Correlation Graph Scaling

| Subdomains | IPs | Total Vertices ($V$) | Total Edges ($E$) | BFS Runtime | DFS Runtime | Explored Vertices |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 50 | 10 | 101 | 140 | 0.018 ms | 0.024 ms | 100% |
| 200 | 30 | 351 | 520 | 0.074 ms | 0.085 ms | 100% |
| 1,000 | 100 | 1,501 | 2,400 | 0.280 ms | 0.356 ms | 100% |
| 3,000 | 250 | 4,251 | 7,000 | 0.760 ms | 0.973 ms | 100% |
| 6,000 | 500 | 8,501 | 14,000 | 1.679 ms | 2.397 ms | 100% |

---

## 9. Quality Assurance & Test Suite

The TargetRecon test suite contains **49 automated unit and integration tests** guaranteeing 100% pass rates across all core systems:

```bash
pytest -v
```

```text
============================= test session starts =============================
platform win32 -- Python 3.12.4, pytest-9.1.1
collected 49 items

tests/test_api_server.py::test_get_health PASSED                         [  2%]
tests/test_api_server.py::test_list_runs_includes_historical_simulation PASSED [  4%]
tests/test_api_server.py::test_get_run_details_and_assets PASSED         [  6%]
tests/test_api_server.py::test_active_run_creation_auto_scope PASSED     [  8%]
tests/test_api_server.py::test_live_banner_matching_endpoint PASSED      [ 10%]
tests/test_api_server.py::test_live_scheduler_endpoint PASSED            [ 12%]
tests/test_api_server.py::test_live_graph_traversal_endpoint PASSED      [ 14%]
tests/test_api_server.py::test_get_benchmark_results_endpoint PASSED     [ 16%]
tests/test_graph.py::test_bfs_traversal PASSED                           [ 18%]
tests/test_graph.py::test_dfs_traversal PASSED                           [ 20%]
tests/test_graph.py::test_path_tracing PASSED                            [ 22%]
tests/test_graph.py::test_shared_infrastructure_detection PASSED         [ 24%]
tests/test_graph.py::test_connected_components PASSED                    [ 26%]
tests/test_graph.py::test_consistency_unresolved_subdomain PASSED        [ 28%]
tests/test_graph.py::test_consistency_fingerprint_disagreement PASSED    [ 30%]
tests/test_graph.py::test_consistency_conflicting_observations PASSED    [ 32%]
tests/test_matcher.py::test_aho_corasick_basic_matching PASSED           [ 34%]
tests/test_matcher.py::test_overlapping_and_nested_patterns PASSED       [ 36%]
tests/test_matcher.py::test_repeated_occurrences PASSED                  [ 38%]
tests/test_matcher.py::test_case_sensitivity PASSED                      [ 40%]
tests/test_matcher.py::test_equivalence_with_naive_matcher PASSED        [ 42%]
tests/test_matcher.py::test_version_extraction PASSED                    [ 44%]
tests/test_matcher.py::test_http_security_header_and_stack_audit PASSED  [ 46%]
tests/test_normalization.py::test_normalize_domain PASSED                [ 48%]
tests/test_normalization.py::test_normalize_ip PASSED                    [ 51%]
tests/test_normalization.py::test_normalize_port PASSED                  [ 53%]
tests/test_normalization.py::test_deduplication_preserving_provenance PASSED [ 55%]
tests/test_passive_fixtures.py::test_fixture_passive_data_ingestion PASSED [ 57%]
tests/test_passive_fixtures.py::test_crtsh_mocked_success PASSED         [ 59%]
tests/test_passive_fixtures.py::test_crtsh_rate_limit_and_timeout PASSED [ 61%]
tests/test_passive_fixtures.py::test_missing_theharvester PASSED         [ 63%]
tests/test_passive_fixtures.py::test_missing_api_keys_shodan_and_censys PASSED [ 65%]
tests/test_passive_fixtures.py::test_parse_whois_redacted_fields PASSED  [ 67%]
tests/test_reporting.py::test_report_json_and_markdown_generation PASSED [ 69%]
tests/test_scheduler.py::test_knapsack_known_optimal PASSED              [ 71%]
tests/test_scheduler.py::test_greedy_is_suboptimal PASSED                [ 73%]
tests/test_scheduler.py::test_discovery_order_baseline PASSED            [ 75%]
tests/test_scheduler.py::test_edge_cases_empty_and_zero_budget PASSED    [ 77%]
tests/test_scheduler.py::test_edge_case_all_costs_exceed_budget PASSED   [ 79%]
tests/test_scheduler.py::test_edge_case_equal_values_and_costs PASSED    [ 81%]
tests/test_scheduler.py::test_compare_strategies PASSED                  [ 83%]
tests/test_scheduler.py::test_candidate_generation PASSED                [ 85%]
tests/test_scope_and_nmap.py::test_scope_manager_hostnames_and_ips PASSED [ 87%]
tests/test_scope_and_nmap.py::test_scope_validation_exception PASSED     [ 89%]
tests/test_scope_and_nmap.py::test_scope_file_loading PASSED             [ 91%]
tests/test_scope_and_nmap.py::test_parse_nmap_xml_offline PASSED         [ 93%]
tests/test_scope_and_nmap.py::test_parse_nmap_malformed_xml PASSED       [ 95%]
tests/test_scope_and_nmap.py::test_hostname_suffix_matching PASSED       [ 97%]
tests/test_scope_and_nmap.py::test_dns_rebinding_and_ip_auditing PASSED  [100%]

============================== 49 passed in 2.97s ==============================
```

---

## 10. Responsible Scanning & Ethical Governance

TargetRecon operates under strict ethical guidelines and defensive engineering principles:

1. **Non-Exploitation Standard:** TargetRecon contains **zero exploit payloads**, brute-forcing routines, vulnerability injection scripts, or credential harvesting tools. It is strictly an external attack surface inventory and reconnaissance system.
2. **Explicit Scope Control:** Active probes are restricted to target root domains and discovered in-scope subdomains, with optional user-supplied CIDR or IP allowlists.
3. **Politeness & Rate Limiting:** All network interactions enforce configurable connection timeouts and inter-probe rate-limit delays to prevent target system degradation or denial of service.
4. **Authorization Requirement:** Scanning third-party assets without prior written consent is strictly prohibited. Always ensure you possess explicit authorization before initiating active scans.
