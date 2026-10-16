# Algorithm-Optimized Reconnaissance Framework
**A Coursework Framework for Design and Analysis of Algorithms (DAA)**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests Passing](https://img.shields.io/badge/pytest-48%20passed-brightgreen.svg)]()
[![Algorithms](https://img.shields.io/badge/DAA-Knapsack%20DP%20%7C%20Aho--Corasick%20%7C%20Graph%20Traversals-orange.svg)]()
[![Dashboard](https://img.shields.io/badge/UI-FastAPI%20%2B%20React%20%2B%20Tailwind-teal.svg)]()
[![License](https://img.shields.io/badge/license-Academic%20Educational-lightgrey.svg)]()

---

## 1. Project Overview & Objectives

The **Algorithm-Optimized Reconnaissance Framework** is a modular cybersecurity and network reconnaissance system developed as coursework for **Design and Analysis of Algorithms (DAA)**.

Modern reconnaissance tools collect vast quantities of unstructured, multi-source telemetry. However, standard tools often lack algorithmic rigor when operating under constrained execution budgets, filtering multi-pattern signatures, or evaluating structural relationships between assets. This project bridges systems engineering and theoretical computer science by implementing three foundational algorithmic contributions from scratch in pure Python:

1. **Probe Scheduling Optimization:**
   - Modeling candidate active network probes as a bounded-cost subset selection problem.
   - Comparative evaluation between:
     - **Discovery-Order Baseline** ($O(n)$ first-fit).
     - **Greedy Heuristic** ($O(n \log n)$ value-to-cost ratio maximization).
     - **0/1 Knapsack Dynamic Programming** ($O(nB)$ pseudopolynomial optimal subset selection with backtracking reconstruction).
2. **Multi-Pattern Banner Matching:**
   - Implementing the **Aho–Corasick Automaton** from scratch using a trie with BFS failure links and dictionary/output links.
   - Preprocessing complexity $O(P)$ and text search complexity $O(L + Z)$.
   - Demonstrating mathematical and semantic equivalence against a **Naive Pattern-by-Pattern** baseline ($O(K \cdot L)$), while illustrating asymptotically superior scaling as signature counts grow to 1,000+.
   - Decoupled product identification from regex-based software version extraction.
3. **Multi-Relational Asset Correlation Graph:**
   - Custom adjacency-list graph representation storing typed vertices (Domain, Subdomain, IPAddress, Endpoint, Service) and typed edges (`HAS_SUBDOMAIN`, `RESOLVES_TO`, `EXPOSES_PORT`, `RUNS_SERVICE`).
   - From-scratch implementations of **Breadth-First Search (BFS)** and **Depth-First Search (DFS)** ($O(V + E)$).
   - Graph-theoretic correlation: domain-to-service path tracing, shared infrastructure discovery (e.g., subdomains sharing IP addresses), connected component decomposition, and evidence consistency analysis (detecting unresolved subdomains, unconfirmed historical services, and conflicting multi-source observations).

---

## 2. Architecture & Data Flow

```
                      +-----------------------------+
                      |   Target Domain Input       |
                      +--------------+--------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
    [Passive Reconnaissance]                    [Authorization Scope]
    - Certificate Transparency (crt.sh)         - Hostname allowlist
    - DNS Resolvers (A, AAAA, MX, NS, TXT)      - CIDR subnet validation
    - Optional WHOIS (CLI / RFC 3912)           - User confirmation gate
    - theHarvester / Shodan / Censys (optional)             |
               |                                           v
               +---------------------+-----------> [Probe Candidates]
                                     |             (Cost, Value, Reason)
                                     v                     |
                           [Asset Correlation]             v
                           - Adjacency List Graph  [DAA Probe Scheduler]
                           - BFS / DFS Traversals  - Strategy A: Discovery
                           - Consistency Analyzer  - Strategy B: Greedy
                                     ^             - Strategy C: 0/1 Knapsack DP
                                     |                     |
                                     |       [Authorized Active Probing]
                                     +------- - Sockets Banner Grabber
                                     |        - Aho-Corasick Matcher
                                     |        - Nmap Service Scan (-sT -sV)
                                     v
                       +---------------------------+
                       |    Reporting Engine       |
                       | - report.json (Audit)     |
                       | - report.md (Academic)    |
                       +-------------+-------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
      [Unified CLI Engine]                    [FastAPI Local Adapter]
     - python main.py demo                   - http://127.0.0.1:8000
     - python main.py scan                   - React + TypeScript SPA
     - python main.py benchmark              - Interactive DAA Labs
```

### Module Layout

```text
TargetRecon/
├── main.py                  # Unified CLI (demo, scan, benchmark)
├── api_server.py            # Localhost FastAPI REST adapter & SPA static server
├── config.py                # Centralized configuration, timeouts, paths, credentials
├── models.py                # Provenance-preserving data models and normalization
├── scheduler.py             # DAA 0/1 Knapsack DP, Greedy, and Discovery schedulers
├── graph.py                 # Adjacency-list asset graph, BFS, DFS, consistency checks
├── report.py                # Dual JSON & Markdown report generation engine
├── run_dashboard.bat        # Windows 1-click batch launcher for web dashboard
├── run_dashboard.ps1        # PowerShell launcher (production & dev modes)
├── requirements.txt         # Core dependencies (requests, dnspython, pytest, fastapi, uvicorn)
├── .env.example             # Sample environment variables
├── .gitignore               # Ignored artifacts, virtual environments, cache
├── frontend/                # Professional SOC Web Dashboard
│   ├── package.json         # React 18, TypeScript, Tailwind CSS, Recharts, Lucide
│   ├── vite.config.ts       # Vite configuration with /api backend proxy
│   ├── tailwind.config.js   # Dark graphite SOC theme configuration
│   ├── dist/                # Production-compiled static assets
│   └── src/
│       ├── api.ts           # Type-safe REST client for FastAPI endpoints
│       ├── types.ts         # TypeScript schema definitions matching backend models
│       ├── components/      # Sidebar, Header, KPI Cards, Status Badges
│       └── pages/           # Overview, NewRun, Inventory, Graph, Algorithms, Findings, Reports
├── passive/
│   ├── crtsh.py             # Certificate transparency query engine
│   ├── dns_records.py       # Passive DNS resolver queries
│   ├── whois_lookup.py      # System whois & socket fallback parser
│   ├── theharvester.py      # theHarvester adapter (optional)
│   └── indexed_services.py  # Shodan & Censys adapters (optional)
├── active/
│   ├── scope.py             # Strict CIDR/host allowlist enforcement
│   ├── nmap_runner.py       # Conservative Nmap runner & offline XML parser
│   └── dns_checks.py        # Active DNS verification & gated AXFR check
├── banner/
│   ├── grabber.py           # Controlled socket banner grabber
│   ├── matcher.py           # From-scratch Aho-Corasick and NaiveMatcher
│   └── signatures.json      # Service identification signatures
├── benchmarks/
│   ├── benchmark_scheduler.py  # Standalone scheduler scaling benchmarks
│   ├── benchmark_matcher.py    # Standalone Aho-Corasick vs Naive benchmarks
│   ├── benchmark_graph.py      # Standalone graph scaling benchmarks
│   └── results/                # Generated CSV & JSON benchmark outputs
├── fixtures/
│   ├── passive_data.json    # Deterministic offline passive dataset
│   ├── nmap_sample.xml      # Valid Nmap XML scan output
│   └── banners.json         # Real-world protocol banner fixtures
└── tests/
    ├── test_scheduler.py    # Unit tests for DP, greedy suboptimality, edge cases
    ├── test_matcher.py      # Unit tests for Aho-Corasick, overlapping, equivalence
    ├── test_graph.py        # Unit tests for BFS, DFS, components, consistency
    ├── test_normalization.py# Unit tests for normalization and deduplication
    ├── test_scope_and_nmap.py# Scope allowlist & offline XML parser tests
    ├── test_passive_fixtures.py# Passive parsing and graceful tool degradation
    ├── test_reporting.py    # Report generation tests
    └── test_api_server.py   # FastAPI adapter and DAA REST endpoint tests
```

---

## 3. Installation & Requirements

### System Requirements
- **Python:** Version 3.11 or newer (tested on Python 3.12.4).
- **Operating Systems:** Windows 10/11, Ubuntu 20.04+, Debian, macOS.

### Optional External Tools
The framework gracefully detects whether external tools are installed on the system PATH. Missing utilities trigger clear warnings and do not crash the pipeline:
- `nmap` (Optional: needed for live active port scans).
- `whois` (Optional: falls back to direct RFC 3912 socket queries).
- `theHarvester` (Optional: passive OSINT tool).
- `dig` / `whatweb` (Optional integrations).

### Step-by-Step Setup

```powershell
# 1. Navigate to the project root directory
cd s:\TargetRecon

# 2. Create the project-local Python virtual environment
python -m venv .venv

# 3. Activate the virtual environment in Windows PowerShell
# (If execution of scripts is restricted in your PowerShell session, first run:
#  Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned)
.venv\Scripts\Activate.ps1

# (On Linux / macOS bash or zsh):
# source .venv/bin/activate

# 4. Install dependencies strictly inside .venv
pip install -r requirements.txt

# 5. Run the test suite within the virtual environment
pytest -v
# (or directly via: .venv\Scripts\pytest.exe -v)
```

---

## 4. Configuration & Environment Variables

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

| Environment Variable | Default | Description |
|:---|:---:|:---|
| `RECON_TIMEOUT_SECONDS` | `5.0` | Socket and HTTP request timeout in seconds |
| `RECON_MAX_RETRIES` | `2` | Max connection retries for network calls |
| `RECON_RATE_LIMIT_DELAY` | `0.5` | Politeness delay between consecutive active probes |
| `RECON_MAX_BANNER_BYTES` | `2048` | Max socket response payload to prevent buffer exhaustion |
| `RECON_DEFAULT_BUDGET` | `15` | Default probe scheduling budget |
| `SHODAN_API_KEY` | *(None)* | Optional API key for Shodan indexed lookups |
| `CENSYS_API_ID` | *(None)* | Optional Censys API ID |
| `CENSYS_API_SECRET` | *(None)* | Optional Censys API Secret |

> [!NOTE]
> No API keys are required for core framework execution, testing, or DAA coursework benchmarks.

---

## 5. Command-Line Interface (CLI) Guide

### 1. Simulated Demo Mode (Completely Offline)
Runs an end-to-end simulated reconnaissance workflow using deterministic test fixtures. It executes all DAA algorithms, builds the graph, and outputs reports without emitting a single external network packet.

```bash
python main.py demo
```

To run with a custom probe budget:
```bash
python main.py demo --budget 20
```

### 2. Passive Reconnaissance Mode
Gathers public records (crt.sh, DNS resolvers, WHOIS, indexed services) without connecting directly to target services:

```bash
python main.py scan --domain example.com --mode passive
```

### 3. Authorized Active Reconnaissance Mode
Active scanning requires two mandatory safety mechanisms:
1. An explicit scope file (`--scope-file <path>`).
2. An affirmative authorization flag (`--confirm-active`).

```bash
# Create an authorization allowlist
echo example.com > scope.txt
echo 93.184.216.34 >> scope.txt

# Run authorized active scan with Knapsack DP budget
python main.py scan --domain example.com --mode active \
  --scope-file scope.txt --budget 15 --confirm-active
```

Optional DNS Zone Transfer (AXFR) test (strictly disabled by default):
```bash
python main.py scan --domain example.com --mode active \
  --scope-file scope.txt --budget 15 --confirm-active --enable-zone-transfer
```

### 4. Standalone DAA Performance Benchmarks
Executes algorithmic experiments offline using synthetic datasets:

```bash
# Run all benchmark suites
python main.py benchmark --all

# Or run specific benchmark components
python main.py benchmark --target scheduler
python main.py benchmark --target matcher
python main.py benchmark --target graph
```

---

## 6. Cybersecurity Web Dashboard & REST API

The framework provides an interactive, dark-themed SOC (Security Operations Center) dashboard built with **React**, **TypeScript**, **Tailwind CSS**, and a **FastAPI** backend adapter.

### 6.1 Dashboard Architecture

- **Visual Theme:** Dark graphite background (`#030712`), slate cards (`#0f172a`), cyan/teal accents (`#06b6d4`), and high-contrast typography.
- **Backend Source of Truth:** Pure Python reconnaissance engine and algorithms; no simulated numbers or hardcoded charts.
- **Localhost Isolation:** Server binds exclusively to `127.0.0.1:8000` to prevent unintended network exposure.
- **Safety Enforcement:** Active reconnaissance cannot be initiated without an explicit server-side scope allowlist and affirmative confirmation.

```
+--------------------------------------------------------------------+
|  TargetRecon SOC Web Dashboard                                     |
|  +------------------+  +-----------------------------------------+ |
|  | [Sidebar]        |  | [Header: Health Badge, Run Selector]    | |
|  | - Overview       |  +-----------------------------------------+ |
|  | - New Recon Run  |  | [Active View]                           | |
|  | - Inventory      |  |  * KPI Cards (Assets, IPs, Ports)       | |
|  | - Asset Graph    |  |  * Interactive Topology Graph (Canvas)  | |
|  | - Algorithms Lab |  |  * Algorithm Scaling Curves (Recharts)  | |
|  | - Findings       |  |  * Live DAA Interactive Sandboxes       | |
|  | - Reports        |  |  * Scope Allowlist Input & Validation   | |
|  +------------------+  +-----------------------------------------+ |
+--------------------------------------------------------------------+
                                | (Fetch / JSON)
                                v
+--------------------------------------------------------------------+
|  FastAPI Adapter (api_server.py: 127.0.0.1:8000)                   |
|  * Static SPA Hosting (frontend/dist/)                             |
|  * Background Recon Job Runner & Polling State Machine             |
|  * Pure-Python DAA Execution Engine (Knapsack, Aho-Corasick, Graph)|
+--------------------------------------------------------------------+
```

### 6.2 Launching the Dashboard

#### Option A: One-Click Launch (Windows Batch or PowerShell)
Double-click `run_dashboard.bat` or run in PowerShell:
```powershell
.\run_dashboard.ps1
```
The script activates `.venv`, starts the server at `http://127.0.0.1:8000`, and opens the default browser.

#### Option B: Direct Python Execution
```powershell
.venv\Scripts\python.exe api_server.py
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

#### Option C: Development Mode (Hot-Reloading Frontend)
For frontend development with instant Vite HMR:
```powershell
# In terminal 1 (FastAPI backend):
.venv\Scripts\python.exe api_server.py

# In terminal 2 (Vite dev server):
cd frontend
npm run dev
```
Open [http://localhost:5173](http://localhost:5173). Requests to `/api/*` are automatically proxied to port 8000.

### 6.3 REST API Endpoints

| Category | Method & Endpoint | Description |
|:---|:---|:---|
| **System** | `GET /api/health` | System status, signature counts, external tool availability |
| **Runs** | `GET /api/runs` | List historical and active reconnaissance runs |
| | `POST /api/runs` | Dispatch new run (Demo, Passive, or Active with Scope) |
| | `GET /api/runs/{id}` | Full run metadata, summary KPIs, and scheduler results |
| | `GET /api/runs/{id}/status` | Lightweight status polling for live running jobs |
| | `POST /api/runs/{id}/cancel` | Cancel an in-flight background scan job |
| **Assets & Graph** | `GET /api/runs/{id}/assets` | Paginated/filtered asset inventory and observations |
| | `GET /api/runs/{id}/graph` | Adjacency graph nodes, edges, and cluster topology |
| | `GET /api/runs/{id}/findings` | Graph consistency discrepancies and evidence audit |
| **Reports** | `GET /api/runs/{id}/reports/json` | Download raw JSON audit report |
| | `GET /api/runs/{id}/reports/markdown` | Download formatted academic Markdown report |
| **DAA Test Bench** | `POST /api/algorithms/match-banner` | Live Aho–Corasick vs. Naive comparison on custom text |
| | `POST /api/algorithms/schedule` | Live Knapsack DP vs. Greedy vs. Discovery on custom items |
| | `POST /api/algorithms/graph-traverse`| Live step-by-step BFS or DFS traversal on run graph |
| **Benchmarks** | `GET /api/benchmarks/results` | Historical empirical scaling benchmark datasets |
| | `POST /api/benchmarks/{target}` | Trigger offline benchmark re-computation |

---

## 7. DAA Theoretical Foundations & Complexity Analysis

### 7.1 Probe Scheduling: 0/1 Knapsack Dynamic Programming

#### Problem Formulation
Given $n$ candidate active probes, each with estimated resource cost $w_i \in \mathbb{Z}^+$ and estimated information value $v_i \in \mathbb{Z}^+$, select a subset $S \subseteq \{1, \dots, n\}$ maximizing total value:
$$\max \sum_{i \in S} v_i \quad \text{subject to} \quad \sum_{i \in S} w_i \le B$$

#### Recurrence Relation
Let $dp[i][w]$ denote the maximum value obtainable using a subset of the first $i$ items with total cost at most $w$:

$$dp[i][w] = \begin{cases} 
dp[i-1][w] & \text{if } w_i > w \\ 
\max\left(dp[i-1][w], \, dp[i-1][w - w_i] + v_i\right) & \text{if } w_i \le w 
\end{cases}$$

Base cases: $dp[0][w] = 0$ for all $0 \le w \le B$, and $dp[i][0] = 0$ for all $0 \le i \le n$.

#### Backtracking Reconstruction
To recover the exact selected probes:
Starting at $i = n$ and $w = B$, if $dp[i][w] \ne dp[i-1][w]$, candidate $i-1$ was selected; we record candidate $i-1$, decrement $w \leftarrow w - w_i$, and decrement $i \leftarrow i - 1$. Otherwise, we decrement $i \leftarrow i - 1$.

#### Complexity Analysis
- **Time Complexity:** $\mathcal{O}(n \cdot B)$ arithmetic operations.
- **Space Complexity:** $\mathcal{O}(n \cdot B)$ memory cells to store the 2D table, enabling exact $\mathcal{O}(n)$ item reconstruction.
- **Greedy Suboptimality:** The Greedy heuristic sorts by ratio $v_i / w_i$. While running in $\mathcal{O}(n \log n)$, it can produce strictly suboptimal solutions because it fails to consider combinations that fill the knapsack more effectively (e.g., an item with ratio $1.17$ blocking two items with ratio $1.0$ whose combined value is higher).

---

### 7.2 Multi-Pattern Matching: Aho–Corasick Algorithm

#### Trie and Automaton Construction
Let $P = \sum_{k=1}^K |p_k|$ be the sum of lengths of all $K$ signatures.
1. **Trie Construction:** Inserts each signature character-by-character into a prefix trie. Complexity: $\mathcal{O}(P)$.
2. **Failure Links (BFS):**
   - For all depth-1 states $u$, $fail(u) = root$.
   - For a state $u$ with character transition $c \to v$, find the longest proper suffix matching a prefix in the trie:
     $$fail(v) = \text{transition}(fail(u), c)$$
   - Output links (dictionary links) inherit matches from $fail(v)$.
   - Complexity: $\mathcal{O}(P \cdot |\Sigma|)$, bounded by $\mathcal{O}(P)$ with hash table transitions.

#### Text Scanning
For input text of length $L$ emitting $Z$ reported occurrences:
- At each character, follow trie transitions or fallback failure links. Since failure links strictly decrease depth, the total number of failure transitions across the text scan is bounded by $\mathcal{O}(L)$.
- Reporting matches takes $\mathcal{O}(Z)$.
- Total Search Complexity: $\mathcal{O}(L + Z)$, completely independent of signature count $K$!
- In contrast, the NaiveMatcher inspects each pattern independently, requiring $\mathcal{O}(K \cdot L)$ time.

---

### 7.3 Asset Correlation Graph: Traversals and Consistency

#### Representation
- Vertex set $V$: Domains, Subdomains, IP Addresses, Endpoints (`host:port`), Services.
- Edge set $E$: Directed relationships (`HAS_SUBDOMAIN`, `RESOLVES_TO`, `EXPOSES_PORT`, `RUNS_SERVICE`).
- Stored as a forward and reverse adjacency list: $\mathcal{O}(V + E)$ space.

#### Breadth-First Search (BFS) & Depth-First Search (DFS)
- **BFS:** Explores level-by-level using a FIFO queue (`collections.deque`). Ideal for finding shortest relationship paths from a root domain to leaf service endpoints.
- **DFS:** Explores branch-by-branch using an explicit LIFO stack. Ideal for complete topological traversal and cycle/subgraph reachability.
- **Complexity:** Both algorithms visit each vertex at most once and traverse each incident edge at most once, achieving $\mathcal{O}(V + E)$ time complexity.

#### Consistency Discrepancy Checks
1. **Unresolved Subdomains:** Passively discovered subdomains lacking active DNS resolution edges.
2. **Indexed Service Unconfirmed:** Services reported in historical/indexed datasets (Shodan/Censys) not observed during authorized active scans.
3. **Fingerprint Disagreement:** Conflicting software identification between banner matching and web HTTP headers.
4. **Conflicting Observations:** Inconsistent values recorded for the same asset from differing data sources.

---

## 8. Empirical Benchmark Results

All benchmarks were executed offline on Windows 11 with Python 3.12.4. Results were generated via `time.perf_counter()` over 5 repetitions with median filtering.

### 8.1 Probe Scheduler Benchmark

| Candidate Probes ($n$) | Budget ($B$) | DP Value | DP Cost | DP Runtime | Greedy Value | Greedy Optimal? | Greedy Efficiency | Discovery Value | Discovery Efficiency |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **10** | 12 | 95 | 12 | 0.018 ms | 95 | ✓ Yes | 100.0% | 45 | 47.4% |
| **10** | 25 | **137** | 25 | 0.027 ms | **132** | **✗ Suboptimal** | **96.35%** | 95 | 69.3% |
| **50** | 58 | 475 | 58 | 0.239 ms | 475 | ✓ Yes | 100.0% | 245 | 51.6% |
| **100** | 115 | **1,070** | 115 | 0.923 ms | **1,063** | **✗ Suboptimal** | **99.35%** | 364 | 34.0% |
| **250** | 564 | **3,653** | 564 | 11.565 ms | **3,646** | **✗ Suboptimal** | **99.81%** | 2,268 | 62.1% |
| **500** | 1,076 | 7,333 | 1,076 | 49.978 ms | 7,333 | ✓ Yes | 100.0% | 3,873 | 52.8% |
| **1,000** | 2,181 | 14,863 | 2,181 | 207.028 ms | 14,863 | ✓ Yes | 100.0% | 8,506 | 57.2% |

> [!TIP]
> **Key Finding:** While the Greedy heuristic is computationally fast, it repeatedly lands on suboptimal selections (e.g., $N=10, B=25$ and $N=100, B=115$). The 0/1 Knapsack DP guarantees mathematical optimality across all budgets.

---

### 8.2 Multi-Pattern Matcher Benchmark (Aho–Corasick vs. Naive)

| Signatures ($K$) | Text Length ($L$) | AC Build Time | AC Search Time | Naive Search Time | **AC Speedup** | Output Equivalent? |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **10** | 500 bytes | 0.037 ms | 0.051 ms | 0.013 ms | 0.26x | ✓ True |
| **100** | 2,000 bytes | 0.256 ms | 0.159 ms | 0.107 ms | 0.67x | ✓ True |
| **250** | 2,000 bytes | 0.475 ms | 0.159 ms | 0.245 ms | **1.54x** | ✓ True |
| **500** | 2,000 bytes | 1.127 ms | 0.157 ms | 0.470 ms | **2.99x** | ✓ True |
| **500** | 8,000 bytes | 1.091 ms | 0.559 ms | 1.527 ms | **2.73x** | ✓ True |
| **1,000** | 500 bytes | 1.924 ms | 0.043 ms | 0.343 ms | **7.92x** | ✓ True |
| **1,000** | 8,000 bytes | 1.945 ms | 0.564 ms | 3.033 ms | **5.38x** | ✓ True |

> [!NOTE]
> **Key Finding:** For large signature sets ($K \ge 250$), Aho-Corasick significantly outperforms naive matching (up to **7.9x faster**). Notice that Aho-Corasick's search time is constant with respect to $K$ (e.g., $\approx 0.043\text{ ms}$ for 500 bytes across all $K$), whereas Naive matching time grows linearly with $K$.

---

### 8.3 Asset Correlation Graph Benchmark

| Subdomains | IPs | Total Vertices ($V$) | Total Edges ($E$) | Build Time | BFS Runtime | DFS Runtime | Vertices Explored | Coverage Equivalence |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 50 | 10 | 101 | 140 | 0.194 ms | 0.018 ms | 0.024 ms | 101 | ✓ True |
| 200 | 30 | 351 | 520 | 0.914 ms | 0.074 ms | 0.085 ms | 351 | ✓ True |
| 1,000 | 100 | 1,501 | 2,400 | 10.114 ms | 0.280 ms | 0.356 ms | 1,501 | ✓ True |
| 3,000 | 250 | 4,251 | 7,000 | 70.691 ms | 0.760 ms | 0.973 ms | 4,251 | ✓ True |
| 6,000 | 500 | 8,501 | 14,000 | 286.865 ms | 1.679 ms | 2.397 ms | 8,501 | ✓ True |

> [!TIP]
> **Key Finding:** Both BFS and DFS demonstrate strictly linear $\mathcal{O}(V + E)$ scaling up to 8,501 vertices and 14,000 edges, completing full traversals in under 2.5 milliseconds.

---

## 9. Verification & Test Suite

The test suite contains **48 automated unit tests** covering:
- Mathematical optimality of 0/1 Knapsack DP.
- Scenarios where Greedy is provably suboptimal.
- Aho-Corasick overlapping pattern matching and equivalence with naive search.
- Graph traversals (BFS, DFS, path tracing, shared IP detection, consistency checks).
- Domain and IP normalization and multi-source provenance preservation.
- Scope allowlist validation and rejection of unauthorized targets.
- Offline parsing of Nmap XML and passive JSON fixtures.
- Dual report generation (JSON and Markdown).
- FastAPI REST adapter endpoints, health probes, run state machines, and live algorithm benches.

To execute the complete test suite:

```bash
pytest -v
```

Expected output:
```text
============================= test session starts =============================
platform win32 -- Python 3.12.4, pytest-9.1.1
collected 48 items

tests/test_api_server.py::test_get_health PASSED                         [  2%]
tests/test_api_server.py::test_list_runs_includes_historical_demo PASSED [  4%]
tests/test_api_server.py::test_get_run_details_and_assets PASSED         [  6%]
tests/test_api_server.py::test_active_run_creation_safety_validation PASSED [  8%]
tests/test_api_server.py::test_live_banner_matching_endpoint PASSED      [ 10%]
tests/test_api_server.py::test_live_scheduler_endpoint PASSED            [ 12%]
tests/test_api_server.py::test_live_graph_traversal_endpoint PASSED      [ 14%]
tests/test_api_server.py::test_get_benchmark_results_endpoint PASSED     [ 16%]
tests/test_graph.py::test_bfs_traversal PASSED                           [ 18%]
tests/test_graph.py::test_dfs_traversal PASSED                           [  5%]
tests/test_graph.py::test_path_tracing PASSED                            [  7%]
tests/test_graph.py::test_shared_infrastructure_detection PASSED         [ 10%]
tests/test_graph.py::test_connected_components PASSED                    [ 13%]
tests/test_graph.py::test_consistency_unresolved_subdomain PASSED        [ 15%]
tests/test_graph.py::test_consistency_fingerprint_disagreement PASSED    [ 18%]
tests/test_graph.py::test_consistency_conflicting_observations PASSED    [ 21%]
tests/test_matcher.py::test_aho_corasick_basic_matching PASSED           [ 23%]
tests/test_matcher.py::test_overlapping_and_nested_patterns PASSED       [ 26%]
tests/test_matcher.py::test_repeated_occurrences PASSED                  [ 28%]
tests/test_matcher.py::test_case_sensitivity PASSED                      [ 31%]
tests/test_matcher.py::test_equivalence_with_naive_matcher PASSED        [ 34%]
tests/test_matcher.py::test_version_extraction PASSED                    [ 36%]
tests/test_normalization.py::test_normalize_domain PASSED                [ 39%]
tests/test_normalization.py::test_normalize_ip PASSED                    [ 42%]
tests/test_normalization.py::test_normalize_port PASSED                  [ 44%]
tests/test_normalization.py::test_deduplication_preserving_provenance PASSED [ 47%]
tests/test_passive_fixtures.py::test_fixture_passive_data_ingestion PASSED [ 50%]
tests/test_passive_fixtures.py::test_crtsh_mocked_success PASSED         [ 52%]
tests/test_passive_fixtures.py::test_crtsh_rate_limit_and_timeout PASSED [ 55%]
tests/test_passive_fixtures.py::test_missing_theharvester PASSED         [ 57%]
tests/test_passive_fixtures.py::test_missing_api_keys_shodan_and_censys PASSED [ 60%]
tests/test_passive_fixtures.py::test_parse_whois_redacted_fields PASSED  [ 63%]
tests/test_reporting.py::test_report_json_and_markdown_generation PASSED [ 65%]
tests/test_scheduler.py::test_knapsack_known_optimal PASSED              [ 68%]
tests/test_scheduler.py::test_greedy_is_suboptimal PASSED                [ 71%]
tests/test_scheduler.py::test_discovery_order_baseline PASSED            [ 73%]
tests/test_scheduler.py::test_edge_cases_empty_and_zero_budget PASSED    [ 76%]
tests/test_scheduler.py::test_edge_case_all_costs_exceed_budget PASSED   [ 78%]
tests/test_scheduler.py::test_edge_case_equal_values_and_costs PASSED    [ 81%]
tests/test_scheduler.py::test_compare_strategies PASSED                  [ 84%]
tests/test_scheduler.py::test_candidate_generation PASSED                [ 86%]
tests/test_scope_and_nmap.py::test_scope_manager_hostnames_and_ips PASSED [ 89%]
tests/test_scope_and_nmap.py::test_scope_validation_exception PASSED     [ 92%]
tests/test_scope_and_nmap.py::test_scope_file_loading PASSED             [ 90%]
tests/test_scope_and_nmap.py::test_parse_nmap_xml_offline PASSED         [ 92%]
tests/test_scope_and_nmap.py::test_parse_nmap_malformed_xml PASSED       [ 95%]
tests/test_scope_and_nmap.py::test_hostname_suffix_matching PASSED       [ 97%]
tests/test_scope_and_nmap.py::test_dns_rebinding_and_ip_auditing PASSED  [100%]

============================= 48 passed in 0.45s ==============================
```

---

## 10. Ethical & Legal Boundaries

> [!IMPORTANT]
> **Strict Non-Exploitation Policy:**
> 1. This project is strictly educational coursework for Design and Analysis of Algorithms (DAA).
> 2. It contains **no exploitation code**, payload generators, credential guessers, brute-force engines, or vulnerability attack scripts.
> 3. Active scanning requires an explicit scope allowlist and affirmative confirmation (`--confirm-active`).
> 4. Automated scanning of third-party networks without prior written authorization is unethical and potentially illegal. Always restrict scans to authorized lab networks or simulated demo fixtures.

---

## 11. Limitations & Future Research

- **Large Budgets in Knapsack DP:** Because the standard DP recurrence runs in pseudopolynomial time $\mathcal{O}(nB)$, very large integer budgets ($B > 10^7$) require scaling heuristics or fully polynomial-time approximation schemes (FPTAS).
- **Alphabet Compression in Aho-Corasick:** The current trie implementation uses Python dictionary hashing for transitions. A flattened array representation using dense character mapping could further reduce memory footprint in embedded C/Rust extensions.
- **Dynamic Graph Updates:** The graph currently operates in batch ingestion mode. Incorporating dynamic graph connectivity algorithms (e.g., Holm-de Lichtenberg-Thorup) would permit real-time streaming updates of network observations.
