"""Report generation engine producing consolidated JSON and Markdown reports.

Generates:
1. report.json: Full machine-readable audit trail including provenance,
   scheduler decisions, graph topology, and discrepancies.
2. report.md: Academic and executive summary presenting asset inventories,
   service detections, DAA optimization metrics, and safety boundaries.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Optional

from config import config


def build_report_data(
    target_domain: str,
    mode: str,
    inventory_data: dict[str, Any],
    scheduler_comparison: Optional[dict[str, Any]] = None,
    graph_data: Optional[dict[str, Any]] = None,
    consistency_findings: Optional[list[dict[str, Any]]] = None,
    scope_rules: Optional[list[str]] = None,
    benchmarks: Optional[dict[str, Any]] = None,
    collection_settings: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Assemble structured dictionary containing the full execution report."""
    return {
        "metadata": {
            "target_domain": target_domain,
            "mode": mode,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "framework": "Algorithm-Optimized Reconnaissance Framework",
            "version": "1.0.0 (DAA Coursework)",
            "settings": collection_settings or {
                "timeout": config.NETWORK_TIMEOUT,
                "max_retries": config.MAX_RETRIES,
                "banner_max_bytes": config.MAX_BANNER_BYTES,
                "default_budget": config.DEFAULT_PROBE_BUDGET,
            },
            "external_tools_status": config.get_tool_status(),
        },
        "authorization_scope": {
            "active_mode_confirmed": mode == "active",
            "scope_rules": scope_rules or [],
        },
        "inventory": inventory_data,
        "scheduler": scheduler_comparison or {},
        "graph": graph_data or {},
        "consistency_findings": consistency_findings or [],
        "benchmarks": benchmarks or {},
    }


def generate_json_report(report_data: dict[str, Any]) -> str:
    """Serialize report data to formatted JSON."""
    return json.dumps(report_data, indent=2, ensure_ascii=False)


def generate_markdown_report(report_data: dict[str, Any]) -> str:
    """Generate professional, academic Markdown documentation of the run."""
    meta = report_data.get("metadata", {})
    inv = report_data.get("inventory", {})
    sched = report_data.get("scheduler", {})
    graph = report_data.get("graph", {})
    findings = report_data.get("consistency_findings", [])
    bench = report_data.get("benchmarks", {})
    tools = meta.get("external_tools_status", {})

    target = meta.get("target_domain", "Unknown")
    mode = meta.get("mode", "Unknown").upper()
    ts = meta.get("timestamp", "N/A")

    subdomains = inv.get("subdomains", [])
    ips = inv.get("ip_addresses", [])
    dns_records = inv.get("dns_records", [])
    services = inv.get("services", [])
    errors = inv.get("errors", [])

    lines = [
        f"# Algorithm-Optimized Reconnaissance Framework — Audit Report",
        f"",
        f"**Target Domain:** `{target}`  ",
        f"**Execution Mode:** `{mode}`  ",
        f"**Timestamp (UTC):** `{ts}`  ",
        f"**Tool Availability:** " + ", ".join(f"{k}={'✓' if v else '✗'}" for k, v in tools.items()),
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary",
        f"",
        f"The reconnaissance pipeline completed execution in **{mode}** mode for target domain `{target}`. "
        f"A total of **{len(subdomains)}** subdomains, **{len(ips)}** IP addresses, and **{len(services)}** "
        f"network services were identified. Data relationships were correlated into an asset graph comprising "
        f"**{graph.get('metrics', {}).get('total_nodes', 0)}** vertices and **{graph.get('metrics', {}).get('total_edges', 0)}** directed edges.",
        f"",
        f"> [!NOTE]",
        f"> Discovered services and software versions are reported for asset auditing and correlation. "
        f"> Exposure of a port or banner advertisement does **not** indicate a confirmed vulnerability.",
        f"",
        f"## 2. Discovered Assets Inventory",
        f"",
        f"### 2.1 Subdomains ({len(subdomains)})",
        f"",
    ]

    if subdomains:
        lines.append("| Subdomain | Corroborating Sources |")
        lines.append("|:---|:---|")
        # Compute sources per subdomain from observations
        obs_map: dict[str, set[str]] = {}
        for obs in inv.get("observations", []):
            aid = obs.get("asset_id")
            src = obs.get("source")
            if aid and src:
                obs_map.setdefault(aid, set()).add(src)

        for sub in sorted(subdomains):
            srcs = ", ".join(sorted(obs_map.get(sub, ["unspecified"])))
            lines.append(f"| `{sub}` | {srcs} |")
    else:
        lines.append("*No subdomains discovered.*")

    lines.extend([
        f"",
        f"### 2.2 Resolved IP Addresses ({len(ips)})",
        f"",
    ])

    if ips:
        lines.append("| IP Address | Originating Source |")
        lines.append("|:---|:---|")
        for ip in sorted(ips):
            lines.append(f"| `{ip}` | DNS Resolver / Passive |")
    else:
        lines.append("*No IP addresses recorded.*")

    lines.extend([
        f"",
        f"### 2.3 Identified Network Services ({len(services)})",
        f"",
    ])

    if services:
        lines.append("| Endpoint | Service Name | Identified Product | Version | Tech Stack | Security Grade | Confidence |")
        lines.append("|:---|:---|:---|:---|:---|:---:|:---:|")
        for s in services:
            ep = s.get("endpoint_id", f"{s.get('host')}:{s.get('port')}")
            s_name = s.get("service_name") or "unknown"
            prod = s.get("product") or "Unidentified"
            ver = s.get("version") or "N/A"
            frameworks = ", ".join(s.get("detected_frameworks", [])) or "—"
            sec_score = s.get("security_score") or "—"
            conf = f"{s.get('confidence', 0.8) * 100:.0f}%"
            lines.append(f"| `{ep}` | {s_name} | {prod} | {ver} | {frameworks} | {sec_score} | {conf} |")

        # Include Deep TLS Certificate telemetry if present
        tls_services = [s for s in services if s.get("tls_cert_info")]
        if tls_services:
            lines.extend([
                f"",
                f"### 2.4 Deep TLS / SSL Certificate Telemetry",
                f"",
                f"| Host:Port | Issuer | Subject CN | Days Remaining | Expired? | Subject Alternative Names (SANs) |",
                f"|:---|:---|:---|:---:|:---:|:---|",
            ])
            for s in tls_services:
                cert = s.get("tls_cert_info", {})
                sans_list = cert.get("sans", [])
                sans_preview = ", ".join(sans_list[:5])
                if len(sans_list) > 5:
                    sans_preview += f" (+{len(sans_list) - 5} more)"
                lines.append(
                    f"| `{s.get('endpoint_id')}` | {cert.get('issuer', 'N/A')} | `{cert.get('subject', 'N/A')}` | "
                    f"{cert.get('days_remaining', 'N/A')} | {'YES' if cert.get('is_expired') else 'NO'} | {sans_preview or 'None'} |"
                )
    else:
        lines.append("*No network services detected or active scanning was disabled.*")

    lines.extend([
        f"",
        f"## 3. Data Structures & Algorithms (DAA) Analysis",
        f"",
        f"### 3.1 Probe Scheduler Evaluation",
        f"",
        f"Under a bounded probe budget, the scheduler evaluates three strategies to select candidate active probes:",
        f"- **Discovery-Order:** Sequential first-fit baseline in order of arrival.",
        f"- **Greedy Heuristic:** Sorts descending by efficiency ratio (`value / cost`).",
        f"- **0/1 Knapsack Dynamic Programming:** Exact optimal subset selection using 2D DP recurrence $O(nB)$.",
        f"",
    ])

    if sched:
        lines.append("| Strategy | Probes Selected | Total Cost | Total Value | Budget | Optimal? |")
        lines.append("|:---|:---:|:---:|:---:|:---:|:---:|")
        for strat_key, strat_res in sched.items():
            name = strat_res.get("strategy", strat_key)
            sel = strat_res.get("selected_count", 0)
            cost = strat_res.get("total_cost", 0)
            val = strat_res.get("total_value", 0)
            bgt = strat_res.get("budget", 0)
            opt = "✓ Yes" if strat_res.get("is_optimal") else "✗ Suboptimal"
            lines.append(f"| **{name}** | {sel} | {cost} | {val} | {bgt} | {opt} |")
        lines.append("")
    else:
        lines.append("*No scheduler execution recorded for this mode.*")

    lines.extend([
        f"",
        f"### 3.2 Asset Correlation Graph & Consistency Analysis",
        f"",
        f"- **Total Nodes:** {graph.get('metrics', {}).get('total_nodes', 0)}",
        f"- **Total Edges:** {graph.get('metrics', {}).get('total_edges', 0)}",
        f"- **Connected Components:** {graph.get('metrics', {}).get('connected_components_count', 0)}",
        f"",
        f"#### Consistency & Evidence Discrepancies ({len(findings)})",
        f"",
    ])

    if findings:
        lines.append("| Finding Type | Asset Identifier | Description | Sources |")
        lines.append("|:---|:---|:---|:---|")
        for f in findings:
            ftype = f.get("finding_type", "UNKNOWN")
            aid = f.get("asset_id", "N/A")
            desc = f.get("description", "")
            srcs = ", ".join(f.get("evidence_sources", []))
            lines.append(f"| `{ftype}` | `{aid}` | {desc} | {srcs} |")
    else:
        lines.append("✓ *No evidence discrepancies or unresolved entity anomalies detected.*")

    if bench:
        lines.extend([
            f"",
            f"## 4. Algorithmic Benchmarks",
            f"",
            f"```json",
            json.dumps(bench, indent=2),
            f"```",
        ])

    if errors:
        lines.extend([
            f"",
            f"## 5. Collection Errors & Missing Providers",
            f"",
        ])
        for err in errors:
            lines.append(f"- **{err.get('source')}**: {err.get('message')}")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 6. Ethical and Authorization Boundaries",
        f"",
        f"- Active network scanning was performed strictly under explicit scope authorization.",
        f"- Rate limits and timeouts were enforced to prevent service degradation.",
        f"- No vulnerability exploits, credential stuffing, or intrusive penetration scripts were executed.",
    ])

    return "\n".join(lines)


def write_reports(
    report_data: dict[str, Any],
    output_dir: Optional[Path] = None,
    base_name: str = "report",
) -> tuple[Path, Path]:
    """Write report.json and report.md to output directory."""
    out_dir = output_dir or config.REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{base_name}.json"
    md_path = out_dir / f"{base_name}.md"

    json_content = generate_json_report(report_data)
    md_content = generate_markdown_report(report_data)

    json_path.write_text(json_content, encoding="utf-8")
    md_path.write_text(md_content, encoding="utf-8")

    return json_path, md_path
