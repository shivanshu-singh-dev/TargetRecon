"""Unit tests for JSON and Markdown report generation."""

import json
import tempfile
from pathlib import Path
from report import build_report_data, generate_json_report, generate_markdown_report, write_reports


def test_report_json_and_markdown_generation():
    """Verify JSON validity and Markdown formatting."""
    inventory_data = {
        "subdomains": ["api.example.com", "mail.example.com"],
        "ip_addresses": ["93.184.216.34"],
        "dns_records": [],
        "services": [
            {
                "endpoint_id": "93.184.216.34:80/tcp",
                "host": "93.184.216.34",
                "port": 80,
                "protocol": "tcp",
                "service_name": "http",
                "product": "nginx",
                "version": "1.24.0",
                "confidence": 0.95,
                "source": "nmap",
            }
        ],
        "observations": [
            {
                "asset_id": "api.example.com",
                "source": "crt.sh",
                "method": "PASSIVE",
                "normalized_value": "api.example.com",
            }
        ],
        "errors": [],
    }

    scheduler_data = {
        "knapsack_dp": {
            "strategy": "0/1-Knapsack-DP",
            "selected_count": 2,
            "total_cost": 5,
            "total_value": 20,
            "budget": 10,
            "is_optimal": True,
        }
    }

    graph_data = {
        "metrics": {
            "total_nodes": 4,
            "total_edges": 3,
            "connected_components_count": 1,
        }
    }

    findings = [
        {
            "finding_type": "UNRESOLVED_SUBDOMAIN",
            "asset_id": "legacy.example.com",
            "description": "Subdomain lacks DNS resolution.",
            "evidence_sources": ["crt.sh"],
        }
    ]

    report_dict = build_report_data(
        target_domain="example.com",
        mode="demo",
        inventory_data=inventory_data,
        scheduler_comparison=scheduler_data,
        graph_data=graph_data,
        consistency_findings=findings,
    )

    # 1. Verify JSON generation and parseability
    json_str = generate_json_report(report_dict)
    parsed = json.loads(json_str)
    assert parsed["metadata"]["target_domain"] == "example.com"
    assert len(parsed["inventory"]["subdomains"]) == 2
    assert parsed["scheduler"]["knapsack_dp"]["is_optimal"] is True

    # 2. Verify Markdown formatting contains essential sections
    md_str = generate_markdown_report(report_dict)
    assert "# Algorithm-Optimized Reconnaissance Framework" in md_str
    assert "## 1. Executive Summary" in md_str
    assert "## 2. Discovered Assets Inventory" in md_str
    assert "0/1 Knapsack Dynamic Programming" in md_str
    assert "UNRESOLVED_SUBDOMAIN" in md_str

    # 3. Test writing files to a temporary directory
    with tempfile.TemporaryDirectory() as tmp_dir:
        json_path, md_path = write_reports(report_dict, output_dir=Path(tmp_dir), base_name="test_report")
        assert json_path.is_file()
        assert md_path.is_file()
        assert json_path.stat().st_size > 0
        assert md_path.stat().st_size > 0
