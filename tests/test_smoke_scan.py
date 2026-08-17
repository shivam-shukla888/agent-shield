"""
Smoke Scan End-to-End Test (Task 7)

Verifies that the minimal sample scan run against test_target fixture runs successfully
and produces the committed sample HTML report artifact docs/examples/sample_scan_report.html.
"""

from pathlib import Path
import pytest

from scripts.smoke_test_scan import run_smoke_scan_and_generate_report


def test_smoke_scan_runs_and_generates_html_report():
    report_path = run_smoke_scan_and_generate_report()
    assert report_path.exists()
    assert report_path.stat().st_size > 0

    content = report_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "AgentShield Security Report" in content
    assert "Local Synthetic Agent Target" in content
