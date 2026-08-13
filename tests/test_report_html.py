"""
Unit tests for HTML Report Rendering (STEP 16B).
"""

from datetime import datetime, timezone
import pytest

from app.domain.report import (
    ReportFinding,
    ReportRisk,
    SecurityReport,
)
from app.engine.report import ReportEngine


def make_test_report(malicious_title: str = "Test Finding") -> SecurityReport:
    finding = ReportFinding(
        finding_id="FIND_HTML_01",
        category="system_prompt_disclosure",
        title=malicious_title,
        severity="critical",
        confidence=0.95,
        description="Exploitable vulnerability detected.",
        evidence="Exfiltrated prompt string",
        affected_probe_ids=["PROBE_1"],
        affected_execution_ids=["EXEC_1"],
        remediation="Harden boundaries.",
    )

    risk = ReportRisk(
        risk_id="RISK_HTML_01",
        finding_id="FIND_HTML_01",
        risk_level="critical",
        risk_score=95.0,
        confidence=0.95,
        factors={"impact": "critical"},
        rationale="Critical impact system prompt disclosure",
    )

    return SecurityReport(
        report_id="REPORT_HTML_001",
        scan_id="SCAN_HTML_001",
        target_name="HTML Agent Target",
        status="completed",
        generated_at=datetime.now(timezone.utc),
        executive_summary="Executive summary for HTML test.",
        summary={"total_probes": 1, "completed_executions": 1, "failed_executions": 0, "total_findings": 1, "critical_risks": 1},
        findings=[finding],
        risk_assessments=[risk],
        recommendations=["Review prompt isolation boundaries."],
    )


def test_html_report_generated():
    engine = ReportEngine()
    report = make_test_report()
    html_out = engine.render_html(report)

    assert isinstance(html_out, str)
    assert len(html_out) > 0


def test_valid_html_structure():
    engine = ReportEngine()
    report = make_test_report()
    html_out = engine.render_html(report)

    assert "<!DOCTYPE html>" in html_out
    assert "<html" in html_out
    assert "</html>" in html_out
    assert "<head>" in html_out
    assert "<body>" in html_out


def test_html_sections_present():
    engine = ReportEngine()
    report = make_test_report()
    html_out = engine.render_html(report)

    assert "Executive Summary" in html_out
    assert "Scan Information" in html_out
    assert "Security Summary" in html_out
    assert "Findings" in html_out
    assert "Risk Assessments" in html_out
    assert "Recommendations" in html_out


def test_html_escaping_and_script_injection_blocked():
    engine = ReportEngine()
    malicious_payload = "<script>alert(1)</script><img src=x onerror=alert(1)>"
    report = make_test_report(malicious_title=malicious_payload)

    html_out = engine.render_html(report)

    # Raw executable script tags must NOT appear unescaped in HTML output
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_out
