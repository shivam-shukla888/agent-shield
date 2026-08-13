"""
Unit tests for PDF Report Rendering (STEP 16B).
"""

from datetime import datetime, timezone
import pytest

from app.domain.report import (
    ReportFinding,
    ReportRisk,
    SecurityReport,
)
from app.engine.report import ReportEngine


def make_pdf_test_report() -> SecurityReport:
    finding = ReportFinding(
        finding_id="FIND_PDF_01",
        category="instruction_override",
        title="Prompt Injection Vulnerability",
        severity="high",
        confidence=0.9,
        description="Target succumbed to instruction override attack.",
        evidence="Exfiltrated instruction text",
        affected_probe_ids=["PROBE_INJ_01"],
        affected_execution_ids=["EXEC_INJ_01"],
        remediation="Validate prompt boundary tokens.",
    )

    risk = ReportRisk(
        risk_id="RISK_PDF_01",
        finding_id="FIND_PDF_01",
        risk_level="high",
        risk_score=82.5,
        confidence=0.9,
        factors={"impact": "high"},
        rationale="High impact prompt injection vulnerability",
    )

    return SecurityReport(
        report_id="REPORT_PDF_001",
        scan_id="SCAN_PDF_001",
        target_name="PDF Target Agent",
        status="completed",
        generated_at=datetime.now(timezone.utc),
        executive_summary="PDF executive summary text.",
        summary={"total_probes": 1, "completed_executions": 1, "failed_executions": 0, "total_findings": 1, "high_risks": 1},
        findings=[finding],
        risk_assessments=[risk],
        recommendations=["Strengthen instruction hierarchy."],
    )


def test_pdf_bytes_generated():
    engine = ReportEngine()
    report = make_pdf_test_report()
    pdf_bytes = engine.render_pdf(report)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


def test_pdf_header_signature_valid():
    engine = ReportEngine()
    report = make_pdf_test_report()
    pdf_bytes = engine.render_pdf(report)

    # Standard PDF file header magic bytes signature %PDF-
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_contains_sections():
    engine = ReportEngine()
    report = make_pdf_test_report()
    pdf_bytes = engine.render_pdf(report)

    # Valid PDF file contains header, content body, and EOF marker
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes
    assert len(pdf_bytes) > 500
