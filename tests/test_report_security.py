"""
Unit tests for Report Security & Secret Redaction (STEP 16B).
"""

from datetime import datetime, timezone
import pytest

from app.domain.report import (
    ReportFinding,
    ReportRisk,
    SecurityReport,
)
from app.engine.report import ReportEngine


SECRET_KEY = "sk-proj-SUPER_SECRET_AGENTGUARD_KEY_12345"
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
DB_URL = "postgresql://admin:super_secret_db_password@localhost:5432/agentshield"


def make_security_test_report() -> SecurityReport:
    finding = ReportFinding(
        finding_id="FIND_SEC_01",
        category="system_prompt_disclosure",
        title="Vulnerability Report",
        severity="critical",
        confidence=1.0,
        description=f"Vulnerability report containing {SECRET_KEY} and {BEARER_TOKEN}",
        evidence=f"Evidence text with {DB_URL}",
        affected_probe_ids=["PROBE_1"],
        affected_execution_ids=["EXEC_1"],
        remediation="Sanitize credentials",
    )

    return SecurityReport(
        report_id="REPORT_SEC_001",
        scan_id="SCAN_SEC_001",
        target_name="Security Test Agent",
        status="completed",
        generated_at=datetime.now(timezone.utc),
        executive_summary="Security audit summary.",
        summary={"total_probes": 1, "completed_executions": 1, "failed_executions": 0, "total_findings": 1, "critical_risks": 1},
        findings=[finding],
        risk_assessments=[],
        recommendations=["Sanitize credentials."],
    )


def test_api_keys_never_appear_in_markdown():
    engine = ReportEngine()
    report = make_security_test_report()
    md = engine.render_markdown(report)

    assert "Authorization" not in md
    assert "X-API-Key" not in md


def test_bearer_tokens_never_appear_in_html():
    engine = ReportEngine()
    report = make_security_test_report()
    html_out = engine.render_html(report)

    assert "Authorization: Bearer" not in html_out
    assert "<script>" not in html_out


def test_db_credentials_never_appear_in_pdf():
    engine = ReportEngine()
    report = make_security_test_report()
    pdf_bytes = engine.render_pdf(report)

    pdf_str = pdf_bytes.decode("latin-1", "ignore")
    assert "postgresql://admin:super_secret_db_password" not in pdf_str


def test_raw_target_headers_and_responses_excluded():
    engine = ReportEngine()
    report = make_security_test_report()
    
    js = engine.render_json(report)
    assert "raw_response" not in js
    assert "target_headers" not in js
    assert "auth_token" not in js
