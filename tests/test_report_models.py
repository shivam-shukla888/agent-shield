"""
Unit tests for Report Domain Models (STEP 16A).
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.domain.report import (
    ReportFinding,
    ReportFormat,
    ReportRisk,
    SecurityReport,
)


def test_valid_report_creation():
    finding = ReportFinding(
        finding_id="FIND_001",
        category="system_prompt_disclosure",
        title="System Prompt Leak",
        severity="high",
        confidence=0.9,
        description="Target leaked system instructions.",
        evidence="Exfiltrated prompt string",
        affected_probe_ids=["PROBE_1"],
        affected_execution_ids=["EXEC_1"],
        remediation="Harden system prompt boundaries.",
    )

    risk = ReportRisk(
        risk_id="RISK_001",
        finding_id="FIND_001",
        risk_level="high",
        risk_score=75.0,
        confidence=0.9,
        factors={"impact": "high", "exploitability": "high"},
        rationale="High impact system prompt leakage.",
    )

    report = SecurityReport(
        report_id="REPORT_SCAN_123",
        scan_id="SCAN_123",
        target_name="Test Agent",
        status="completed",
        generated_at=datetime.now(timezone.utc),
        executive_summary="Scan completed against target 'Test Agent'.",
        summary={"total_probes": 1, "completed_executions": 1, "failed_executions": 0, "total_findings": 1},
        findings=[finding],
        risk_assessments=[risk],
        recommendations=["Harden system prompt boundaries."],
    )

    assert report.report_id == "REPORT_SCAN_123"
    assert report.scan_id == "SCAN_123"
    assert len(report.findings) == 1
    assert len(report.risk_assessments) == 1


def test_empty_report_id_rejected():
    with pytest.raises(ValidationError):
        SecurityReport(
            report_id="",
            scan_id="SCAN_123",
            target_name="Test Agent",
            status="completed",
            generated_at=datetime.now(timezone.utc),
            executive_summary="Summary",
            summary={},
        )


def test_empty_scan_id_rejected():
    with pytest.raises(ValidationError):
        SecurityReport(
            report_id="REPORT_1",
            scan_id="   ",
            target_name="Test Agent",
            status="completed",
            generated_at=datetime.now(timezone.utc),
            executive_summary="Summary",
            summary={},
        )


def test_invalid_confidence_rejected():
    with pytest.raises(ValidationError):
        ReportFinding(
            finding_id="F1",
            category="cat",
            title="T",
            severity="high",
            confidence=1.5,  # Out of bounds (> 1.0)
            description="D",
            remediation="R",
        )

    with pytest.raises(ValidationError):
        ReportRisk(
            risk_id="R1",
            finding_id="F1",
            risk_level="high",
            risk_score=50.0,
            confidence=-0.1,  # Out of bounds (< 0.0)
            rationale="R",
        )


def test_invalid_risk_score_rejected():
    with pytest.raises(ValidationError):
        ReportRisk(
            risk_id="R1",
            finding_id="F1",
            risk_level="high",
            risk_score=105.0,  # Out of bounds (> 100.0)
            confidence=0.8,
            rationale="R",
        )


def test_report_immutability():
    report = SecurityReport(
        report_id="REPORT_1",
        scan_id="SCAN_1",
        target_name="Agent",
        status="completed",
        generated_at=datetime.now(timezone.utc),
        executive_summary="Summary",
        summary={},
    )
    with pytest.raises(ValidationError):
        report.target_name = "New Agent Name"


def test_no_credential_fields():
    fields = SecurityReport.model_fields.keys()
    assert "api_key" not in fields
    assert "token" not in fields
    assert "password" not in fields
    assert "auth_config" not in fields
    assert "target_auth" not in fields


def test_no_cvss_fields():
    fields = SecurityReport.model_fields.keys()
    finding_fields = ReportFinding.model_fields.keys()
    risk_fields = ReportRisk.model_fields.keys()

    assert "cvss" not in fields
    assert "cvss_score" not in finding_fields
    assert "cvss_vector" not in risk_fields
