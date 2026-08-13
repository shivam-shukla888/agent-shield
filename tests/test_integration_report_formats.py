"""
Integration test suite verifying end-to-end report rendering across all 4 formats (STEP 16B).

Formats: Markdown, JSON, HTML, PDF.
Statuses: Completed, Partial, Failed scans.
"""

from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from app.api.schemas import (
    ScanFindingResponse,
    ScanResponse,
    ScanRiskResponse,
    ScanSummaryResponse,
)
from app.api.service import ScanService
from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    FindingSeverity,
    FindingStatus,
    ImpactLevel,
    ProbeCategory,
    RiskFactors,
    RiskLevel,
    ScanStatus,
    ToolPrivilege,
)
from app.engine.scan import ScanEngine
from app.main import create_app
from app.repositories.scan import InMemoryScanRepository


API_KEY = "sk-proj-FORMAT_INTEGRATION_KEY_5555"


def create_mock_scan_response(scan_id: str, status: ScanStatus) -> ScanResponse:
    finding = ScanFindingResponse(
        finding_id=f"FIND_{scan_id}",
        title="Prompt Injection",
        category=ProbeCategory.INSTRUCTION_OVERRIDE,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.CONFIRMED,
        confidence=0.9,
        description="Vulnerability description",
        impact="Prompt override",
        remediation="Validate prompt tokens",
        affected_probe_ids=["PROBE_1"],
        affected_execution_ids=["EXEC_1"],
        evidence=[],
    )

    factors = RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.READ,
    )

    risk = ScanRiskResponse(
        risk_id=f"RISK_{scan_id}",
        finding_id=f"FIND_{scan_id}",
        risk_level=RiskLevel.HIGH,
        risk_score=85.0,
        confidence=0.9,
        factors=factors,
        rationale="High risk injection",
    )

    summary = ScanSummaryResponse(
        total_probes=1,
        completed_executions=1,
        failed_executions=0,
        safe_evaluations=0,
        violation_evaluations=1,
        inconclusive_evaluations=0,
        error_evaluations=0,
        total_findings=1,
        info_risks=0, low_risks=0, medium_risks=0, high_risks=1, critical_risks=0,
    )

    return ScanResponse(
        scan_id=scan_id,
        target_name="Format Integration Target",
        status=status,
        started_at="2026-01-01T12:00:00Z",
        completed_at="2026-01-01T12:01:00Z",
        summary=summary,
        findings=[finding],
        risk_assessments=[risk],
    )


def test_all_four_formats_for_completed_scan():
    repo = InMemoryScanRepository()
    repo.save(create_mock_scan_response("SCAN_COMPLETED_4FMT", ScanStatus.COMPLETED))

    mock_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    # 1. Markdown
    r_md = client.get("/api/v1/scans/SCAN_COMPLETED_4FMT/report?format=markdown", headers={"X-API-Key": API_KEY})
    assert r_md.status_code == 200
    assert "text/markdown" in r_md.headers["content-type"]
    assert "# AgentGuard Security Report" in r_md.text

    # 2. JSON
    r_js = client.get("/api/v1/scans/SCAN_COMPLETED_4FMT/report?format=json", headers={"X-API-Key": API_KEY})
    assert r_js.status_code == 200
    assert "application/json" in r_js.headers["content-type"]
    assert r_js.json()["report_id"] == "REPORT_SCAN_COMPLETED_4FMT"

    # 3. HTML
    r_html = client.get("/api/v1/scans/SCAN_COMPLETED_4FMT/report?format=html", headers={"X-API-Key": API_KEY})
    assert r_html.status_code == 200
    assert "text/html" in r_html.headers["content-type"]
    assert "<!DOCTYPE html>" in r_html.text

    # 4. PDF
    r_pdf = client.get("/api/v1/scans/SCAN_COMPLETED_4FMT/report?format=pdf", headers={"X-API-Key": API_KEY})
    assert r_pdf.status_code == 200
    assert "application/pdf" in r_pdf.headers["content-type"]
    assert r_pdf.content.startswith(b"%PDF-")


def test_reporting_for_partial_and_failed_scans():
    repo = InMemoryScanRepository()
    repo.save(create_mock_scan_response("SCAN_PARTIAL_4FMT", ScanStatus.PARTIAL))
    repo.save(create_mock_scan_response("SCAN_FAILED_4FMT", ScanStatus.FAILED))

    mock_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    # Partial scan HTML
    r1 = client.get("/api/v1/scans/SCAN_PARTIAL_4FMT/report?format=html", headers={"X-API-Key": API_KEY})
    assert r1.status_code == 200
    assert "PARTIAL" in r1.text

    # Failed scan PDF
    r2 = client.get("/api/v1/scans/SCAN_FAILED_4FMT/report?format=pdf", headers={"X-API-Key": API_KEY})
    assert r2.status_code == 200
    assert r2.content.startswith(b"%PDF-")
