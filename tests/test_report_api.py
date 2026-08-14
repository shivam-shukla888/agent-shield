"""
Unit tests for Report API Endpoint (STEP 16A).
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
from app.domain import FindingSeverity, FindingStatus, ProbeCategory, RiskLevel, ScanStatus
from app.domain.scan import ScanResult
from app.engine.scan import ScanEngine
from app.main import create_app
from app.repositories.scan import InMemoryScanRepository


API_KEY = "sk-proj-TEST_AGENTSHIELD_KEY_12345"


def make_dummy_scan_response(scan_id: str = "SCAN_API_001") -> ScanResponse:
    finding = ScanFindingResponse(
        finding_id="FIND_01",
        title="Prompt Injection",
        category=ProbeCategory.INSTRUCTION_OVERRIDE,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.CONFIRMED,
        confidence=0.9,
        description="Instruction override succeeded",
        impact="Prompt override",
        remediation="Validate prompt boundaries",
        affected_probe_ids=["PROBE_1"],
        affected_execution_ids=["EXEC_1"],
        evidence=[],
    )

    risk = ScanRiskResponse(
        risk_id="RISK_01",
        finding_id="FIND_01",
        risk_level=RiskLevel.HIGH,
        risk_score=80.0,
        confidence=0.9,
        factors={"impact": "high", "exploitability": "high", "blast_radius": "medium", "asset_sensitivity": "confidential", "tool_privilege": "read"},
        rationale="High risk instruction override",
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
        info_risks=0,
        low_risks=0,
        medium_risks=0,
        high_risks=1,
        critical_risks=0,
    )

    return ScanResponse(
        scan_id=scan_id,
        target_name="API Test Target",
        status=ScanStatus.COMPLETED,
        started_at="2026-01-01T12:00:00Z",
        completed_at="2026-01-01T12:01:00Z",
        summary=summary,
        findings=[finding],
        risk_assessments=[risk],
    )


def test_markdown_report_returns_200():
    repo = InMemoryScanRepository()
    repo.save(make_dummy_scan_response("SCAN_MD_200"))
    
    mock_scan_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_scan_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    resp = client.get(
        "/api/v1/scans/SCAN_MD_200/report?format=markdown",
        headers={"X-API-Key": API_KEY},
    )

    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "# AgentShield Security Report" in resp.text
    assert "API Test Target" in resp.text


def test_json_report_returns_200():
    repo = InMemoryScanRepository()
    repo.save(make_dummy_scan_response("SCAN_JS_200"))

    mock_scan_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_scan_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    resp = client.get(
        "/api/v1/scans/SCAN_JS_200/report?format=json",
        headers={"X-API-Key": API_KEY},
    )

    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    data = resp.json()
    assert data["report_id"] == "REPORT_SCAN_JS_200"
    assert data["scan_id"] == "SCAN_JS_200"


def test_invalid_format_rejected():
    app = create_app(api_key=API_KEY)
    client = TestClient(app)

    resp = client.get(
        "/api/v1/scans/SCAN_MD_200/report?format=xml",
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 400


def test_unknown_scan_returns_404():
    app = create_app(api_key=API_KEY)
    client = TestClient(app)

    resp = client.get(
        "/api/v1/scans/SCAN_NONEXISTENT/report",
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 404


def test_authentication_required_for_report():
    app = create_app(api_key=API_KEY)
    client = TestClient(app)

    resp = client.get("/api/v1/scans/SCAN_123/report")
    assert resp.status_code == 401


def test_report_endpoint_does_not_trigger_new_scan():
    repo = InMemoryScanRepository()
    repo.save(make_dummy_scan_response("SCAN_IDEMPOTENT"))

    mock_scan_engine = ScanEngine.__new__(ScanEngine)
    mock_scan_engine.run_scan = MagicMock()
    service = ScanService(scan_engine=mock_scan_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    client.get("/api/v1/scans/SCAN_IDEMPOTENT/report", headers={"X-API-Key": API_KEY})
    # Verify ScanEngine.run_scan was never called
    mock_scan_engine.run_scan.assert_not_called()


def test_report_endpoint_works_for_partial_and_failed_scans():
    repo = InMemoryScanRepository()
    
    partial_resp = ScanResponse(
        scan_id="SCAN_PARTIAL_01",
        target_name="Partial Target",
        status=ScanStatus.PARTIAL,
        started_at="2026-01-01T12:00:00Z",
        completed_at="2026-01-01T12:01:00Z",
        summary=ScanSummaryResponse(
            total_probes=2,
            completed_executions=1,
            failed_executions=1,
            safe_evaluations=0,
            violation_evaluations=1,
            inconclusive_evaluations=0,
            error_evaluations=1,
            total_findings=1,
            info_risks=0, low_risks=0, medium_risks=0, high_risks=1, critical_risks=0,
        ),
        findings=[],
        risk_assessments=[],
    )

    failed_resp = ScanResponse(
        scan_id="SCAN_FAILED_01",
        target_name="Failed Target",
        status=ScanStatus.FAILED,
        started_at="2026-01-01T12:00:00Z",
        completed_at="2026-01-01T12:01:00Z",
        summary=ScanSummaryResponse(
            total_probes=1,
            completed_executions=0,
            failed_executions=1,
            safe_evaluations=0,
            violation_evaluations=0,
            inconclusive_evaluations=0,
            error_evaluations=1,
            total_findings=0,
            info_risks=0, low_risks=0, medium_risks=0, high_risks=0, critical_risks=0,
        ),
        findings=[],
        risk_assessments=[],
    )

    repo.save(partial_resp)
    repo.save(failed_resp)

    mock_scan_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_scan_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    r1 = client.get("/api/v1/scans/SCAN_PARTIAL_01/report?format=markdown", headers={"X-API-Key": API_KEY})
    assert r1.status_code == 200
    assert "PARTIAL" in r1.text

    r2 = client.get("/api/v1/scans/SCAN_FAILED_01/report?format=json", headers={"X-API-Key": API_KEY})
    assert r2.status_code == 200
    assert r2.json()["status"] == "failed"
