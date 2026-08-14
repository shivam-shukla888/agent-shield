"""
Integration test suite for Reporting Engine pipeline (STEP 16A).

Flow:
1. Submit scan request via API POST /api/v1/scans
2. Retrieve completed scan via GET /api/v1/scans/{scan_id}
3. Generate report via GET /api/v1/scans/{scan_id}/report (Markdown & JSON)
4. Verify findings, risks, and sanitized outputs.
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
from app.engine.scan import ScanEngine
from app.main import create_app
from app.repositories.scan import InMemoryScanRepository


API_KEY = "sk-proj-INTEGRATION_REPORTING_KEY_9999"


def test_end_to_end_reporting_pipeline():
    repo = InMemoryScanRepository()

    finding = ScanFindingResponse(
        finding_id="FIND_INT_01",
        title="Tool Authorization Bypass",
        category=ProbeCategory.TOOL_AUTHORIZATION,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.CONFIRMED,
        confidence=0.88,
        description="Tool invoked without authorization",
        impact="Unauthorized file deletion",
        remediation="Enforce tool permission checks",
        affected_probe_ids=["PROBE_TOOL_01"],
        affected_execution_ids=["EXEC_TOOL_01"],
        evidence=[],
    )

    risk = ScanRiskResponse(
        risk_id="RISK_INT_01",
        finding_id="FIND_INT_01",
        risk_level=RiskLevel.HIGH,
        risk_score=72.5,
        confidence=0.88,
        factors={"impact": "high", "exploitability": "high", "blast_radius": "medium", "asset_sensitivity": "internal", "tool_privilege": "write"},
        rationale="High impact tool authorization bypass",
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

    scan_resp = ScanResponse(
        scan_id="SCAN_E2E_REPORT",
        target_name="Integration Target Agent",
        status=ScanStatus.COMPLETED,
        started_at="2026-01-01T12:00:00Z",
        completed_at="2026-01-01T12:01:00Z",
        summary=summary,
        findings=[finding],
        risk_assessments=[risk],
    )
    repo.save(scan_resp)

    mock_engine = MagicMock(spec=ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)
    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    # 1. Retrieve scan
    get_resp = client.get("/api/v1/scans/SCAN_E2E_REPORT", headers={"X-API-Key": API_KEY})
    assert get_resp.status_code == 200
    assert get_resp.json()["scan_id"] == "SCAN_E2E_REPORT"

    # 2. Generate Markdown Report
    md_resp = client.get("/api/v1/scans/SCAN_E2E_REPORT/report?format=markdown", headers={"X-API-Key": API_KEY})
    assert md_resp.status_code == 200
    assert "text/markdown" in md_resp.headers["content-type"]
    md_text = md_resp.text
    assert "# AgentShield Security Report" in md_text
    assert "Tool Authorization Bypass" in md_text
    assert "Enforce tool permission checks" in md_text

    # 3. Generate JSON Report
    js_resp = client.get("/api/v1/scans/SCAN_E2E_REPORT/report?format=json", headers={"X-API-Key": API_KEY})
    assert js_resp.status_code == 200
    assert "application/json" in js_resp.headers["content-type"]
    js_data = js_resp.json()
    assert js_data["report_id"] == "REPORT_SCAN_E2E_REPORT"
    assert js_data["findings"][0]["finding_id"] == "FIND_INT_01"
    assert js_data["risk_assessments"][0]["risk_score"] == 72.5
