"""
Unit tests for Report Download Endpoint & Content-Disposition security (STEP 16B).
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


API_KEY = "sk-proj-DOWNLOAD_TEST_KEY_12345"


def make_download_scan_response(scan_id: str = "SCAN_DL_001") -> ScanResponse:
    finding = ScanFindingResponse(
        finding_id="FIND_DL_01",
        title="Sample Finding",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.CONFIRMED,
        confidence=0.8,
        description="Sample vulnerability",
        impact="Low impact",
        remediation="Sample fix",
        affected_probe_ids=["PROBE_1"],
        affected_execution_ids=["EXEC_1"],
        evidence=[],
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
        info_risks=0, low_risks=0, medium_risks=1, high_risks=0, critical_risks=0,
    )

    return ScanResponse(
        scan_id=scan_id,
        target_name="Download Target",
        status=ScanStatus.COMPLETED,
        started_at="2026-01-01T12:00:00Z",
        completed_at="2026-01-01T12:01:00Z",
        summary=summary,
        findings=[finding],
        risk_assessments=[],
    )


def test_markdown_download_endpoint():
    repo = InMemoryScanRepository()
    repo.save(make_download_scan_response("SCAN_MD_DL"))

    mock_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    resp = client.get("/api/v1/scans/SCAN_MD_DL/report?format=markdown", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "Content-Disposition" in resp.headers
    assert 'attachment; filename="agentshield-report-SCAN_MD_DL.md"' in resp.headers["Content-Disposition"]


def test_json_download_endpoint():
    repo = InMemoryScanRepository()
    repo.save(make_download_scan_response("SCAN_JS_DL"))

    mock_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    resp = client.get("/api/v1/scans/SCAN_JS_DL/report?format=json", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    assert "Content-Disposition" in resp.headers
    assert 'attachment; filename="agentshield-report-SCAN_JS_DL.json"' in resp.headers["Content-Disposition"]


def test_html_download_endpoint():
    repo = InMemoryScanRepository()
    repo.save(make_download_scan_response("SCAN_HTML_DL"))

    mock_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    resp = client.get("/api/v1/scans/SCAN_HTML_DL/report?format=html", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Content-Disposition" in resp.headers
    assert 'attachment; filename="agentshield-report-SCAN_HTML_DL.html"' in resp.headers["Content-Disposition"]


def test_pdf_download_endpoint():
    repo = InMemoryScanRepository()
    repo.save(make_download_scan_response("SCAN_PDF_DL"))

    mock_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)

    app = create_app(api_key=API_KEY, service=service)
    client = TestClient(app)

    resp = client.get("/api/v1/scans/SCAN_PDF_DL/report?format=pdf", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 200
    assert "application/pdf" in resp.headers["content-type"]
    assert "Content-Disposition" in resp.headers
    assert 'attachment; filename="agentshield-report-SCAN_PDF_DL.pdf"' in resp.headers["Content-Disposition"]
    assert resp.content.startswith(b"%PDF-")


def test_invalid_format_returns_400():
    app = create_app(api_key=API_KEY)
    client = TestClient(app)

    resp = client.get("/api/v1/scans/SCAN_123/report?format=docx", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 400


def test_header_injection_and_path_traversal_sanitized():
    repo = InMemoryScanRepository()
    malicious_id = "SCAN_TEST_123\r\nSet-Cookie:admin=true\r\n../etc/passwd"
    repo.save(make_download_scan_response(malicious_id))

    mock_engine = ScanEngine.__new__(ScanEngine)
    service = ScanService(scan_engine=mock_engine, repository=repo)

    result = service.generate_report(malicious_id, report_format="markdown")
    assert result is not None
    content, media_type, filename = result

    # CRLF, path traversal (..), and directory slashes must NOT appear in generated filename header
    assert "\r" not in filename
    assert "\n" not in filename
    assert ".." not in filename
    assert "/" not in filename
    assert "\\" not in filename
    assert filename == "agentshield-report-SCAN_TEST_123__Set-Cookie_admin_true_____etc_passwd.md"
