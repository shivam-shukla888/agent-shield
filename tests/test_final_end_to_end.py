"""
Final End-to-End System Integration Validation Test Suite (STEP 20A)

Validates the full REST API scan pipeline against a local synthetic agent target:
POST /api/v1/scans ──► 202 Accepted ──► ScanService ──► Background Job ──► ScanEngine ──►
TargetAdapter ──► Probes ──► Evaluations ──► Findings ──► RiskAssessments ──►
Repository ──► GET /api/v1/scans/{scan_id} ──► GET /api/v1/scans/{scan_id}/report
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.api.routes import set_scan_service
from app.api.service import ScanService
from app.domain.target import TargetConfig
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.report import ReportEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app
from app.probes.basic import get_basic_probes
from app.repositories import InMemoryScanRepository
from test_target.main import local_target_app
from test_target.tools import reset_test_state


def create_test_scan_service() -> ScanService:
    """Construct ScanService with GenericHTTPAdapter connected to local_target_app via MockTransport."""
    test_client = TestClient(local_target_app)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        res = test_client.request(
            method=request.method,
            url=str(request.url),
            content=request.content,
            headers=dict(request.headers),
        )
        return httpx.Response(
            status_code=res.status_code,
            headers=dict(res.headers),
            content=res.content,
        )

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = TargetConfig(
        name="Local Synthetic Agent Target",
        endpoint="http://testagent.local/chat",
        request_template={"prompt": "{{input}}"},
        response_path="response",
        timeout_seconds=5.0,
    )
    adapter = GenericHTTPAdapter(config=config, client=client)
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = DeterministicEvaluator()
    finding_engine = FindingEngine()
    risk_engine = RiskEngine()
    scan_engine = ScanEngine(
        attack_engine=attack_engine,
        evaluator=evaluator,
        finding_engine=finding_engine,
        risk_engine=risk_engine,
    )
    repo = InMemoryScanRepository()
    report_engine = ReportEngine()
    return ScanService(scan_engine=scan_engine, repository=repo, report_engine=report_engine)


@pytest.fixture(autouse=True)
def reset_synthetic_target():
    reset_test_state()


class TestFinalEndToEndScanPipeline:
    """Full End-to-End REST API scan lifecycle validation."""

    def test_e2e_scan_submission_retrieval_and_report_generation(self):
        service = create_test_scan_service()
        app = create_app(service=service, api_key="e2e-master-key")
        client = TestClient(app)

        api_headers = {"X-API-Key": "e2e-master-key"}

        # 1. Submit scan request
        payload = {
            "scan_id": "FINAL_E2E_SCAN_001",
            "target": {
                "target_name": "Local Synthetic Agent Target",
                "endpoint": "http://testagent.local/chat",
                "request_template": {"prompt": "{{input}}"},
                "response_path": "response",
            },
            "probes": {
                "probe_ids": ["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001", "TOOL_AUTH_001"]
            },
            "risk_context": {
                "impact": "high",
                "exploitability": "high",
                "blast_radius": "medium",
                "asset_sensitivity": "confidential",
                "tool_privilege": "write",
            },
        }

        submit_res = client.post("/api/v1/scans", json=payload, headers=api_headers)
        assert submit_res.status_code == 202
        data = submit_res.json()
        assert data["scan_id"] == "FINAL_E2E_SCAN_001"
        assert data["target_name"] == "Local Synthetic Agent Target"
        assert data["status"] in ("created", "running", "completed")

        # 2. Retrieve completed scan via GET /api/v1/scans/{scan_id}
        get_res = client.get("/api/v1/scans/FINAL_E2E_SCAN_001", headers=api_headers)
        assert get_res.status_code == 200
        scan_data = get_res.json()

        assert scan_data["scan_id"] == "FINAL_E2E_SCAN_001"
        assert scan_data["status"] == "completed"
        assert scan_data["started_at"] is not None
        assert scan_data["completed_at"] is not None

        # Assert summary counts
        summary = scan_data["summary"]
        assert summary["total_probes"] == 3
        assert summary["completed_executions"] == 3
        assert summary["failed_executions"] == 0
        assert summary["violation_evaluations"] == 3
        assert summary["total_findings"] == 3

        # Assert findings sanitization (no raw Authorization headers or secrets)
        assert len(scan_data["findings"]) == 3
        for finding in scan_data["findings"]:
            assert "finding_id" in finding
            assert "category" in finding
            assert "severity" in finding
            assert "confidence" in finding
            assert "title" in finding
            assert "description" in finding

        # Assert risk assessments
        assert len(scan_data["risk_assessments"]) == 3
        for risk in scan_data["risk_assessments"]:
            assert "risk_id" in risk
            assert "risk_level" in risk
            assert risk["risk_score"] > 50.0

        # 3. Retrieve paginated list via GET /api/v1/scans
        list_res = client.get("/api/v1/scans?limit=10&offset=0", headers=api_headers)
        assert list_res.status_code == 200
        scans_list = list_res.json()
        assert len(scans_list) >= 1
        assert scans_list[0]["scan_id"] == "FINAL_E2E_SCAN_001"

        # 4. Generate Security Reports in Markdown, JSON, HTML, PDF
        md_res = client.get("/api/v1/scans/FINAL_E2E_SCAN_001/report?format=markdown", headers=api_headers)
        assert md_res.status_code == 200
        assert md_res.headers["content-type"].startswith("text/markdown")
        assert "FINAL_E2E_SCAN_001" in md_res.text
        assert "System Prompt Disclosure" in md_res.text

        json_report_res = client.get("/api/v1/scans/FINAL_E2E_SCAN_001/report?format=json", headers=api_headers)
        assert json_report_res.status_code == 200
        assert json_report_res.headers["content-type"].startswith("application/json")
        report_json = json_report_res.json()
        assert report_json["scan_id"] == "FINAL_E2E_SCAN_001"
        assert len(report_json["findings"]) == 3

        html_res = client.get("/api/v1/scans/FINAL_E2E_SCAN_001/report?format=html", headers=api_headers)
        assert html_res.status_code == 200
        assert html_res.headers["content-type"].startswith("text/html")
        assert "<!DOCTYPE html>" in html_res.text or "<html" in html_res.text.lower()
        assert "FINAL_E2E_SCAN_001" in html_res.text

        pdf_res = client.get("/api/v1/scans/FINAL_E2E_SCAN_001/report?format=pdf", headers=api_headers)
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"].startswith("application/pdf")
        assert len(pdf_res.content) > 100
