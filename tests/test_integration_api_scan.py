"""
Integration Test: End-to-End REST API Scan Execution (STEP 10B)

Pipeline:
POST /api/v1/scans ──► ScanService ──► ScanEngine ──► AttackEngine ──► GenericHTTPAdapter ──► Local Target ──► Findings ──► RiskAssessments ──► ScanResponse
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.api.routes import set_scan_service
from app.api.service import ScanService
from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    ImpactLevel,
    ProbeCategory,
    RiskFactors,
    ScanStatus,
    TargetConfig,
    ToolPrivilege,
)
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app
from test_target.main import local_target_app
from test_target.tools import reset_test_state


def create_in_memory_adapter() -> GenericHTTPAdapter:
    """Helper creating GenericHTTPAdapter connected via in-memory mock transport to local_target_app."""
    test_client = TestClient(local_target_app)

    def handler(request: httpx.Request) -> httpx.Response:
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

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Local Security Test Target Fixture",
        endpoint="http://testagent.local/chat",
        request_template={"prompt": "{{input}}"},
        response_path="response",
        timeout_seconds=5.0,
    )
    return GenericHTTPAdapter(config=config, client=client)


@pytest.fixture(autouse=True)
def reset_state() -> None:
    """Reset synthetic database state prior to integration test."""
    reset_test_state()


def test_end_to_end_api_scan_integration_against_vulnerable_target() -> None:
    """
    End-to-End API Integration Test:
    Submits a ScanRequest via POST /api/v1/scans to trigger ScanService and ScanEngine
    against local_target_app. Verifies complete execution, 3 findings, 3 risk assessments,
    correct summary counts, and safe ScanResponse returned with HTTP 200.
    """
    adapter = create_in_memory_adapter()
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
    service = ScanService(scan_engine=scan_engine)
    app_instance = create_app(service=service)
    client = TestClient(app_instance)

    payload = {
        "scan_id": "SCAN_API_INTEGRATION_001",
        "target": {
            "target_name": "Local Security Test Target Fixture",
            "endpoint": "http://testagent.local/chat",
            "method": "POST",
            "request_template": {"prompt": "{{input}}"},
            "response_path": "response",
            "timeout_seconds": 5.0,
        },
        "probes": {
            "probe_ids": [
                "PROMPT_LEAK_001",
                "INSTRUCTION_OVERRIDE_001",
                "TOOL_AUTH_001",
            ]
        },
        "risk_context": {
            "impact": "high",
            "exploitability": "high",
            "blast_radius": "medium",
            "asset_sensitivity": "confidential",
            "tool_privilege": "write",
        },
    }

    post_response = client.post("/api/v1/scans", json=payload)
    assert post_response.status_code == 202
    assert post_response.json()["scan_id"] == "SCAN_API_INTEGRATION_001"
    assert post_response.json()["status"] == "created"

    response = client.get("/api/v1/scans/SCAN_API_INTEGRATION_001")
    assert response.status_code == 200

    data = response.json()
    assert data["scan_id"] == "SCAN_API_INTEGRATION_001"
    assert data["target_name"] == "Local Security Test Target Fixture"
    assert data["status"] == "completed"

    # Assert Summary
    summary = data["summary"]
    assert summary["total_probes"] == 3
    assert summary["completed_executions"] == 3
    assert summary["failed_executions"] == 0
    assert summary["violation_evaluations"] == 3
    assert summary["total_findings"] == 3

    # Assert Findings
    findings = data["findings"]
    assert len(findings) == 3
    finding_categories = {f["category"] for f in findings}
    assert finding_categories == {
        "system_prompt_disclosure",
        "instruction_override",
        "tool_authorization",
    }

    # Assert Risk Assessments
    risk_assessments = data["risk_assessments"]
    assert len(risk_assessments) == 3
    for ra in risk_assessments:
        assert ra["risk_level"] in ("high", "critical")
        assert ra["risk_score"] > 60.0

    # Assert Security Non-Disclosure (No raw responses, executions, headers, or internal metadata)
    assert "executions" not in data
    assert "raw_response" not in response.text
    assert "headers" not in data
    assert "metadata" not in data
