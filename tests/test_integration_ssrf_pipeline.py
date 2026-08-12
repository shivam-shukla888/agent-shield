"""
Integration Test: SSRF Security Pipeline Boundary (STEP 10C)

Pipeline:
POST /api/v1/scans (Private Target Endpoint) ──► ScanService ──► ScanEngine ──► AttackEngine ──► GenericHTTPAdapter ──► SSRF Policy ──► BLOCK ──► TargetResult (SSRF_REJECTION) ──► Evaluation (ERROR) ──► ScanResult (PARTIAL) ──► Safe ScanResponse
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


def test_integration_ssrf_pipeline_blocks_private_endpoint_without_network_call() -> None:
    """
    Integration Test proving that an SSRF-blocked endpoint (127.0.0.1) is blocked
    at the TargetAdapter network boundary BEFORE any network connection is attempted,
    yielding an operational error evaluation and safe ScanResponse without credentials or stack traces.
    """
    transport_called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200, json={"response": "SHOULD_NEVER_BE_REACHED"})

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Blocked Private Agent", endpoint="http://127.0.0.1:8000/chat")
    adapter = GenericHTTPAdapter(config=config, client=mock_client)

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
        "scan_id": "SCAN_SSRF_INTEGRATION_001",
        "target": {
            "target_name": "Blocked Private Agent",
            "endpoint": "http://127.0.0.1:8000/chat",
            "method": "POST",
            "timeout_seconds": 5.0,
        },
        "probes": {
            "probe_ids": ["PROMPT_LEAK_001"]
        },
        "risk_context": {
            "impact": "high",
            "exploitability": "high",
            "blast_radius": "medium",
            "asset_sensitivity": "confidential",
            "tool_privilege": "write",
        },
    }

    post_res = client.post("/api/v1/scans", json=payload)

    # 1. API Endpoint accepts request and returns HTTP 202 Accepted with ScanResponse
    assert post_res.status_code == 202

    # 2. CRITICAL INVARIANT: Outbound HTTP transport MUST NOT BE CALLED
    assert transport_called is False

    # 3. Assert scan completed with FAILED/PARTIAL status due to execution error evaluation
    response = client.get("/api/v1/scans/SCAN_SSRF_INTEGRATION_001")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "SCAN_SSRF_INTEGRATION_001"
    assert data["status"] in ("failed", "partial")

    # 4. Assert summary counts capture the probe execution and error evaluation
    summary = data["summary"]
    assert summary["total_probes"] == 1
    assert summary["completed_executions"] == 1
    assert summary["failed_executions"] == 0
    assert summary["error_evaluations"] == 1
    assert summary["total_findings"] == 0

    # 5. Assert safe response contents (no internal stack traces or raw adapter details)
    assert "SHOULD_NEVER_BE_REACHED" not in response.text
    assert "executions" not in data
    assert "raw_response" not in response.text
