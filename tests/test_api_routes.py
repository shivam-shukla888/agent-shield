"""
Unit and API Route Tests for AgentShield REST API (STEP 10B).
"""

from typing import Optional
import pytest
from fastapi.testclient import TestClient

from app.adapters.base import TargetAdapter
from app.api.routes import set_scan_service
from app.api.service import ScanService
from app.domain import (
    ScanStatus,
    TargetConfig,
    TargetResult,
)
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app


class RouteMockAdapter(TargetAdapter):
    def __init__(self):
        super().__init__(TargetConfig(name="Route Mock Target", endpoint="http://mock.local/chat"))

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


def create_test_client() -> TestClient:
    adapter = RouteMockAdapter()
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
    application = create_app(service=service)
    return TestClient(application)


def make_valid_payload():
    return {
        "scan_id": "SCAN_ROUTE_100",
        "target": {
            "target_name": "API Test Agent",
            "endpoint": "http://api.target.local/chat",
            "method": "POST",
            "headers": {"Authorization": "Bearer SECRET_HEADER"},
            "timeout_seconds": 30.0,
        },
        "probes": {
            "probe_ids": ["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"]
        },
        "risk_context": {
            "impact": "high",
            "exploitability": "high",
            "blast_radius": "medium",
            "asset_sensitivity": "confidential",
            "tool_privilege": "write",
        },
    }


def test_post_api_v1_scans_returns_202():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    assert res.status_code == 202


def test_valid_response_contains_scan_id():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    data = res.json()
    assert data["scan_id"] == "SCAN_ROUTE_100"


def test_valid_response_contains_status():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    data = res.json()
    assert data["status"] in ("created", "completed")


def test_valid_response_contains_summary():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    data = res.json()
    assert "summary" in data
    assert data["summary"]["total_probes"] == 2


def test_valid_response_contains_findings():
    client = create_test_client()
    post_res = client.post("/api/v1/scans", json=make_valid_payload())
    scan_id = post_res.json()["scan_id"]
    res = client.get(f"/api/v1/scans/{scan_id}")
    data = res.json()
    assert "findings" in data
    assert len(data["findings"]) > 0


def test_valid_response_contains_risk_assessments():
    client = create_test_client()
    post_res = client.post("/api/v1/scans", json=make_valid_payload())
    scan_id = post_res.json()["scan_id"]
    res = client.get(f"/api/v1/scans/{scan_id}")
    data = res.json()
    assert "risk_assessments" in data
    assert len(data["risk_assessments"]) > 0


def test_invalid_target_rejected():
    client = create_test_client()
    payload = make_valid_payload()
    payload["target"]["target_name"] = "  "
    res = client.post("/api/v1/scans", json=payload)
    assert res.status_code == 422


def test_invalid_timeout_rejected():
    client = create_test_client()
    payload = make_valid_payload()
    payload["target"]["timeout_seconds"] = 500.0
    res = client.post("/api/v1/scans", json=payload)
    assert res.status_code == 422


def test_invalid_url_scheme_rejected():
    client = create_test_client()
    payload = make_valid_payload()
    payload["target"]["endpoint"] = "ftp://invalid.local/chat"
    res = client.post("/api/v1/scans", json=payload)
    assert res.status_code == 422


def test_duplicate_probe_rejected():
    client = create_test_client()
    payload = make_valid_payload()
    payload["probes"]["probe_ids"] = ["PROMPT_LEAK_001", "PROMPT_LEAK_001"]
    res = client.post("/api/v1/scans", json=payload)
    assert res.status_code == 422


def test_unknown_probe_returns_400():
    client = create_test_client()
    payload = make_valid_payload()
    payload["probes"]["probe_ids"] = ["UNKNOWN_PROBE_999"]
    res = client.post("/api/v1/scans", json=payload)
    assert res.status_code == 400
    assert "Unknown probe ID" in res.json()["detail"]


def test_malformed_request_returns_422():
    client = create_test_client()
    res = client.post("/api/v1/scans", json={"invalid": "payload"})
    assert res.status_code == 422


def test_unexpected_service_error_returns_500():
    class FailingService:
        def execute_scan(self, request):
            raise Exception("Sensitive DB Connection Exception: postgresql://admin:secret_pass@localhost/db")

    client = TestClient(create_app(service=FailingService()))
    res = client.post("/api/v1/scans", json=make_valid_payload())
    assert res.status_code == 500
    assert res.json()["detail"] == "Scan execution failed."


def test_internal_exception_details_are_not_leaked():
    class ExceptionLeakerService:
        def execute_scan(self, request):
            raise RuntimeError("C:\\SecretFiles\\path\\to\\config.key leaking info")

    client = TestClient(create_app(service=ExceptionLeakerService()))
    res = client.post("/api/v1/scans", json=make_valid_payload())
    assert res.status_code == 500
    assert "config.key" not in res.text
    assert res.json()["detail"] == "Scan execution failed."


def test_credentials_are_not_returned():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    text = res.text
    assert "SECRET_HEADER" not in text
    assert "api_key" not in text


def test_raw_response_is_not_returned():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    data = res.json()
    assert "raw_response" not in res.text
    assert "executions" not in data


def test_raw_headers_are_not_returned():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    text = res.text
    assert "headers" not in text


def test_target_auth_config_is_not_returned():
    client = create_test_client()
    res = client.post("/api/v1/scans", json=make_valid_payload())
    text = res.text
    assert "auth_config" not in text
