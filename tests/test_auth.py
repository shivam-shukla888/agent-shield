"""
Unit and API Security Tests for API Key Authentication (STEP 12A).
"""

from typing import Optional
from fastapi.testclient import TestClient
import pytest

from app.adapters.base import TargetAdapter
from app.api.service import ScanService
from app.domain import TargetConfig, TargetResult
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app
from app.repositories import InMemoryScanRepository
from app.security.auth import APIKeyAuthenticator, extract_api_key


class AuthMockAdapter(TargetAdapter):
    def __init__(self):
        super().__init__(TargetConfig(name="Auth Mock Target", endpoint="http://mock.local/chat"))

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


def create_authenticated_test_client(master_api_key: Optional[str] = "master-secret-key-999") -> TestClient:
    adapter = AuthMockAdapter()
    scan_engine = ScanEngine(
        attack_engine=AttackEngine(adapter=adapter),
        evaluator=DeterministicEvaluator(),
        finding_engine=FindingEngine(),
        risk_engine=RiskEngine(),
    )
    repository = InMemoryScanRepository()
    service = ScanService(scan_engine=scan_engine, repository=repository)
    application = create_app(service=service, api_key=master_api_key)
    return TestClient(application)


def make_valid_payload(scan_id: str = "SCAN_AUTH_001"):
    return {
        "scan_id": scan_id,
        "target": {
            "target_name": "Auth Test Agent",
            "endpoint": "http://target.local/chat",
            "method": "POST",
            "timeout_seconds": 15.0,
        },
        "probes": {"probe_ids": ["PROMPT_LEAK_001"]},
        "risk_context": {
            "impact": "high",
            "exploitability": "high",
            "blast_radius": "medium",
            "asset_sensitivity": "confidential",
            "tool_privilege": "write",
        },
    }


def test_authenticator_disabled_by_default():
    auth = APIKeyAuthenticator(api_key=None)
    assert not auth.is_enabled
    assert auth.verify_key(None) is True
    assert auth.verify_key("any-key") is True


def test_authenticator_valid_key():
    auth = APIKeyAuthenticator(api_key="secret-key-123")
    assert auth.is_enabled
    assert auth.verify_key("secret-key-123") is True
    assert auth.verify_key("  secret-key-123  ") is True


def test_authenticator_invalid_key():
    auth = APIKeyAuthenticator(api_key="secret-key-123")
    assert auth.verify_key("wrong-key") is False
    assert auth.verify_key("") is False
    assert auth.verify_key(None) is False


def test_extract_api_key_header():
    class MockRequest:
        def __init__(self, headers):
            self.headers = headers

    # 1. X-API-Key header
    req_x_key = MockRequest({"x-api-key": "key-x-123"})
    assert extract_api_key(req_x_key) == "key-x-123"

    # 2. Authorization Bearer header
    req_bearer = MockRequest({"authorization": "Bearer key-bearer-456"})
    assert extract_api_key(req_bearer) == "key-bearer-456"

    # 3. None when missing
    req_empty = MockRequest({})
    assert extract_api_key(req_empty) is None


def test_api_auth_x_api_key_header_success():
    client = create_authenticated_test_client("master-secret-key-999")
    headers = {"X-API-Key": "master-secret-key-999"}

    # POST /api/v1/scans
    res_post = client.post("/api/v1/scans", json=make_valid_payload("SCAN_AUTH_POST"), headers=headers)
    assert res_post.status_code == 202

    # GET /api/v1/scans/{scan_id}
    res_get = client.get("/api/v1/scans/SCAN_AUTH_POST", headers=headers)
    assert res_get.status_code == 200

    # GET /api/v1/scans
    res_list = client.get("/api/v1/scans", headers=headers)
    assert res_list.status_code == 200


def test_api_auth_authorization_bearer_header_success():
    client = create_authenticated_test_client("master-secret-key-999")
    headers = {"Authorization": "Bearer master-secret-key-999"}

    res_post = client.post("/api/v1/scans", json=make_valid_payload("SCAN_BEARER"), headers=headers)
    assert res_post.status_code == 202


def test_api_auth_missing_header_returns_401():
    client = create_authenticated_test_client("master-secret-key-999")

    # POST /api/v1/scans without headers
    res_post = client.post("/api/v1/scans", json=make_valid_payload())
    assert res_post.status_code == 401
    assert res_post.json()["detail"] == "Invalid or missing API key."

    # GET /api/v1/scans without headers
    res_list = client.get("/api/v1/scans")
    assert res_list.status_code == 401

    # GET /api/v1/scans/{id} without headers
    res_get = client.get("/api/v1/scans/SCAN_1")
    assert res_get.status_code == 401


def test_api_auth_invalid_key_returns_401():
    client = create_authenticated_test_client("master-secret-key-999")
    headers = {"X-API-Key": "invalid-wrong-key"}

    res = client.post("/api/v1/scans", json=make_valid_payload(), headers=headers)
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid or missing API key."


def test_api_auth_health_endpoint_remains_public():
    client = create_authenticated_test_client("master-secret-key-999")

    # GET /health should succeed without any headers
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_api_auth_secret_key_not_leaked_in_401_body():
    client = create_authenticated_test_client("SUPER_SECRET_MASTER_KEY_XYZ")
    res = client.post("/api/v1/scans", json=make_valid_payload(), headers={"X-API-Key": "WRONG_KEY"})

    assert res.status_code == 401
    assert "SUPER_SECRET_MASTER_KEY_XYZ" not in res.text
    assert "AGENTSHIELD_API_KEY" not in res.text


def test_api_auth_disabled_when_env_key_not_set():
    client = create_authenticated_test_client(master_api_key=None)

    # All endpoints should allow access without auth headers
    res_post = client.post("/api/v1/scans", json=make_valid_payload("SCAN_NO_AUTH"))
    assert res_post.status_code == 202

    res_get = client.get("/api/v1/scans/SCAN_NO_AUTH")
    assert res_get.status_code == 200

    res_list = client.get("/api/v1/scans")
    assert res_list.status_code == 200
