"""
Unit and Integration Tests for Scan History Endpoints (STEP 11A)

This module tests GET /api/v1/scans/{scan_id} and GET /api/v1/scans endpoints,
deterministic ordering, 404 behavior, and security boundary preservation.
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
from app.repositories.scan import InMemoryScanRepository


class HistoryMockAdapter(TargetAdapter):
    def __init__(self):
        super().__init__(TargetConfig(name="History Mock Target", endpoint="http://mock.local/chat"))

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


def create_history_test_client() -> TestClient:
    adapter = HistoryMockAdapter()
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
    repository = InMemoryScanRepository()
    service = ScanService(scan_engine=scan_engine, repository=repository)
    application = create_app(service=service)
    return TestClient(application)


def make_scan_payload(scan_id: str = "SCAN_HIST_100"):
    return {
        "scan_id": scan_id,
        "target": {
            "target_name": "History Test Agent",
            "endpoint": "http://target.local/chat",
            "method": "POST",
            "headers": {"Authorization": "Bearer SECRET_TOKEN"},
            "timeout_seconds": 15.0,
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


def test_get_scan_by_id_returns_200():
    client = create_history_test_client()
    # 1. Execute scan
    post_res = client.post("/api/v1/scans", json=make_scan_payload("SCAN_FETCH_200"))
    assert post_res.status_code == 202

    # 2. Retrieve scan by ID
    get_res = client.get("/api/v1/scans/SCAN_FETCH_200")
    assert get_res.status_code == 200

    data = get_res.json()
    assert data["scan_id"] == "SCAN_FETCH_200"
    assert data["target_name"] == "History Test Agent"
    assert data["status"] == "completed"
    assert "summary" in data
    assert len(data["findings"]) > 0


def test_get_scan_by_id_404_when_not_found():
    client = create_history_test_client()
    res = client.get("/api/v1/scans/NON_EXISTENT_SCAN_999")
    assert res.status_code == 404
    assert res.json()["detail"] == "Scan 'NON_EXISTENT_SCAN_999' not found."


def test_get_scan_by_id_strips_whitespace_param():
    client = create_history_test_client()
    client.post("/api/v1/scans", json=make_scan_payload("SCAN_PAD_001"))

    res = client.get("/api/v1/scans/%20%20SCAN_PAD_001%20%20")
    assert res.status_code == 200
    assert res.json()["scan_id"] == "SCAN_PAD_001"


def test_get_scans_returns_empty_list_initially():
    client = create_history_test_client()
    res = client.get("/api/v1/scans")
    assert res.status_code == 200
    assert res.json() == []


def test_get_scans_returns_history_in_deterministic_order():
    client = create_history_test_client()

    # Execute 3 scans
    client.post("/api/v1/scans", json=make_scan_payload("SCAN_SEQ_001"))
    client.post("/api/v1/scans", json=make_scan_payload("SCAN_SEQ_002"))
    client.post("/api/v1/scans", json=make_scan_payload("SCAN_SEQ_003"))

    res = client.get("/api/v1/scans")
    assert res.status_code == 200
    scans = res.json()
    assert len(scans) == 3

    # Assert deterministic IDs returned
    returned_ids = [s["scan_id"] for s in scans]
    assert "SCAN_SEQ_001" in returned_ids
    assert "SCAN_SEQ_002" in returned_ids
    assert "SCAN_SEQ_003" in returned_ids


def test_get_scan_preserves_security_boundaries():
    client = create_history_test_client()
    client.post("/api/v1/scans", json=make_scan_payload("SCAN_SEC_001"))

    get_res = client.get("/api/v1/scans/SCAN_SEC_001")
    text = get_res.text

    assert "SECRET_TOKEN" not in text
    assert "headers" not in text
    assert "raw_response" not in text
    assert "executions" not in get_res.json()


def test_get_scan_unexpected_error_returns_500():
    class FailingRepoScanService:
        def get_scan(self, scan_id: str):
            raise RuntimeError("Database connection string postgresql://admin:pass@host failed")

        def list_scans(self):
            raise RuntimeError("Internal memory fault")

    client = TestClient(create_app(service=FailingRepoScanService()))  # type: ignore

    res_get = client.get("/api/v1/scans/SCAN_1")
    assert res_get.status_code == 500
    assert res_get.json()["detail"] == "Scan retrieval failed."
    assert "postgresql" not in res_get.text

    res_list = client.get("/api/v1/scans")
    assert res_list.status_code == 500
    assert res_list.json()["detail"] == "Scan listing failed."
    assert "memory fault" not in res_list.text
