"""
Unit and Integration Security Tests for Async Scan Jobs (STEP 13A).
"""

import threading
from typing import Optional
from fastapi.testclient import TestClient
import pytest

from app.adapters.base import TargetAdapter
from app.api.service import ScanService
from app.domain import ScanStatus, TargetConfig, TargetResult
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app
from app.repositories import InMemoryScanRepository


class AsyncMockAdapter(TargetAdapter):
    def __init__(self, should_fail: bool = False):
        super().__init__(TargetConfig(name="Async Mock Target", endpoint="http://mock.local/chat"))
        self.should_fail = should_fail

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        if self.should_fail:
            raise RuntimeError("Simulated target connector crash")
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


def create_async_test_client(adapter: Optional[TargetAdapter] = None) -> TestClient:
    if adapter is None:
        adapter = AsyncMockAdapter()
    scan_engine = ScanEngine(
        attack_engine=AttackEngine(adapter=adapter),
        evaluator=DeterministicEvaluator(),
        finding_engine=FindingEngine(),
        risk_engine=RiskEngine(),
    )
    repository = InMemoryScanRepository()
    service = ScanService(scan_engine=scan_engine, repository=repository)
    application = create_app(service=service)
    return TestClient(application)


def make_payload(scan_id: str = "SCAN_ASYNC_001"):
    return {
        "scan_id": scan_id,
        "target": {
            "target_name": "Async Target Agent",
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


def test_post_scan_returns_202_accepted():
    client = create_async_test_client()
    res = client.post("/api/v1/scans", json=make_payload("SCAN_ASYNC_202"))
    assert res.status_code == 202

    data = res.json()
    assert data["scan_id"] == "SCAN_ASYNC_202"
    assert data["status"] == "created"


def test_async_scan_lifecycle_and_result_retrieval():
    client = create_async_test_client()
    post_res = client.post("/api/v1/scans", json=make_payload("SCAN_LIFECYCLE_01"))
    assert post_res.status_code == 202

    # In TestClient, BackgroundTasks complete before post returns
    get_res = client.get("/api/v1/scans/SCAN_LIFECYCLE_01")
    assert get_res.status_code == 200

    data = get_res.json()
    assert data["scan_id"] == "SCAN_LIFECYCLE_01"
    assert data["status"] == "completed"
    assert "summary" in data
    assert data["summary"]["total_probes"] == 1
    assert len(data["findings"]) > 0


def test_async_scan_concurrency():
    client = create_async_test_client()
    errors = []

    def dispatch_scan(index: int):
        try:
            res = client.post("/api/v1/scans", json=make_payload(f"SCAN_CONCURRENCY_{index}"))
            if res.status_code != 202:
                errors.append(f"Unexpected status code {res.status_code}")
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=dispatch_scan, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0

    list_res = client.get("/api/v1/scans")
    assert list_res.status_code == 200
    scans = list_res.json()
    assert len(scans) == 5
    for s in scans:
        assert s["status"] == "completed"


def test_async_scan_background_error_handling():
    failing_adapter = AsyncMockAdapter(should_fail=True)
    client = create_async_test_client(adapter=failing_adapter)

    # Dispatch scan with failing adapter
    post_res = client.post("/api/v1/scans", json=make_payload("SCAN_FAIL_01"))
    assert post_res.status_code == 202

    # Retrieval should show PARTIAL or FAILED status safely without crashing
    get_res = client.get("/api/v1/scans/SCAN_FAIL_01")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["status"] in ("partial", "failed")


def test_async_scan_preserves_security_boundaries():
    client = create_async_test_client()
    payload = make_payload("SCAN_SEC_ASYNC")
    payload["target"]["headers"] = {"Authorization": "Bearer SECRET_ASYNC_TOKEN"}

    post_res = client.post("/api/v1/scans", json=payload)
    assert post_res.status_code == 202
    assert "SECRET_ASYNC_TOKEN" not in post_res.text

    get_res = client.get("/api/v1/scans/SCAN_SEC_ASYNC")
    assert get_res.status_code == 200
    assert "SECRET_ASYNC_TOKEN" not in get_res.text
    assert "headers" not in get_res.text
    assert "raw_response" not in get_res.text
