"""
Unit and Integration Tests for API Rate Limiting and Client Isolation (STEP 12B).
"""

import time
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
from app.security.rate_limit import InMemoryRateLimiter


class RateLimitMockAdapter(TargetAdapter):
    def __init__(self):
        super().__init__(TargetConfig(name="Rate Limit Mock Target", endpoint="http://mock.local/chat"))

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


def create_rate_limited_test_client(
    master_api_key: Optional[str] = "test-rate-key-123",
    rate_limit_rpm: int = 3,
) -> TestClient:
    adapter = RateLimitMockAdapter()
    scan_engine = ScanEngine(
        attack_engine=AttackEngine(adapter=adapter),
        evaluator=DeterministicEvaluator(),
        finding_engine=FindingEngine(),
        risk_engine=RiskEngine(),
    )
    repository = InMemoryScanRepository()
    service = ScanService(scan_engine=scan_engine, repository=repository)
    application = create_app(service=service, api_key=master_api_key, rate_limit_rpm=rate_limit_rpm)
    return TestClient(application)


def make_payload(scan_id: str = "SCAN_RL_001"):
    return {
        "scan_id": scan_id,
        "target": {
            "target_name": "Rate Limit Target",
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


def test_rate_limiter_unit_under_and_over_limit():
    limiter = InMemoryRateLimiter(requests_per_window=2, window_seconds=60.0)

    # 1. First request -> OK
    is_limited, _ = limiter.check_and_record("client_1")
    assert not is_limited

    # 2. Second request -> OK
    is_limited, _ = limiter.check_and_record("client_1")
    assert not is_limited

    # 3. Third request -> Rate limited (429)
    is_limited, retry_after = limiter.check_and_record("client_1")
    assert is_limited
    assert retry_after > 0.0


def test_rate_limiter_unit_client_isolation():
    limiter = InMemoryRateLimiter(requests_per_window=1, window_seconds=60.0)

    # Client 1 uses quota
    is_limited_1, _ = limiter.check_and_record("client_1")
    assert not is_limited_1

    # Client 1 second request limited
    is_limited_1_again, _ = limiter.check_and_record("client_1")
    assert is_limited_1_again

    # Client 2 request under quota -> OK
    is_limited_2, _ = limiter.check_and_record("client_2")
    assert not is_limited_2


def test_rate_limiter_unit_window_expiration():
    limiter = InMemoryRateLimiter(requests_per_window=1, window_seconds=0.2)
    now = time.time()

    # Request 1 at t=now
    is_limited, _ = limiter.check_and_record("client_1", now=now)
    assert not is_limited

    # Request 2 at t=now -> Limited
    is_limited, _ = limiter.check_and_record("client_1", now=now)
    assert is_limited

    # Request 3 at t=now+0.3 (after window) -> OK
    is_limited, _ = limiter.check_and_record("client_1", now=now + 0.3)
    assert not is_limited


def test_rate_limiter_unit_clear():
    limiter = InMemoryRateLimiter(requests_per_window=1, window_seconds=60.0)
    limiter.check_and_record("client_1")
    assert limiter.check_and_record("client_1")[0] is True

    limiter.clear()
    assert limiter.check_and_record("client_1")[0] is False


def test_api_rate_limit_post_scans_returns_429_when_exceeded():
    client = create_rate_limited_test_client(master_api_key="test-key-rl", rate_limit_rpm=2)
    headers = {"X-API-Key": "test-key-rl"}

    # Request 1 -> 202
    res1 = client.post("/api/v1/scans", json=make_payload("RL_01"), headers=headers)
    assert res1.status_code == 202

    # Request 2 -> 202
    res2 = client.post("/api/v1/scans", json=make_payload("RL_02"), headers=headers)
    assert res2.status_code == 202

    # Request 3 -> 429 Too Many Requests
    res3 = client.post("/api/v1/scans", json=make_payload("RL_03"), headers=headers)
    assert res3.status_code == 429
    assert res3.json()["detail"] == "Rate limit exceeded. Try again later."
    assert "Retry-After" in res3.headers
    assert int(res3.headers["Retry-After"]) >= 1


def test_api_rate_limit_unauthenticated_does_not_consume_quota():
    client = create_rate_limited_test_client(master_api_key="valid-key-xyz", rate_limit_rpm=1)

    # 1. Invalid key request returns 401
    res_401 = client.post("/api/v1/scans", json=make_payload("RL_BAD"), headers={"X-API-Key": "wrong-key"})
    assert res_401.status_code == 401

    # 2. Valid key request should still succeed (202 Accepted) because 401 didn't consume valid key's quota
    res_200 = client.post("/api/v1/scans", json=make_payload("RL_GOOD"), headers={"X-API-Key": "valid-key-xyz"})
    assert res_200.status_code == 202


def test_api_rate_limit_health_endpoint_remains_unlimited():
    client = create_rate_limited_test_client(master_api_key="valid-key-xyz", rate_limit_rpm=1)
    headers = {"X-API-Key": "valid-key-xyz"}

    # Exceed limit on /api/v1/scans
    client.post("/api/v1/scans", json=make_payload("RL_01"), headers=headers)
    res_429 = client.post("/api/v1/scans", json=make_payload("RL_02"), headers=headers)
    assert res_429.status_code == 429

    # /health should still return 200 OK
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"
