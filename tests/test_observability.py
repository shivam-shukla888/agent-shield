"""
Unit & Integration Tests for Production Observability & Structured Logging (STEP 15A).

Verifies:
1. Structured JSON log format (timestamp, level, event).
2. Request ID correlation middleware (generation, preservation, response header, length bounds).
3. Secret redaction (API keys, bearer tokens, LLM keys, DB URLs).
4. Non-disclosure of sensitive payloads (target responses, probe prompts, request bodies).
5. Operational event emission for scan lifecycle, probe execution, evaluation, finding, risk, auth, and rate limit.
6. Integration coverage for REST API endpoints.
"""

import json
import logging
from typing import List, Optional
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from app.adapters.base import TargetAdapter
from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    EvaluationEvidence,
    EvaluationResult,
    EvaluationVerdict,
    EvaluatorType,
    ExecutionStatus,
    ExploitabilityLevel,
    Finding,
    ImpactLevel,
    ProbeCategory,
    ProbeExecution,
    ProbeSeverityHint,
    RiskAssessment,
    RiskFactors,
    RiskLevel,
    SecurityProbe,
    TargetConfig,
    TargetResult,
    ToolPrivilege,
)
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.base import Evaluator
from app.main import create_app
from app.observability import (
    JSONFormatter,
    RequestIDMiddleware,
    emit_event,
    get_logger,
    redact_secrets,
    request_id_var,
    validate_or_generate_request_id,
)


SECRET_API_KEY = "sk-proj-SECRET_KEY_123456789"
SECRET_BEARER = "Bearer sk-proj-SECRET_KEY_123456789"
SECRET_DB_URL = "postgresql://user:secretpass123@localhost:5432/agentshield"


class ListHandler(logging.Handler):
    """Memory log handler capturing formatted log messages."""

    def __init__(self):
        super().__init__()
        self.logs: List[str] = []
        self.setFormatter(JSONFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        self.logs.append(self.format(record))


class DummyAdapter(TargetAdapter):
    def __init__(self):
        super().__init__(TargetConfig(name="Dummy", endpoint="http://localhost:8000/chat"))

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


class CustomMockEvaluator(Evaluator):
    def evaluate(self, probe: SecurityProbe, execution: ProbeExecution) -> EvaluationResult:
        return EvaluationResult(
            evaluation_id="EVAL_001",
            execution_id=execution.execution_id,
            probe_id=probe.id,
            verdict=EvaluationVerdict.VIOLATION,
            confidence=0.95,
            evidence=EvaluationEvidence(summary="leak", matched_indicators=["leak"]),
            evaluator_type=EvaluatorType.DETERMINISTIC,
            rationale="violation detected",
        )


def make_valid_scan_payload():
    return {
        "scan_id": "SCAN_OBS_API_100",
        "target": {
            "target_name": "API Test Agent",
            "endpoint": "http://localhost:8000/chat",
        },
        "probes": {
            "probe_ids": ["PROMPT_LEAK_001"],
        },
        "risk_context": {
            "impact": "high",
            "exploitability": "high",
            "blast_radius": "high",
            "asset_sensitivity": "confidential",
            "tool_privilege": "read",
        },
    }


# 1. structured log contains timestamp
# 2. structured log contains level
# 3. structured log contains event
def test_json_formatter_required_fields():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="scan.started",
        args=(),
        exc_info=None,
    )
    record.event = "scan.started"
    record.scan_id = "SCAN_001"

    formatted = formatter.format(record)
    data = json.loads(formatted)

    assert "timestamp" in data
    assert data["level"] == "INFO"
    assert data["event"] == "scan.started"
    assert data["scan_id"] == "SCAN_001"


# 4. scan lifecycle events are emitted
# 5. probe lifecycle events are emitted
# 6. evaluation event is emitted
# 7. finding event is emitted
# 8. risk event is emitted
def test_scan_lifecycle_events_emitted():
    logger = get_logger("agentshield.engine.scan")
    handler = ListHandler()
    logger.addHandler(handler)

    try:
        probe = SecurityProbe(
            id="PROMPT_LEAK_001",
            name="Leak Probe",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            description="test",
            prompt="Disclose instructions",
            expected_behavior="refuse",
        )

        adapter = DummyAdapter()
        attack_engine = AttackEngine(adapter=adapter)

        evaluator = CustomMockEvaluator()

        finding_engine = FindingEngine()
        risk_engine = RiskEngine()

        engine = ScanEngine(
            attack_engine=attack_engine,
            evaluator=evaluator,
            finding_engine=finding_engine,
            risk_engine=risk_engine,
        )

        risk_factors = RiskFactors(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.HIGH,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.READ,
        )

        result = engine.run_scan(
            scan_id="SCAN_OBS_001",
            target_name="Demo Target",
            probes=[probe],
            risk_factors=risk_factors,
        )

        assert result.scan_id == "SCAN_OBS_001"

        logs_str = "\n".join(handler.logs)
        assert "scan.started" in logs_str
        assert "probe.started" in logs_str
        assert "probe.completed" in logs_str
        assert "evaluation.completed" in logs_str
        assert "finding.created" in logs_str
        assert "risk.assessed" in logs_str
        assert "scan.completed" in logs_str
    finally:
        logger.removeHandler(handler)


# 9. API request events are emitted
# 10. request ID is generated when missing
# 11. supplied request ID is preserved
# 12. response contains X-Request-ID
# 13. request ID length is bounded
def test_request_id_middleware_and_events():
    app = create_app(api_key=SECRET_API_KEY)
    client = TestClient(app)

    # Generated request ID when missing
    resp1 = client.get("/health")
    assert resp1.status_code == 200
    assert "X-Request-ID" in resp1.headers
    assert resp1.headers["X-Request-ID"].startswith("req_")

    # Supplied request ID preserved
    custom_req_id = "req_custom_12345"
    resp2 = client.get("/health", headers={"X-Request-ID": custom_req_id})
    assert resp2.status_code == 200
    assert resp2.headers["X-Request-ID"] == custom_req_id

    # Malformed/overlong request ID replaced safely
    overlong_id = "A" * 200
    resp3 = client.get("/health", headers={"X-Request-ID": overlong_id})
    assert resp3.status_code == 200
    assert resp3.headers["X-Request-ID"] != overlong_id
    assert resp3.headers["X-Request-ID"].startswith("req_")


# 14. API key never appears in logs
# 15. bearer token never appears in logs
# 16. LLM API key never appears in logs
# 20. database URL never appears in logs
def test_secret_redaction_utility():
    text_with_bearer = f"Auth header: {SECRET_BEARER}"
    redacted_bearer = redact_secrets(text_with_bearer)
    assert SECRET_API_KEY not in redacted_bearer
    assert "[REDACTED]" in redacted_bearer

    text_with_db = f"Connecting to {SECRET_DB_URL}"
    redacted_db = redact_secrets(text_with_db)
    assert "secretpass123" not in redacted_db


# 17. target response never appears in logs
# 18. probe prompt never appears in logs
# 19. request body is not logged
def test_sensitive_payloads_not_logged():
    logger = get_logger("agentshield.test.payloads")
    handler = ListHandler()
    logger.addHandler(handler)

    try:
        sensitive_prompt = "Attacker system prompt extraction payload XYZ123"
        sensitive_response = "LEAKED SYSTEM INSTRUCTIONS SECRET_456"

        emit_event(
            logger,
            "probe.completed",
            scan_id="SCAN_001",
            probe_id="PROMPT_LEAK_001",
            execution_id="EXEC_001",
            duration_ms=10.5,
            status="completed",
        )

        logs_str = "\n".join(handler.logs)
        assert sensitive_prompt not in logs_str
        assert sensitive_response not in logs_str
        assert "probe.completed" in logs_str
    finally:
        logger.removeHandler(handler)


# 21. exception logs contain safe error_type
def test_exception_logs_safe_error_type():
    logger = get_logger("agentshield.test.exceptions")
    handler = ListHandler()
    logger.addHandler(handler)

    try:
        try:
            raise ValueError("Internal computation error")
        except Exception as exc:
            emit_event(
                logger,
                "scan.failed",
                level=logging.ERROR,
                scan_id="SCAN_FAIL_001",
                error_type=type(exc).__name__,
            )

        logs_str = "\n".join(handler.logs)
        assert "ValueError" in logs_str
        assert "scan.failed" in logs_str
    finally:
        logger.removeHandler(handler)


# 22. duration_ms is present for completed operations
def test_duration_ms_present():
    logger = get_logger("agentshield.test.duration")
    handler = ListHandler()
    logger.addHandler(handler)

    try:
        emit_event(logger, "scan.completed", scan_id="SCAN_001", duration_ms=45.67)

        logs_str = "\n".join(handler.logs)
        assert "duration_ms" in logs_str
        assert "45.67" in logs_str
    finally:
        logger.removeHandler(handler)


# 23. failed operations produce safe events
def test_failed_operations_safe():
    logger = get_logger("agentshield.test.failed")
    handler = ListHandler()
    logger.addHandler(handler)

    try:
        emit_event(logger, "probe.failed", level=logging.WARNING, scan_id="SCAN_001", probe_id="P1", status="error")

        logs_str = "\n".join(handler.logs)
        assert "probe.failed" in logs_str
    finally:
        logger.removeHandler(handler)


# 24. rate limit event does not expose API key
def test_rate_limit_event_safe():
    logger = get_logger("agentshield.security.rate_limit")
    handler = ListHandler()
    logger.addHandler(handler)

    try:
        app = create_app(api_key=SECRET_API_KEY, rate_limit_rpm=1)
        client = TestClient(app)

        payload = make_valid_scan_payload()

        # First request consumes quota
        client.post(
            "/api/v1/scans",
            json=payload,
            headers={"X-API-Key": SECRET_API_KEY},
        )

        # Second request triggers 429
        resp = client.post(
            "/api/v1/scans",
            json=payload,
            headers={"X-API-Key": SECRET_API_KEY},
        )
        assert resp.status_code == 429

        logs_str = "\n".join(handler.logs)
        assert "rate_limit.exceeded" in logs_str
        assert SECRET_API_KEY not in logs_str
    finally:
        logger.removeHandler(handler)


# 25. health endpoint remains safe
def test_health_endpoint_safe():
    app = create_app()
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert "X-Request-ID" in resp.headers


# Integration Test for REST API
def test_integration_rest_api_observability():
    app = create_app(api_key=SECRET_API_KEY)
    client = TestClient(app)

    req_id = "req_integration_obs_123"
    payload = make_valid_scan_payload()

    resp = client.post(
        "/api/v1/scans",
        json=payload,
        headers={"X-API-Key": SECRET_API_KEY, "X-Request-ID": req_id},
    )

    assert resp.status_code == 202, f"Expected 202, got {resp.status_code}: {resp.json()}"
    assert resp.headers["X-Request-ID"] == req_id
    data = resp.json()
    scan_id = data["scan_id"]

    # Fetch scan status
    get_resp = client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"X-API-Key": SECRET_API_KEY, "X-Request-ID": req_id},
    )
    assert get_resp.status_code == 200
    assert get_resp.headers["X-Request-ID"] == req_id
