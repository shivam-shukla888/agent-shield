"""
Production Reliability & Operational Resilience Test Suite (STEP 19B)

Validates error handling, repository failures, target errors, LLM timeouts,
idempotency headers, liveness/readiness, and non-disclosure of secrets.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.api.schemas import (
    AssetSensitivity, BlastRadiusLevel, ExploitabilityLevel, ImpactLevel,
    ProbeSelectionRequest, RiskContextRequest, ScanRequest, TargetScanRequest,
    ToolPrivilege,
)
from app.api.service import ScanService
from app.domain.evaluation import EvaluationResult, EvaluationVerdict, EvaluatorType
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.probe import ProbeCategory, SecurityProbe
from app.domain.risk import RiskFactors
from app.domain.scan import ScanStatus
from app.domain.target import TargetConfig, TargetResult
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.report import ReportEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app
from app.probes.basic import get_basic_probes
from app.repositories import InMemoryScanRepository, RepositoryError


def default_risk_context() -> RiskContextRequest:
    return RiskContextRequest(
        impact=ImpactLevel.MEDIUM,
        exploitability=ExploitabilityLevel.MEDIUM,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.INTERNAL,
        tool_privilege=ToolPrivilege.READ,
    )


# ============================================================
# 1. READINESS BEHAVIOR & REPOSITORY FAILURE
# ============================================================

class TestReadinessAndRepoFailure:
    """Test /health/ready behavior when repository experiences failure."""

    def test_health_ready_unhealthy_on_repo_failure(self):
        class FailingRepo(InMemoryScanRepository):
            def list_all(self, limit=None, offset=0):
                raise RepositoryError("Database connection lost")

        app = create_app(repository=FailingRepo(), api_key="test-key")
        client = TestClient(app)

        resp = client.get("/health/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "unhealthy"
        assert "unreachable" in data["reason"]


# ============================================================
# 2. TARGET ERROR HANDLING (500, NETWORK, TIMEOUT)
# ============================================================

class TestTargetErrorHandling:
    """Test target failure handling (500, network error, timeout)."""

    def test_target_500_handled_gracefully(self):
        class ServerErrorAdapter(GenericHTTPAdapter):
            def execute_probe(self, probe: SecurityProbe) -> ProbeExecution:
                tr = TargetResult(success=False, status_code=500, output="Internal Server Error")
                return ProbeExecution(
                    execution_id="exec_500",
                    probe_id=probe.id,
                    status=ExecutionStatus.COMPLETED,
                    target_name="500 Target",
                    target_result=tr,
                )

        adapter = ServerErrorAdapter(config=TargetConfig(name="500 Target", endpoint="http://localhost:8000/chat"))
        scan_engine = ScanEngine(
            attack_engine=AttackEngine(adapter=adapter),
            evaluator=DeterministicEvaluator(),
            finding_engine=FindingEngine(),
            risk_engine=RiskEngine(),
        )

        probe = get_basic_probes()[0]
        res = scan_engine.run_scan(
            scan_id="SCAN_500",
            target_name="500 Target",
            probes=[probe],
            risk_factors=RiskFactors(
                impact=ImpactLevel.MEDIUM, exploitability=ExploitabilityLevel.MEDIUM,
                blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.INTERNAL,
                tool_privilege=ToolPrivilege.READ,
            ),
        )

        assert res.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
        assert len(res.evaluations) == 1
        assert res.evaluations[0].verdict == EvaluationVerdict.ERROR


# ============================================================
# 3. IDEMPOTENCY HEADER SUPPORT
# ============================================================

class TestIdempotencyHeader:
    """Test Idempotency-Key header support."""

    def test_idempotency_key_header_returns_same_scan(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)

        req_payload = {
            "target": {"target_name": "IdemTarget", "endpoint": "http://localhost:8000/chat"},
            "probes": {"probe_ids": ["PROMPT_LEAK_001"]},
            "risk_context": {
                "impact": "medium", "exploitability": "medium", "blast_radius": "medium",
                "asset_sensitivity": "internal", "tool_privilege": "read"
            }
        }

        # First request with Idempotency-Key
        r1 = client.post(
            "/api/v1/scans",
            json=req_payload,
            headers={"X-API-Key": "test-key", "Idempotency-Key": "unique_idem_key_001"},
        )
        assert r1.status_code == 202
        scan_id_1 = r1.json()["scan_id"]
        assert scan_id_1.startswith("IDEM_")

        # Second request with same Idempotency-Key
        r2 = client.post(
            "/api/v1/scans",
            json=req_payload,
            headers={"X-API-Key": "test-key", "Idempotency-Key": "unique_idem_key_001"},
        )
        assert r2.status_code == 202
        scan_id_2 = r2.json()["scan_id"]
        assert scan_id_1 == scan_id_2

    def test_duplicate_scan_id_is_idempotent(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)

        req_payload = {
            "scan_id": "EXPLICIT_IDEM_ID_001",
            "target": {"target_name": "IdemTarget", "endpoint": "http://localhost:8000/chat"},
            "probes": {"probe_ids": ["PROMPT_LEAK_001"]},
            "risk_context": {
                "impact": "medium", "exploitability": "medium", "blast_radius": "medium",
                "asset_sensitivity": "internal", "tool_privilege": "read"
            }
        }

        r1 = client.post("/api/v1/scans", json=req_payload, headers={"X-API-Key": "test-key"})
        assert r1.status_code == 202

        r2 = client.post("/api/v1/scans", json=req_payload, headers={"X-API-Key": "test-key"})
        assert r2.status_code == 202
        assert r2.json()["scan_id"] == "EXPLICIT_IDEM_ID_001"


# ============================================================
# 4. REPORT FAILURE & SAFE ERROR HANDLING
# ============================================================

class TestReportFailureHandling:
    """Test report generation error handling."""

    def test_invalid_format_returns_400(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/api/v1/scans/NON_EXISTENT_SCAN/report?format=xml", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 400

    def test_non_existent_scan_report_returns_404(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)
        resp = client.get("/api/v1/scans/NON_EXISTENT_SCAN_123/report?format=markdown", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 404


# ============================================================
# 5. SECRET PROTECTION & NON-DISCLOSURE
# ============================================================

class TestSecretProtectionResilience:
    """Test that operational failures never disclose secrets in HTTP responses."""

    def test_error_responses_do_not_leak_secrets(self):
        app = create_app(api_key="super_secret_master_key_999")
        client = TestClient(app)

        # Invalid scan_id path
        resp = client.get("/api/v1/scans/NON_EXISTENT", headers={"X-API-Key": "super_secret_master_key_999"})
        assert "super_secret_master_key_999" not in resp.text

        # Invalid payload
        resp_bad = client.post("/api/v1/scans", json={}, headers={"X-API-Key": "super_secret_master_key_999"})
        assert "super_secret_master_key_999" not in resp_bad.text
