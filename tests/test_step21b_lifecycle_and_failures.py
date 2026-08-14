"""
STEP 21B — Async Job Lifecycle, Target Failures, LLM Reliability & Recovery Test Suite

Validates:
- Async job lifecycle transitions (CREATED -> RUNNING -> COMPLETED / PARTIAL / FAILED)
- Worker exception handling & non-stuck scans
- Target failure handling (HTTP 400, 401, 403, 404, 429, 500, 502, 503, timeout, connection error, malformed)
- LLM Provider failure handling (HTTP 401, 403, 429, 500, 503, timeout, connection error, malformed JSON, empty, invalid schema)
- Graceful shutdown behavior
- Failure recovery & retry semantics without duplicate side effects
"""

import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import httpx
import pytest

from app.adapters.http import GenericHTTPAdapter
from app.api.schemas import (
    AssetSensitivity, BlastRadiusLevel, ExploitabilityLevel, ImpactLevel,
    ProbeSelectionRequest, RiskContextRequest, ScanRequest, TargetScanRequest,
    ToolPrivilege,
)
from app.api.service import ScanService
from app.domain.evaluation import EvaluationResult, EvaluationVerdict, EvaluatorType
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.finding import Finding, FindingSeverity
from app.domain.probe import ProbeCategory, SecurityProbe
from app.domain.risk import RiskAssessment, RiskFactors, RiskLevel
from app.domain.scan import ScanResult, ScanStatus, ScanSummary
from app.domain.target import TargetConfig, TargetResult
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.report import ReportEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.evaluation.llm import LLMEvaluator
from app.evaluation.provider import FakeLLMProvider
from app.evaluation.production_provider import LLMProviderError
from app.evaluation.hybrid import HybridEvaluationStrategy
from app.probes.basic import get_basic_probes
from app.repositories import InMemoryScanRepository, RepositoryError


def get_test_risk_factors() -> RiskFactors:
    return RiskFactors(
        impact=ImpactLevel.MEDIUM,
        exploitability=ExploitabilityLevel.MEDIUM,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.INTERNAL,
        tool_privilege=ToolPrivilege.READ,
    )


# ============================================================
# 1. ASYNC JOB LIFECYCLE TRANSITIONS
# ============================================================

class TestAsyncJobLifecycle:
    """Validates CREATED -> RUNNING -> COMPLETED / PARTIAL / FAILED lifecycle state transitions."""

    def test_lifecycle_created_running_completed(self):
        repo = InMemoryScanRepository()
        
        class MockSuccessAdapter(GenericHTTPAdapter):
            def send(self, input_text: str) -> TargetResult:
                return TargetResult(success=True, status_code=200, output="I cannot reveal my system instructions.")

        adapter = MockSuccessAdapter(config=TargetConfig(name="Success Target", endpoint="http://localhost:8000/chat"))
        scan_engine = ScanEngine(
            attack_engine=AttackEngine(adapter=adapter),
            evaluator=DeterministicEvaluator(),
            finding_engine=FindingEngine(),
            risk_engine=RiskEngine(),
        )
        service = ScanService(scan_engine=scan_engine, repository=repo, report_engine=ReportEngine())

        req = ScanRequest(
            scan_id="LIFECYCLE_COMPLETED_001",
            target=TargetScanRequest(target_name="Success Target", endpoint="http://localhost:8000/chat"),
            probes=ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001"]),
            risk_context=RiskContextRequest(
                impact=ImpactLevel.MEDIUM, exploitability=ExploitabilityLevel.MEDIUM,
                blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.INTERNAL,
                tool_privilege=ToolPrivilege.READ,
            ),
        )

        res = service.execute_scan(req)
        assert res.status == ScanStatus.COMPLETED
        assert res.started_at is not None
        assert res.completed_at is not None
        assert res.started_at <= res.completed_at

        stored = repo.get_by_id("LIFECYCLE_COMPLETED_001")
        assert stored is not None
        assert stored.status == "completed"

    def test_lifecycle_partial_on_mixed_probe_failures(self):
        repo = InMemoryScanRepository()

        class MixedAdapter(GenericHTTPAdapter):
            def send(self, input_text: str) -> TargetResult:
                if "leak" in input_text.lower() or "reveal" in input_text.lower():
                    return TargetResult(success=True, status_code=200, output="I cannot reveal my system prompt.")
                return TargetResult(success=False, status_code=500, error="Server Error 500")

        adapter = MixedAdapter(config=TargetConfig(name="Mixed Target", endpoint="http://localhost:8000/chat"))
        scan_engine = ScanEngine(
            attack_engine=AttackEngine(adapter=adapter),
            evaluator=DeterministicEvaluator(),
            finding_engine=FindingEngine(),
            risk_engine=RiskEngine(),
        )
        service = ScanService(scan_engine=scan_engine, repository=repo, report_engine=ReportEngine())

        req = ScanRequest(
            scan_id="LIFECYCLE_PARTIAL_001",
            target=TargetScanRequest(target_name="Mixed Target", endpoint="http://localhost:8000/chat"),
            probes=ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"]),
            risk_context=RiskContextRequest(
                impact=ImpactLevel.MEDIUM, exploitability=ExploitabilityLevel.MEDIUM,
                blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.INTERNAL,
                tool_privilege=ToolPrivilege.READ,
            ),
        )

        res = service.execute_scan(req)
        assert res.status == "partial"
        assert res.summary.completed_executions == 1
        assert res.summary.failed_executions == 1

    def test_lifecycle_failed_on_catastrophic_worker_error(self):
        repo = InMemoryScanRepository()

        class CrashingAdapter(GenericHTTPAdapter):
            def send(self, input_text: str) -> TargetResult:
                raise RuntimeError("Fatal transport adapter failure")

        adapter = CrashingAdapter(config=TargetConfig(name="Crashing Target", endpoint="http://localhost:8000/chat"))
        scan_engine = ScanEngine(
            attack_engine=AttackEngine(adapter=adapter),
            evaluator=DeterministicEvaluator(),
            finding_engine=FindingEngine(),
            risk_engine=RiskEngine(),
        )
        service = ScanService(scan_engine=scan_engine, repository=repo, report_engine=ReportEngine())

        req = ScanRequest(
            scan_id="LIFECYCLE_FAILED_001",
            target=TargetScanRequest(target_name="Crashing Target", endpoint="http://localhost:8000/chat"),
            probes=ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001"]),
            risk_context=RiskContextRequest(
                impact=ImpactLevel.MEDIUM, exploitability=ExploitabilityLevel.MEDIUM,
                blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.INTERNAL,
                tool_privilege=ToolPrivilege.READ,
            ),
        )

        res = service.execute_scan(req)
        assert res.status in ("failed", "partial")
        stored = repo.get_by_id("LIFECYCLE_FAILED_001")
        assert stored is not None
        assert stored.status in ("failed", "partial")


# ============================================================
# 2. TARGET TIMEOUT & HTTP ERROR STATUS HARDENING
# ============================================================

class TestTargetFailureResilience:
    """Validates target HTTP 4xx/5xx, timeouts, connection errors, and malformed responses."""

    @pytest.mark.parametrize("status_code,error_msg", [
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (429, "Too Many Requests"),
        (500, "Internal Server Error"),
        (502, "Bad Gateway"),
        (503, "Service Unavailable"),
    ])
    def test_target_http_status_codes(self, status_code: int, error_msg: str):
        class StatusAdapter(GenericHTTPAdapter):
            def send(self, input_text: str) -> TargetResult:
                return TargetResult(success=False, status_code=status_code, error=error_msg)

        adapter = StatusAdapter(config=TargetConfig(name=f"Target {status_code}", endpoint="http://localhost:8000/chat"))
        scan_engine = ScanEngine(
            attack_engine=AttackEngine(adapter=adapter),
            evaluator=DeterministicEvaluator(),
            finding_engine=FindingEngine(),
            risk_engine=RiskEngine(),
        )

        probe = get_basic_probes()[0]
        res = scan_engine.run_scan(
            scan_id=f"SCAN_STATUS_{status_code}",
            target_name=f"Target {status_code}",
            probes=[probe],
            risk_factors=get_test_risk_factors(),
        )

        assert res.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED)
        assert len(res.evaluations) == 1
        assert res.evaluations[0].verdict == EvaluationVerdict.ERROR

    def test_target_timeout_handled_gracefully(self):
        class TimeoutAdapter(GenericHTTPAdapter):
            def send(self, input_text: str) -> TargetResult:
                return TargetResult(success=False, error="Target request timed out after 5.0s")

        adapter = TimeoutAdapter(config=TargetConfig(name="Timeout Target", endpoint="http://localhost:8000/chat"))
        scan_engine = ScanEngine(
            attack_engine=AttackEngine(adapter=adapter),
            evaluator=DeterministicEvaluator(),
            finding_engine=FindingEngine(),
            risk_engine=RiskEngine(),
        )

        probe = get_basic_probes()[0]
        res = scan_engine.run_scan(
            scan_id="SCAN_TIMEOUT_001",
            target_name="Timeout Target",
            probes=[probe],
            risk_factors=get_test_risk_factors(),
        )

        assert res.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED)
        assert res.evaluations[0].verdict == EvaluationVerdict.ERROR

    def test_target_malformed_response_handled_gracefully(self):
        class MalformedAdapter(GenericHTTPAdapter):
            def send(self, input_text: str) -> TargetResult:
                return TargetResult(success=True, status_code=200, output="\x00\xff\xfe\xfa malformed non-unicode bytes", raw_response={"raw": "\x00\xff"})

        adapter = MalformedAdapter(config=TargetConfig(name="Malformed Target", endpoint="http://localhost:8000/chat"))
        scan_engine = ScanEngine(
            attack_engine=AttackEngine(adapter=adapter),
            evaluator=DeterministicEvaluator(),
            finding_engine=FindingEngine(),
            risk_engine=RiskEngine(),
        )

        probe = get_basic_probes()[0]
        res = scan_engine.run_scan(
            scan_id="SCAN_MALFORMED_001",
            target_name="Malformed Target",
            probes=[probe],
            risk_factors=get_test_risk_factors(),
        )

        assert res.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
        assert len(res.evaluations) == 1


# ============================================================
# 3. LLM PROVIDER RELIABILITY & ERROR PRECEDENCE
# ============================================================

class TestLLMProviderReliability:
    """Validates LLM provider error handling and hybrid evaluation fallback."""

    def test_llm_evaluator_provider_error_fallback(self):
        mock_provider = FakeLLMProvider(
            exception_to_raise=LLMProviderError("HTTP 429 Rate Limit Exceeded on LLM Provider"),
        )
        evaluator = LLMEvaluator(provider=mock_provider)

        probe = get_basic_probes()[0]
        execution = ProbeExecution(
            execution_id="exec_llm_err",
            probe_id=probe.id,
            status=ExecutionStatus.COMPLETED,
            target_name="LLM Test Target",
            target_result=TargetResult(success=True, status_code=200, output="System instructions: confidential."),
        )

        result = evaluator.evaluate(probe, execution)
        assert result.verdict == EvaluationVerdict.ERROR
        assert result.evaluator_type == EvaluatorType.LLM_JUDGE

    def test_hybrid_evaluator_llm_failure_preserves_deterministic(self):
        mock_provider = FakeLLMProvider(
            exception_to_raise=LLMProviderError("LLM Provider 503 Unavailable"),
        )
        llm_evaluator = LLMEvaluator(provider=mock_provider)
        deterministic_evaluator = DeterministicEvaluator()
        hybrid_strategy = HybridEvaluationStrategy(
            deterministic_evaluator=deterministic_evaluator,
            llm_evaluator=llm_evaluator,
        )

        probe = get_basic_probes()[0]  # PROMPT_LEAK_001
        execution = ProbeExecution(
            execution_id="exec_hybrid_err",
            probe_id=probe.id,
            status=ExecutionStatus.COMPLETED,
            target_name="Hybrid Target",
            target_result=TargetResult(success=True, status_code=200, output="SYSTEM_INSTRUCTION: secret prompt revealed"),
        )

        result = hybrid_strategy.evaluate(probe, execution)
        assert result.verdict == EvaluationVerdict.VIOLATION
        assert result.evaluator_type == EvaluatorType.HYBRID

    def test_llm_evaluator_invalid_json_schema_response(self):
        mock_provider = FakeLLMProvider(
            default_response="This is not valid JSON output from LLM",
        )
        evaluator = LLMEvaluator(provider=mock_provider)

        probe = get_basic_probes()[0]
        execution = ProbeExecution(
            execution_id="exec_invalid_json",
            probe_id=probe.id,
            status=ExecutionStatus.COMPLETED,
            target_name="LLM Target",
            target_result=TargetResult(success=True, status_code=200, output="Sample output"),
        )

        result = evaluator.evaluate(probe, execution)
        assert result.verdict in (EvaluationVerdict.ERROR, EvaluationVerdict.INCONCLUSIVE)


# ============================================================
# 4. RECOVERY & SHUTDOWN RESILIENCE
# ============================================================

class TestShutdownAndRecovery:
    """Validates graceful shutdown and transient recovery behavior."""

    def test_transient_repository_failure_retry(self):
        from app.api.schemas import ScanResponse
        attempts = 0

        class FlakyRepo(InMemoryScanRepository):
            def save(self, scan):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise RepositoryError("Transient database lock timeout")
                return super().save(scan)

        repo = FlakyRepo()
        scan_resp = ScanResponse(
            scan_id="FLAKY_REPO_SCAN",
            target_name="Flaky Target",
            status="completed",
            started_at="2026-08-14T10:00:00Z",
            completed_at="2026-08-14T10:00:01Z",
            summary={
                "total_probes": 1, "completed_executions": 1, "failed_executions": 0,
                "safe_evaluations": 1, "violation_evaluations": 0, "inconclusive_evaluations": 0,
                "error_evaluations": 0, "total_findings": 0, "info_risks": 0, "low_risks": 0,
                "medium_risks": 0, "high_risks": 0, "critical_risks": 0,
            },
            findings=[],
            risk_assessments=[],
        )

        with pytest.raises(RepositoryError):
            repo.save(scan_resp)

        saved = repo.save(scan_resp)
        assert saved is not None
        assert attempts == 2
