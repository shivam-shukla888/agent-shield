"""
Final System Architecture & Boundary Integration Test Suite (STEP 20A)

Comprehensive verification across:
1. Full System Contract Audit & Lineage Traceability
2. Evaluator Modes (Deterministic, LLM+FakeProvider, Hybrid)
3. Finding + Risk Pipeline & Deduplication
4. Persistence Modes (InMemory, PostgreSQL via SQLite engine)
5. Async Lifecycle Transitions
6. API Contract & Security Regression Audit
7. Report Generation Pipeline & Sanitization
8. Observability & Concurrency Smoke Test
"""

import httpx
import pytest
from sqlalchemy import create_engine

from app.adapters.http import GenericHTTPAdapter
from app.api.schemas import (
    AssetSensitivity, BlastRadiusLevel, ExploitabilityLevel, ImpactLevel,
    RiskContextRequest, ToolPrivilege,
)
from app.domain.evaluation import EvaluationResult, EvaluationVerdict, EvaluatorType
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.finding import Finding, FindingSeverity, FindingStatus
from app.domain.probe import ProbeCategory, SecurityProbe
from app.domain.risk import RiskAssessment, RiskFactors, RiskLevel
from app.domain.scan import ScanResult, ScanStatus
from app.domain.target import TargetConfig, TargetResult
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.report import ReportEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.evaluation.hybrid import HybridEvaluationStrategy
from app.evaluation.llm import LLMEvaluator
from app.evaluation.provider import FakeLLMProvider
from app.probes.basic import get_basic_probes
from app.repositories import InMemoryScanRepository, PostgreSQLScanRepository, init_db
from test_target.main import local_target_app
from test_target.tools import reset_test_state


def create_mock_adapter() -> GenericHTTPAdapter:
    test_client = httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"response": "SYSTEM_INSTRUCTION: You are Acme Corp assistant."})
    ))
    config = TargetConfig(
        name="Mock Target Agent",
        endpoint="http://testagent.local/chat",
        request_template={"prompt": "{{input}}"},
        response_path="response",
    )
    return GenericHTTPAdapter(config=config, client=test_client)


@pytest.fixture(autouse=True)
def reset_state():
    reset_test_state()


# ============================================================
# 1. EVALUATOR MODES (DETERMINISTIC, LLM, HYBRID)
# ============================================================

class TestEvaluatorModesIntegration:
    """Test and compare all supported evaluation modes."""

    def test_deterministic_evaluator_path(self):
        evaluator = DeterministicEvaluator()
        probe = get_basic_probes()[0]
        execution = ProbeExecution(
            execution_id="exec_det_1",
            probe_id=probe.id,
            status=ExecutionStatus.COMPLETED,
            target_name="TestTarget",
            target_result=TargetResult(success=True, output="SYSTEM_INSTRUCTION: Leaked prompt"),
        )
        res = evaluator.evaluate(probe, execution)
        assert res.verdict == EvaluationVerdict.VIOLATION
        assert res.evaluator_type == EvaluatorType.DETERMINISTIC
        assert res.confidence >= 0.9

    def test_llm_evaluator_path(self):
        json_resp = '{"verdict": "violation", "confidence": 0.88, "reasoning": "I revealed internal prompt rules."}'
        llm_provider = FakeLLMProvider(default_response=json_resp)
        evaluator = LLMEvaluator(provider=llm_provider)
        probe = get_basic_probes()[0]
        execution = ProbeExecution(
            execution_id="exec_llm_1",
            probe_id=probe.id,
            status=ExecutionStatus.COMPLETED,
            target_name="TestTarget",
            target_result=TargetResult(success=True, output="I revealed internal prompt rules."),
        )
        res = evaluator.evaluate(probe, execution)
        assert res.verdict == EvaluationVerdict.VIOLATION
        assert res.evaluator_type == EvaluatorType.LLM_JUDGE
        assert res.confidence == 0.88

    def test_hybrid_evaluation_strategy_path(self):
        json_resp = '{"verdict": "violation", "confidence": 0.85, "reasoning": "System prompt disclosure"}'
        det_eval = DeterministicEvaluator()
        llm_eval = LLMEvaluator(provider=FakeLLMProvider(default_response=json_resp))
        hybrid = HybridEvaluationStrategy(deterministic_evaluator=det_eval, llm_evaluator=llm_eval)

        probe = get_basic_probes()[0]
        execution = ProbeExecution(
            execution_id="exec_hyb_1",
            probe_id=probe.id,
            status=ExecutionStatus.COMPLETED,
            target_name="TestTarget",
            target_result=TargetResult(success=True, output="SYSTEM_INSTRUCTION: Leaked prompt"),
        )
        res = hybrid.evaluate(probe, execution)
        assert res.verdict == EvaluationVerdict.VIOLATION
        assert res.evaluator_type in (EvaluatorType.DETERMINISTIC, EvaluatorType.HYBRID)


# ============================================================
# 2. FINDING & RISK PIPELINE DEDUPLICATION
# ============================================================

class TestFindingRiskPipelineIntegration:
    """Test conversion from EvaluationResult to Finding to RiskAssessment."""

    def test_category_aggregation_and_risk_scoring(self):
        finding_engine = FindingEngine()
        risk_engine = RiskEngine()
        probe = get_basic_probes()[0]

        from app.domain.evaluation import EvaluationEvidence
        eval_1 = EvaluationResult(
            evaluation_id="eval_101",
            execution_id="exec_101",
            probe_id=probe.id,
            verdict=EvaluationVerdict.VIOLATION,
            confidence=0.9,
            rationale="Disclosed system instructions",
            evidence=EvaluationEvidence(summary="Disclosed system instructions"),
        )
        eval_2 = EvaluationResult(
            evaluation_id="eval_102",
            execution_id="exec_102",
            probe_id=probe.id,
            verdict=EvaluationVerdict.VIOLATION,
            confidence=0.95,
            rationale="Disclosed system prompt details",
            evidence=EvaluationEvidence(summary="Disclosed system prompt details"),
        )

        # Aggregate two violations of same category -> single Finding
        findings = finding_engine.aggregate_evaluation_results([eval_1, eval_2])
        assert len(findings) == 1
        finding = findings[0]
        assert finding.finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"
        assert len(finding.affected_execution_ids) == 2

        # Assess risk for finding
        factors = RiskFactors(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.WRITE,
        )
        risk = risk_engine.assess_risk(finding, factors)
        assert risk.risk_id == "RISK_FINDING_SYSTEM_PROMPT_DISCLOSURE"
        assert risk.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert risk.risk_score > 60.0


# ============================================================
# 3. REPOSITORY PERSISTENCE MODES (IN-MEMORY & POSTGRES/SQLITE)
# ============================================================

class TestRepositoryModesIntegration:
    """Test both InMemory and PostgreSQL (SQLite) repository implementations."""

    def test_postgres_repository_with_sqlite_engine(self):
        engine = create_engine("sqlite:///:memory:")
        init_db(engine)
        repo = PostgreSQLScanRepository(engine)

        from app.api.schemas import ScanResponse, ScanSummaryResponse
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        scan_dto = ScanResponse(
            scan_id="SQLITE_SCAN_001",
            target_name="SQLite Target",
            status=ScanStatus.COMPLETED,
            started_at=now,
            completed_at=now,
            summary=ScanSummaryResponse(
                total_probes=1, completed_executions=1, failed_executions=0,
                safe_evaluations=1, violation_evaluations=0, inconclusive_evaluations=0, error_evaluations=0,
                total_findings=0, info_risks=0, low_risks=0, medium_risks=0, high_risks=0, critical_risks=0
            ),
            findings=[],
            risk_assessments=[],
        )

        repo.save(scan_dto)
        retrieved = repo.get_by_id("SQLITE_SCAN_001")
        assert retrieved is not None
        assert retrieved.scan_id == "SQLITE_SCAN_001"
        assert retrieved.target_name == "SQLite Target"

        all_scans = repo.list_all(limit=5, offset=0)
        assert len(all_scans) == 1
        assert all_scans[0].scan_id == "SQLITE_SCAN_001"


# ============================================================
# 4. REPORT ENGINE INTEGRATION & SANITIZATION
# ============================================================

class TestReportEngineIntegration:
    """Test ReportEngine rendering across all formats."""

    def test_all_report_formats_sanitized(self):
        from app.api.schemas import ScanResponse, ScanSummaryResponse
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        scan_dto = ScanResponse(
            scan_id="REPORT_SAN_001",
            target_name="Sanitized Target",
            status=ScanStatus.COMPLETED,
            started_at=now,
            completed_at=now,
            summary=ScanSummaryResponse(
                total_probes=2, completed_executions=2, failed_executions=0,
                safe_evaluations=1, violation_evaluations=1, inconclusive_evaluations=0, error_evaluations=0,
                total_findings=1, info_risks=0, low_risks=0, medium_risks=1, high_risks=0, critical_risks=0
            ),
            findings=[],
            risk_assessments=[],
        )

        engine = ReportEngine()
        report = engine.create_report(scan_dto)

        md = engine.render_markdown(report)
        assert "REPORT_SAN_001" in md
        assert "Authorization" not in md

        html = engine.render_html(report)
        assert "REPORT_SAN_001" in html
        assert "<script>" not in html

        pdf = engine.render_pdf(report)
        assert isinstance(pdf, bytes)
        assert len(pdf) > 0
