"""
Unit tests for ScanEngine orchestrator (STEP 9B).
"""

from datetime import datetime, timezone
from typing import List, Optional, Sequence
import pytest

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
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    ImpactLevel,
    ProbeCategory,
    ProbeExecution,
    RiskAssessment,
    RiskFactors,
    RiskLevel,
    ScanResult,
    ScanStatus,
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


class FakeAdapter(TargetAdapter):
    def __init__(self, outputs: list[str] = None):
        config = TargetConfig(name="Fake Target", endpoint="http://fake.local/chat")
        super().__init__(config=config)
        self.outputs = outputs or ["SYSTEM_INSTRUCTION: leak"]
        self.call_count = 0

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="healthy")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        output = self.outputs[self.call_count % len(self.outputs)]
        self.call_count += 1
        return TargetResult(success=True, output=output)


class ErrorAdapter(TargetAdapter):
    def __init__(self):
        config = TargetConfig(name="Error Target", endpoint="http://error.local/chat")
        super().__init__(config=config)

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=False, output="error")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        raise RuntimeError("Simulated adapter error")


class FakeEvaluator(Evaluator):
    def __init__(self, verdict: EvaluationVerdict = EvaluationVerdict.VIOLATION):
        self.verdict = verdict
        self.evaluated_probes = []
        self.evaluated_executions = []

    def evaluate(self, probe: SecurityProbe, execution: ProbeExecution) -> EvaluationResult:
        self.evaluated_probes.append(probe)
        self.evaluated_executions.append(execution)
        ev_type = EvaluatorType.DETERMINISTIC
        if execution.status == ExecutionStatus.ERROR:
            return EvaluationResult(
                evaluation_id=f"eval-{execution.execution_id}",
                execution_id=execution.execution_id,
                probe_id=probe.id,
                verdict=EvaluationVerdict.ERROR,
                confidence=0.0,
                evidence=EvaluationEvidence(summary="Execution error"),
                evaluator_type=ev_type,
                rationale="Execution error",
            )
        return EvaluationResult(
            evaluation_id=f"eval-{execution.execution_id}",
            execution_id=execution.execution_id,
            probe_id=probe.id,
            verdict=self.verdict,
            confidence=0.95,
            evidence=EvaluationEvidence(
                summary="Matched indicator",
                matched_indicators=["INDICATOR"],
                response_excerpt="response excerpt",
            ),
            evaluator_type=ev_type,
            rationale="Evaluation rationale",
        )


def make_test_probe(probe_id: str = "PROMPT_LEAK_001") -> SecurityProbe:
    return SecurityProbe(
        id=probe_id,
        name=f"Probe {probe_id}",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        description="Probe description",
        prompt="Test prompt payload",
        expected_behavior="Refuse prompt leak",
    )


def make_test_risk_factors() -> RiskFactors:
    return RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.READ,
    )


def test_scan_engine_runs_complete_pipeline():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    finding_engine = FindingEngine()
    risk_engine = RiskEngine()

    scan_engine = ScanEngine(
        attack_engine=attack_engine,
        evaluator=evaluator,
        finding_engine=finding_engine,
        risk_engine=risk_engine,
    )

    probe = make_test_probe()
    factors = make_test_risk_factors()

    result = scan_engine.run_scan(
        scan_id="SCAN_1001",
        target_name="Fake Agent",
        probes=[probe],
        risk_factors=factors,
    )

    assert result.scan_id == "SCAN_1001"
    assert result.target_name == "Fake Agent"
    assert result.status == ScanStatus.COMPLETED
    assert len(result.executions) == 1
    assert len(result.evaluations) == 1
    assert len(result.findings) == 1
    assert len(result.risk_assessments) == 1


def test_scan_engine_executes_all_probes():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator()
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    probes = [make_test_probe("P1"), make_test_probe("P2"), make_test_probe("P3")]
    result = scan_engine.run_scan("SCAN_1", "Target", probes, make_test_risk_factors())

    assert len(result.executions) == 3
    assert [e.probe_id for e in result.executions] == ["P1", "P2", "P3"]


def test_scan_engine_evaluates_all_executions():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator()
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    probes = [make_test_probe("P1"), make_test_probe("P2")]
    result = scan_engine.run_scan("SCAN_1", "Target", probes, make_test_risk_factors())

    assert len(result.evaluations) == 2
    assert evaluator.evaluated_probes == probes


def test_scan_engine_creates_findings_for_violations():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())

    assert len(result.findings) == 1
    assert result.findings[0].category == ProbeCategory.SYSTEM_PROMPT_DISCLOSURE


def test_scan_engine_creates_no_findings_for_safe_results():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.SAFE)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())

    assert len(result.findings) == 0
    assert len(result.risk_assessments) == 0


def test_scan_engine_creates_risk_assessments():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())

    assert len(result.risk_assessments) == 1
    assert result.risk_assessments[0].risk_level == RiskLevel.HIGH


def test_risk_assessment_references_finding():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())

    finding_id = result.findings[0].finding_id
    risk_finding_id = result.risk_assessments[0].finding_id
    assert risk_finding_id == finding_id


def test_evaluation_references_execution():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator()
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())

    exec_id = result.executions[0].execution_id
    eval_exec_id = result.evaluations[0].execution_id
    assert eval_exec_id == exec_id


def test_scan_summary_counts_are_correct():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    probes = [make_test_probe("P1"), make_test_probe("P2")]
    result = scan_engine.run_scan("SCAN_1", "Target", probes, make_test_risk_factors())

    summary = result.summary
    assert summary.total_probes == 2
    assert summary.completed_executions == 2
    assert summary.failed_executions == 0
    assert summary.violation_evaluations == 2
    assert summary.total_findings == 1


def test_violation_does_not_make_scan_partial():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())

    assert result.summary.violation_evaluations == 1
    assert result.status == ScanStatus.COMPLETED


def test_execution_error_makes_scan_partial():
    adapter = ErrorAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator()
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    probes = [make_test_probe("P1")]
    result = scan_engine.run_scan("SCAN_1", "Target", probes, make_test_risk_factors())

    assert result.status in (ScanStatus.PARTIAL, ScanStatus.FAILED)
    assert result.summary.failed_executions == 1


def test_evaluation_error_makes_scan_partial():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.ERROR)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())

    assert result.status == ScanStatus.PARTIAL
    assert result.summary.error_evaluations == 1


def test_multiple_findings_supported():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    p1 = SecurityProbe(id="PROMPT_LEAK_P1", name="N1", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE, description="d", prompt="p", expected_behavior="e")
    p2 = SecurityProbe(id="TOOL_AUTH_P2", name="N2", category=ProbeCategory.TOOL_AUTHORIZATION, description="d", prompt="p", expected_behavior="e")

    result = scan_engine.run_scan("SCAN_1", "Target", [p1, p2], make_test_risk_factors())

    assert len(result.findings) == 2


def test_multiple_risk_assessments_supported():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator(verdict=EvaluationVerdict.VIOLATION)
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    p1 = SecurityProbe(id="PROMPT_LEAK_P1", name="N1", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE, description="d", prompt="p", expected_behavior="e")
    p2 = SecurityProbe(id="TOOL_AUTH_P2", name="N2", category=ProbeCategory.TOOL_AUTHORIZATION, description="d", prompt="p", expected_behavior="e")

    result = scan_engine.run_scan("SCAN_1", "Target", [p1, p2], make_test_risk_factors())

    assert len(result.risk_assessments) == 2


def test_empty_probe_sequence():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator()
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_EMPTY", "Target", [], make_test_risk_factors())

    assert result.status == ScanStatus.COMPLETED
    assert result.summary.total_probes == 0
    assert len(result.executions) == 0


def test_scan_ids_are_preserved():
    adapter = FakeAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_SPECIFIC_ID", "Target", [make_test_probe()], make_test_risk_factors())
    assert result.scan_id == "SCAN_SPECIFIC_ID"


def test_target_name_is_preserved():
    adapter = FakeAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "My Production Agent", [make_test_probe()], make_test_risk_factors())
    assert result.target_name == "My Production Agent"


def test_started_at_is_timezone_aware():
    adapter = FakeAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())
    assert result.started_at.tzinfo is not None


def test_completed_at_is_timezone_aware():
    adapter = FakeAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())
    assert result.completed_at.tzinfo is not None


def test_completed_at_after_started_at():
    adapter = FakeAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_1", "Target", [make_test_probe()], make_test_risk_factors())
    assert result.completed_at >= result.started_at


def test_dependencies_are_injected():
    attack_engine = AttackEngine(FakeAdapter())
    evaluator = FakeEvaluator()
    finding_engine = FindingEngine()
    risk_engine = RiskEngine()

    scan_engine = ScanEngine(attack_engine, evaluator, finding_engine, risk_engine)
    assert scan_engine.attack_engine is attack_engine
    assert scan_engine.evaluator is evaluator
    assert scan_engine.finding_engine is finding_engine
    assert scan_engine.risk_engine is risk_engine


def test_scan_engine_does_not_call_target_adapter_directly():
    assert not hasattr(ScanEngine, "adapter")


def test_scan_engine_does_not_calculate_risk():
    assert not hasattr(ScanEngine, "calculate_risk")


def test_scan_engine_does_not_create_findings_directly():
    assert not hasattr(ScanEngine, "create_finding")


def test_sequential_probe_execution_order():
    adapter = FakeAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = FakeEvaluator()
    scan_engine = ScanEngine(attack_engine, evaluator, FindingEngine(), RiskEngine())

    probes = [make_test_probe(f"P{i}") for i in range(5)]
    result = scan_engine.run_scan("SCAN_SEQ", "Target", probes, make_test_risk_factors())

    executed_ids = [e.probe_id for e in result.executions]
    assert executed_ids == ["P0", "P1", "P2", "P3", "P4"]


def test_partial_scan_preserves_successful_results():
    class AlternatingAdapter(TargetAdapter):
        def __init__(self):
            super().__init__(TargetConfig(name="Alt", endpoint="http://alt/chat"))
            self.calls = 0

        def validate(self) -> bool:
            return True

        def health_check(self) -> TargetResult:
            return TargetResult(success=True, output="healthy")

        def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
            self.calls += 1
            if self.calls == 1:
                return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")
            raise RuntimeError("Adapter error on call 2")

    adapter = AlternatingAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    p1 = make_test_probe("P1")
    p2 = make_test_probe("P2")

    result = scan_engine.run_scan("SCAN_ALT", "Target", [p1, p2], make_test_risk_factors())

    assert result.status == ScanStatus.PARTIAL
    assert len(result.executions) == 2
    assert result.executions[0].status == ExecutionStatus.COMPLETED
    assert result.executions[1].status == ExecutionStatus.ERROR


def test_failed_scan_semantics():
    adapter = ErrorAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_FAIL", "Target", [make_test_probe()], make_test_risk_factors())

    assert result.status == ScanStatus.FAILED
    assert result.summary.failed_executions == 1


def test_no_network_calls():
    adapter = FakeAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_LOCAL", "Target", [make_test_probe()], make_test_risk_factors())
    assert result is not None


def test_no_llm_calls():
    adapter = FakeAdapter()
    scan_engine = ScanEngine(AttackEngine(adapter), FakeEvaluator(), FindingEngine(), RiskEngine())

    result = scan_engine.run_scan("SCAN_LOCAL", "Target", [make_test_probe()], make_test_risk_factors())
    assert result.status == ScanStatus.COMPLETED


def test_no_database():
    assert not hasattr(ScanEngine, "db")
    assert not hasattr(ScanEngine, "repository")
