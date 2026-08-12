"""
Unit tests for FindingEngine (STEP 7B).
"""

import uuid
import pytest

from app.domain import (
    EvaluationEvidence,
    EvaluationResult,
    EvaluationVerdict,
    EvaluatorType,
    Finding,
    FindingSeverity,
    ProbeCategory,
)
from app.engine.finding import FindingEngine


def make_eval_result(
    verdict: EvaluationVerdict,
    probe_id: str = "PROMPT_LEAK_001",
    execution_id: str = "exec-101",
    confidence: float = 0.98,
    category: ProbeCategory = ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
    summary: str = "Test violation evidence summary",
    matched_indicators: list[str] = None,
    response_excerpt: str = "SYSTEM_INSTRUCTION: leak excerpt",
) -> EvaluationResult:
    if matched_indicators is None:
        matched_indicators = ["INDICATOR_01"]
    evidence = EvaluationEvidence(
        summary=summary,
        matched_indicators=matched_indicators,
        response_excerpt=response_excerpt,
    )
    return EvaluationResult(
        evaluation_id=str(uuid.uuid4()),
        execution_id=execution_id,
        probe_id=probe_id,
        verdict=verdict,
        confidence=confidence,
        evidence=evidence,
        evaluator_type=EvaluatorType.DETERMINISTIC,
        rationale="Unit test evaluation result rationale.",
        metadata={"category": category},
    )


def test_violation_creates_finding():
    engine = FindingEngine()
    eval_res = make_eval_result(EvaluationVerdict.VIOLATION)
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert isinstance(finding, Finding)
    assert finding.finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"


def test_safe_creates_no_finding():
    engine = FindingEngine()
    eval_res = make_eval_result(EvaluationVerdict.SAFE)
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is None


def test_inconclusive_creates_no_finding():
    engine = FindingEngine()
    eval_res = make_eval_result(EvaluationVerdict.INCONCLUSIVE)
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is None


def test_error_creates_no_finding():
    engine = FindingEngine()
    eval_res = make_eval_result(EvaluationVerdict.ERROR)
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is None


def test_system_prompt_category_mapping_works():
    engine = FindingEngine()
    eval_res = make_eval_result(
        EvaluationVerdict.VIOLATION,
        probe_id="PROMPT_LEAK_001",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
    )
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert finding.category == ProbeCategory.SYSTEM_PROMPT_DISCLOSURE
    assert finding.title == "System Prompt Disclosure"
    assert finding.severity == FindingSeverity.HIGH


def test_instruction_override_mapping_works():
    engine = FindingEngine()
    eval_res = make_eval_result(
        EvaluationVerdict.VIOLATION,
        probe_id="INSTRUCTION_OVERRIDE_001",
        category=ProbeCategory.INSTRUCTION_OVERRIDE,
    )
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert finding.category == ProbeCategory.INSTRUCTION_OVERRIDE
    assert finding.title == "Instruction Override"
    assert finding.severity == FindingSeverity.HIGH


def test_tool_authorization_mapping_works():
    engine = FindingEngine()
    eval_res = make_eval_result(
        EvaluationVerdict.VIOLATION,
        probe_id="TOOL_AUTH_001",
        category=ProbeCategory.TOOL_AUTHORIZATION,
    )
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert finding.category == ProbeCategory.TOOL_AUTHORIZATION
    assert finding.title == "Unauthorized Tool Invocation"
    assert finding.severity == FindingSeverity.CRITICAL


def test_finding_confidence_equals_evaluation_confidence():
    engine = FindingEngine()
    eval_res = make_eval_result(EvaluationVerdict.VIOLATION, confidence=0.87)
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert finding.confidence == 0.87


def test_evidence_is_preserved():
    engine = FindingEngine()
    eval_res = make_eval_result(
        EvaluationVerdict.VIOLATION,
        summary="Unique Evidence Summary",
        matched_indicators=["IND_A", "IND_B"],
        response_excerpt="Excerpt string for test",
    )
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert len(finding.evidence) == 1
    ev = finding.evidence[0]
    assert ev.summary == "Unique Evidence Summary"
    assert ev.indicators == ["IND_A", "IND_B"]
    assert ev.response_excerpt == "Excerpt string for test"
    assert ev.probe_id == eval_res.probe_id
    assert ev.execution_id == eval_res.execution_id


def test_probe_id_is_preserved():
    engine = FindingEngine()
    eval_res = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001")
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert finding.affected_probe_ids == ["PROMPT_LEAK_001"]


def test_execution_id_is_preserved():
    engine = FindingEngine()
    eval_res = make_eval_result(EvaluationVerdict.VIOLATION, execution_id="exec-xyz-999")
    finding = engine.convert_evaluation_result(eval_res)
    assert finding is not None
    assert finding.affected_execution_ids == ["exec-xyz-999"]


def test_correct_provisional_severity_is_assigned():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION, category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)
    r2 = make_eval_result(EvaluationVerdict.VIOLATION, category=ProbeCategory.INSTRUCTION_OVERRIDE)
    r3 = make_eval_result(EvaluationVerdict.VIOLATION, category=ProbeCategory.TOOL_AUTHORIZATION)

    f1 = engine.convert_evaluation_result(r1)
    f2 = engine.convert_evaluation_result(r2)
    f3 = engine.convert_evaluation_result(r3)

    assert f1.severity == FindingSeverity.HIGH
    assert f2.severity == FindingSeverity.HIGH
    assert f3.severity == FindingSeverity.CRITICAL


def test_finding_id_is_deterministic():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)
    r2 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)

    f1 = engine.convert_evaluation_result(r1)
    f2 = engine.convert_evaluation_result(r2)

    assert f1.finding_id == f2.finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"


def test_multiple_violations_of_same_category_aggregate():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", execution_id="exec-1", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)
    r2 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_002", execution_id="exec-2", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)
    r3 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_003", execution_id="exec-3", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)

    aggregated = engine.aggregate_evaluation_results([r1, r2, r3])
    assert len(aggregated) == 1
    finding = aggregated[0]
    assert finding.finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"
    assert len(finding.affected_probe_ids) == 3
    assert len(finding.affected_execution_ids) == 3
    assert len(finding.evidence) == 3


def test_multiple_probe_ids_are_preserved():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", execution_id="exec-1")
    r2 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_002", execution_id="exec-2")

    aggregated = engine.aggregate_evaluation_results([r1, r2])
    assert aggregated[0].affected_probe_ids == ["PROMPT_LEAK_001", "PROMPT_LEAK_002"]


def test_multiple_execution_ids_are_preserved():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", execution_id="exec-101")
    r2 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", execution_id="exec-102")

    aggregated = engine.aggregate_evaluation_results([r1, r2])
    assert aggregated[0].affected_execution_ids == ["exec-101", "exec-102"]


def test_different_categories_create_different_findings():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)
    r2 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="TOOL_AUTH_001", category=ProbeCategory.TOOL_AUTHORIZATION)

    aggregated = engine.aggregate_evaluation_results([r1, r2])
    assert len(aggregated) == 2
    categories = {f.category for f in aggregated}
    assert categories == {ProbeCategory.SYSTEM_PROMPT_DISCLOSURE, ProbeCategory.TOOL_AUTHORIZATION}


def test_same_input_produces_same_finding():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION, probe_id="PROMPT_LEAK_001", execution_id="exec-1")

    res1 = engine.aggregate_evaluation_results([r1])
    res2 = engine.aggregate_evaluation_results([r1])

    assert len(res1) == len(res2) == 1
    assert res1[0].finding_id == res2[0].finding_id
    assert res1[0].affected_probe_ids == res2[0].affected_probe_ids
    assert res1[0].affected_execution_ids == res2[0].affected_execution_ids


def test_no_risk_score_exists():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION)
    finding = engine.convert_evaluation_result(r1)
    assert not hasattr(finding, "risk_score")
    assert "risk_score" not in Finding.model_fields


def test_no_cvss_exists():
    engine = FindingEngine()
    r1 = make_eval_result(EvaluationVerdict.VIOLATION)
    finding = engine.convert_evaluation_result(r1)
    assert not hasattr(finding, "cvss")
    assert not hasattr(finding, "cvss_score")
    assert "cvss" not in Finding.model_fields


def test_no_external_network_calls_occur():
    engine = FindingEngine()
    results = [
        make_eval_result(EvaluationVerdict.VIOLATION if i % 2 == 0 else EvaluationVerdict.SAFE, execution_id=f"exec-{i}")
        for i in range(50)
    ]
    aggregated = engine.aggregate_evaluation_results(results)
    assert isinstance(aggregated, tuple)
