import pytest
from pydantic import ValidationError

from app.domain.evaluation import (
    EvaluationEvidence,
    EvaluationResult,
    EvaluationVerdict,
    EvaluatorType,
)


def test_valid_safe_evaluation_result() -> None:
    """Test 1: Valid SAFE verdict EvaluationResult creation."""
    evidence = EvaluationEvidence(
        summary="Target correctly refused system prompt disclosure",
        matched_indicators=["refusal_phrase_detected"],
        response_excerpt="I cannot reveal system instructions.",
    )
    result = EvaluationResult(
        evaluation_id="eval-001",
        execution_id="exec-100",
        probe_id="PROMPT_LEAK_001",
        verdict=EvaluationVerdict.SAFE,
        confidence=0.98,
        evidence=evidence,
        rationale="Target output matches standard refusal policy.",
    )
    assert result.verdict == EvaluationVerdict.SAFE
    assert result.confidence == 0.98
    assert result.evaluator_type == EvaluatorType.DETERMINISTIC
    assert result.evidence.summary == "Target correctly refused system prompt disclosure"


def test_valid_violation_evaluation_result() -> None:
    """Test 2: Valid VIOLATION verdict EvaluationResult creation."""
    evidence = EvaluationEvidence(
        summary="Target leaked internal system prompt string",
        matched_indicators=["SYSTEM_INSTRUCTION_HEADER"],
        response_excerpt="SYSTEM_INSTRUCTION: You are a support assistant...",
    )
    result = EvaluationResult(
        evaluation_id="eval-002",
        execution_id="exec-101",
        probe_id="PROMPT_LEAK_001",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=1.0,
        evidence=evidence,
        rationale="Target output disclosed system instructions.",
    )
    assert result.verdict == EvaluationVerdict.VIOLATION
    assert result.confidence == 1.0


def test_valid_inconclusive_evaluation_result() -> None:
    """Test 3: Valid INCONCLUSIVE verdict EvaluationResult creation."""
    evidence = EvaluationEvidence(
        summary="Target response text was ambiguous or partially truncated",
        matched_indicators=[],
        response_excerpt="System info: N/A",
    )
    result = EvaluationResult(
        evaluation_id="eval-003",
        execution_id="exec-102",
        probe_id="INSTRUCTION_OVERRIDE_001",
        verdict=EvaluationVerdict.INCONCLUSIVE,
        confidence=0.45,
        evidence=evidence,
        rationale="Could not determine if override succeeded from partial string match.",
    )
    assert result.verdict == EvaluationVerdict.INCONCLUSIVE
    assert result.confidence == 0.45


def test_valid_error_evaluation_result() -> None:
    """Test 4: Valid ERROR verdict EvaluationResult creation."""
    evidence = EvaluationEvidence(
        summary="Target returned HTTP 504 Timeout, evaluation could not be completed",
        matched_indicators=["TRANSPORT_TIMEOUT"],
    )
    result = EvaluationResult(
        evaluation_id="eval-004",
        execution_id="exec-103",
        probe_id="TOOL_AUTH_001",
        verdict=EvaluationVerdict.ERROR,
        confidence=0.0,
        evidence=evidence,
        rationale="Target execution failed at transport layer due to timeout.",
    )
    assert result.verdict == EvaluationVerdict.ERROR
    assert result.confidence == 0.0


def test_confidence_accepts_boundary_values() -> None:
    """Test 5 & 6: Confidence accepts exact boundary values 0.0 and 1.0."""
    evidence = EvaluationEvidence(summary="Boundary check")

    res_min = EvaluationResult(
        evaluation_id="eval-min",
        execution_id="exec-0",
        probe_id="PROBE_0",
        verdict=EvaluationVerdict.INCONCLUSIVE,
        confidence=0.0,
        evidence=evidence,
        rationale="Min confidence",
    )
    assert res_min.confidence == 0.0

    res_max = EvaluationResult(
        evaluation_id="eval-max",
        execution_id="exec-1",
        probe_id="PROBE_1",
        verdict=EvaluationVerdict.SAFE,
        confidence=1.0,
        evidence=evidence,
        rationale="Max confidence",
    )
    assert res_max.confidence == 1.0


def test_confidence_below_zero_rejected() -> None:
    """Test 7: Confidence below 0.0 is rejected."""
    evidence = EvaluationEvidence(summary="Test")
    with pytest.raises(ValidationError) as exc_info:
        EvaluationResult(
            evaluation_id="eval-err",
            execution_id="exec-1",
            probe_id="PROBE_1",
            verdict=EvaluationVerdict.SAFE,
            confidence=-0.05,
            evidence=evidence,
            rationale="Negative confidence",
        )
    assert "confidence" in str(exc_info.value)


def test_confidence_above_one_rejected() -> None:
    """Test 8: Confidence above 1.0 is rejected."""
    evidence = EvaluationEvidence(summary="Test")
    with pytest.raises(ValidationError) as exc_info:
        EvaluationResult(
            evaluation_id="eval-err",
            execution_id="exec-1",
            probe_id="PROBE_1",
            verdict=EvaluationVerdict.SAFE,
            confidence=1.05,
            evidence=evidence,
            rationale="Excessive confidence",
        )
    assert "confidence" in str(exc_info.value)


def test_empty_evaluation_id_rejected() -> None:
    """Test 9: Empty or whitespace-only evaluation_id is rejected."""
    evidence = EvaluationEvidence(summary="Test")
    with pytest.raises(ValidationError) as exc_info:
        EvaluationResult(
            evaluation_id="",
            execution_id="exec-1",
            probe_id="PROBE_1",
            verdict=EvaluationVerdict.SAFE,
            confidence=0.9,
            evidence=evidence,
            rationale="Empty ID",
        )
    assert "evaluation_id" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        EvaluationResult(
            evaluation_id="   ",
            execution_id="exec-1",
            probe_id="PROBE_1",
            verdict=EvaluationVerdict.SAFE,
            confidence=0.9,
            evidence=evidence,
            rationale="Whitespace ID",
        )
    assert "evaluation_id" in str(exc_info.value)


def test_evidence_excerpt_is_bounded() -> None:
    """Test 10: Evidence response_excerpt is automatically bounded to <= 500 characters."""
    long_string = "A" * 1000
    evidence = EvaluationEvidence(
        summary="Long excerpt test",
        response_excerpt=long_string,
    )
    assert evidence.response_excerpt is not None
    assert len(evidence.response_excerpt) <= 500
    assert evidence.response_excerpt.endswith("...")


def test_evaluation_result_references_ids() -> None:
    """Test 11: EvaluationResult accurately references execution_id and probe_id."""
    evidence = EvaluationEvidence(summary="Reference test")
    result = EvaluationResult(
        evaluation_id="eval-999",
        execution_id="exec-888",
        probe_id="PROMPT_LEAK_001",
        verdict=EvaluationVerdict.SAFE,
        confidence=0.9,
        evidence=evidence,
        rationale="ID reference check",
    )
    assert result.execution_id == "exec-888"
    assert result.probe_id == "PROMPT_LEAK_001"


def test_evaluation_result_contains_no_risk_score_or_severity() -> None:
    """Test 12 & 13: EvaluationResult contains no risk_score or final severity attributes."""
    evidence = EvaluationEvidence(summary="Decoupling test")
    result = EvaluationResult(
        evaluation_id="eval-100",
        execution_id="exec-100",
        probe_id="PROBE_100",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.95,
        evidence=evidence,
        rationale="Security decoupling assertion",
    )
    assert not hasattr(result, "risk_score")
    assert not hasattr(result, "cvss")
    assert not hasattr(result, "severity")
    assert not hasattr(result, "remediation")
    assert not hasattr(result, "finding_status")


def test_top_level_immutability() -> None:
    """Test 14: EvaluationResult is top-level immutable due to ConfigDict(frozen=True)."""
    evidence = EvaluationEvidence(summary="Freeze test")
    result = EvaluationResult(
        evaluation_id="eval-freeze",
        execution_id="exec-100",
        probe_id="PROBE_100",
        verdict=EvaluationVerdict.SAFE,
        confidence=0.9,
        evidence=evidence,
        rationale="Immutability check",
    )
    with pytest.raises(ValidationError):
        result.confidence = 0.5  # type: ignore[misc]


def test_evaluator_type_is_deterministic_by_default() -> None:
    """Test 15: Evaluator type defaults to DETERMINISTIC."""
    evidence = EvaluationEvidence(summary="Default type test")
    result = EvaluationResult(
        evaluation_id="eval-type",
        execution_id="exec-100",
        probe_id="PROBE_100",
        verdict=EvaluationVerdict.SAFE,
        confidence=0.9,
        evidence=evidence,
        rationale="Default type check",
    )
    assert result.evaluator_type == EvaluatorType.DETERMINISTIC
