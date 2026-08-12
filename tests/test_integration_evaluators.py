"""
Integration Tests Proving Deterministic and LLM Evaluator Boundaries (STEP 13B).
"""

from datetime import datetime, timezone
import pytest

from app.domain import (
    EvaluationVerdict,
    EvaluatorType,
    ExecutionStatus,
    ProbeCategory,
    ProbeExecution,
    SecurityProbe,
    TargetError,
    TargetErrorCode,
    TargetResult,
)
from app.evaluation.deterministic import DeterministicEvaluator
from app.evaluation.llm import LLMEvaluator
from app.evaluation.provider import FakeLLMProvider


def make_probe(probe_id: str, name: str, category: ProbeCategory) -> SecurityProbe:
    return SecurityProbe(
        id=probe_id,
        name=name,
        category=category,
        description=f"Description for {name}",
        prompt="Test prompt",
        expected_behavior=f"Expected behavior for {name}",
    )


def make_execution(probe_id: str, output: str, success: bool = True) -> ProbeExecution:
    target_res = TargetResult(
        success=success,
        output=output,
        error=TargetError(code=TargetErrorCode.UNKNOWN_ERROR, message="Failed") if not success else None,
    )
    return ProbeExecution(
        execution_id=f"EXEC_{probe_id}",
        target_name="Test Target Agent",
        probe_id=probe_id,
        prompt_text="Test prompt",
        target_result=target_res,
        status=ExecutionStatus.COMPLETED if success else ExecutionStatus.ERROR,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def test_evaluators_side_by_side_execution():
    det_evaluator = DeterministicEvaluator()

    llm_response_map = {
        "PROMPT_LEAK_001": '{"verdict": "violation", "confidence": 0.95, "rationale": "Leaked prompt"}',
        "INSTRUCTION_OVERRIDE_001": '{"verdict": "safe", "confidence": 0.90, "rationale": "Maintained persona"}',
    }
    llm_evaluator = LLMEvaluator(provider=FakeLLMProvider(response_map=llm_response_map))

    probe_leak = make_probe("PROMPT_LEAK_001", "Leak Probe", ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)
    exec_leak = make_execution("PROMPT_LEAK_001", "SYSTEM_INSTRUCTION: leak")

    # 1. Deterministic Evaluation
    det_res = det_evaluator.evaluate(probe_leak, exec_leak)
    assert det_res.verdict == EvaluationVerdict.VIOLATION
    assert det_res.evaluator_type == EvaluatorType.DETERMINISTIC

    # 2. LLM Evaluation
    llm_res = llm_evaluator.evaluate(probe_leak, exec_leak)
    assert llm_res.verdict == EvaluationVerdict.VIOLATION
    assert llm_res.evaluator_type == EvaluatorType.LLM_JUDGE


def test_evaluators_consistent_transport_error_handling():
    det_evaluator = DeterministicEvaluator()
    fake_provider = FakeLLMProvider()
    llm_evaluator = LLMEvaluator(provider=fake_provider)

    probe = make_probe("PROMPT_LEAK_001", "Leak Probe", ProbeCategory.SYSTEM_PROMPT_DISCLOSURE)
    exec_error = make_execution("PROMPT_LEAK_001", output="", success=False)

    det_res = det_evaluator.evaluate(probe, exec_error)
    llm_res = llm_evaluator.evaluate(probe, exec_error)

    # Both evaluators MUST return EvaluationVerdict.ERROR on transport failure
    assert det_res.verdict == EvaluationVerdict.ERROR
    assert llm_res.verdict == EvaluationVerdict.ERROR
    assert det_res.confidence == 0.0
    assert llm_res.confidence == 0.0

    # LLM Provider MUST NOT have been called
    assert len(fake_provider.call_history) == 0
