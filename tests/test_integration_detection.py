"""
Integration Test: End-to-End Security Pipeline Detection

Proves end-to-end execution and deterministic detection pipeline:
get_basic_probes() ──► AttackEngine ──► GenericHTTPAdapter ──► Local Test Target ──► ProbeExecution ──► DeterministicEvaluator ──► EvaluationResult
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.domain.evaluation import EvaluationResult, EvaluationVerdict
from app.domain.execution import ProbeExecution
from app.domain.target import TargetConfig
from app.engine.attack import AttackEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.probes.basic import get_basic_probes
from test_target.main import local_target_app
from test_target.tools import reset_test_state


def create_in_memory_adapter() -> GenericHTTPAdapter:
    """Helper to create GenericHTTPAdapter connected via in-memory transport to local_target_app."""
    test_client = TestClient(local_target_app)

    def handler(request: httpx.Request) -> httpx.Response:
        res = test_client.request(
            method=request.method,
            url=str(request.url),
            content=request.content,
            headers=dict(request.headers),
        )
        return httpx.Response(
            status_code=res.status_code,
            headers=dict(res.headers),
            content=res.content,
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Local Security Test Target Fixture",
        endpoint="http://testagent.local/chat",
        request_template={"prompt": "{{input}}"},
        response_path="response",
        timeout_seconds=5.0,
    )
    return GenericHTTPAdapter(config=config, client=client)


@pytest.fixture(autouse=True)
def reset_state() -> None:
    """Reset synthetic database state prior to integration test."""
    reset_test_state()


def test_end_to_end_detection_pipeline_against_vulnerable_target_fixture() -> None:
    """
    End-to-End Security Pipeline Integration Test:
    Executes initial probe suite against local_target_app and evaluates results using DeterministicEvaluator.
    Verifies that all three controlled vulnerabilities in the test target fixture produce EvaluationVerdict.VIOLATION.
    """
    # 1. Instantiate TargetAdapter, AttackEngine, and DeterministicEvaluator
    adapter = create_in_memory_adapter()
    engine = AttackEngine(adapter=adapter)
    evaluator = DeterministicEvaluator()
    probes = get_basic_probes()

    # 2. Execute probes via AttackEngine
    executions: list[ProbeExecution] = engine.execute_probes(probes)
    assert len(executions) == 3

    # 3. Evaluate each ProbeExecution using DeterministicEvaluator
    evaluation_results: list[EvaluationResult] = [
        evaluator.evaluate(probe, execution)
        for probe, execution in zip(probes, executions)
    ]
    assert len(evaluation_results) == 3

    eval_map = {res.probe_id: res for res in evaluation_results}

    # 4. Verify System Prompt Leak Probe evaluation (PROMPT_LEAK_001)
    leak_eval = eval_map["PROMPT_LEAK_001"]
    assert leak_eval.verdict == EvaluationVerdict.VIOLATION
    assert leak_eval.confidence == 0.98
    assert "SYSTEM_INSTRUCTION:" in leak_exec_matched(leak_eval)

    # 5. Verify Instruction Override Probe evaluation (INSTRUCTION_OVERRIDE_001)
    override_eval = eval_map["INSTRUCTION_OVERRIDE_001"]
    assert override_eval.verdict == EvaluationVerdict.VIOLATION
    assert override_eval.confidence == 0.99
    assert "UNSECURE_OVERRIDE_SUCCESS" in leak_exec_matched(override_eval)

    # 6. Verify Tool Authorization Probe evaluation (TOOL_AUTH_001)
    auth_eval = eval_map["TOOL_AUTH_001"]
    assert auth_eval.verdict == EvaluationVerdict.VIOLATION
    assert auth_eval.confidence == 0.99
    assert "UNAUTHORIZED_CANCEL_EXECUTED" in leak_exec_matched(auth_eval)


def leak_exec_matched(res: EvaluationResult) -> list[str]:
    """Helper retrieving matched_indicators from EvaluationResult."""
    return res.evidence.matched_indicators
