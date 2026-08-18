"""
Integration Test: End-to-End Security Pipeline to Finding Engine (STEP 7B)

Pipeline:
get_basic_probes() ──► AttackEngine ──► Local Test Target ──► ProbeExecution ──► DeterministicEvaluator ──► EvaluationResult ──► FindingEngine ──► Finding
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.domain.evaluation import EvaluationResult, EvaluationVerdict
from app.domain.execution import ProbeExecution
from app.domain.finding import Finding, FindingSeverity
from app.domain.probe import ProbeCategory
from app.domain.target import TargetConfig
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.probes.basic import get_basic_probes
from test_target.main import local_target_app
from test_target.tools import reset_test_state


def create_in_memory_adapter() -> GenericHTTPAdapter:
    """Helper creating GenericHTTPAdapter connected via in-memory mock transport to local_target_app."""
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


def test_end_to_end_finding_pipeline_against_vulnerable_target() -> None:
    """
    End-to-End Pipeline Test:
    Executes initial probe suite against local_target_app, evaluates results using DeterministicEvaluator,
    and aggregates Findings using FindingEngine.
    """
    # 1. Pipeline components instantiation
    adapter = create_in_memory_adapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = DeterministicEvaluator()
    finding_engine = FindingEngine()
    probes = get_basic_probes()

    # 2. Execute probes
    executions: list[ProbeExecution] = attack_engine.execute_probes(probes)
    assert len(executions) == len(probes)

    # 3. Evaluate results
    eval_results: list[EvaluationResult] = [
        evaluator.evaluate(probe, execution)
        for probe, execution in zip(probes, executions)
    ]
    assert len(eval_results) == len(probes)
    violations = [r for r in eval_results if r.verdict == EvaluationVerdict.VIOLATION]
    assert len(violations) == 3

    # 4. Convert and aggregate into Findings
    findings: tuple[Finding, ...] = finding_engine.aggregate_evaluation_results(eval_results)
    assert len(findings) == 3

    finding_map = {f.category: f for f in findings}

    # 5. Verify System Prompt Disclosure Finding
    f_leak = finding_map[ProbeCategory.SYSTEM_PROMPT_DISCLOSURE]
    assert f_leak.finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"
    assert f_leak.title == "System Prompt Disclosure"
    assert f_leak.severity == FindingSeverity.HIGH
    assert f_leak.confidence == 0.98
    assert f_leak.affected_probe_ids == ["PROMPT_LEAK_001"]
    assert f_leak.affected_execution_ids == [executions[0].execution_id]
    assert len(f_leak.evidence) == 1
    assert f_leak.evidence[0].probe_id == "PROMPT_LEAK_001"
    assert f_leak.evidence[0].execution_id == executions[0].execution_id

    # 6. Verify Instruction Override Finding
    f_override = finding_map[ProbeCategory.INSTRUCTION_OVERRIDE]
    assert f_override.finding_id == "FINDING_INSTRUCTION_OVERRIDE"
    assert f_override.title == "Instruction Override"
    assert f_override.severity == FindingSeverity.HIGH
    assert f_override.confidence == 0.99
    assert f_override.affected_probe_ids == ["INSTRUCTION_OVERRIDE_001"]
    assert f_override.affected_execution_ids == [executions[1].execution_id]
    assert len(f_override.evidence) == 1
    assert f_override.evidence[0].probe_id == "INSTRUCTION_OVERRIDE_001"
    assert f_override.evidence[0].execution_id == executions[1].execution_id

    # 7. Verify Unauthorized Tool Invocation Finding
    f_tool = finding_map[ProbeCategory.TOOL_AUTHORIZATION]
    assert f_tool.finding_id == "FINDING_TOOL_AUTHORIZATION"
    assert f_tool.title == "Unauthorized Tool Invocation"
    assert f_tool.severity == FindingSeverity.CRITICAL
    assert f_tool.confidence == 0.99
    assert f_tool.affected_probe_ids == ["TOOL_AUTH_001"]
    assert f_tool.affected_execution_ids == [executions[2].execution_id]
    assert len(f_tool.evidence) == 1
    assert f_tool.evidence[0].probe_id == "TOOL_AUTH_001"
    assert f_tool.evidence[0].execution_id == executions[2].execution_id
