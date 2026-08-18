"""
Integration Test: End-to-End Complete Security Scan (STEP 9B)

Pipeline:
get_basic_probes() ──► ScanEngine ──► AttackEngine ──► GenericHTTPAdapter ──► Local Test Target ──► ProbeExecution ──► DeterministicEvaluator ──► EvaluationResult ──► FindingEngine ──► Finding ──► RiskEngine ──► RiskAssessment ──► ScanResult
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    EvaluationVerdict,
    ExecutionStatus,
    ExploitabilityLevel,
    ImpactLevel,
    ProbeCategory,
    RiskFactors,
    RiskLevel,
    ScanResult,
    ScanStatus,
    TargetConfig,
    ToolPrivilege,
)
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
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


def test_end_to_end_full_scan_pipeline_against_vulnerable_target() -> None:
    """
    End-to-End Full Scan Integration Test:
    Executes initial probe suite against local_target_app via ScanEngine orchestrator.
    Verifies that all 3 probes execute, produce violations, yield 3 Findings and 3 RiskAssessments,
    and construct a valid, complete ScanResult in COMPLETED status.
    """
    # 1. Pipeline components instantiation
    adapter = create_in_memory_adapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = DeterministicEvaluator()
    finding_engine = FindingEngine()
    risk_engine = RiskEngine()

    scan_engine = ScanEngine(
        attack_engine=attack_engine,
        evaluator=evaluator,
        finding_engine=finding_engine,
        risk_engine=risk_engine,
    )

    probes = get_basic_probes()
    risk_factors = RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.WRITE,
    )

    # 2. Execute full scan
    scan_result: ScanResult = scan_engine.run_scan(
        scan_id="SCAN_E2E_001",
        target_name="Local Security Test Target Fixture",
        probes=probes,
        risk_factors=risk_factors,
        metadata={"scan_type": "full_integration"},
    )

    # 3. Assert top-level scan properties
    assert scan_result.scan_id == "SCAN_E2E_001"
    assert scan_result.target_name == "Local Security Test Target Fixture"
    assert scan_result.status == ScanStatus.COMPLETED
    assert scan_result.started_at is not None
    assert scan_result.completed_at is not None
    assert scan_result.completed_at >= scan_result.started_at

    # 4. Assert Executions & Evaluations
    assert len(scan_result.executions) == len(probes)
    assert all(e.status == ExecutionStatus.COMPLETED for e in scan_result.executions)
    assert len(scan_result.evaluations) == len(probes)
    violations = [ev for ev in scan_result.evaluations if ev.verdict == EvaluationVerdict.VIOLATION]
    assert len(violations) == 3

    # 5. Assert Findings
    assert len(scan_result.findings) == 3
    finding_categories = {f.category for f in scan_result.findings}
    assert finding_categories == {
        ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        ProbeCategory.INSTRUCTION_OVERRIDE,
        ProbeCategory.TOOL_AUTHORIZATION,
    }

    # 6. Assert Risk Assessments
    assert len(scan_result.risk_assessments) == 3
    for ra in scan_result.risk_assessments:
        assert ra.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert ra.risk_score > 60.0

    # 7. Assert Lineage Relationships
    exec_map = {e.execution_id: e for e in scan_result.executions}
    finding_map = {f.finding_id: f for f in scan_result.findings}

    for ev in scan_result.evaluations:
        assert ev.execution_id in exec_map

    for ra in scan_result.risk_assessments:
        assert ra.finding_id in finding_map

    # 8. Assert ScanSummary
    summary = scan_result.summary
    assert summary.total_probes == 3
    assert summary.completed_executions == 3
    assert summary.failed_executions == 0
    assert summary.safe_evaluations == 0
    assert summary.violation_evaluations == 3
    assert summary.error_evaluations == 0
    assert summary.total_findings == 3
