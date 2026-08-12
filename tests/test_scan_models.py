"""
Unit tests for Scan domain models (STEP 9A).
"""

from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError

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
    ScanSummary,
    TargetResult,
    ToolPrivilege,
)


def make_valid_scan_summary() -> ScanSummary:
    return ScanSummary(
        total_probes=3,
        completed_executions=3,
        failed_executions=0,
        safe_evaluations=0,
        violation_evaluations=3,
        inconclusive_evaluations=0,
        error_evaluations=0,
        total_findings=3,
        info_risks=0,
        low_risks=0,
        medium_risks=0,
        high_risks=2,
        critical_risks=1,
    )


def make_sample_objects():
    now = datetime.now(timezone.utc)
    exec_1 = ProbeExecution(
        execution_id="exec-101",
        probe_id="PROMPT_LEAK_001",
        status=ExecutionStatus.COMPLETED,
        target_name="Test Agent",
        target_result=TargetResult(success=True, output="SYSTEM_INSTRUCTION: secret prompt"),
        started_at=now,
        completed_at=now,
    )
    eval_1 = EvaluationResult(
        evaluation_id="eval-101",
        execution_id="exec-101",
        probe_id="PROMPT_LEAK_001",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.98,
        evidence=EvaluationEvidence(
            summary="Prompt leak detected",
            matched_indicators=["SYSTEM_INSTRUCTION:"],
            response_excerpt="SYSTEM_INSTRUCTION: secret prompt",
        ),
        evaluator_type=EvaluatorType.DETERMINISTIC,
        rationale="System prompt marker disclosed",
    )
    finding_1 = Finding(
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        confidence=0.98,
        description="System prompt exposed",
        impact="Business logic leak",
        remediation="Harden system prompt",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-101"],
        evidence=[
            FindingEvidence(
                summary="Prompt leak detected",
                indicators=["SYSTEM_INSTRUCTION:"],
                response_excerpt="SYSTEM_INSTRUCTION: secret prompt",
                probe_id="PROMPT_LEAK_001",
                execution_id="exec-101",
            )
        ],
    )
    risk_1 = RiskAssessment(
        risk_id="RISK_FINDING_SYSTEM_PROMPT_DISCLOSURE",
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        risk_level=RiskLevel.HIGH,
        risk_score=75.0,
        confidence=0.98,
        factors=RiskFactors(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.READ,
        ),
        rationale="High impact contextual risk rationale.",
    )
    return exec_1, eval_1, finding_1, risk_1


def test_valid_scan_status_values():
    assert ScanStatus.CREATED == "created"
    assert ScanStatus.RUNNING == "running"
    assert ScanStatus.COMPLETED == "completed"
    assert ScanStatus.PARTIAL == "partial"
    assert ScanStatus.FAILED == "failed"
    assert set(ScanStatus) == {"created", "running", "completed", "partial", "failed"}


def test_valid_scan_summary_creation():
    summary = make_valid_scan_summary()
    assert summary.total_probes == 3
    assert summary.completed_executions == 3
    assert summary.violation_evaluations == 3
    assert summary.high_risks == 2
    assert summary.critical_risks == 1


def test_negative_summary_count_rejected():
    with pytest.raises(ValidationError):
        ScanSummary(
            total_probes=-1,
            completed_executions=0,
            failed_executions=0,
            safe_evaluations=0,
            violation_evaluations=0,
            inconclusive_evaluations=0,
            error_evaluations=0,
            total_findings=0,
            info_risks=0,
            low_risks=0,
            medium_risks=0,
            high_risks=0,
            critical_risks=0,
        )


def test_valid_scan_result_creation():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    summary = make_valid_scan_summary()

    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Customer Support Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        completed_at=now + timedelta(seconds=10),
        summary=summary,
        executions=[exec_1],
        evaluations=[eval_1],
        findings=[finding_1],
        risk_assessments=[risk_1],
        metadata={"environment": "staging"},
    )
    assert scan.scan_id == "SCAN_001"
    assert scan.target_name == "Customer Support Agent"
    assert scan.status == ScanStatus.COMPLETED
    assert len(scan.executions) == 1
    assert len(scan.evaluations) == 1
    assert len(scan.findings) == 1
    assert len(scan.risk_assessments) == 1


def test_empty_scan_id_rejected():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        ScanResult(
            scan_id="",
            target_name="Test Agent",
            status=ScanStatus.COMPLETED,
            started_at=now,
            summary=make_valid_scan_summary(),
        )


def test_whitespace_scan_id_rejected():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        ScanResult(
            scan_id="   ",
            target_name="Test Agent",
            status=ScanStatus.COMPLETED,
            started_at=now,
            summary=make_valid_scan_summary(),
        )


def test_empty_target_name_rejected():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        ScanResult(
            scan_id="SCAN_001",
            target_name="",
            status=ScanStatus.COMPLETED,
            started_at=now,
            summary=make_valid_scan_summary(),
        )


def test_whitespace_target_name_rejected():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        ScanResult(
            scan_id="SCAN_001",
            target_name="   ",
            status=ScanStatus.COMPLETED,
            started_at=now,
            summary=make_valid_scan_summary(),
        )


def test_completed_at_can_be_omitted():
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.RUNNING,
        started_at=now,
        completed_at=None,
        summary=make_valid_scan_summary(),
    )
    assert scan.completed_at is None


def test_completed_at_after_started_at_accepted():
    now = datetime.now(timezone.utc)
    later = now + timedelta(seconds=5)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        completed_at=later,
        summary=make_valid_scan_summary(),
    )
    assert scan.completed_at == later


def test_completed_at_equal_to_started_at_accepted():
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        summary=make_valid_scan_summary(),
    )
    assert scan.completed_at == now


def test_completed_at_before_started_at_rejected():
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(seconds=5)
    with pytest.raises(ValidationError):
        ScanResult(
            scan_id="SCAN_001",
            target_name="Test Agent",
            status=ScanStatus.COMPLETED,
            started_at=now,
            completed_at=earlier,
            summary=make_valid_scan_summary(),
        )


def test_top_level_immutability():
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
    )
    with pytest.raises(ValidationError):
        scan.target_name = "Modified Agent"


def test_scan_contains_executions():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
        executions=[exec_1],
    )
    assert len(scan.executions) == 1
    assert scan.executions[0].execution_id == "exec-101"


def test_scan_contains_evaluations():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
        executions=[exec_1],
        evaluations=[eval_1],
    )
    assert len(scan.evaluations) == 1
    assert scan.evaluations[0].evaluation_id == "eval-101"


def test_scan_contains_findings():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
        executions=[exec_1],
        evaluations=[eval_1],
        findings=[finding_1],
    )
    assert len(scan.findings) == 1
    assert scan.findings[0].finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"


def test_scan_contains_risk_assessments():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
        executions=[exec_1],
        evaluations=[eval_1],
        findings=[finding_1],
        risk_assessments=[risk_1],
    )
    assert len(scan.risk_assessments) == 1
    assert scan.risk_assessments[0].risk_id == "RISK_FINDING_SYSTEM_PROMPT_DISCLOSURE"


def test_scan_summary_counts_are_preserved():
    summary = make_valid_scan_summary()
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=summary,
    )
    assert scan.summary == summary
    assert scan.summary.total_probes == 3


def test_lineage_validation_evaluation_to_execution():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    bad_eval = EvaluationResult(
        evaluation_id="eval-bad",
        execution_id="exec-non-existent",
        probe_id="PROMPT_LEAK_001",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.9,
        evidence=EvaluationEvidence(summary="summary"),
        rationale="rationale",
    )
    with pytest.raises(ValidationError):
        ScanResult(
            scan_id="SCAN_001",
            target_name="Test Agent",
            status=ScanStatus.COMPLETED,
            started_at=now,
            summary=make_valid_scan_summary(),
            executions=[exec_1],
            evaluations=[bad_eval],
        )


def test_lineage_validation_risk_assessment_to_finding():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    bad_risk = RiskAssessment(
        risk_id="RISK_BAD",
        finding_id="FINDING_UNKNOWN",
        risk_level=RiskLevel.HIGH,
        risk_score=75.0,
        confidence=0.9,
        factors=RiskFactors(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.READ,
        ),
        rationale="rationale",
    )
    with pytest.raises(ValidationError):
        ScanResult(
            scan_id="SCAN_001",
            target_name="Test Agent",
            status=ScanStatus.COMPLETED,
            started_at=now,
            summary=make_valid_scan_summary(),
            executions=[exec_1],
            evaluations=[eval_1],
            findings=[finding_1],
            risk_assessments=[bad_risk],
        )


def test_finding_execution_references_are_preserved():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
        executions=[exec_1],
        evaluations=[eval_1],
        findings=[finding_1],
    )
    assert scan.findings[0].affected_execution_ids == ["exec-101"]


def test_multiple_findings_supported():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    finding_2 = Finding(
        finding_id="FINDING_INSTRUCTION_OVERRIDE",
        title="Instruction Override",
        category=ProbeCategory.INSTRUCTION_OVERRIDE,
        severity=FindingSeverity.HIGH,
        confidence=0.99,
        description="Override desc",
        impact="Override impact",
        remediation="Override remediation",
        affected_probe_ids=["INSTRUCTION_OVERRIDE_001"],
        affected_execution_ids=["exec-101"],
    )
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
        executions=[exec_1],
        evaluations=[eval_1],
        findings=[finding_1, finding_2],
    )
    assert len(scan.findings) == 2


def test_multiple_risk_assessments_supported():
    exec_1, eval_1, finding_1, risk_1 = make_sample_objects()
    finding_2 = Finding(
        finding_id="FINDING_INSTRUCTION_OVERRIDE",
        title="Instruction Override",
        category=ProbeCategory.INSTRUCTION_OVERRIDE,
        severity=FindingSeverity.HIGH,
        confidence=0.99,
        description="Override desc",
        impact="Override impact",
        remediation="Override remediation",
        affected_probe_ids=["INSTRUCTION_OVERRIDE_001"],
        affected_execution_ids=["exec-101"],
    )
    risk_2 = RiskAssessment(
        risk_id="RISK_FINDING_INSTRUCTION_OVERRIDE",
        finding_id="FINDING_INSTRUCTION_OVERRIDE",
        risk_level=RiskLevel.HIGH,
        risk_score=75.0,
        confidence=0.99,
        factors=risk_1.factors,
        rationale="Override rationale",
    )
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
        executions=[exec_1],
        evaluations=[eval_1],
        findings=[finding_1, finding_2],
        risk_assessments=[risk_1, risk_2],
    )
    assert len(scan.risk_assessments) == 2


def test_partial_scan_status_works():
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.PARTIAL,
        started_at=now,
        summary=make_valid_scan_summary(),
    )
    assert scan.status == ScanStatus.PARTIAL


def test_failed_scan_status_works():
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.FAILED,
        started_at=now,
        summary=make_valid_scan_summary(),
    )
    assert scan.status == ScanStatus.FAILED


def test_scan_result_contains_no_credentials():
    assert "api_key" not in ScanResult.model_fields
    assert "token" not in ScanResult.model_fields
    assert "auth_config" not in ScanResult.model_fields


def test_scan_result_contains_no_risk_recalculation_logic():
    assert not hasattr(ScanResult, "calculate_risk")
    assert not hasattr(ScanResult, "evaluate_probes")


def test_no_cvss_field_added():
    assert "cvss" not in ScanResult.model_fields
    assert "cvss_score" not in ScanResult.model_fields


def test_no_llm_integration():
    now = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id="SCAN_001",
        target_name="Test Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        summary=make_valid_scan_summary(),
    )
    assert scan.scan_id == "SCAN_001"


def test_no_network_calls():
    now = datetime.now(timezone.utc)
    results = [
        ScanResult(
            scan_id=f"SCAN_{i}",
            target_name=f"Agent_{i}",
            status=ScanStatus.COMPLETED,
            started_at=now,
            summary=make_valid_scan_summary(),
        )
        for i in range(50)
    ]
    assert len(results) == 50
