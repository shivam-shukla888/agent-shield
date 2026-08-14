"""
Unit tests for ReportEngine (STEP 16A).
"""

from datetime import datetime, timezone
import pytest

from app.api.schemas import (
    ScanFindingResponse,
    ScanResponse,
    ScanRiskResponse,
    ScanSummaryResponse,
)
from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    ImpactLevel,
    ProbeCategory,
    RiskAssessment,
    RiskFactors,
    RiskLevel,
    ScanResult,
    ScanStatus,
    ScanSummary,
    ToolPrivilege,
)
from app.engine.report import ReportEngine


def make_dummy_scan_result() -> ScanResult:
    finding = Finding(
        finding_id="FIND_SYS_01",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        title="System Prompt Leakage",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.CONFIRMED,
        confidence=0.95,
        description="Leaked system instructions",
        impact="Full prompt extraction",
        remediation="Isolate prompt context",
        affected_probe_ids=["PROBE_SYS_01"],
        affected_execution_ids=["EXEC_SYS_01"],
        evidence=[FindingEvidence(probe_id="PROBE_SYS_01", execution_id="EXEC_SYS_01", summary="Prompt revealed")],
    )

    factors = RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.READ,
    )

    risk1 = RiskAssessment(
        risk_id="RISK_SYS_01",
        finding_id="FIND_SYS_01",
        risk_level=RiskLevel.HIGH,
        risk_score=75.0,
        confidence=0.95,
        factors=factors,
        rationale="High impact prompt leakage",
    )

    risk2 = RiskAssessment(
        risk_id="RISK_SYS_02",
        finding_id="FIND_SYS_01",
        risk_level=RiskLevel.CRITICAL,
        risk_score=90.0,
        confidence=0.95,
        factors=factors,
        rationale="Critical risk prompt leakage",
    )

    summary = ScanSummary(
        total_probes=2,
        completed_executions=2,
        failed_executions=0,
        safe_evaluations=0,
        violation_evaluations=2,
        inconclusive_evaluations=0,
        error_evaluations=0,
        total_findings=1,
        info_risks=0,
        low_risks=0,
        medium_risks=0,
        high_risks=1,
        critical_risks=1,
    )

    return ScanResult(
        scan_id="SCAN_TEST_001",
        target_name="Production Agent",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        summary=summary,
        findings=[finding],
        risk_assessments=[risk1, risk2],
    )


def test_scan_result_converts_to_security_report():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    assert report.scan_id == "SCAN_TEST_001"
    assert report.report_id == "REPORT_SCAN_TEST_001"
    assert report.target_name == "Production Agent"
    assert report.status == "completed"
    assert len(report.findings) == 1
    assert len(report.risk_assessments) == 2


def test_executive_summary_generated():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    assert "Production Agent" in report.executive_summary
    assert "CRITICAL" in report.executive_summary
    assert "90.00" in report.executive_summary


def test_finding_conversion_works():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    f = report.findings[0]
    assert f.finding_id == "FIND_SYS_01"
    assert f.category == "system_prompt_disclosure"
    assert f.severity == "high"
    assert f.confidence == 0.95


def test_risk_conversion_works():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    assert len(report.risk_assessments) == 2
    r0 = report.risk_assessments[0]
    assert r0.risk_id == "RISK_SYS_02"  # Sorted higher risk score first
    assert r0.risk_score == 90.0


def test_recommendations_generated_and_deduplicated():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    assert len(report.recommendations) == 1
    assert "system prompt isolation" in report.recommendations[0].lower()


def test_risk_ordering_deterministic():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    scores = [r.risk_score for r in report.risk_assessments]
    assert scores == sorted(scores, reverse=True)


def test_report_id_deterministic():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    r1 = engine.create_report(result)
    r2 = engine.create_report(result)
    assert r1.report_id == r2.report_id == "REPORT_SCAN_TEST_001"


def test_same_input_produces_same_report():
    engine = ReportEngine()
    result = make_dummy_scan_result()
    t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    r1 = engine.create_report(result, generated_at=t)
    r2 = engine.create_report(result, generated_at=t)

    assert engine.render_markdown(r1) == engine.render_markdown(r2)
    assert engine.render_json(r1) == engine.render_json(r2)


def test_no_risk_recalculation():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    # The risk score matches the input score without recalculation
    assert report.risk_assessments[0].risk_score == 90.0
    assert report.risk_assessments[1].risk_score == 75.0


def test_markdown_and_json_rendering():
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    md = engine.render_markdown(report)
    js = engine.render_json(report)

    assert "# AgentShield Security Report" in md
    assert "Production Agent" in md
    assert '"report_id": "REPORT_SCAN_TEST_001"' in js


def test_security_sanitization_in_reports():
    secret_key = "sk-proj-SUPER_SECRET_KEY_12345"
    engine = ReportEngine()
    result = make_dummy_scan_result()

    report = engine.create_report(result)
    md = engine.render_markdown(report)
    js = engine.render_json(report)

    assert secret_key not in md
    assert secret_key not in js
    assert "Authorization" not in md
    assert "X-API-Key" not in md
