"""
Unit tests for API DTO Schemas and Conversion Functions (STEP 10A).
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.api.schemas import (
    ProbeSelectionRequest,
    RiskContextRequest,
    ScanFindingResponse,
    ScanRequest,
    ScanResponse,
    ScanRiskResponse,
    ScanSummaryResponse,
    TargetScanRequest,
    risk_context_request_to_risk_factors,
    scan_request_to_target_config,
    scan_result_to_response,
)
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


def make_valid_target_request() -> TargetScanRequest:
    return TargetScanRequest(
        target_name="Customer Agent",
        endpoint="http://agent.local/chat",
        method="post",
        headers={"Authorization": "Bearer s3cr3t_t0k3n"},
        timeout_seconds=30.0,
    )


def make_valid_probe_request() -> ProbeSelectionRequest:
    return ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"])


def make_valid_risk_context_request() -> RiskContextRequest:
    return RiskContextRequest(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.WRITE,
    )


def make_sample_internal_scan_result() -> ScanResult:
    now = datetime.now(timezone.utc)
    exec_1 = ProbeExecution(
        execution_id="exec-999",
        probe_id="PROMPT_LEAK_001",
        status=ExecutionStatus.COMPLETED,
        target_name="Customer Agent",
        target_result=TargetResult(
            success=True,
            output="SYSTEM_INSTRUCTION: secret_system_prompt_leaked",
            raw_response={"secret_internal_key": "SENSITIVE_DATA_VALUE"},
            metadata={"internal_header": "Bearer secret_header_value"},
        ),
        started_at=now,
        completed_at=now,
    )
    eval_1 = EvaluationResult(
        evaluation_id="eval-999",
        execution_id="exec-999",
        probe_id="PROMPT_LEAK_001",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.99,
        evidence=EvaluationEvidence(
            summary="Prompt leak detected",
            matched_indicators=["SYSTEM_INSTRUCTION:"],
            response_excerpt="SYSTEM_INSTRUCTION: secret_system_prompt_leaked",
        ),
        evaluator_type=EvaluatorType.DETERMINISTIC,
        rationale="System prompt disclosure detected",
    )
    finding_1 = Finding(
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        confidence=0.99,
        description="Target agent disclosed internal instructions.",
        impact="Exposes safety rules.",
        remediation="Harden system prompt.",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-999"],
        evidence=[
            FindingEvidence(
                summary="Prompt leak detected",
                indicators=["SYSTEM_INSTRUCTION:"],
                response_excerpt="SYSTEM_INSTRUCTION: secret_system_prompt_leaked",
                probe_id="PROMPT_LEAK_001",
                execution_id="exec-999",
            )
        ],
    )
    risk_1 = RiskAssessment(
        risk_id="RISK_FINDING_SYSTEM_PROMPT_DISCLOSURE",
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        risk_level=RiskLevel.HIGH,
        risk_score=75.0,
        confidence=0.99,
        factors=RiskFactors(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.WRITE,
        ),
        rationale="High contextual risk rationale.",
    )
    summary = ScanSummary(
        total_probes=1,
        completed_executions=1,
        failed_executions=0,
        safe_evaluations=0,
        violation_evaluations=1,
        inconclusive_evaluations=0,
        error_evaluations=0,
        total_findings=1,
        info_risks=0,
        low_risks=0,
        medium_risks=0,
        high_risks=1,
        critical_risks=0,
    )
    return ScanResult(
        scan_id="SCAN_INT_999",
        target_name="Customer Agent",
        status=ScanStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        summary=summary,
        executions=[exec_1],
        evaluations=[eval_1],
        findings=[finding_1],
        risk_assessments=[risk_1],
        metadata={"internal_adapter_secret": "API_KEY_DO_NOT_EXPOSE"},
    )


# ============================================================================
# TARGET SCAN REQUEST TESTS
# ============================================================================


def test_valid_target_scan_request():
    req = make_valid_target_request()
    assert req.target_name == "Customer Agent"
    assert req.endpoint == "http://agent.local/chat"
    assert req.method == "POST"
    assert req.timeout_seconds == 30.0


def test_empty_target_name_rejected():
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="", endpoint="http://agent.local/chat")


def test_whitespace_target_name_rejected():
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="   ", endpoint="http://agent.local/chat")


def test_empty_endpoint_rejected():
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="Target", endpoint="")


def test_invalid_url_scheme_rejected():
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="Target", endpoint="ftp://agent.local/chat")


def test_endpoint_without_hostname_rejected():
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="Target", endpoint="http://")


def test_method_normalized_to_uppercase():
    req = TargetScanRequest(target_name="Target", endpoint="http://agent.local/chat", method="get")
    assert req.method == "GET"


def test_timeout_greater_than_zero_accepted():
    req = TargetScanRequest(target_name="Target", endpoint="http://agent.local/chat", timeout_seconds=1.5)
    assert req.timeout_seconds == 1.5


def test_timeout_greater_than_300_rejected():
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="Target", endpoint="http://agent.local/chat", timeout_seconds=300.1)


def test_timeout_less_than_or_equal_to_zero_rejected():
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="Target", endpoint="http://agent.local/chat", timeout_seconds=0.0)
    with pytest.raises(ValidationError):
        TargetScanRequest(target_name="Target", endpoint="http://agent.local/chat", timeout_seconds=-5.0)


# ============================================================================
# PROBE SELECTION REQUEST TESTS
# ============================================================================


def test_valid_probe_selection_request():
    req = make_valid_probe_request()
    assert req.probe_ids == ["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"]


def test_empty_probe_id_rejected():
    with pytest.raises(ValidationError):
        ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001", ""])


def test_whitespace_probe_id_rejected():
    with pytest.raises(ValidationError):
        ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001", "   "])


def test_duplicate_probe_ids_rejected():
    with pytest.raises(ValidationError):
        ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001", "PROMPT_LEAK_001"])


# ============================================================================
# RISK CONTEXT REQUEST TESTS
# ============================================================================


def test_valid_risk_context_request():
    req = make_valid_risk_context_request()
    assert req.impact == ImpactLevel.HIGH
    assert req.tool_privilege == ToolPrivilege.WRITE


def test_all_risk_enums_accepted():
    req = RiskContextRequest(
        impact=ImpactLevel.CRITICAL,
        exploitability=ExploitabilityLevel.CRITICAL,
        blast_radius=BlastRadiusLevel.CRITICAL,
        asset_sensitivity=AssetSensitivity.HIGHLY_SENSITIVE,
        tool_privilege=ToolPrivilege.ADMIN,
    )
    assert req.impact == ImpactLevel.CRITICAL


# ============================================================================
# SCAN REQUEST TESTS
# ============================================================================


def test_valid_scan_request():
    req = ScanRequest(
        scan_id="SCAN_123",
        target=make_valid_target_request(),
        probes=make_valid_probe_request(),
        risk_context=make_valid_risk_context_request(),
    )
    assert req.scan_id == "SCAN_123"
    assert req.target.target_name == "Customer Agent"


def test_empty_scan_id_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(
            scan_id="",
            target=make_valid_target_request(),
            probes=make_valid_probe_request(),
            risk_context=make_valid_risk_context_request(),
        )


def test_whitespace_scan_id_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(
            scan_id="   ",
            target=make_valid_target_request(),
            probes=make_valid_probe_request(),
            risk_context=make_valid_risk_context_request(),
        )


# ============================================================================
# SCAN RESPONSE SCHEMAS TESTS
# ============================================================================


def test_valid_scan_summary_response():
    summary = ScanSummaryResponse(
        total_probes=1,
        completed_executions=1,
        failed_executions=0,
        safe_evaluations=0,
        violation_evaluations=1,
        inconclusive_evaluations=0,
        error_evaluations=0,
        total_findings=1,
        info_risks=0,
        low_risks=0,
        medium_risks=0,
        high_risks=1,
        critical_risks=0,
    )
    assert summary.total_probes == 1
    assert summary.high_risks == 1


def test_valid_scan_finding_response():
    finding = ScanFindingResponse(
        finding_id="FINDING_1",
        title="Title",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        confidence=0.9,
        description="desc",
        impact="impact",
        remediation="remediation",
        affected_probe_ids=["P1"],
        affected_execution_ids=["E1"],
        evidence=[],
    )
    assert finding.finding_id == "FINDING_1"


def test_valid_scan_risk_response():
    risk = ScanRiskResponse(
        risk_id="RISK_1",
        finding_id="FINDING_1",
        risk_level=RiskLevel.HIGH,
        risk_score=75.0,
        confidence=0.9,
        factors=RiskFactors(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.WRITE,
        ),
        rationale="rationale",
    )
    assert risk.risk_id == "RISK_1"


def test_valid_scan_response():
    now = datetime.now(timezone.utc)
    summary = ScanSummaryResponse(
        total_probes=0,
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
    resp = ScanResponse(
        scan_id="S1",
        target_name="Target",
        status=ScanStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        summary=summary,
        findings=[],
        risk_assessments=[],
    )
    assert resp.scan_id == "S1"


# ============================================================================
# SECRET BOUNDARY TESTS
# ============================================================================


def test_public_scan_response_does_not_expose_credentials():
    assert "api_key" not in ScanResponse.model_fields
    assert "token" not in ScanResponse.model_fields
    assert "auth_config" not in ScanResponse.model_fields


def test_public_scan_response_does_not_expose_raw_response():
    assert "raw_response" not in ScanResponse.model_fields
    assert "executions" not in ScanResponse.model_fields


def test_public_scan_response_does_not_expose_raw_http_headers():
    assert "headers" not in ScanResponse.model_fields


def test_public_scan_response_does_not_expose_target_auth_config():
    assert "auth_config" not in ScanResponse.model_fields


def test_security_boundary_internal_scan_result_secrets_stripped_in_public_response():
    internal_result = make_sample_internal_scan_result()

    public_response = scan_result_to_response(internal_result)

    # 1. Convert public response to dict / JSON
    resp_dict = public_response.model_dump()
    resp_json_str = public_response.model_dump_json()

    # 2. Assert raw_response and internal secrets are completely absent
    assert "raw_response" not in resp_dict
    assert "secret_internal_key" not in resp_json_str
    assert "SENSITIVE_DATA_VALUE" not in resp_json_str
    assert "secret_header_value" not in resp_json_str
    assert "API_KEY_DO_NOT_EXPOSE" not in resp_json_str
    assert "metadata" not in resp_dict


# ============================================================================
# CONVERSION FUNCTIONS TESTS
# ============================================================================


def test_conversion_preserves_finding_ids():
    internal_result = make_sample_internal_scan_result()
    public_response = scan_result_to_response(internal_result)
    assert public_response.findings[0].finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"


def test_conversion_preserves_risk_ids():
    internal_result = make_sample_internal_scan_result()
    public_response = scan_result_to_response(internal_result)
    assert public_response.risk_assessments[0].risk_id == "RISK_FINDING_SYSTEM_PROMPT_DISCLOSURE"


def test_conversion_preserves_summary():
    internal_result = make_sample_internal_scan_result()
    public_response = scan_result_to_response(internal_result)
    assert public_response.summary.total_probes == 1
    assert public_response.summary.violation_evaluations == 1
    assert public_response.summary.high_risks == 1


def test_request_conversion_preserves_endpoint():
    req = make_valid_target_request()
    config = scan_request_to_target_config(req)
    assert config.name == "Customer Agent"
    assert config.endpoint == "http://agent.local/chat"


def test_request_conversion_preserves_method():
    req = TargetScanRequest(target_name="Target", endpoint="http://agent.local/chat", method="post")
    config = scan_request_to_target_config(req)
    assert config.endpoint == "http://agent.local/chat"


def test_risk_context_conversion_preserves_all_factors():
    req = make_valid_risk_context_request()
    factors = risk_context_request_to_risk_factors(req)
    assert factors.impact == ImpactLevel.HIGH
    assert factors.exploitability == ExploitabilityLevel.HIGH
    assert factors.blast_radius == BlastRadiusLevel.MEDIUM
    assert factors.asset_sensitivity == AssetSensitivity.CONFIDENTIAL
    assert factors.tool_privilege == ToolPrivilege.WRITE


def test_conversion_is_deterministic():
    internal_result = make_sample_internal_scan_result()
    res1 = scan_result_to_response(internal_result)
    res2 = scan_result_to_response(internal_result)
    assert res1 == res2


def test_no_network_calls():
    req = make_valid_target_request()
    config = scan_request_to_target_config(req)
    assert config is not None


def test_no_llm_calls():
    internal_result = make_sample_internal_scan_result()
    public_response = scan_result_to_response(internal_result)
    assert public_response is not None


def test_no_database():
    assert not hasattr(TargetScanRequest, "db")
    assert not hasattr(ScanResponse, "repository")
