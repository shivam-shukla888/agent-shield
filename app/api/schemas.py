"""
AgentShield API Contract Layer (DTO Schemas & Conversions)

This module defines public API Request and Response Data Transfer Objects (DTOs)
and deterministic conversion functions mapping between API DTOs and internal domain models.

ARCHITECTURAL DIRECTIVES:
1. Clean separation: External API DTOs are separate from internal domain models.
2. Public responses (ScanResponse) are SAFE BY DEFAULT: They MUST NOT expose raw target outputs,
   raw HTTP headers, internal adapter metadata, API keys, bearer tokens, or TargetAuthConfig.
3. Syntactic validation for target endpoints (http/https scheme and non-empty hostname).
4. No business logic or external network calls inside schema validators or conversion functions.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.finding import FindingEvidence, FindingSeverity, FindingStatus
from app.domain.probe import ProbeCategory
from app.domain.risk import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    ImpactLevel,
    RiskAssessment,
    RiskFactors,
    RiskLevel,
    ToolPrivilege,
)
from app.domain.scan import ScanResult, ScanStatus
from app.domain.target import TargetConfig


# ============================================================================
# PUBLIC REQUEST SCHEMAS (DTOs)
# ============================================================================


class TargetScanRequest(BaseModel):
    """
    Public DTO representing a target agent scan request configuration.
    """

    model_config = ConfigDict(frozen=True)

    target_name: str = Field(..., description="Non-empty descriptive name of the target agent")
    endpoint: str = Field(..., description="Non-empty target HTTP/HTTPS endpoint URL")
    method: str = Field(default="POST", description="HTTP method (e.g. POST, GET)")
    headers: Dict[str, str] = Field(default_factory=dict, description="Optional request HTTP headers")
    request_template: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional JSON request payload template"
    )
    response_path: Optional[str] = Field(
        default=None, description="Optional JSONPath key path for target response extraction"
    )
    timeout_seconds: float = Field(
        default=30.0, description="HTTP request timeout in seconds (0.0 < timeout <= 300.0)"
    )

    @field_validator("target_name")
    @classmethod
    def validate_target_name(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("target_name must be a non-empty string")
        return stripped

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint_url(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("endpoint must be a non-empty string")

        parsed = urlparse(stripped)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("endpoint must use http or https URL scheme")
        if not parsed.netloc:
            raise ValueError("endpoint must contain a valid hostname")

        return stripped

    @field_validator("method")
    @classmethod
    def validate_and_normalize_method(cls, v: str) -> str:
        stripped = v.strip().upper()
        if not stripped:
            raise ValueError("method must be a non-empty string")
        return stripped

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if v <= 0.0:
            raise ValueError("timeout_seconds must be greater than 0")
        if v > 300.0:
            raise ValueError("timeout_seconds must not exceed 300.0 seconds")
        return v


class ProbeSelectionRequest(BaseModel):
    """
    Public DTO representing selection of security probes to execute.
    """

    model_config = ConfigDict(frozen=True)

    probe_ids: List[str] = Field(..., description="Non-empty list of unique probe identifiers")

    @field_validator("probe_ids")
    @classmethod
    def validate_probe_ids(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("probe_ids list must not be empty")

        cleaned_ids: List[str] = []
        seen = set()
        for probe_id in v:
            stripped = probe_id.strip()
            if not stripped:
                raise ValueError("probe_id must not be empty or whitespace-only")
            if stripped in seen:
                raise ValueError(f"Duplicate probe_id '{stripped}' is not allowed in ProbeSelectionRequest")
            seen.add(stripped)
            cleaned_ids.append(stripped)

        return cleaned_ids


class RiskContextRequest(BaseModel):
    """
    Public DTO representing caller-supplied environmental risk factors.
    """

    model_config = ConfigDict(frozen=True)

    impact: ImpactLevel = Field(..., description="Target business impact level")
    exploitability: ExploitabilityLevel = Field(..., description="Vulnerability exploitability level")
    blast_radius: BlastRadiusLevel = Field(..., description="Target blast radius scope")
    asset_sensitivity: AssetSensitivity = Field(..., description="Data/asset sensitivity classification")
    tool_privilege: ToolPrivilege = Field(..., description="Highest tool privilege granted to agent")


class ScanRequest(BaseModel):
    """
    Unified public request object initiating an AgentShield security scan.
    """

    model_config = ConfigDict(frozen=True)

    scan_id: Optional[str] = Field(default=None, description="Optional custom scan identifier")
    target: TargetScanRequest = Field(..., description="Target agent scan configuration")
    probes: ProbeSelectionRequest = Field(..., description="Selection of security probes to execute")
    risk_context: RiskContextRequest = Field(..., description="Caller-supplied environmental risk factors")

    @field_validator("scan_id")
    @classmethod
    def validate_optional_scan_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            raise ValueError("scan_id must not be empty or whitespace-only when provided")
        return stripped


# ============================================================================
# PUBLIC RESPONSE SCHEMAS (DTOs)
# ============================================================================


class ScanSummaryResponse(BaseModel):
    """
    Public DTO for scan summary statistics.
    """

    model_config = ConfigDict(frozen=True)

    total_probes: int
    completed_executions: int
    failed_executions: int

    safe_evaluations: int
    violation_evaluations: int
    inconclusive_evaluations: int
    error_evaluations: int

    total_findings: int

    info_risks: int
    low_risks: int
    medium_risks: int
    high_risks: int
    critical_risks: int


class ScanFindingResponse(BaseModel):
    """
    Public DTO for a confirmed security finding.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str
    title: str
    category: ProbeCategory
    severity: FindingSeverity
    status: FindingStatus
    confidence: float
    description: str
    impact: str
    remediation: str
    affected_probe_ids: List[str]
    affected_execution_ids: List[str]
    evidence: List[FindingEvidence]


class ScanRiskResponse(BaseModel):
    """
    Public DTO for a contextual risk assessment.
    """

    model_config = ConfigDict(frozen=True)

    risk_id: str
    finding_id: str
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    factors: RiskFactors
    rationale: str


class ScanResponse(BaseModel):
    """
    Unified public response object returned to external API clients.
    """

    model_config = ConfigDict(frozen=True)

    scan_id: str
    target_name: str
    status: ScanStatus

    started_at: datetime
    completed_at: Optional[datetime] = None

    summary: ScanSummaryResponse
    findings: List[ScanFindingResponse]
    risk_assessments: List[ScanRiskResponse]


# ============================================================================
# EXPLICIT DETERMINISTIC CONVERSION FUNCTIONS
# ============================================================================


def scan_request_to_target_config(request: TargetScanRequest) -> TargetConfig:
    """
    Convert a public TargetScanRequest DTO into an internal TargetConfig model.
    """
    return TargetConfig(
        name=request.target_name,
        endpoint=request.endpoint,
        request_template=request.request_template,
        response_path=request.response_path,
        timeout_seconds=request.timeout_seconds,
    )


def risk_context_request_to_risk_factors(request: RiskContextRequest) -> RiskFactors:
    """
    Convert a public RiskContextRequest DTO into internal RiskFactors domain model.
    """
    return RiskFactors(
        impact=request.impact,
        exploitability=request.exploitability,
        blast_radius=request.blast_radius,
        asset_sensitivity=request.asset_sensitivity,
        tool_privilege=request.tool_privilege,
    )


def scan_result_to_response(scan_result: ScanResult) -> ScanResponse:
    """
    Convert an internal ScanResult into a public ScanResponse DTO.

    SECURITY INVARIANT:
    Excludes execution raw_response, target HTTP headers, internal adapter metadata,
    and credentials.
    """
    summary_resp = ScanSummaryResponse(
        total_probes=scan_result.summary.total_probes,
        completed_executions=scan_result.summary.completed_executions,
        failed_executions=scan_result.summary.failed_executions,
        safe_evaluations=scan_result.summary.safe_evaluations,
        violation_evaluations=scan_result.summary.violation_evaluations,
        inconclusive_evaluations=scan_result.summary.inconclusive_evaluations,
        error_evaluations=scan_result.summary.error_evaluations,
        total_findings=scan_result.summary.total_findings,
        info_risks=scan_result.summary.info_risks,
        low_risks=scan_result.summary.low_risks,
        medium_risks=scan_result.summary.medium_risks,
        high_risks=scan_result.summary.high_risks,
        critical_risks=scan_result.summary.critical_risks,
    )

    finding_resps = [
        ScanFindingResponse(
            finding_id=f.finding_id,
            title=f.title,
            category=f.category,
            severity=f.severity,
            status=f.status,
            confidence=f.confidence,
            description=f.description,
            impact=f.impact,
            remediation=f.remediation,
            affected_probe_ids=list(f.affected_probe_ids),
            affected_execution_ids=list(f.affected_execution_ids),
            evidence=list(f.evidence),
        )
        for f in scan_result.findings
    ]

    risk_resps = [
        ScanRiskResponse(
            risk_id=r.risk_id,
            finding_id=r.finding_id,
            risk_level=r.risk_level,
            risk_score=r.risk_score,
            confidence=r.confidence,
            factors=r.factors,
            rationale=r.rationale,
        )
        for r in scan_result.risk_assessments
    ]

    return ScanResponse(
        scan_id=scan_result.scan_id,
        target_name=scan_result.target_name,
        status=scan_result.status,
        started_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        summary=summary_resp,
        findings=finding_resps,
        risk_assessments=risk_resps,
    )
