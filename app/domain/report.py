"""
Report Domain Models (STEP 16A)

This module defines strongly typed, immutable domain models representing security reports,
reporting finding summaries, reporting risk summaries, and report generation formats.

ARCHITECTURAL DIRECTIVES:
1. Top-level models use `model_config = ConfigDict(frozen=True)` for strict immutability.
2. Identifiers (`report_id`, `scan_id`, `target_name`) must be non-empty strings.
3. `confidence` is strictly bounded within [0.0, 1.0].
4. `risk_score` is strictly bounded within [0.0, 100.0].
5. Contains NO credentials, API keys, bearer tokens, target response bodies, or raw HTTP headers.
6. Does NOT include CVSS metrics.
"""

from datetime import datetime

from enum import StrEnum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReportFormat(StrEnum):
    """Supported output formats for security report rendering."""
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


class ReportFinding(BaseModel):
    """
    Public sanitized report DTO representing a confirmed security finding.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(..., description="Non-empty unique finding identifier")
    category: str = Field(..., description="Vulnerability probe category identifier")
    title: str = Field(..., description="Human-readable finding title")
    severity: str = Field(..., description="Finding severity classification (info, low, medium, high, critical)")
    confidence: float = Field(..., description="Verdict confidence score bounded in [0.0, 1.0]")
    description: str = Field(..., description="Detailed description of the security vulnerability")
    evidence: Optional[str] = Field(default=None, description="Bounded evidence summary excerpt")
    affected_probe_ids: List[str] = Field(default_factory=list, description="List of probe IDs contributing to finding")
    affected_execution_ids: List[str] = Field(default_factory=list, description="List of execution IDs associated with finding")
    remediation: str = Field(..., description="Actionable remediation guidance")

    @field_validator("finding_id", "category", "title", "severity")
    @classmethod
    def validate_non_empty_str(cls, v: str, info: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return v.strip()

    @field_validator("confidence")
    @classmethod
    def validate_confidence_bounds(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("confidence must be bounded within [0.0, 1.0]")
        return float(v)


class ReportRisk(BaseModel):
    """
    Public sanitized report DTO representing a contextual risk assessment.
    """

    model_config = ConfigDict(frozen=True)

    risk_id: str = Field(..., description="Non-empty unique risk assessment identifier")
    finding_id: str = Field(..., description="Associated finding identifier")
    risk_level: str = Field(..., description="Calculated contextual risk level (info, low, medium, high, critical)")
    risk_score: float = Field(..., description="Calculated contextual risk score bounded in [0.0, 100.0]")
    confidence: float = Field(..., description="Risk assessment confidence bounded in [0.0, 1.0]")
    factors: Dict[str, str] = Field(default_factory=dict, description="Environmental risk factor string representations")
    rationale: str = Field(..., description="Human-readable justification for risk level")

    @field_validator("risk_id", "finding_id", "risk_level")
    @classmethod
    def validate_non_empty_str(cls, v: str, info: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return v.strip()

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score_bounds(cls, v: float) -> float:
        if v < 0.0 or v > 100.0:
            raise ValueError("risk_score must be bounded within [0.0, 100.0]")
        return float(v)

    @field_validator("confidence")
    @classmethod
    def validate_confidence_bounds(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("confidence must be bounded within [0.0, 1.0]")
        return float(v)


class SecurityReport(BaseModel):
    """
    Complete immutable security report container object for a security scan.
    """

    model_config = ConfigDict(frozen=True)

    report_id: str = Field(..., description="Non-empty unique report identifier")
    scan_id: str = Field(..., description="Associated non-empty scan identifier")
    target_name: str = Field(..., description="Target AI agent name")
    status: str = Field(..., description="Scan execution lifecycle status")
    generated_at: datetime = Field(..., description="UTC timestamp when report was generated")
    executive_summary: str = Field(..., description="Concise human-readable executive summary")
    summary: Dict[str, int] = Field(..., description="Statistical summary counts map")
    findings: List[ReportFinding] = Field(default_factory=list, description="Collection of report findings")
    risk_assessments: List[ReportRisk] = Field(default_factory=list, description="Collection of report risk assessments")
    recommendations: List[str] = Field(default_factory=list, description="Deduplicated actionable remediation recommendations")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe operational report metadata")

    @field_validator("report_id", "scan_id", "target_name", "status", "executive_summary")
    @classmethod
    def validate_non_empty_str(cls, v: str, info: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return v.strip()
