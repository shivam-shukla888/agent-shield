"""
Finding Domain Models

This module defines strongly typed domain models for human-facing security findings in AgentShield.

ARCHITECTURAL DIRECTIVES:
1. EvaluationResult = evaluation of one executed probe ("One executed probe's evaluation").
2. Finding = human-readable security issue derived from one or more evaluation results
   ("A human-readable security issue derived from one or more evaluation results").
3. ProbeSeverityHint (on SecurityProbe) is an initial test-design priority hint.
   Finding.severity is the final issue classification.
4. Finding severity (FindingSeverity) measures how dangerous/important the confirmed issue is.
5. Evaluation / Finding confidence (0.0 to 1.0) measures certainty in the finding
   ("How certain are we that this finding is real?").
6. Finding.severity and confidence are separate concepts and must NOT be combined into one number in this layer.
7. Finding model is designed to support aggregation across multiple probe IDs and execution IDs.
8. Finding contains NO risk scores, CVSS calculations, or LLM-generated remediations (handled in future Risk/Report engines).
"""

from enum import StrEnum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.probe import ProbeCategory


class FindingSeverity(StrEnum):
    """
    Final security finding severity classification.

    DISTINCTION FROM OTHER CONCEPTS:
    - ProbeSeverityHint: Initial test-design priority/impact hint assigned to a probe.
    - Confidence: Certainty score (0.0 to 1.0) measuring finding validity.
    - FindingSeverity: Final, confirmed security issue impact classification.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """
    Lifecycle status of a security finding.

    MVP CONVENTION:
    Findings created from confirmed violations normally start in OPEN status.
    Lifecycle management is not implemented in this domain contract step.
    """

    OPEN = "open"
    CONFIRMED = "confirmed"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


class FindingEvidence(BaseModel):
    """
    Structured evidence supporting a security finding.

    SECURITY NOTE:
    - Target responses are UNTRUSTED external data.
    - response_excerpt is automatically bounded to max 500 characters.
    - Do not store credentials or unbounded target outputs.
    """

    model_config = ConfigDict(frozen=True)

    summary: str = Field(..., description="Human-readable summary of evaluation evidence")
    indicators: List[str] = Field(
        default_factory=list,
        description="List of matched indicators or detection criteria"
    )
    response_excerpt: Optional[str] = Field(
        default=None,
        description="Bounded excerpt of target response text (max 500 characters)"
    )
    probe_id: Optional[str] = Field(
        default=None,
        description="Probe ID associated with this evidence item"
    )
    execution_id: Optional[str] = Field(
        default=None,
        description="Execution ID associated with this evidence item"
    )

    @field_validator("response_excerpt")
    @classmethod
    def bound_response_excerpt(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 500:
            return v[:497] + "..."
        return v


class Finding(BaseModel):
    """
    Human-readable security finding derived from one or more probe evaluations.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    This provides top-level field reassignment protection, but does not guarantee deep
    immutability of nested mutable structures (e.g. metadata dict or list elements).
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(..., description="Non-empty stable unique identifier for this finding")
    title: str = Field(..., description="Non-empty human-readable finding title")
    category: ProbeCategory = Field(..., description="Security category associated with the issue")
    severity: FindingSeverity = Field(..., description="Final security issue severity classification")
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Finding lifecycle status (defaults to OPEN for MVP)"
    )
    confidence: float = Field(..., description="Certainty score between 0.0 and 1.0 ('How certain are we that this finding is real?')")
    description: str = Field(..., description="Non-empty description of the security issue")
    impact: str = Field(..., description="Non-empty explanation of potential security impact")
    remediation: str = Field(..., description="Non-empty remediation recommendations")
    affected_probe_ids: List[str] = Field(..., description="At least one probe ID that discovered or contributed to this finding")
    affected_execution_ids: List[str] = Field(..., description="At least one execution ID referencing test runs for this finding")
    evidence: List[FindingEvidence] = Field(
        default_factory=list,
        description="Evidence items supporting this finding"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional operational or remediation metadata"
    )

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("finding_id must not be empty or whitespace-only")
        return stripped

    @field_validator("title")
    @classmethod
    def validate_title_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty or whitespace-only")
        return stripped

    @field_validator("description")
    @classmethod
    def validate_description_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("description must not be empty or whitespace-only")
        return stripped

    @field_validator("impact")
    @classmethod
    def validate_impact_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("impact must not be empty or whitespace-only")
        return stripped

    @field_validator("remediation")
    @classmethod
    def validate_remediation_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("remediation must not be empty or whitespace-only")
        return stripped

    @field_validator("confidence")
    @classmethod
    def validate_confidence_range(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0 inclusive")
        return v

    @field_validator("affected_probe_ids")
    @classmethod
    def validate_affected_probe_ids_not_empty(cls, v: List[str]) -> List[str]:
        if not v or len(v) == 0:
            raise ValueError("affected_probe_ids must contain at least one probe ID")
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("probe ID elements in affected_probe_ids must not be empty")
        return [item.strip() for item in v]

    @field_validator("affected_execution_ids")
    @classmethod
    def validate_affected_execution_ids_not_empty(cls, v: List[str]) -> List[str]:
        if not v or len(v) == 0:
            raise ValueError("affected_execution_ids must contain at least one execution ID")
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("execution ID elements in affected_execution_ids must not be empty")
        return [item.strip() for item in v]

    @field_validator("evidence", mode="before")
    @classmethod
    def coerce_evidence_list(cls, v: Any) -> Any:
        if isinstance(v, (FindingEvidence, dict)):
            return [v]
        return v
