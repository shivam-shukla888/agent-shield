"""
Risk Assessment Domain Models

This module defines strongly typed domain models for contextual security risk assessment in AgentShield.

ARCHITECTURAL DIRECTIVES:
1. Finding vs RiskAssessment: Finding represents a discovered security vulnerability.
   RiskAssessment represents the contextual danger of that finding in a specific target environment.
2. FindingSeverity vs RiskLevel: FindingSeverity is the classification of the security issue itself.
   RiskLevel is the contextual risk level after evaluating environment factors (e.g. tool privileges, asset sensitivity).
3. Risk Score vs Confidence: risk_score (0.0 to 100.0) measures "How dangerous is this issue?".
   confidence (0.0 to 1.0) measures "How certain are we about this risk assessment?".
4. STEP 8A defines ONLY the domain contract and models. No scoring algorithm, CVSS calculators,
   or RiskEngine implementations are included.
"""

from enum import StrEnum
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(StrEnum):
    """
    Contextual risk level assigned to a finding within a specific target environment.

    DISTINCTION:
    - FindingSeverity: Classification of the security issue.
    - RiskLevel: Contextual danger of that issue for a specific target environment.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ImpactLevel(StrEnum):
    """Potential security impact of exploiting a vulnerability."""

    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExploitabilityLevel(StrEnum):
    """Ease and probability of successfully exploiting a vulnerability."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BlastRadiusLevel(StrEnum):
    """Scope of systems, data, or downstream components affected if exploited."""

    LIMITED = "limited"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetSensitivity(StrEnum):
    """Classification of data or system assets exposed to or managed by the agent."""

    PUBLIC = "public"
    INTERNAL = "internal"
    PERSONAL = "personal"
    CONFIDENTIAL = "confidential"
    HIGHLY_SENSITIVE = "highly_sensitive"


class ToolPrivilege(StrEnum):
    """Privilege level of capabilities or tools accessible to the agent."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    ADMIN = "admin"


class RiskFactors(BaseModel):
    """
    Contextual input factors used to assess risk for a security finding.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    Describes contextual risk inputs; does NOT calculate a score internally.
    """

    model_config = ConfigDict(frozen=True)

    impact: ImpactLevel = Field(..., description="Potential security impact level")
    exploitability: ExploitabilityLevel = Field(..., description="Vulnerability exploitability level")
    blast_radius: BlastRadiusLevel = Field(..., description="Affected scope / blast radius level")
    asset_sensitivity: AssetSensitivity = Field(..., description="Sensitivity level of target assets")
    tool_privilege: ToolPrivilege = Field(..., description="Highest privilege level of accessible tools")


class RiskAssessment(BaseModel):
    """
    Contextual risk assessment object associated with a security finding.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    This provides top-level field reassignment protection, but does not guarantee deep
    immutability of nested mutable structures (e.g. metadata dict).
    """

    model_config = ConfigDict(frozen=True)

    risk_id: str = Field(..., description="Non-empty unique identifier for this risk assessment")
    finding_id: str = Field(..., description="Non-empty reference to the associated Finding")
    risk_level: RiskLevel = Field(..., description="Assigned contextual risk level")
    risk_score: float = Field(..., description="Numerical risk score between 0.0 and 100.0 inclusive")
    confidence: float = Field(..., description="Assessment certainty score between 0.0 and 1.0 inclusive")
    factors: RiskFactors = Field(..., description="Contextual risk factors")
    rationale: str = Field(..., description="Non-empty rationale explaining the assigned risk level and score")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional operational or contextual risk metadata"
    )

    @field_validator("risk_id")
    @classmethod
    def validate_risk_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("risk_id must not be empty or whitespace-only")
        return stripped

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("finding_id must not be empty or whitespace-only")
        return stripped

    @field_validator("rationale")
    @classmethod
    def validate_rationale_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("rationale must not be empty or whitespace-only")
        return stripped

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score_range(cls, v: float) -> float:
        if v < 0.0 or v > 100.0:
            raise ValueError("risk_score must be between 0.0 and 100.0 inclusive")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence_range(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0 inclusive")
        return v
