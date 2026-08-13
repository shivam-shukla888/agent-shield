"""
Evaluation Domain Models

This module defines strongly typed domain models for evaluating the outcome of executed security probes.

ARCHITECTURAL DIRECTIVES:
1. TargetResult = what the target agent returned.
2. EvaluationResult = what AgentShield concluded about that specific probe execution.
3. Finding = future aggregated security issue (NOT created in this module).
4. EvaluationResult contains NO vulnerability risk scores, final severities, CVSS scores, or remediations.
5. Evaluator confidence (0.0 to 1.0) measures evaluation certainty, NOT vulnerability severity.
"""

from enum import StrEnum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvaluationVerdict(StrEnum):
    """Normalized verdict outcome for a security probe evaluation."""

    SAFE = "safe"
    VIOLATION = "violation"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class EvaluatorType(StrEnum):
    """Classification of the evaluator engine mechanism."""

    DETERMINISTIC = "deterministic"
    LLM_JUDGE = "llm_judge"
    HYBRID = "hybrid"


class EvaluationEvidence(BaseModel):
    """
    Structured evidence supporting an evaluation verdict.

    SECURITY NOTE:
    - Target responses are UNTRUSTED external data.
    - response_excerpt is automatically bounded to prevent storing unbounded target output.
    """

    model_config = ConfigDict(frozen=True)

    summary: str = Field(..., description="Human-readable summary of evaluation evidence")
    matched_indicators: List[str] = Field(
        default_factory=list,
        description="List of text indicators or pattern rules matched during evaluation"
    )
    response_excerpt: Optional[str] = Field(
        default=None,
        description="Bounded excerpt of target response text (max 500 characters)"
    )

    @field_validator("response_excerpt")
    @classmethod
    def bound_response_excerpt(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 500:
            return v[:497] + "..."
        return v


class EvaluationResult(BaseModel):
    """
    Normalized result of evaluating one executed security probe.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    This does not guarantee deep immutability of nested mutable structures (e.g. metadata dict).
    """

    model_config = ConfigDict(frozen=True)

    evaluation_id: str = Field(..., description="Unique identifier (UUID) for this evaluation result")
    execution_id: str = Field(..., description="Identifier of the ProbeExecution run being evaluated")
    probe_id: str = Field(..., description="Identifier of the SecurityProbe evaluated (e.g. PROMPT_LEAK_001)")
    verdict: EvaluationVerdict = Field(..., description="Evaluation outcome verdict (SAFE, VIOLATION, etc.)")
    confidence: float = Field(..., description="Evaluator certainty score between 0.0 and 1.0")
    evidence: EvaluationEvidence = Field(..., description="Structured evidence supporting the verdict")
    evaluator_type: EvaluatorType = Field(
        default=EvaluatorType.DETERMINISTIC,
        description="Engine type that produced this evaluation"
    )
    rationale: str = Field(..., description="Detailed explanation for why the verdict and confidence were assigned")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Operational metadata or rule execution context"
    )

    @field_validator("evaluation_id")
    @classmethod
    def validate_evaluation_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("evaluation_id must not be empty or whitespace-only")
        return stripped

    @field_validator("execution_id")
    @classmethod
    def validate_execution_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("execution_id must not be empty or whitespace-only")
        return stripped

    @field_validator("probe_id")
    @classmethod
    def validate_probe_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("probe_id must not be empty or whitespace-only")
        return stripped

    @field_validator("confidence")
    @classmethod
    def validate_confidence_range(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0 inclusive")
        return v
