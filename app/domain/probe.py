"""
Security Probe Domain Models

This module defines strongly typed domain models for AgentShield security test probes.

ARCHITECTURAL MANDATES:
1. A SecurityProbe describes WHAT to test, NOT HOW to execute or evaluate it.
2. Probe definitions must NOT contain execution logic, attack mutation algorithms,
   or vulnerability judging rules.
3. A Probe is a test specification probe, NOT a confirmed vulnerability finding.
4. severity_hint is an initial probe-level priority hint, NOT the final vulnerability severity.
"""

from enum import StrEnum
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ProbeCategory(StrEnum):
    """Normalized security test probe categories."""

    SYSTEM_PROMPT_DISCLOSURE = "system_prompt_disclosure"
    INSTRUCTION_OVERRIDE = "instruction_override"
    TOOL_AUTHORIZATION = "tool_authorization"


class ProbeSeverityHint(StrEnum):
    """Initial priority / impact hint for a security probe."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityProbe(BaseModel):
    """
    Declarative specification of a single security probe / test case.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    This does not guarantee deep immutability of nested mutable structures (e.g. metadata dict).
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Stable, unique machine-readable probe identifier (e.g. PROMPT_LEAK_001)")
    name: str = Field(..., description="Human-readable probe title")
    category: ProbeCategory = Field(..., description="Primary security category classification")
    description: str = Field(..., description="Detailed description of what security control this probe tests")
    prompt: str = Field(..., description="The raw test input or probe prompt payload to dispatch")
    expected_behavior: str = Field(..., description="Human-readable description of how a secure target SHOULD respond")
    severity_hint: ProbeSeverityHint = Field(
        default=ProbeSeverityHint.MEDIUM,
        description="Initial expected impact hint (NOT final vulnerability severity)"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional tags, framework references, or operational metadata"
    )

    @field_validator("id")
    @classmethod
    def validate_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Probe ID must not be empty or whitespace-only")
        return stripped

    @field_validator("name")
    @classmethod
    def validate_name_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Probe name must not be empty or whitespace-only")
        return stripped

    @field_validator("prompt")
    @classmethod
    def validate_prompt_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Probe prompt must not be empty or whitespace-only")
        return stripped
