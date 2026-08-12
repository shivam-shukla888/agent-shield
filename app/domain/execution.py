"""
Probe Execution Domain Models

This module defines strongly typed domain models for tracking security probe execution state.

ARCHITECTURAL DIRECTIVES:
1. ProbeExecution records WHAT HAPPENED when a probe was executed against a target.
2. ProbeExecution contains NO vulnerability verdicts, severity scoring, or security findings.
3. target_result references the normalized TargetResult object returned by TargetAdapter.
4. ExecutionStatus.ERROR represents an unhandled execution/adapter exception, whereas
   TargetResult.error represents a normalized transport failure (timeout, 5xx, etc.).
"""

from datetime import datetime
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.domain.target import TargetResult


class ExecutionStatus(StrEnum):
    """Normalized status of a probe execution lifecycle."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


class ProbeExecution(BaseModel):
    """
    Representation of a single probe execution run against a target agent.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    """

    model_config = ConfigDict(frozen=True)

    execution_id: str = Field(..., description="Unique run identifier (UUID) for this specific execution")
    probe_id: str = Field(..., description="Identifier of the SecurityProbe being executed (e.g. PROMPT_LEAK_001)")
    status: ExecutionStatus = Field(..., description="Current status of the execution run")
    target_name: str = Field(..., description="Human-readable name of the target agent")
    target_result: Optional[TargetResult] = Field(
        default=None,
        description="Normalized target execution result returned by TargetAdapter"
    )
    started_at: Optional[datetime] = Field(default=None, description="UTC timestamp when probe execution started")
    completed_at: Optional[datetime] = Field(default=None, description="UTC timestamp when probe execution finished")
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if execution encountered an unhandled Python/adapter exception (status=ERROR)"
    )
