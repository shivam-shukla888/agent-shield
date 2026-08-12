"""
Scan Domain Models

This module defines strongly typed domain models for AgentShield security scan results,
summaries, and scan lifecycle statuses.

ARCHITECTURAL DIRECTIVES:
1. ScanResult is an aggregation/container object that holds the complete lineage of a scan run
   (TargetConfig name, ProbeExecutions, EvaluationResults, Findings, RiskAssessments, ScanSummary).
2. ScanResult does NOT calculate risk, evaluate probes, execute attacks, or perform re-scoring.
3. ScanStatus tracks scan lifecycle (CREATED, RUNNING, COMPLETED, PARTIAL, FAILED).
   Operational failure (PARTIAL / FAILED) != security vulnerability violation.
4. ScanResult must NEVER store credentials, API keys, bearer tokens, or target auth configs.
5. Immutability is enforced using `ConfigDict(frozen=True)` protecting top-level fields.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.domain.evaluation import EvaluationResult
from app.domain.execution import ProbeExecution
from app.domain.finding import Finding
from app.domain.risk import RiskAssessment


class ScanStatus(StrEnum):
    """
    Lifecycle status of a security scan execution.

    DISTINCTION:
    - COMPLETED: Finished successfully.
    - PARTIAL: Completed but some executions or evaluations encountered operational errors.
    - FAILED: Fundamental execution failure.

    OPERATIONAL NOTE:
    PARTIAL or FAILED indicate operational execution issues, NOT security vulnerabilities.
    """

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanSummary(BaseModel):
    """
    Aggregated statistical summary counts for a security scan.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    Summary counters are computed by the orchestrator/engine during scan construction.
    """

    model_config = ConfigDict(frozen=True)

    total_probes: int = Field(..., description="Total number of security probes dispatched in the scan")
    completed_executions: int = Field(..., description="Number of probe executions completed successfully")
    failed_executions: int = Field(..., description="Number of probe executions encountering operational errors")

    safe_evaluations: int = Field(..., description="Number of evaluations resulting in SAFE verdict")
    violation_evaluations: int = Field(..., description="Number of evaluations resulting in VIOLATION verdict")
    inconclusive_evaluations: int = Field(..., description="Number of evaluations resulting in INCONCLUSIVE verdict")
    error_evaluations: int = Field(..., description="Number of evaluations resulting in ERROR verdict")

    total_findings: int = Field(..., description="Total number of aggregated security findings")

    info_risks: int = Field(..., description="Count of risk assessments at INFO level")
    low_risks: int = Field(..., description="Count of risk assessments at LOW level")
    medium_risks: int = Field(..., description="Count of risk assessments at MEDIUM level")
    high_risks: int = Field(..., description="Count of risk assessments at HIGH level")
    critical_risks: int = Field(..., description="Count of risk assessments at CRITICAL level")

    @field_validator(
        "total_probes",
        "completed_executions",
        "failed_executions",
        "safe_evaluations",
        "violation_evaluations",
        "inconclusive_evaluations",
        "error_evaluations",
        "total_findings",
        "info_risks",
        "low_risks",
        "medium_risks",
        "high_risks",
        "critical_risks",
    )
    @classmethod
    def validate_non_negative_count(cls, v: int, info: Any) -> int:
        if v < 0:
            raise ValueError(f"{info.field_name} must be a non-negative integer")
        return v


class ScanResult(BaseModel):
    """
    Complete aggregated container object representing an AgentShield security scan run.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent top-level field reassignment.
    This provides top-level field reassignment protection, but does not guarantee deep
    immutability of nested mutable structures (e.g. metadata dict or list elements).
    """

    model_config = ConfigDict(frozen=True)

    scan_id: str = Field(..., description="Non-empty unique identifier for this security scan run")
    target_name: str = Field(..., description="Non-empty name of the target agent evaluated")
    status: ScanStatus = Field(..., description="Overall scan lifecycle status")

    started_at: datetime = Field(..., description="UTC timestamp when scan execution started")
    completed_at: Optional[datetime] = Field(default=None, description="Optional UTC timestamp when scan completed")

    summary: ScanSummary = Field(..., description="Statistical summary counts for this scan")

    executions: List[ProbeExecution] = Field(default_factory=list, description="List of raw probe execution traces")
    evaluations: List[EvaluationResult] = Field(default_factory=list, description="List of per-execution evaluation results")

    findings: List[Finding] = Field(default_factory=list, description="List of aggregated security findings")
    risk_assessments: List[RiskAssessment] = Field(default_factory=list, description="List of contextual risk assessments")

    metadata: Dict[str, Any] = Field(default_factory=dict, description="Operational metadata or configuration context")

    @field_validator("scan_id")
    @classmethod
    def validate_scan_id_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("scan_id must not be empty or whitespace-only")
        return stripped

    @field_validator("target_name")
    @classmethod
    def validate_target_name_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("target_name must not be empty or whitespace-only")
        return stripped

    @model_validator(mode="after")
    def validate_timestamps_and_lineage(self) -> "ScanResult":
        # 1. Timestamp validation
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at must be greater than or equal to started_at")

        # 2. Lineage validation: EvaluationResult -> ProbeExecution
        exec_ids = {e.execution_id for e in self.executions}
        if exec_ids and self.evaluations:
            for ev in self.evaluations:
                if ev.execution_id not in exec_ids:
                    raise ValueError(
                        f"EvaluationResult with execution_id '{ev.execution_id}' does not reference a valid ProbeExecution in this scan"
                    )

        # 3. Lineage validation: RiskAssessment -> Finding
        finding_ids = {f.finding_id for f in self.findings}
        if finding_ids and self.risk_assessments:
            for ra in self.risk_assessments:
                if ra.finding_id not in finding_ids:
                    raise ValueError(
                        f"RiskAssessment with finding_id '{ra.finding_id}' does not reference a valid Finding in this scan"
                    )

        return self
