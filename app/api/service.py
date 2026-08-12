"""
ScanService Implementation

This module defines ScanService, which bridges public API requests (ScanRequest DTOs)
and the internal ScanEngine orchestrator.

ARCHITECTURAL DIRECTIVES:
1. ScanService converts public DTOs (TargetScanRequest, RiskContextRequest) into internal domain models.
2. Resolves requested probe IDs against get_basic_probes() in exact client-requested order.
3. Preserves scan_id if supplied, or generates a unique scan identifier if omitted.
4. Invokes ScanEngine.run_scan() synchronously in-memory.
5. Converts internal ScanResult into a public, safe ScanResponse DTO.
6. Does NOT execute attack logic, evaluation logic, or risk calculation directly.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional, Sequence

from fastapi import BackgroundTasks

from app.api.schemas import (
    RiskContextRequest,
    ScanRequest,
    ScanResponse,
    ScanSummaryResponse,
    TargetScanRequest,
    risk_context_request_to_risk_factors,
    scan_request_to_target_config,
    scan_result_to_response,
)
from app.domain.probe import SecurityProbe
from app.domain.scan import ScanStatus
from app.domain.target import TargetConfig
from app.domain.risk import RiskFactors
from app.engine.scan import ScanEngine
from app.probes.basic import get_basic_probes
from app.repositories.scan import InMemoryScanRepository, ScanRepository


def resolve_probes(probe_ids: Sequence[str]) -> List[SecurityProbe]:
    """
    Resolve probe ID strings to SecurityProbe instances using get_basic_probes().

    Args:
        probe_ids (Sequence[str]): Ordered collection of probe ID strings requested by client.

    Returns:
        List[SecurityProbe]: Resolved probes matching requested order.

    Raises:
        ValueError: If an unknown probe ID is encountered.
    """
    all_probes = get_basic_probes()
    probe_map = {p.id: p for p in all_probes}

    resolved: List[SecurityProbe] = []
    for pid in probe_ids:
        clean_pid = pid.strip()
        if clean_pid not in probe_map:
            raise ValueError(f"Unknown probe ID: {clean_pid}")
        resolved.append(probe_map[clean_pid])

    return resolved


class ScanService:
    """
    Service layer bridging API endpoints to the ScanEngine orchestrator and ScanRepository.
    """

    def __init__(
        self,
        scan_engine: ScanEngine,
        repository: Optional[ScanRepository] = None,
    ) -> None:
        """
        Initialize ScanService with injected ScanEngine and optional ScanRepository instances.

        Args:
            scan_engine (ScanEngine): Instantiated scan orchestrator engine.
            repository (Optional[ScanRepository]): Storage repository abstraction for scan history.
                Defaults to an InMemoryScanRepository instance if omitted.
        """
        if not isinstance(scan_engine, ScanEngine):
            raise ValueError("scan_engine must be a valid ScanEngine instance")

        if repository is None:
            repository = InMemoryScanRepository()
        elif not isinstance(repository, ScanRepository):
            raise ValueError("repository must be a valid ScanRepository instance")

        self.scan_engine = scan_engine
        self.repository = repository

    def submit_scan(
        self,
        request: ScanRequest,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> ScanResponse:
        """
        Submit a security scan for asynchronous execution.
        Creates an initial ScanResponse with status ScanStatus.CREATED and persists it,
        then dispatches the scan execution job in the background.

        Args:
            request (ScanRequest): Validated public request payload DTO.
            background_tasks (Optional[BackgroundTasks]): FastAPI BackgroundTasks manager.

        Returns:
            ScanResponse: Initial public response payload DTO with status CREATED.
        """
        # 1. Resolve scan_id (preserve if provided, generate UUID if omitted)
        scan_id = request.scan_id.strip() if request.scan_id else f"SCAN_{uuid.uuid4().hex[:12].upper()}"

        # 2. Convert TargetScanRequest -> TargetConfig (synchronous validation)
        target_config = scan_request_to_target_config(request.target)

        # 3. Convert RiskContextRequest -> RiskFactors
        risk_factors = risk_context_request_to_risk_factors(request.risk_context)

        # 4. Resolve requested probes (synchronous probe validation)
        probes = resolve_probes(request.probes.probe_ids)

        now = datetime.now(timezone.utc)
        empty_summary = ScanSummaryResponse(
            total_probes=len(probes),
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

        initial_response = ScanResponse(
            scan_id=scan_id,
            target_name=target_config.name,
            status=ScanStatus.CREATED,
            started_at=now,
            completed_at=None,
            summary=empty_summary,
            findings=[],
            risk_assessments=[],
        )

        # 5. Persist initial CREATED response in repository
        self.repository.save(initial_response)

        # 6. Schedule background execution
        if background_tasks is not None:
            background_tasks.add_task(self._execute_async_job, scan_id, target_config, probes, risk_factors)
        else:
            self._execute_async_job(scan_id, target_config, probes, risk_factors)

        return initial_response

    def _execute_async_job(
        self,
        scan_id: str,
        target_config: TargetConfig,
        probes: List[SecurityProbe],
        risk_factors: RiskFactors,
    ) -> None:
        """
        Background worker task executing scan, evaluating probes, and updating repository status.
        """
        now = datetime.now(timezone.utc)
        try:
            # Update status to RUNNING
            existing = self.repository.get_by_id(scan_id)
            started_at = existing.started_at if existing else now
            running_response = ScanResponse(
                scan_id=scan_id,
                target_name=target_config.name,
                status=ScanStatus.RUNNING,
                started_at=started_at,
                completed_at=None,
                summary=existing.summary if existing else ScanSummaryResponse(
                    total_probes=len(probes),
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
                ),
                findings=[],
                risk_assessments=[],
            )
            self.repository.save(running_response)

            # Update TargetAdapter configuration if adapter exists
            if hasattr(self.scan_engine.attack_engine, "adapter") and self.scan_engine.attack_engine.adapter is not None:
                self.scan_engine.attack_engine.adapter.config = target_config

            # Execute scan via ScanEngine
            scan_result = self.scan_engine.run_scan(
                scan_id=scan_id,
                target_name=target_config.name,
                probes=probes,
                risk_factors=risk_factors,
            )

            # Convert internal ScanResult -> public ScanResponse DTO
            final_response = scan_result_to_response(scan_result)
            self.repository.save(final_response)
        except Exception:
            # Operational failure: update status to FAILED
            failed_response = ScanResponse(
                scan_id=scan_id,
                target_name=target_config.name,
                status=ScanStatus.FAILED,
                started_at=now,
                completed_at=datetime.now(timezone.utc),
                summary=ScanSummaryResponse(
                    total_probes=len(probes),
                    completed_executions=0,
                    failed_executions=len(probes),
                    safe_evaluations=0,
                    violation_evaluations=0,
                    inconclusive_evaluations=0,
                    error_evaluations=len(probes),
                    total_findings=0,
                    info_risks=0,
                    low_risks=0,
                    medium_risks=0,
                    high_risks=0,
                    critical_risks=0,
                ),
                findings=[],
                risk_assessments=[],
            )
            self.repository.save(failed_response)

    def execute_scan(self, request: ScanRequest) -> ScanResponse:
        """
        Execute a security scan synchronously from a public ScanRequest DTO.
        """
        initial = self.submit_scan(request, background_tasks=None)
        completed = self.get_scan(initial.scan_id)
        return completed if completed is not None else initial

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        """
        Retrieve a previously executed scan by its scan_id.

        Args:
            scan_id (str): Unique scan identifier.

        Returns:
            Optional[ScanResponse]: Stored scan response DTO if found, else None.
        """
        if not scan_id or not scan_id.strip():
            return None
        return self.repository.get_by_id(scan_id.strip())

    def list_scans(self) -> List[ScanResponse]:
        """
        Retrieve all previously executed scans in deterministic order.

        Returns:
            List[ScanResponse]: Collection of stored scan response DTOs.
        """
        return self.repository.list_all()

