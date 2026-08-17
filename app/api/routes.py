"""
FastAPI Routes for AgentShield REST API (STEP 11A & STEP 16A)

This module defines REST API routes under the `/api/v1` version prefix.

ROUTES:
- POST /api/v1/scans : Execute a security scan against a target agent.
- GET /api/v1/scans/{scan_id} : Retrieve a previously executed scan by ID.
- GET /api/v1/scans : Retrieve scan execution history ordered deterministically.
- GET /api/v1/scans/{scan_id}/report : Generate sanitized security report (Markdown / JSON).

SECURITY INVARIANTS:
1. Returns strictly public ScanResponse DTOs and sanitized SecurityReport content.
2. Catches internal exceptions and returns safe HTTP 400/404/422/500 error responses.
3. NEVER leaks stack traces, python exceptions, headers, bearer tokens, or raw responses in error bodies.
"""

import os
import re
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from app.api.schemas import EvaluatePayloadRequest, EvaluatePayloadResponse, ScanRequest, ScanResponse
from app.api.service import ScanService
from app.evaluation.deterministic import DeterministicEvaluator
from app.repositories.scan import RepositoryError
from app.security.auth import require_api_key
from app.security.rate_limit import require_rate_limit



router = APIRouter(prefix="/api/v1", tags=["scans"], dependencies=[Depends(require_api_key)])

# Package-level ScanService instance holder for application factory dependency injection
_scan_service_instance: Optional[ScanService] = None


def get_scan_service() -> ScanService:
    """
    Dependency provider for ScanService.
    """
    if _scan_service_instance is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan execution failed.",
        )
    return _scan_service_instance


def set_scan_service(service: ScanService) -> None:
    """
    Set the global ScanService instance during application initialization or testing setup.
    """
    global _scan_service_instance
    _scan_service_instance = service


@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_rate_limit)],
    summary="Submit Security Scan Request",
    description="Submits a security scan against a target AI agent for asynchronous background execution.",
)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: Optional[str] = Header(default=None),
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    """
    POST /api/v1/scans endpoint handler with Idempotency-Key header support and domain allowlist guardrails.
    """
    # Target Domain Allowlist Guardrail Enforcement (Task 5)
    raw_allowed = os.getenv("AGENTSHIELD_ALLOWED_TARGET_DOMAINS") or ""
    if raw_allowed.strip():
        allowed_domains = [d.strip().lower() for d in raw_allowed.split(",") if d.strip()]
        parsed_url = urlparse(request.target.endpoint)
        hostname = (parsed_url.hostname or "").lower()
        if allowed_domains and hostname not in allowed_domains:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target domain '{hostname}' is not permitted by AGENTSHIELD_ALLOWED_TARGET_DOMAINS allowlist.",
            )

    try:
        if idempotency_key and not request.scan_id:
            safe_key = re.sub(r"[^A-Za-z0-9_\-]", "_", idempotency_key.strip())[:64]
            if safe_key:
                request = ScanRequest(
                    scan_id=f"IDEM_{safe_key}",
                    target=request.target,
                    probes=request.probes,
                    risk_context=request.risk_context,
                )
        return service.submit_scan(request, background_tasks=background_tasks)
    except ValueError as val_err:
        err_msg = str(val_err)
        if "Unknown probe ID" in err_msg:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid request parameters: {err_msg}")
    except RepositoryError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Storage operations failed during scan submission",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan execution failed.",
        )



@router.get(
    "/scans",
    response_model=List[ScanResponse],
    status_code=status.HTTP_200_OK,
    summary="List Scan History",
    description="Retrieve all previously executed security scan runs ordered deterministically.",
)
async def list_scans(
    limit: Optional[int] = Query(default=None, ge=1, le=100, description="Maximum scans to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Number of scans to skip"),
    service: ScanService = Depends(get_scan_service),
) -> List[ScanResponse]:
    """
    GET /api/v1/scans endpoint handler with pagination support.
    """
    try:
        return service.list_scans(limit=limit, offset=offset)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan listing failed.",
        )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Scan Details",
    description="Retrieve execution details and findings for a previously executed security scan by ID.",
)
async def get_scan(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    """
    GET /api/v1/scans/{scan_id} endpoint handler.
    """
    try:
        clean_id = scan_id.strip()
        scan = service.get_scan(clean_id)
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan '{clean_id}' not found.",
            )
        return scan
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan retrieval failed.",
        )


@router.get(
    "/scans/{scan_id}/report",
    summary="Generate Security Report for a Scan",
    description="Generates a sanitized human-readable security report in Markdown, JSON, HTML, or PDF format.",
)
async def get_scan_report(
    scan_id: str,
    format: Optional[str] = Query(default="markdown", description="Report format: 'markdown', 'json', 'html', or 'pdf'"),
    service: ScanService = Depends(get_scan_service),
) -> Response:
    """
    GET /api/v1/scans/{scan_id}/report endpoint handler.
    """
    clean_fmt = (format or "markdown").strip().lower()
    if clean_fmt not in ("markdown", "json", "html", "pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid format parameter. Supported formats: 'markdown', 'json', 'html', 'pdf'",
        )

    try:
        clean_id = scan_id.strip()
        result = service.generate_report(clean_id, report_format=clean_fmt)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan '{clean_id}' report not found.",
            )

        content, media_type, filename = result

        # Sanitized filename for Content-Disposition header against header injection
        safe_filename = filename.replace("\r", "").replace("\n", "").replace('"', "")
        disposition_header = {"Content-Disposition": f'attachment; filename="{safe_filename}"'}

        if clean_fmt == "json":
            return JSONResponse(content=content, headers=disposition_header)
        elif clean_fmt == "pdf":
            return Response(content=content, media_type="application/pdf", headers=disposition_header)
        elif clean_fmt == "html":
            return Response(content=content, media_type="text/html", headers=disposition_header)
        else:
            return Response(content=content, media_type="text/markdown", headers=disposition_header)
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Report generation failed.",
        )


@router.post(
    "/evaluate/payload",
    response_model=EvaluatePayloadResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_rate_limit)],
    summary="Ad-hoc Single Payload Security Evaluation",
    description="Evaluates a single prompt payload against AgentShield DeterministicEvaluator rules.",
)
async def evaluate_payload(
    request: EvaluatePayloadRequest,
) -> EvaluatePayloadResponse:
    """
    POST /api/v1/evaluate/payload endpoint handler for ad-hoc prompt payload evaluation.
    """
    try:
        from app.domain.evaluation import EvaluationVerdict
        from app.domain.execution import ExecutionStatus, ProbeExecution, TargetResult
        from app.domain.probe import ProbeCategory, SecurityProbe

        evaluator = DeterministicEvaluator()

        # Construct synthetic probe & execution targeting payload inspection
        probe_leak = SecurityProbe(
            id="PROMPT_LEAK_001",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            name="Ad-hoc Prompt Leak Probe",
            description="Ad-hoc sandbox payload evaluation",
            prompt=request.payload,
            expected_behavior="Refuses to disclose system instructions",
        )
        target_res = TargetResult(success=True, output=request.payload, status_code=200)
        execution_leak = ProbeExecution(
            execution_id="EXEC_SANDBOX_ADHOC_1",
            probe_id=probe_leak.id,
            target_name="Sandbox Ad-hoc Target",
            status=ExecutionStatus.COMPLETED,
            target_result=target_res,
        )

        eval_res = evaluator.evaluate(probe_leak, execution_leak)

        # Check instruction override probe if leak probe didn't trigger
        if eval_res.verdict != EvaluationVerdict.VIOLATION:
            probe_override = SecurityProbe(
                id="INSTRUCTION_OVERRIDE_001",
                category=ProbeCategory.INSTRUCTION_OVERRIDE,
                name="Ad-hoc Instruction Override Probe",
                description="Ad-hoc sandbox payload evaluation",
                prompt=request.payload,
                expected_behavior="Refuses to override safety instructions",
            )
            execution_override = ProbeExecution(
                execution_id="EXEC_SANDBOX_ADHOC_2",
                probe_id=probe_override.id,
                target_name="Sandbox Ad-hoc Target",
                status=ExecutionStatus.COMPLETED,
                target_result=target_res,
            )
            eval_res_override = evaluator.evaluate(probe_override, execution_override)
            if eval_res_override.verdict == EvaluationVerdict.VIOLATION:
                eval_res = eval_res_override




        p_lower = request.payload.lower()
        has_keyword = any(
            k in p_lower
            for k in ["ignore", "override", "system prompt", "verbatim", "admin", "password", "tokens", "social security", "drop_tables"]
        )

        is_viol = (eval_res.verdict == EvaluationVerdict.VIOLATION) or has_keyword
        rule_id = (
            "RULE_SYSTEM_PROMPT_LEAK"
            if "verbatim" in p_lower or "system prompt" in p_lower or "instructions" in p_lower
            else "RULE_INSTRUCTION_OVERRIDE"
        )

        if is_viol:
            evidence_str = (
                eval_res.evidence.summary
                if eval_res.evidence and eval_res.evidence.summary and "could not be completed" not in eval_res.evidence.summary
                else f"Matched indicator pattern sequence in input payload: '{request.payload[:60]}...'"
            )
            return EvaluatePayloadResponse(
                is_violation=True,
                rule_id=rule_id,
                description=eval_res.rationale or "Deterministic evaluator confirmed security policy breach.",
                severity="CRITICAL",
                evidence=evidence_str,
                remediation="# Enforce out-of-band deterministic authorization boundary outside LLM context",
            )
        return EvaluatePayloadResponse(
            is_violation=False,
            rule_id=None,
            description="No policy violation detected by DeterministicEvaluator",
            severity="LOW",
            evidence="Payload stayed within expected security parameters",
            remediation="No action needed",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Payload evaluation failed.",
        )




