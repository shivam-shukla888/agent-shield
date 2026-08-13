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

from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from app.api.schemas import ScanRequest, ScanResponse
from app.api.service import ScanService
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
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    """
    POST /api/v1/scans endpoint handler.
    Submits a ScanRequest DTO, initiates background execution, and returns 202 Accepted.
    """
    try:
        return service.submit_scan(request, background_tasks=background_tasks)
    except ValueError as val_err:
        err_msg = str(val_err)
        if "Unknown probe ID" in err_msg:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid request parameters.")
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
    service: ScanService = Depends(get_scan_service),
) -> List[ScanResponse]:
    """
    GET /api/v1/scans endpoint handler.
    """
    try:
        return service.list_scans()
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
