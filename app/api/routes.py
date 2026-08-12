"""
FastAPI Routes for AgentShield REST API (STEP 11A)

This module defines REST API routes under the `/api/v1` version prefix.

ROUTES:
- POST /api/v1/scans : Execute a synchronous security scan against a target agent.
- GET /api/v1/scans/{scan_id} : Retrieve a previously executed scan by ID.
- GET /api/v1/scans : Retrieve scan execution history ordered deterministically.

SECURITY INVARIANTS:
1. Returns strictly public ScanResponse DTOs.
2. Catches internal exceptions and returns safe HTTP 400/404/422/500 error responses.
3. NEVER leaks stack traces, python exceptions, headers, bearer tokens, or raw responses in error bodies.
"""

from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from app.api.schemas import ScanRequest, ScanResponse
from app.api.service import ScanService
from app.repositories.scan import RepositoryError
from app.security.auth import require_api_key
from app.security.rate_limit import require_rate_limit


router = APIRouter(prefix="/api/v1", tags=["scans"], dependencies=[Depends(require_api_key)])

# Package-level ScanService instance holder for application factory dependency injection
_scan_service_instance: Optional[ScanService] = None


def set_scan_service(service: ScanService) -> None:
    """
    Register the global ScanService instance for application routing.
    """
    global _scan_service_instance
    _scan_service_instance = service


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


@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Dispatch Security Scan",
    description="Asynchronously dispatch a suite of security probes against a target AI agent and return HTTP 202 Accepted with a CREATED scan status.",
    dependencies=[Depends(require_rate_limit)],
)
def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    """
    POST /api/v1/scans endpoint handler.
    """
    try:
        return service.submit_scan(request, background_tasks=background_tasks)
    except ValueError as exc:
        err_msg = str(exc)
        if "Unknown probe ID" in err_msg:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid request parameters.")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan execution failed.",
        )


@router.get(
    "/scans",
    response_model=List[ScanResponse],
    status_code=status.HTTP_200_OK,
    summary="List Security Scans",
    description="Retrieve scan execution history in deterministic order (newest first).",
)
def list_scans(
    service: ScanService = Depends(get_scan_service),
) -> List[ScanResponse]:
    """
    GET /api/v1/scans endpoint handler.
    """
    try:
        return service.list_scans()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan listing failed.",
        )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Security Scan by ID",
    description="Retrieve a previously executed security scan by its unique scan_id.",
)
def get_scan(
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

