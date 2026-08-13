"""
Request ID Correlation & Lifecycle Middleware (STEP 15A)

This module implements RequestIDMiddleware for FastAPI/Starlette applications.

BEHAVIOR:
1. Reads `X-Request-ID` header if present and valid (<= 128 chars, alphanumeric + hyphens/underscores).
2. Generates unique UUID request_id if missing or malformed.
3. Binds request_id to ContextVar (request_id_var) for structured logging across async calls.
4. Measures request duration using monotonic clock (time.perf_counter()).
5. Emits `api.request.started` and `api.request.completed` / `api.request.failed` events.
6. Returns `X-Request-ID` header in all HTTP responses.
7. NEVER logs authorization headers, bearer tokens, request bodies, or response bodies.
"""

import re
import time
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.observability.logging import emit_event, get_logger, request_id_var

logger = get_logger("agentshield.api")

SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


def validate_or_generate_request_id(incoming_id: str | None) -> str:
    """
    Validate an incoming request ID header or generate a fresh UUID request ID.

    Args:
        incoming_id (Optional[str]): Header string value from X-Request-ID.

    Returns:
        str: Validated or newly generated request ID.
    """
    if incoming_id and isinstance(incoming_id, str):
        clean = incoming_id.strip()
        if SAFE_ID_PATTERN.match(clean):
            return clean
    return f"req_{uuid.uuid4().hex}"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    HTTP Middleware binding request correlation IDs and logging request lifecycle events.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        raw_header = request.headers.get("x-request-id") or request.headers.get("X-Request-ID")
        req_id = validate_or_generate_request_id(raw_header)

        # Bind to ContextVar
        token = request_id_var.set(req_id)

        start_time = time.perf_counter()
        emit_event(
            logger,
            "api.request.started",
            method=request.method,
            path=request.url.path,
            request_id=req_id,
        )

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            
            emit_event(
                logger,
                "api.request.completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
                request_id=req_id,
            )
            response.headers["X-Request-ID"] = req_id
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = "default-src 'none'"
            response.headers["X-XSS-Protection"] = "0"
            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            emit_event(
                logger,
                "api.request.failed",
                level=30,  # WARNING / ERROR
                method=request.method,
                path=request.url.path,
                error_type=type(exc).__name__,
                duration_ms=duration_ms,
                request_id=req_id,
            )
            raise
        finally:
            request_id_var.reset(token)
