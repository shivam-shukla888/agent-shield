"""
AgentShield FastAPI Main Application & Composition Root
"""

import os
from typing import Optional
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine

from app.adapters.http import GenericHTTPAdapter
from app.api.routes import router as api_router, set_scan_service
from app.api.service import ScanService
from app.domain.target import TargetConfig
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.observability.middleware import RequestIDMiddleware
from app.observability.security_headers import SecurityHeadersMiddleware
from app.repositories import (
    InMemoryScanRepository,
    PostgreSQLScanRepository,
    ScanRepository,
    init_db,
)
from app.security.auth import APIKeyAuthenticator, set_api_key_authenticator
from app.security.rate_limit import InMemoryRateLimiter, set_rate_limiter


class HealthResponse(BaseModel):
    status: str


def create_app(
    service: Optional[ScanService] = None,
    repository: Optional[ScanRepository] = None,
    api_key: Optional[str] = None,
    rate_limit_rpm: Optional[int] = None,
) -> FastAPI:
    """
    Application factory constructing the FastAPI app and setting up dependency composition.

    Args:
        service (Optional[ScanService]): Optional pre-configured ScanService instance.
        repository (Optional[ScanRepository]): Optional pre-configured ScanRepository instance.
        api_key (Optional[str]): Optional master API key for authentication. If omitted, checks
            AGENTSHIELD_API_KEY or API_KEY environment variables.
        rate_limit_rpm (Optional[int]): Optional requests per minute limit for scan endpoints.
            If omitted, checks AGENTSHIELD_RATE_LIMIT_RPM or RATE_LIMIT_RPM env vars (default 60).

    Returns:
        FastAPI: Configured FastAPI application instance.
    """
    application = FastAPI(
        title="AgentShield API",
        description="AgentShield AI Agent Security Testing & Risk Analysis Platform API",
        version="0.1.0",
    )

    # Register Request ID Correlation Middleware & Security Headers Middleware
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(RequestIDMiddleware)

    # Configure API Key Authenticator
    configured_api_key = api_key if api_key is not None else (os.getenv("AGENTSHIELD_API_KEY") or os.getenv("API_KEY"))
    authenticator = APIKeyAuthenticator(api_key=configured_api_key)
    set_api_key_authenticator(authenticator)

    # Configure Rate Limiter
    if rate_limit_rpm is not None:
        rpm = rate_limit_rpm
    else:
        env_rpm = os.getenv("AGENTSHIELD_RATE_LIMIT_RPM") or os.getenv("RATE_LIMIT_RPM")
        rpm = int(env_rpm) if env_rpm and env_rpm.isdigit() else 60

    rate_limiter = InMemoryRateLimiter(requests_per_window=rpm, window_seconds=60.0)
    set_rate_limiter(rate_limiter)

    if service is None:
        if repository is None:
            db_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
            if db_url and db_url.strip():
                engine = create_engine(db_url.strip())
                init_db(engine)
                repository = PostgreSQLScanRepository(engine)
            else:
                repository = InMemoryScanRepository()

        # Default MVP Composition Root
        default_config = TargetConfig(name="Default Target", endpoint="http://localhost:8000/chat")
        adapter = GenericHTTPAdapter(config=default_config)
        attack_engine = AttackEngine(adapter=adapter)
        evaluator = DeterministicEvaluator()
        finding_engine = FindingEngine()
        risk_engine = RiskEngine()
        scan_engine = ScanEngine(
            attack_engine=attack_engine,
            evaluator=evaluator,
            finding_engine=finding_engine,
            risk_engine=risk_engine,
        )
        service = ScanService(scan_engine=scan_engine, repository=repository)

    set_scan_service(service)

    @application.get("/health", response_model=HealthResponse)
    def health_check() -> HealthResponse:
        """Health check (liveness) endpoint to verify application availability."""
        return HealthResponse(status="ok")

    @application.get("/health/ready")
    def readiness_check() -> JSONResponse:
        """
        Readiness check endpoint verifying backing storage connectivity safely.
        Returns HTTP 200 {"status": "ready"} or HTTP 503 {"status": "unhealthy"}.
        Does NOT expose database credentials, SQL errors, or internal stack traces.
        """
        if repository is not None:
            try:
                repository.list(limit=1)
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={"status": "unhealthy", "reason": "Storage repository is unreachable"},
                )
        return JSONResponse(status_code=200, content={"status": "ready"})

    application.include_router(api_router)
    return application


app = create_app()
