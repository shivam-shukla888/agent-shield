# AgentShield — Deployment Guide

## Architecture Overview

```
Developer
 ↓
Git (push / PR)
 ↓
CI Pipeline (.github/workflows/ci.yml)
 ├── Python 3.11/3.12 Test Matrix
 ├── Full pytest Suite
 ├── Security Tests
 ├── Secret Leak Scan
 └── Docker Build Validation
 ↓
Release Artifact (Docker Image)
 ↓
Deployment (docker compose up -d)
 ├── agentshield (FastAPI + Uvicorn)
 └── postgres (PostgreSQL 16)
```

## Environment Separation

### Development

```bash
# Local development — no Docker required
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -e .[dev]
uvicorn app.main:app --reload
pytest
```

- Uses in-memory repository (no PostgreSQL required)
- Uses `fake` LLM provider (no API keys required)
- No API key authentication enforced by default

### Test (CI)

```bash
# CI pipeline — runs automatically on push/PR
# See .github/workflows/ci.yml
pytest -v --tb=short
```

- Uses in-memory repository
- Uses `fake` LLM provider
- All tests are offline — no external API calls
- Docker build validated but no production database required

### Production

```bash
# Production deployment via Docker Compose
cp .env.example .env
# Edit .env with real values
docker compose up -d
```

- PostgreSQL database required (`DATABASE_URL`)
- API key required (`AGENTSHIELD_API_KEY`)
- TLS termination via reverse proxy recommended
- Structured JSON logs to stdout

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/shivam-shukla888/agent-shield.git
cd agent-shield
cp .env.example .env
```

Edit `.env` with production values:
- Generate API key: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- Set `DATABASE_URL` to your PostgreSQL instance
- Configure LLM provider if needed

### 2. Build and Deploy

```bash
docker compose up -d
```

### 3. Verify

```bash
# Liveness
curl http://localhost:8000/health

# Readiness
curl http://localhost:8000/health/ready

# Logs
docker compose logs -f agentshield
```

## Docker Image

The production Docker image:
- Base: `python:3.11-slim`
- Non-root user: `agentshield` (UID 1000)
- ASGI server: Uvicorn
- No secrets baked in
- Minimal OS packages (only `curl` for health checks)

## Database

PostgreSQL schema is initialized automatically on first startup via `init_db()`.

- Schema creation is idempotent (safe to restart)
- No destructive migrations
- Scan history is persisted in PostgreSQL

## Configuration Validation

On startup, `AppConfig.from_env()` validates:
- Port range (1..65535)
- Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Rate limit (positive integer)
- LLM timeout (0.0 < timeout ≤ 300.0)
- Database URL scheme (postgresql://, postgres://, sqlite://)
- Cloud LLM providers require API key

Invalid configuration causes immediate startup failure with sanitized error messages (no secret leakage).

## Security

- API endpoints require `X-API-Key` header
- Rate limiting on scan submission endpoints
- SSRF protection on outbound target requests
- Security response headers on all responses
- Secrets wrapped in `SecretStr` — never logged or printed
- Non-root container user
- No privileged mode

See [production-checklist.md](./production-checklist.md) for full checklist.
