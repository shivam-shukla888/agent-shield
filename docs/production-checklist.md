# AgentShield — Production Deployment Checklist

## Pre-Deployment

- [ ] **API Key**: Generate a strong `AGENTSHIELD_API_KEY` (`python -c "import secrets; print(secrets.token_urlsafe(32))"`)
- [ ] **Database**: PostgreSQL 16+ instance provisioned and accessible
- [ ] **DATABASE_URL**: Set `postgresql://user:password@host:5432/agentshield` (never commit)
- [ ] **Environment file**: `.env` created from `.env.example` with real values
- [ ] **Secrets**: No real secrets committed to git (`.env` in `.gitignore`)

## Container Build

- [ ] `docker build -t agentshield:latest .` completes successfully
- [ ] Image size is reasonable (< 500 MB)
- [ ] Non-root user `agentshield` is active (`USER agentshield` in Dockerfile)
- [ ] No secrets baked into image layers

## TLS / Reverse Proxy

- [ ] TLS termination via reverse proxy (nginx, Traefik, AWS ALB, etc.)
- [ ] AgentShield container listens on HTTP internally (port 8000)
- [ ] Reverse proxy forwards `X-Request-ID` header if present
- [ ] `Strict-Transport-Security` header configured at proxy layer
- [ ] Rate limiting at proxy layer complements application-level limiting

## Health Checks

- [ ] `GET /health` returns `{"status": "ok", "version": "..."}` (liveness)
- [ ] `GET /health/ready` returns `{"status": "ready"}` (readiness)
- [ ] Container orchestrator health checks configured
- [ ] Health endpoints are public (no API key required)

## Database

- [ ] PostgreSQL schema initialized on first startup (automatic via `init_db`)
- [ ] Connection pooling configured if high concurrency expected
- [ ] Database credentials rotated regularly
- [ ] Point-in-time recovery (PITR) enabled on PostgreSQL

## Backups

- [ ] PostgreSQL `pg_dump` scheduled (daily minimum)
- [ ] Backup retention policy defined (7+ days recommended)
- [ ] Backup restore procedure tested
- [ ] Backups stored in separate location from production database

## Logging & Monitoring

- [ ] Structured JSON logs forwarded to log aggregator (ELK, Datadog, CloudWatch)
- [ ] `X-Request-ID` correlation tracked across services
- [ ] Error rate alerts configured
- [ ] Latency percentile alerts configured (p99)
- [ ] Disk usage monitoring on database volume

## Container Resources

- [ ] Memory limit set (recommended: 512 MB minimum, 1 GB for production)
- [ ] CPU limit set (recommended: 0.5 vCPU minimum)
- [ ] Restart policy: `unless-stopped` or orchestrator equivalent
- [ ] Graceful shutdown timeout: 30 seconds minimum

## Secret Management

- [ ] Secrets injected via environment variables (not files or image layers)
- [ ] Secret rotation procedure documented
- [ ] API key rotation does not require image rebuild
- [ ] No secrets in CI logs (masked in GitHub Actions)

## Rollback

- [ ] Previous container image tagged and available
- [ ] Rollback procedure: `docker compose pull && docker compose up -d`
- [ ] Database migrations are backward-compatible (current schema is additive only)
- [ ] Rollback tested in staging environment

## Upgrade Procedure

1. Pull/build new image: `docker build -t agentshield:vX.Y.Z .`
2. Stop current container: `docker compose down`
3. Update image tag in `docker-compose.yml`
4. Start new container: `docker compose up -d`
5. Verify health: `curl http://localhost:8000/health`
6. Verify readiness: `curl http://localhost:8000/health/ready`
7. Monitor logs: `docker compose logs -f agentshield`

## Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `APP_HOST` | No | `0.0.0.0` | Server bind address |
| `APP_PORT` | No | `8000` | Server bind port |
| `LOG_LEVEL` | No | `INFO` | Logging verbosity |
| `AGENTSHIELD_API_KEY` | **Yes** | — | API authentication key |
| `AGENTSHIELD_RATE_LIMIT_RPM` | No | `60` | Rate limit per minute |
| `DATABASE_URL` | Recommended | — | PostgreSQL connection URL |
| `AGENTSHIELD_LLM_PROVIDER` | No | `fake` | LLM provider backend |
| `AGENTSHIELD_LLM_API_KEY` | Conditional | — | Required for cloud LLM providers |
| `AGENTSHIELD_LLM_MODEL` | No | — | LLM model identifier |
| `AGENTSHIELD_LLM_TIMEOUT` | No | `30.0` | LLM request timeout (seconds) |
| `AGENTSHIELD_LLM_ENDPOINT` | No | — | Custom LLM endpoint URL |
