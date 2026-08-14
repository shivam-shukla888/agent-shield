# AgentShield — Operational Troubleshooting Runbook

This runbook provides actionable troubleshooting procedures for common operational issues encountered in production deployments.

---

### Procedure 1: Service Won't Start
- **Symptom**: Container or process exits immediately upon launch.
- **Check**: Inspect container startup logs: `docker compose logs agentshield`
- **Action**: Verify environment variables in `.env`:
  - `AGENTSHIELD_API_KEY` must be set.
  - `APP_PORT` must be an integer between 1 and 65535.
  - `DATABASE_URL` must be a valid PostgreSQL connection string if supplied.
- **Verify**: Run `curl http://localhost:8000/health` to confirm liveness.

---

### Procedure 2: PostgreSQL Unavailable / Storage Health Failing
- **Symptom**: `GET /health/ready` returns HTTP 503 `{"status": "unhealthy", "reason": "Storage repository is unreachable"}`.
- **Check**: Test database connection from container host:
  ```bash
  docker exec -it agentshield-postgres pg_isready -U agentshield
  ```
- **Action**: Restart database service or update network access credentials in `DATABASE_URL`.
- **Verify**: `curl http://localhost:8000/health/ready` returns HTTP 200 `{"status": "ready"}`.

---

### Procedure 3: API Key Rejected
- **Symptom**: API clients receive HTTP 401 `{"detail": "Invalid API key"}` or 403.
- **Check**: Compare request header `X-API-Key` with configured `AGENTSHIELD_API_KEY`.
- **Action**: Ensure request contains exact `X-API-Key` header value without trailing spaces.
- **Verify**: Test API endpoint with key:
  ```bash
  curl -H "X-API-Key: $AGENTSHIELD_API_KEY" http://localhost:8000/api/v1/scans
  ```

---

### Procedure 4: Rate Limit Exceeded
- **Symptom**: API clients receive HTTP 429 `{"detail": "Rate limit exceeded. Try again later."}`.
- **Check**: Inspect structured JSON logs for `event: rate_limit.exceeded`.
- **Action**: Check client call frequency. Increase `AGENTSHIELD_RATE_LIMIT_RPM` environment variable if higher throughput is required.
- **Verify**: Retry request after `Retry-After` header interval.

---

### Procedure 5: Scans Stuck in `RUNNING` or `CREATED`
- **Symptom**: A scan remains in `RUNNING` status indefinitely.
- **Check**: Check target agent responsiveness and log events for `probe.started`.
- **Action**: Verify target endpoint URL is reachable and responding within target timeout (default 30s).
- **Verify**: Resubmit scan and check status updates to `COMPLETED` or `PARTIAL`.

---

### Procedure 6: High Latency / Slow Responses
- **Symptom**: High response times on scan endpoints or report generation.
- **Check**: Measure endpoint duration in structured logs (`duration_ms` field).
- **Action**: Apply pagination on scan listing (`GET /api/v1/scans?limit=20&offset=0`).
- **Verify**: Check `p99` latency on `/api/v1/scans` returns `< 20ms`.
