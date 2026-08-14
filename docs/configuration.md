# AgentShield — Production Configuration Specification

This document details all supported environment variables for configuring AgentShield in development, testing, and production environments.

| Environment Variable | Required? | Default | Allowed Values | Security Sensitivity | Description |
|---|---|---|---|---|---|
| `AGENTSHIELD_API_KEY` | **Yes** | None | Secret string | **High** | Master API key required for HTTP authentication (`X-API-Key`) |
| `DATABASE_URL` | No | None | PostgreSQL DSN | **High** | PostgreSQL connection string (e.g. `postgresql://user:pass@db:5432/agentshield`) |
| `AGENTSHIELD_RATE_LIMIT_RPM` | No | `60` | Integer `> 0` | Low | Allowed API request quota per sliding window per client key |
| `AGENTSHIELD_LLM_PROVIDER` | No | `fake` | `fake`, `production` | Low | Selected LLM provider backend mechanism |
| `AGENTSHIELD_LLM_API_KEY` | Optional | None | Secret string | **High** | API key for production LLM provider |
| `AGENTSHIELD_LLM_MODEL` | Optional | `gpt-4o-mini` | String | Low | Target model name for LLM judge evaluator |
| `AGENTSHIELD_LLM_TIMEOUT` | No | `15.0` | Float `> 0` | Low | Max HTTP request duration for LLM judge requests in seconds |
| `AGENTSHIELD_LLM_ENDPOINT` | Optional | None | HTTP/HTTPS URL | Medium | Custom LLM gateway or endpoint URL |
| `APP_ENV` | No | `production` | `development`, `test`, `production` | Low | Active application operational environment |
| `APP_PORT` | No | `8000` | Integer `1-65535` | Low | TCP listening port for FastAPI web server |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | Low | Log output verbosity level |

---

## Configuration Security Invariants

1. Missing `AGENTSHIELD_API_KEY` in `production` environment raises a sanitized startup error.
2. Configuration validation errors NEVER output secret values or connection strings.
3. Database DSN passwords are automatically masked in representation outputs and logs.
