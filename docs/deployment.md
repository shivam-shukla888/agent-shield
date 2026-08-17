# AgentShield 🛡️ — Production & Public Demo Deployment Specification

**Document Version:** 1.0.0  
**Date:** August 18, 2026  
**Target Repository:** `github.com/shivam-shukla888/agent-shield`

---

## 1. Deployment Architecture Recommendation

For public demo exposure with zero-friction setup and strong security isolation, AgentShield recommends a **Decoupled Hosted Architecture**:

```
+------------------------------------+          +------------------------------------+
|  Frontend Workstation (Public)     |          |  Backend API & Engine (Hosted)     |
|                                    |          |                                    |
|  Streamlit Community Cloud / App   |  REST    |  Render / Railway / HF Space       |
|  (streamlit_app.py / app.py)       | -------> |  FastAPI ASGI Container            |
|  - Renders UI & Visualizations     |  HTTPS   |  - SSRF Security Boundary          |
|  - Reads BACKEND_URL from Secrets  |          |  - DeterministicEvaluator Engine   |
+------------------------------------+          +------------------------------------+
```

### Recommendation Rationale
1. **Lowest Setup Friction**: Streamlit Community Cloud hosts the UI for free directly from GitHub. Render / Railway hosts the production FastAPI container using the root [`Dockerfile`](../Dockerfile) with zero infrastructure maintenance.
2. **Security Isolation**: The backend container enforces server-side target domain allowlisting (`AGENTSHIELD_ALLOWED_TARGET_DOMAINS`), SSRF IP blocklists, and per-IP rate limiting before any outbound HTTP request is attempted.
3. **Stateless Operations**: Uses in-memory scan repositories by default with optional PostgreSQL persistence (`DATABASE_URL`).

---

## 2. Environment Variables & Configuration Matrix

| Variable Name | Required? | Default Value | Description / Public Demo Guardrail |
| :--- | :---: | :--- | :--- |
| `AGENTSHIELD_API_KEY` | **Yes** | `changeme-generate-a-real-key` | Master API key required in `X-API-Key` or `Authorization: Bearer` header. |
| `AGENTSHIELD_ALLOWED_TARGET_DOMAINS` | **Yes (Demo)** | `localhost,127.0.0.1,testagent.local,test_target` | Comma-separated allowed target hostnames. Rejects unlisted target URLs with HTTP 400. |
| `AGENTSHIELD_DEMO_GUARDRAILS` | Optional | `true` | Enables safe demo defaults (pre-populated target allowlist, low scan timeout). |
| `AGENTSHIELD_RATE_LIMIT_RPM` | Optional | `30` | Sliding-window requests per minute per IP / API key. Returns HTTP 429 when exceeded. |
| `BACKEND_URL` | UI Only | `http://localhost:8000` | Public URL of hosted FastAPI backend service. |
| `APP_HOST` | Container | `0.0.0.0` | Container bind address. |
| `APP_PORT` | Container | `8000` | Container HTTP port. |
| `LOG_LEVEL` | Optional | `INFO` | Structured JSON log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

---

## 3. Container Build & Local Execution

### Build Container Image
```bash
docker build -t agentshield:latest .
```

### Run Container (Production Mode)
```bash
docker run -d \
  --name agentshield-app \
  -p 8000:8000 \
  -e AGENTSHIELD_API_KEY="your-secure-api-key-here" \
  -e AGENTSHIELD_ALLOWED_TARGET_DOMAINS="localhost,127.0.0.1,testagent.local" \
  -e AGENTSHIELD_DEMO_GUARDRAILS="true" \
  -e AGENTSHIELD_RATE_LIMIT_RPM="30" \
  agentshield:latest
```

### Run Container Stack via Docker Compose
```bash
cp .env.example .env
docker compose up -d
```

---

## 4. Health Check Endpoints

AgentShield provides explicit container health check endpoints:

### Liveness Probe (`GET /health/live`)
- **URL**: `http://localhost:8000/health/live`
- **Response**: `HTTP 200 OK`
```json
{
  "status": "live",
  "timestamp": "2026-08-18T00:00:00.000000+00:00"
}
```

### Readiness Probe (`GET /health/ready`)
- **URL**: `http://localhost:8000/health/ready`
- **Response**: `HTTP 200 OK`
```json
{
  "status": "ready",
  "timestamp": "2026-08-18T00:00:00.000000+00:00",
  "version": "1.0.0"
}
```

---

## 5. Hosted Public Demo Step-by-Step Setup

### Step 1: Deploy Backend Container to Render / Railway
1. Connect GitHub repository `shivam-shukla888/agent-shield` to [Render.com](https://render.com).
2. Create **Web Service** using `Dockerfile`.
3. Configure Environment Variables:
   - `AGENTSHIELD_API_KEY` = `<generated-random-secret>`
   - `AGENTSHIELD_ALLOWED_TARGET_DOMAINS` = `localhost,127.0.0.1,testagent.local,test_target`
   - `AGENTSHIELD_DEMO_GUARDRAILS` = `true`
   - `AGENTSHIELD_RATE_LIMIT_RPM` = `30`
4. Copy the live service URL: `https://agentshield-api.onrender.com`.

### Step 2: Deploy Streamlit UI to Streamlit Community Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io/).
2. Click **New App** -> Select repository `shivam-shukla888/agent-shield` (`main` branch).
3. Main file path: `streamlit_app.py`.
4. Under **App Settings -> Secrets**, add:
   ```toml
   BACKEND_URL = "https://agentshield-api.onrender.com"
   API_KEY = "<generated-random-secret>"
   IS_DEMO = false
   ```
5. Deploy. The Streamlit app will launch with a public live URL.

---

## 6. Hosted Security Guardrails & SSRF Verification

To ensure public safety when AgentShield is hosted on a public domain:

1. **Domain Allowlist Rejection**:
   Attempting a scan against an unlisted domain (`http://malicious.external.com`) returns `HTTP 400 Bad Request`:
   ```json
   {
     "detail": "Target domain 'malicious.external.com' is not permitted by AGENTSHIELD_ALLOWED_TARGET_DOMAINS allowlist"
   }
   ```
2. **SSRF Metadata Block**:
   Attempting a scan against AWS metadata (`http://169.254.169.254/latest/meta-data`) returns `HTTP 400 Bad Request` from the SSRF protection engine.
3. **Secret Non-Disclosure**:
   API keys and environment secrets are never returned in scan responses, audit logs, or Streamlit DOM elements.
