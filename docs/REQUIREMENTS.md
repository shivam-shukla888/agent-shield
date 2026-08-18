# AgentShield 🛡️ — System Requirements & Dependency Inventory

**Document Version:** 1.0.0  
**Date:** August 18, 2026  
**Target Repository:** `github.com/shivam-shukla888/agent-shield`

This document provides a ground-truth inventory of every API key, credential, database, external CLI, and third-party service dependency required to run AgentShield locally, in CI/CD, and in production deployments.

---

## 1. Consolidated Requirements Matrix

| Requirement | Required or Optional | Purpose | Where to get it | Free Tier Available? |
| :--- | :---: | :--- | :--- | :---: |
| **Python 3.11+** | **Required** | Core runtime environment for FastAPI backend and Streamlit UI | [python.org](https://www.python.org/downloads/) | Yes (Open Source) |
| `AGENTSHIELD_API_KEY` | Optional | Master API key for endpoint authentication (`X-API-Key` / `Authorization`) | User-generated string (e.g. `openssl rand -hex 32`) | Yes (Self-generated) |
| `DATABASE_URL` | Optional | Persistent PostgreSQL scan storage (`postgresql://user:pass@host:5432/db`) | Render Postgres, Neon.tech, Supabase, local Docker | Yes (Neon, Supabase, Render) |
| `AGENTSHIELD_LLM_PROVIDER` | Optional | Selects LLM Judge backend (`fake`, `ollama`, `openai`, `anthropic`, `groq`) | Environment setting (Defaults to `fake`) | Yes (`fake`, `ollama`, `groq`) |
| `AGENTSHIELD_LLM_API_KEY` | Conditional | Vendor API key required **only** when `AGENTSHIELD_LLM_PROVIDER` is `openai`, `anthropic`, or `groq` | OpenAI, Anthropic, or Groq developer consoles | Yes (Groq has high-rate free tier) |
| `AGENTSHIELD_LLM_MODEL` | Optional | LLM model identifier (e.g. `gpt-4o`, `claude-3-5-sonnet-20240620`, `llama3`) | Environment setting | N/A |
| `AGENTSHIELD_LLM_ENDPOINT` | Optional | Custom REST API endpoint for local Ollama or OpenAI-compatible model servers | Environment setting (e.g. `http://localhost:11434/v1/chat/completions`) | N/A |
| `AGENTSHIELD_RATE_LIMIT_RPM` | Optional | Sliding-window request rate limit ceiling (requests per minute) | Environment setting (Default `60`) | N/A |
| `AGENTSHIELD_ALLOWED_TARGET_DOMAINS` | Optional | Hostname allowlist for target URL scan probes (SSRF defense) | Environment setting (Default empty / unrestricted) | N/A |
| **Docker / Docker Compose** | Optional | Container runtime for production server deployment and containerized testing | [docker.com](https://www.docker.com/) | Yes (Community Edition) |
| **Ollama CLI** | Optional | Local LLM server for zero-cost, zero-data-leakage LLM Judge evaluations | [ollama.com](https://ollama.com/) | Yes (Open Source) |

---

## 2. API Keys & Secrets Reference

All secrets in AgentShield are parsed via Pydantic `SecretStr` in [`app/config.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/app/config.py) and [`app/evaluation/config.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/app/evaluation/config.py), ensuring they are never logged or exposed in tracebacks.

### 1. Backend Authentication Key (`AGENTSHIELD_API_KEY` / `API_KEY`)
* **Code Reference:** `app/config.py:135`, `app/main.py:89`
* **Purpose:** Protects REST API endpoints (`POST /api/v1/scans`, `POST /api/v1/evaluate/payload`, `GET /api/v1/scans`) requiring valid `X-API-Key` or `Authorization: Bearer <key>` headers.
* **Behavior if Missing:** Gracefully disables authentication (local development mode). Unauthenticated clients can access all endpoints.
* **Behavior if Invalid:** Returns HTTP `401 Unauthorized`.

### 2. LLM Judge API Key (`AGENTSHIELD_LLM_API_KEY` / `LLM_API_KEY`)
* **Code Reference:** `app/config.py:149`, `app/evaluation/config.py:107`
* **Purpose:** Authenticates requests to external cloud LLM providers (`openai`, `anthropic`, `groq`).
* **Behavior if Missing:**
  * **If provider is `fake` or `ollama`:** Ignored (`None`).
  * **If provider is `openai`, `anthropic`, or `groq`:** Hard startup crash (`ValueError: AGENTSHIELD_LLM_API_KEY is required when AGENTSHIELD_LLM_PROVIDER is set to ...`).

### 3. Database Connection URL (`DATABASE_URL` / `POSTGRES_URL`)
* **Code Reference:** `app/config.py:144`, `app/main.py:105`
* **Purpose:** Establishes SQLAlchemy ORM connections to PostgreSQL for persistent scan storage.
* **Behavior if Missing:** Gracefully falls back to `InMemoryScanRepository`. All scan history is preserved in RAM during process execution.

---

## 3. LLM Provider Options & Setup

AgentShield supports 5 provider modes for semantic LLM Judge evaluation:

| Mode | Provider Type | API Key Needed? | Local Setup | Recommended Model |
| :--- | :--- | :---: | :--- | :--- |
| **Default / Dev** | `fake` | No | None (Built-in mock) | N/A |
| **Local Zero-Cost** | `ollama` | No | Ollama binary + model | `llama3` |
| **Cloud Free-Tier** | `groq` | Yes | None | `llama-3.1-70b-versatile` |
| **Cloud Paid** | `openai` | Yes | None | `gpt-4o` |
| **Cloud Paid** | `anthropic` | Yes | None | `claude-3-5-sonnet-20240620` |

---

## 4. Environment Execution Pathways

### Pathway A: Zero-Cost, Fully Local Setup (Development / Testing)

Requires **zero cloud API keys**, **zero paid subscriptions**, and **no external database**.

```bash
# 1. Clone repository
git clone https://github.com/shivam-shukla888/agent-shield.git
cd agent-shield

# 2. Create and activate virtual environment
python -m venv .venv
# On Windows PowerShell: .\.venv\Scripts\Activate.ps1
# On macOS/Linux: source .venv/bin/activate

# 3. Install dependencies
pip install -e .[dev]

# 4. Start FastAPI Backend (Runs in-memory with Fake LLM Judge)
python -m uvicorn app.main:app --reload --port 8000

# 5. (Optional) Run Streamlit Workstation UI in a separate terminal
python -m streamlit run app.py
```

#### Optional: Enable Local LLM Judge via Ollama
```bash
# Install Ollama from https://ollama.com
ollama pull llama3

# Start AgentShield with local Ollama provider
export AGENTSHIELD_LLM_PROVIDER="ollama"
export AGENTSHIELD_LLM_MODEL="llama3"
python -m uvicorn app.main:app --port 8000
```

---

### Pathway B: Production / Hosted Setup (Full Security & Persistence)

Includes master API key authentication, PostgreSQL scan persistence, and Cloud LLM Judge evaluation.

```bash
# 1. Environment Configuration (.env)
export APP_HOST="0.0.0.0"
export APP_PORT="8000"
export LOG_LEVEL="INFO"
export AGENTSHIELD_API_KEY="your-secure-random-api-key"
export AGENTSHIELD_RATE_LIMIT_RPM="60"
export DATABASE_URL="postgresql://user:password@postgres-host:5432/agentshield"
export AGENTSHIELD_LLM_PROVIDER="groq" # or openai / anthropic
export AGENTSHIELD_LLM_API_KEY="gsk_your_groq_api_key"
export AGENTSHIELD_LLM_MODEL="llama-3.1-70b-versatile"
export AGENTSHIELD_ALLOWED_TARGET_DOMAINS="localhost,127.0.0.1,testagent.local,api.internal"

# 2. Run via Docker Compose
docker compose up -d
```

---

## 5. CI/CD Requirements

AgentShield's GitHub Actions workflow ([`.github/workflows/ci.yml`](file:///.github/workflows/ci.yml)) is **100% self-contained**.

* **GitHub Repository Secrets Required:** **Zero (0)**
* **Automated CI Validation:**
  1. Python 3.11 & 3.12 unit and integration test suite
  2. Security hardening and SSRF verification tests
  3. Static type checks (`mypy`) and linting (`flake8`)
  4. Dockerfile build validation and container health verification
  5. Secret leak scanning for hardcoded keys or credentials
