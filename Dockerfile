# ============================================================
# AgentGuard / AgentShield — Production Container Image
# ============================================================
# - Base: python:3.11-slim (minimal, no dev tools).
# - Non-root user "agentguard" (UID 1000).
# - Zero baked-in secrets.
# - Uvicorn ASGI production server.
# ============================================================

FROM python:3.11-slim AS base

# ---------- OS-level setup ----------
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ---------- Non-root user ----------
RUN groupadd --gid 1000 agentguard \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash agentguard

# ---------- Application directory ----------
WORKDIR /opt/agentguard

# ---------- Python dependencies ----------
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . || true

# Install runtime deps explicitly so the layer is cached even
# before the full source copy.
COPY . .
RUN pip install --no-cache-dir .

# ---------- Ownership ----------
RUN chown -R agentguard:agentguard /opt/agentguard

# ---------- Switch to non-root user ----------
USER agentguard

# ---------- Runtime ----------
ENV APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Graceful SIGTERM via exec form (PID 1).
CMD ["python", "-m", "uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-level", "info", \
     "--access-log", \
     "--proxy-headers"]
