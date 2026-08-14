# AgentShield — Container Security & Infrastructure Hardening

## 1. Container Hardening Standards

AgentShield production container artifacts are engineered according to the principle of least privilege and container security best practices.

### Key Security Controls
- **Non-Root Execution**: Container process runs under dedicated unprivileged user `agentshield` (`UID 1000:1000`).
- **Minimal Image Footprint**: Multi-stage Docker build utilizing official Python slim runtime images to minimize attack surface.
- **Zero Secrets In Image**: Docker images contain no hardcoded secrets, `.env` files, or production credentials.
- **No Build Tooling In Production**: Compiler toolchains, dev dependencies, and test artifacts are stripped in the builder stage.
- **Internal Network Isolation**: PostgreSQL database service operates on an isolated internal bridge network (`agentshield-net`) without public host port bindings.

---

## 2. Security Configuration Example (`docker-compose.yml`)

```yaml
version: '3.8'

services:
  app:
    build: .
    image: agentshield:1.0.0
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - AGENTSHIELD_API_KEY=${AGENTSHIELD_API_KEY}
      - DATABASE_URL=${DATABASE_URL}
      - APP_ENV=production
    networks:
      - agentshield-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=agentshield
      - POSTGRES_USER=agentshield
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - agentshield-net

networks:
  agentshield-net:
    driver: bridge

volumes:
  postgres_data:
```
