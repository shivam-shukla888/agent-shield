# AgentShield Changelog

All notable changes to the AgentShield platform are documented in this file.

## [1.0.0] - 2026-08-13 (Production Release) *(Originally released as AgentGuard; project renamed to AgentShield)*

### Core Security Scanning & Probes
- Implemented core modular monolith scanner supporting HTTP targets (`GenericHTTPAdapter`).
- Added initial security probe suite (System Prompt Disclosure, Instruction Override, Tool Authorization Bypass).
- Implemented target response extraction via JSONPath and template rendering.

### Evaluation Strategies
- **Deterministic Engine**: Added fast pattern and regex matching in-memory.
- **LLM Judge Evaluator**: Integrated semantic evaluation via `LLMEvaluator` with `FakeLLMProvider` and `ProductionLLMProvider`.
- **Hybrid Strategy**: Implemented fallback evaluation strategy prioritizing deterministic certainty while leveraging LLM semantic judgment.

### Finding & Risk Engines
- **FindingEngine**: Automated grouping and category-level deduplication of probe evaluation violations.
- **RiskEngine**: Contextual risk calculation formula incorporating impact, exploitability, blast radius, asset sensitivity, and tool privileges.

### REST API & Authentication
- Exposed versioned REST API (`/api/v1/scans`, `/api/v1/scans/{id}`, `/api/v1/scans/{id}/report`).
- Implemented constant-time API key authentication (`X-API-Key` & `Bearer` token support).
- Added in-memory sliding window rate limiting per client API key with `Retry-After` header.
- Added support for `Idempotency-Key` header for idempotent scan submissions.

### Persistence & Storage
- Implemented dual-repository architecture: `InMemoryScanRepository` and `PostgreSQLScanRepository` (SQLAlchemy 2.0).
- Added paginated scan listing (`limit`, `offset`) with deterministic tie-breaking sorting (`started_at DESC`, `scan_id DESC`).

### Reporting Engine
- Multi-format report generation: Markdown, JSON, HTML, and PDF formats.
- Added strict untrusted content sanitization and escaping across all report formats.

### Security Hardening & Observability
- Outbound SSRF target protection blocking loopback, private IPv4/IPv6, link-local, and cloud metadata IPs.
- Single-line structured JSON logger with request correlation IDs (`X-Request-ID`).
- Masked secret strings (`SecretStr`) and sanitized HTTP error responses (zero stack trace disclosure).

### Containerization & Deployment
- Production multi-stage Dockerfile with non-root runtime user (`agentshield:1000`).
- Docker Compose configuration with PostgreSQL service isolation and health checks.
- GitHub Actions CI/CD pipeline running unit tests, security tests, and Docker validation.
