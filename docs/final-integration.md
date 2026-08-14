# AgentGuard — Final System Integration & End-to-End Architecture

## 1. Complete System Architecture & Dataflow

AgentGuard is a production-grade, modular security testing platform built to evaluate AI agents against threat vectors safely and deterministically.

```
Client
  ↓
Authentication (X-API-Key / Bearer)
  ↓
Rate Limiter (In-Memory Sliding Window)
  ↓
FastAPI Router (/api/v1/scans)
  ↓
ScanService (DTO ↔ Domain Conversion)
  ↓
Async Background Task (In-Process)
  ↓
ScanEngine (Orchestrator)
  ├── AttackEngine (Probe Execution) ──► TargetAdapter (GenericHTTPAdapter + SSRF Validation) ──► Target Agent
  ├── Evaluator Strategy (Deterministic / LLM / Hybrid) ──► EvaluationResult
  ├── FindingEngine (Category Aggregation) ──► Finding
  └── RiskEngine (Contextual Scoring) ──► RiskAssessment
  ↓
ScanResult (Domain Model)
  ↓
Repository Layer (InMemoryScanRepository / PostgreSQLScanRepository)
  ↓
Report Engine (Markdown / JSON / HTML / PDF)
  ↓
Public ScanResponse / Report Download DTO
```

---

## 2. Supported Evaluation Modes

1. **DeterministicEvaluator**: Fast, 100% reproducible pattern and rule matching in-memory. Operates with high throughput (> 5,000 evals/sec).
2. **LLMEvaluator**: Uses LLM-as-a-Judge for complex semantic vulnerability detection via `FakeLLMProvider` or `ProductionLLMProvider`.
3. **HybridEvaluationStrategy**: Combines deterministic speed with LLM semantic reasoning. Deterministic violations override LLM judgments for maximum safety and confidence.

---

## 3. Persistence Modes & Schema Management

- **InMemoryScanRepository**: Thread-safe in-memory store for high-throughput testing and local development. Includes safe pagination and deterministic sorting (`started_at DESC`, `scan_id DESC`).
- **PostgreSQLScanRepository**: Production relational storage using SQLAlchemy 2.0. Auto-managed schema initialization via `init_db()`. Credentials are encapsulated securely using `DATABASE_URL`.

---

## 4. Security & Isolation Boundaries

- **SSRF Hardening**: Outbound target requests are validated to block `127.0.0.0/8`, `::1`, RFC1918 private IPv4 ranges, link-local addresses, multicast, and DNS names resolving to internal IPs.
- **Secret Protection**: Credentials, API keys, and database connection strings are masked via Pydantic `SecretStr` and redacted from structured JSON log events.
- **Untrusted Input Escaping**: All target responses and evidence excerpts are treated as untrusted data and sanitized/escaped across Markdown, HTML, and PDF reports.
