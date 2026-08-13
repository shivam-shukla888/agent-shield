# Production Observability & Structured Logging Specification (STEP 15A)

## Overview

AgentShield provides a production-ready, structured JSON logging and request correlation facility (`app/observability/`). This subsystem equips security operations and DevOps teams with machine-readable operational telemetry while enforcing strict security boundaries to prevent credential or sensitive payload disclosure.

---

## Architectural Directives & Design Principles

1. **Structured Machine-Readable Output**: All log entries are formatted as single-line, valid JSON objects emitted to stdout.
2. **Request Correlation**: Incoming HTTP requests are assigned or validated against an `X-Request-ID` correlation token, bound to Python async `contextvars` (`request_id_var`) and attached to all HTTP response headers.
3. **Strict Secret Redaction**: Reusable regex redaction sanitizes Bearer tokens, API keys, database credentials, passwords, and authorization secrets across all log fields before emission.
4. **Data Non-Disclosure**: System prompts, target response texts, authorization headers, request bodies, and database connection strings are strictly excluded from log records.
5. **Exception Safety**: Unhandled errors and exceptions log safe `error_type` class names rather than raw exception strings or tracebacks that might expose internal endpoints or secrets.
6. **Monotonic High-Precision Timing**: Operation durations (`duration_ms`) are calculated using `time.perf_counter()` and rounded to 2 decimal places.

---

## JSON Log Record Schema

Every log entry conforms to the following standardized JSON schema:

```json
{
  "timestamp": "2026-08-13T18:27:48.123456+00:00",
  "level": "INFO",
  "event": "scan.completed",
  "request_id": "req_8f1a39b2c01d4a8e",
  "scan_id": "SCAN_20260813_001",
  "target_name": "Production Customer Support Agent",
  "status": "completed",
  "duration_ms": 142.85,
  "total_probes": 5,
  "completed_executions": 5,
  "failed_executions": 0,
  "total_findings": 1,
  "total_risks": 1
}
```

### Standard Fields

| Field | Type | Description |
|---|---|---|
| `timestamp` | `string` | ISO-8601 UTC timestamp format |
| `level` | `string` | Logging severity level (`INFO`, `WARNING`, `ERROR`, `DEBUG`) |
| `event` | `string` | Dot-delimited machine-readable event identifier |
| `request_id` | `string` (optional) | Correlated request identifier bound to current context |
| `duration_ms` | `float` (optional) | Monotonic operation duration in milliseconds |
| `error_type` | `string` (optional) | Exception class name for failed operations |

---

## Event Taxonomy Table

The platform emits structured events across all operational boundaries:

| Boundary / Category | Event Name | Level | Context Fields |
|---|---|---|---|
| **API Request Lifecycle** | `api.request.started` | `INFO` | `method`, `path`, `request_id` |
| | `api.request.completed` | `INFO` | `method`, `path`, `status_code`, `duration_ms`, `request_id` |
| | `api.request.failed` | `WARNING` | `method`, `path`, `error_type`, `duration_ms`, `request_id` |
| **Authentication & Limits** | `auth.success` | `INFO` | `status` |
| | `auth.failure` | `WARNING` | `status` |
| | `rate_limit.exceeded` | `WARNING` | `status` |
| **Scan Lifecycle** | `scan.created` | `INFO` | `scan_id`, `target_name`, `total_probes`, `status` |
| | `scan.started` | `INFO` | `scan_id`, `target_name`, `total_probes` |
| | `scan.completed` | `INFO` | `scan_id`, `target_name`, `status`, `duration_ms`, summary counters |
| | `scan.partial` | `WARNING` | `scan_id`, `target_name`, `status`, `duration_ms`, summary counters |
| | `scan.failed` | `ERROR` | `scan_id`, `target_name`, `status`, `duration_ms`, summary counters |
| **Probe Lifecycle** | `probe.started` | `INFO` | `scan_id`, `probe_id` |
| | `probe.completed` | `INFO` | `scan_id`, `probe_id`, `execution_id`, `duration_ms`, `status` |
| | `probe.failed` | `WARNING` | `scan_id`, `probe_id`, `execution_id`, `duration_ms`, `status` |
| **Evaluation Lifecycle** | `evaluation.completed` | `INFO` | `scan_id`, `probe_id`, `execution_id`, `evaluator_type`, `verdict`, `confidence`, `duration_ms` |
| | `evaluation.error` | `WARNING` | `scan_id`, `probe_id`, `execution_id`, `evaluator_type`, `verdict`, `confidence`, `duration_ms` |
| **Finding & Risk** | `finding.created` | `INFO` | `scan_id`, `finding_id`, `category`, `severity`, `confidence` |
| | `risk.assessed` | `INFO` | `scan_id`, `risk_id`, `finding_id`, `risk_level`, `risk_score`, `confidence` |
| **LLM Provider** | `llm.request.started` | `INFO` | `provider`, `model` |
| | `llm.request.completed` | `INFO` | `provider`, `model`, `status`, `duration_ms` |
| | `llm.request.failed` | `WARNING` | `provider`, `model`, `status`, `error_type`, `duration_ms` |
| **Repository Operations** | `repository.save` | `INFO` | `repository_type`, `operation`, `scan_id` |
| | `repository.get` | `INFO` | `repository_type`, `operation`, `scan_id`, `found` |
| | `repository.list` | `INFO` | `repository_type`, `operation`, `total_scans` |

---

## Secret & Data Non-Disclosure Policy

To ensure compliance with enterprise security directives, the observability module enforces automatic redaction:

```python
# Automatic redaction rules enforced by JSONFormatter
REDACT_PATTERNS = [
    (r"(Bearer\s+)[A-Za-z0-9_\-\.=]+", r"\1[REDACTED]"),
    (r"(X-API-Key:\s*)[A-Za-z0-9_\-\.=]+", r"\1[REDACTED]"),
    (r"(api_key=)[A-Za-z0-9_\-\.=]+", r"\1[REDACTED]"),
    (r"sk-[A-Za-z0-9]{20,}", "[REDACTED_API_KEY]"),
    (r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s]+", "postgresql://[REDACTED]@..."),
]
```

---

## Verification & Testing

The observability module is verified by automated test suite [`tests/test_observability.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/tests/test_observability.py), asserting:
- Single-line JSON log structure (`timestamp`, `level`, `event`).
- Complete lifecycle event emissions across scan, probe, evaluation, finding, and risk components.
- Request correlation generation, preservation, and HTTP header propagation.
- Zero leakage of API keys, bearer tokens, LLM credentials, target response bodies, system prompts, or database URLs.
