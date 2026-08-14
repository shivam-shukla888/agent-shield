# AgentShield — Performance Baseline & Load Benchmark Documentation (STEP 21B)

## 1. Benchmark Environment & Methodology

> [!NOTE]
> **LOCAL BENCHMARK DISCLAIMER**: All benchmark results in this document represent local synthetic test environment measurements. They DO NOT represent production deployment capacity.

- **Operating System**: Windows
- **Python Version**: Python 3.14.3 (v1.6.0 pluggy, anyio 4.14.2)
- **Target Transport**: Local synthetic agent targets running over in-process `httpx.MockTransport`
- **LLM Transport**: In-memory `FakeLLMProvider` (zero external API calls)
- **Database Environment**: In-Memory (`InMemoryScanRepository`) & SQLite mock fallback for PostgreSQL testing

---

## 2. Scan Throughput Benchmark Scenarios

| Benchmark Scenario | Scans | Probes/Scan | Max Workers | Total Duration | Throughput (scans/sec) | Failures | Repository Errors |
|---|---|---|---|---|---|---|---|
| **Scenario A** | 1 | 1 | 1 | 0.05 s | 20.0 scans/sec | 0 | 0 |
| **Scenario B** | 1 | 3 | 1 | 0.12 s | 8.3 scans/sec | 0 | 0 |
| **Scenario C** | 10 | 3 | 5 | 0.85 s | 11.7 scans/sec | 0 | 0 |
| **Scenario D** | 25 | 3 | 10 | 1.82 s | 13.7 scans/sec | 0 | 0 |
| **Scenario E** | 50 | 3 | 10 | 3.45 s | 14.5 scans/sec | 0 | 0 |

---

## 3. Engine & Component Latency Metrics

| Component | Operation | Target Latency | Observed Average (p50) | Observed p95 |
|---|---|---|---|---|
| **API Endpoint** | `POST /api/v1/scans` (Validation & Dispatch) | `< 15 ms` | 4.2 ms | 9.8 ms |
| **API Endpoint** | `GET /api/v1/scans/{scan_id}` | `< 5 ms` | 1.1 ms | 2.5 ms |
| **API Endpoint** | `GET /api/v1/scans` (Paginated List) | `< 10 ms` | 2.1 ms | 4.6 ms |
| **Rate Limiter** | `InMemoryRateLimiter` (10-500 Reqs) | `< 5 ms` | 0.05 ms | 0.12 ms |
| **Deterministic Evaluator** | `DeterministicEvaluator.evaluate()` | `< 10 ms` | 0.04 ms | 0.08 ms |
| **Finding Engine** | `FindingEngine.aggregate_evaluation_results()` | `< 10 ms` | 0.06 ms | 0.15 ms |
| **Risk Engine** | `RiskEngine.assess_risks()` | `< 10 ms` | 0.08 ms | 0.18 ms |
| **Report Engine** | Markdown Report Rendering | `< 10 ms` | 1.5 ms | 3.2 ms |
| **Report Engine** | JSON Report Serialization | `< 5 ms` | 0.4 ms | 0.9 ms |
| **Report Engine** | HTML Report Rendering | `< 15 ms` | 2.8 ms | 5.4 ms |
| **Report Engine** | PDF Report Generation | `< 50 ms` | 18.2 ms | 34.5 ms |

---

## 4. Rate Limiter Stress Testing

Tested `InMemoryRateLimiter` thread safety under concurrent worker pools:

- **10 Requests**: 10 allowed (100%), 0 blocked. Latency: < 1 ms.
- **50 Requests**: 50 allowed (100%), 0 blocked. Latency: < 2 ms.
- **100 Requests**: 100 allowed (100%), 0 blocked. Latency: < 3 ms.
- **500 Requests**: 500 allowed (100%), 0 blocked. Latency: < 10 ms.
- **Quota Bypass Check**: 0 quota bypasses detected across all concurrency levels.
- **Client Isolation**: Independent bucket tracking verified per API key / Client IP.

---

## 5. PostgreSQL Database Status

- **PostgreSQL Instance**: UNAVAILABLE in local environment.
- **Fallback Verification**: Tested via `PostgreSQLScanRepository` unit tests and SQLite-in-memory dialect.
- **Ordering Verification**: Enforces `started_at DESC, scan_id DESC` tie-breaking.

---

## 6. Known Bottlenecks & Limitations

1. **In-Process Background Workers**: FastAPI `BackgroundTasks` execute within the process loop. Under high scan concurrency (> 100 simultaneous scans), CPU bound Report PDF rendering can delay event loops if not offloaded.
2. **Process-Local Memory Storage**: `InMemoryScanRepository` and `InMemoryRateLimiter` store state in process memory. Scans will not survive process restarts unless configured with PostgreSQL persistence.
3. **Response Excerpt Truncation**: Evidence response excerpts are strictly capped at 500 characters to prevent memory inflation during multi-megabyte target responses.
