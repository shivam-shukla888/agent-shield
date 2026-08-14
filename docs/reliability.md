# AgentGuard — System Reliability & Resilience Architecture (STEP 21B)

## 1. Runtime Pipeline Architecture

```
POST /api/v1/scans ──► ScanService ──► Background Job ──► ScanEngine ──► AttackEngine ──► TargetAdapter ──► Evaluator ──► FindingEngine ──► RiskEngine ──► Repository ──► ScanResponse ──► Reports
```

---

## 2. Scan Lifecycle & State Transition Matrix

The scan lifecycle follows explicit, deterministic state transitions:

```
          ┌──────────┐
          │ CREATED  │
          └────┬─────┘
               │ (Background Task Dispatched)
               ▼
          ┌──────────┐
          │ RUNNING  │
          └────┬─────┘
               │
    ┌──────────┼──────────┐
    │ All Safe │ Mixed    │ Catastrophic Worker Exception
    ▼          ▼          ▼
┌───────────┐ ┌─────────┐ ┌────────┐
│ COMPLETED │ │ PARTIAL │ │ FAILED │
└───────────┘ └─────────┘ └────────┘
```

- **CREATED**: API request validated; initial placeholder record stored.
- **RUNNING**: Background worker executing security probes against Target Adapter.
- **COMPLETED**: All probes and evaluations finished cleanly without operational errors.
- **PARTIAL**: Probes completed, but one or more probes or evaluations encountered operational errors (e.g. HTTP 500, timeout). Probes that succeeded are fully preserved.
- **FAILED**: Catastrophic execution or worker crash. System captures exception and marks scan as FAILED safely.

---

## 3. Failure Handling & Failure Domain Isolation

### 3.1 Target Failure & Timeout Behavior
- Target HTTP error status codes (400, 401, 403, 404, 429, 500, 502, 503) produce `TargetResult(success=False)`.
- Operational transport errors return `EvaluationVerdict.ERROR` and **NEVER** produce security vulnerability findings.
- Probes execute sequentially; a timeout on probe N does not prevent execution of probe N+1.

### 3.2 LLM Provider Reliability & Fallback
- Transport failures (401, 403, 429, 500, 503, timeout, malformed JSON) in `LLMEvaluator` produce `EvaluationVerdict.ERROR`.
- `HybridEvaluationStrategy` guarantees that if the LLM judge fails, the `DeterministicEvaluator` result is preserved (e.g. prompt leaks are still detected).
- Credentials are isolated: target tokens and LLM API keys are handled separately and sanitized from all exception messages.

### 3.3 Repository Concurrency & Failure Handling
- `InMemoryScanRepository` uses `threading.Lock()` to ensure thread-safe concurrent `save()`, `get_by_id()`, and `list_all()` operations.
- `PostgreSQLScanRepository` provides transactional isolation.
- Operational repository failures cause `/health/ready` to return `HTTP 503 Service Unavailable`.

---

## 4. Concurrency & Idempotency Guarantees

- **Concurrent Scan Submissions**: Multiple requests across different targets, API keys, or clients generate unique, non-colliding scan IDs.
- **Same Scan ID Concurrency**: Submitting multiple requests with the same explicit `scan_id` is idempotent; duplicate requests return `HTTP 202` with the existing scan status without state corruption.
- **Data Lineage Consistency**: `ExecutionID`, `Finding.affected_execution_ids`, `Finding.affected_probe_ids`, `RiskAssessment.finding_id`, and `ScanResponse` remain correlated under concurrent execution.

---

## 5. Graceful Shutdown & Process Termination

- **In-Process Background Jobs**: Background tasks run in the FastAPI process thread pool. Jobs active during process termination cannot survive process restarts unless stored in a persistent backend.
- **Data Protection**: Completed scan results saved to repository prior to shutdown remain valid and retrievable.
