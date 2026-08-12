# Attack Engine Architecture & Execution Contract

This document defines the architectural contract, design boundaries, and execution semantics for **AgentShield's Attack Engine** (`AttackEngine`).

---

## 1. PURPOSE & RESPONSIBILITIES

The `AttackEngine` is responsible for orchestrating the execution of `SecurityProbe` specifications against a target agent via an abstract `TargetAdapter`.

```
SecurityProbe ──► AttackEngine ──► TargetAdapter ──► TargetAgent ──► TargetResult ──► ProbeExecution
```

### Primary Responsibilities
1. **Probe Dispatch**: Passes abstract security probe prompts to the configured `TargetAdapter`.
2. **Execution Tracking**: Generates unique `execution_id` (UUID) strings, records `started_at` / `completed_at` timestamps, and assigns `ExecutionStatus`.
3. **Result Encapsulation**: Packages normalized `TargetResult` objects into `ProbeExecution` records.
4. **Fault Tolerance**: Traps unhandled adapter-level Python exceptions, recording `status = ERROR` for the failing execution while continuing to process remaining probes in the scan suite.

---

## 2. OUT OF SCOPE (WHAT ATTACK ENGINE MUST NOT DO)

To preserve architectural separation of concerns, the `AttackEngine` **must NEVER**:
* **Judge Vulnerabilities**: The engine does not parse response text to decide if a jailbreak or prompt leak succeeded.
* **Assign Severity or Calculate Risk**: Severity hints belong to probes; risk scoring belongs to downstream engines.
* **Generate Security Findings**: `Finding` objects are produced solely by the **Detection Engine**.
* **Directly Access HTTP/Network**: The engine receives `TargetAdapter` via dependency injection and does not know transport implementation details.
* **Modify Target Configuration**: The engine cannot alter endpoint URLs, headers, or authentication tokens.

---

## 3. DOMAIN MODEL DISTINCTIONS

### Probe vs. Execution
* **`SecurityProbe`**: Declarative specification of **WHAT** to test (e.g. `PROMPT_LEAK_001`). Immutable and reusable across scans.
* **`ProbeExecution`**: A single instance of running a probe against a target agent at a specific point in time. Identifies **ONE PARTICULAR RUN** with a unique UUID.

### TargetResult vs. ProbeExecution
* **`TargetResult`**: Describes target communication behavior (extracted text output, status code, latency, transport error).
* **`ProbeExecution`**: The overall execution record wrapping the `TargetResult` along with run UUID, probe ID, status, and execution timestamps.

---

## 4. EXECUTION STATUS & ERROR SEMANTICS

The engine manages an `ExecutionStatus` enum: `PENDING`, `RUNNING`, `COMPLETED`, `ERROR`.

### Error Semantics: `ExecutionStatus.ERROR` vs. `TargetResult.error`

> [!IMPORTANT]
> **Crucial Distinction**:
> * **`ExecutionStatus.COMPLETED` + `TargetResult.error`**: The target request was executed, but the adapter returned a transport-level failure (e.g., HTTP 504 Timeout, HTTP 401 Auth Error, HTTP 500 Crash). From the `AttackEngine`'s perspective, the probe execution finished successfully and recorded the target's transport outcome.
> * **`ExecutionStatus.ERROR`**: An unhandled Python exception occurred inside the engine or adapter code itself (e.g., memory exhaustion, unhandled runtime bug). The execution loop catches the exception, logs `status = ERROR`, and continues scanning.

---

## 5. WHY RETRIES ARE DISABLED

AgentShield's `AttackEngine` **does NOT automatically retry** failed or timed-out requests.

### Reasoning
AI agents often invoke external tools and functions (`cancel_order`, `send_email`, `process_payment`). A network timeout or socket drop does **NOT** guarantee that the target agent did not execute the tool side-effect. Automatically retrying a timed-out probe risks duplicating real-world side-effects or causing compounding rate-limit penalties.

---

## 6. SEQUENTIAL EXECUTION & FUTURE CONCURRENCY

### Week 1 MVP Behavior (Sequential)
Probes execute in deterministic order (`probe 1` $\rightarrow$ `probe 2` $\rightarrow$ `probe 3`). Sequential execution ensures:
1. Predictable, reproducible test ordering across test runs.
2. Prevention of race conditions when testing agents with stateful tools or shared memory.
3. Simple, audit-friendly logging trajectories.

### Future Concurrency Roadmap
Future releases will introduce worker pools and async task queues for parallel scan execution, while preserving per-agent state isolation boundaries.
