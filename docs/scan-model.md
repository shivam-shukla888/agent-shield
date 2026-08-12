# Scan Result Domain Contract & Specification (STEP 9A)

This document defines the architectural contract, data structure, status lifecycle, lineage relationships, and security boundaries for **AgentShield's Scan Domain Contract** (`ScanStatus`, `ScanSummary`, `ScanResult`).

---

## 1. PURPOSE OF SCANRESULT

`ScanResult` serves as the complete, top-level aggregated container representing an AgentShield security scan run. It encapsulates the full operational and security testing lifecycle:

```
SecurityProbe
      ↓
ProbeExecution
      ↓
EvaluationResult
      ↓
Finding
      ↓
RiskAssessment
      ↓
ScanResult
```

> [!IMPORTANT]
> **Container Object**:
> `ScanResult` aggregates already-computed objects from the pipeline. It does **NOT** compute risk scores, execute probes, perform evaluations, or generate report artifacts internally.

---

## 2. SCAN LIFECYCLE STATUS (`ScanStatus`)

`ScanStatus` models the operational execution state of a security scan:

| Status Value | Meaning | Operational Semantics |
| :--- | :--- | :--- |
| **`CREATED`** | Scan object initialized | Scan created, execution has not started. |
| **`RUNNING`** | Execution in progress | Probe dispatch and target communication active. |
| **`COMPLETED`** | Successfully completed | All probe executions and evaluations finished cleanly. |
| **`PARTIAL`** | Partial operational completion | Scan finished, but some executions or evaluations encountered operational errors. |
| **`FAILED`** | Operational failure | Fundamental execution failure prevented scan completion. |

> [!WARNING]
> **Operational Failure $\neq$ Security Violation**:
> `PARTIAL` or `FAILED` statuses indicate operational or transport execution issues (e.g. HTTP 504 Timeout or network unreachable). They do **NOT** imply security vulnerabilities.

---

## 3. STATISTICAL SUMMARY (`ScanSummary`)

`ScanSummary` provides declarative, aggregated counters for the scan run:

```python
ScanSummary(
    total_probes=3,
    completed_executions=3,
    failed_executions=0,
    safe_evaluations=0,
    violation_evaluations=3,
    inconclusive_evaluations=0,
    error_evaluations=0,
    total_findings=3,
    info_risks=0,
    low_risks=0,
    medium_risks=0,
    high_risks=2,
    critical_risks=1,
)
```

- All counters are strictly non-negative integers (`>= 0`).
- Summary values are constructed declaratively by the scan orchestrator/engine.

---

## 4. CROSS-OBJECT LINEAGE & VALIDATION

`ScanResult` maintains strict relational lineage across pipeline objects:

1. **Execution Lineage**: `EvaluationResult.execution_id` must correspond to a valid `ProbeExecution.execution_id` in `executions`.
2. **Finding Lineage**: `Finding.affected_execution_ids` references execution IDs represented in the scan.
3. **Risk Lineage**: `RiskAssessment.finding_id` must reference a valid `Finding.finding_id` present in `findings`.

---

## 5. IMMUTABILITY & TOP-LEVEL PROTECTION

All scan domain models (`ScanSummary`, `ScanResult`) use `ConfigDict(frozen=True)`:

- **Reassignment Protection**: Reassigning top-level fields (e.g. `scan.target_name = "New"`) raises a `ValidationError`.
- **Nested Mutability Note**: `frozen=True` protects top-level attributes, but does not guarantee deep immutability of nested mutable Python objects (e.g. `metadata` dictionaries or list elements).

---

## 6. SECURITY & SECRET BOUNDARY

`ScanResult` enforces strict secret non-disclosure rules:

- ❌ **No Credentials**: `ScanResult` must **NEVER** store API keys, passwords, bearer tokens, or target authorization headers.
- ❌ **No TargetAuthConfig**: `TargetAuthConfig` objects are omitted from `ScanResult` to prevent accidental credential leakage in saved scan artifacts or reports.
- ✔ **Safe Data**: Contains target name, public endpoint, execution output excerpts, findings, and risk assessments.

---

## 7. FUTURE SCAN ENGINE RESPONSIBILITY

`ScanResult` is purely a declarative domain container. Future components will interact with it as follows:

* **ScanEngine / Orchestrator**: Will execute probes, call evaluators, invoke finding & risk engines, construct summary metrics, and instantiate the final `ScanResult`.
* **Report Generators**: Will ingest a immutable `ScanResult` to render HTML/Markdown/JSON audit reports.
