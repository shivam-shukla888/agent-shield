# Scan Engine Orchestrator Specification (STEP 9B)

This document defines the architectural specification, component boundary contracts, dependency injection patterns, operational error semantics, and execution flow for **AgentShield's Scan Engine** (`ScanEngine`).

---

## 1. PURPOSE OF SCANENGINE

`ScanEngine` is the top-level orchestration layer of AgentShield. It coordinates all previously built security pipeline engines into a single end-to-end security scan:

```text
                 ScanEngine
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
 AttackEngine    Evaluator     FindingEngine
       │             │             │
       ▼             ▼             ▼
 TargetAdapter  EvaluationResult  Finding
                                     │
                                     ▼
                                RiskEngine
                                     │
                                     ▼
                              RiskAssessment
                                     │
                                     ▼
                                ScanResult
```

> [!IMPORTANT]
> **Strict Orchestrator Boundary**:
> `ScanEngine` is strictly an orchestrator. It does **NOT** format target HTTP requests, evaluate response strings, aggregate findings directly, or compute risk scores internally.

---

## 2. CONSTRUCTOR DEPENDENCY INJECTION

`ScanEngine` relies on explicit constructor dependency injection:

```python
ScanEngine(
    attack_engine=attack_engine,
    evaluator=evaluator,
    finding_engine=finding_engine,
    risk_engine=risk_engine,
)
```

### Architectural Benefits
- **Testability**: Unit tests pass mock or fake engine implementations.
- **Pluggability**: Concrete engines (e.g. replacing `DeterministicEvaluator` with an `LLMJudgeEvaluator`) plug in without modifying `ScanEngine` orchestration logic.

---

## 3. ORCHESTRATION PIPELINE FLOW

The main entry point `ScanEngine.run_scan()` executes the pipeline sequentially:

1. **Identifier & Input Validation**: Strips and validates non-empty `scan_id` and `target_name`.
2. **Timestamp Recording**: Captures `started_at` in timezone-aware UTC.
3. **Empty Probe Check**: Returns a valid `ScanStatus.COMPLETED` result with zero counters if `probes` is empty.
4. **Attack Dispatch (`AttackEngine`)**: Calls `self.attack_engine.execute_probes(probes)` to produce `List[ProbeExecution]`.
5. **Execution Evaluation (`Evaluator`)**: Evaluates each probe/execution pair via `self.evaluator.evaluate(probe, execution)` to produce `List[EvaluationResult]`.
6. **Finding Aggregation (`FindingEngine`)**: Calls `self.finding_engine.aggregate_evaluation_results(evaluations)` to derive category-deduplicated `Finding` objects.
7. **Risk Assessment (`RiskEngine`)**: Assesses contextual environment risk for each `Finding` using caller-injected `RiskFactors`.
8. **Status & Summary Computation**: Computes overall `ScanStatus` and builds declarative `ScanSummary`.
9. **Artifact Assembly**: Constructs and returns the final immutable `ScanResult`.

---

## 4. COMPONENT BOUNDARIES

### AttackEngine Boundary
- `ScanEngine` calls `AttackEngine.execute_probes(probes)`.
- `ScanEngine` never calls `TargetAdapter` directly or inspects raw HTTP requests/headers.

### Evaluator Boundary
- `ScanEngine` passes `(probe, execution)` to `Evaluator.evaluate()`.
- `ScanEngine` never inspects target response bodies or executes regex detection rules.

### FindingEngine Boundary
- `ScanEngine` passes evaluations to `FindingEngine.aggregate_evaluation_results()`.
- `ScanEngine` never constructs `Finding` objects directly.

### RiskEngine Boundary
- `ScanEngine` passes `(finding, risk_factors)` to `RiskEngine.assess_risk()`.
- `ScanEngine` never calculates numeric risk scores or risk level thresholds internally.

---

## 5. ENVIRONMENTAL RISK CONTEXT INJECTION

Risk assessments are contextual. `ScanEngine` requires the caller to provide `RiskFactors`:

```python
scan_engine.run_scan(
    scan_id="SCAN_001",
    target_name="Support Agent",
    probes=probes,
    risk_factors=RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.WRITE,
    ),
)
```

---

## 6. OPERATIONAL ERROR VS. SECURITY VIOLATION SEMANTICS

| Operational Event | Category | ScanStatus Impact |
| :--- | :--- | :--- |
| `EvaluationVerdict.VIOLATION` | **Security Finding** | `ScanStatus.COMPLETED` (Discovered vulnerability is a successful security result). |
| `ExecutionStatus.ERROR` | **Operational Transport Failure** | `ScanStatus.PARTIAL` or `FAILED`. |
| `EvaluationVerdict.ERROR` | **Operational Evaluator Failure** | `ScanStatus.PARTIAL` or `FAILED`. |

---

## 7. SEQUENTIAL EXECUTION & DETERMINISM

- **Sequential Execution**: In the MVP, probes execute sequentially to simplify failure isolation, log tracing, and deterministic ordering.
- **Determinism**: Given identical probes, target responses, and risk factors, `ScanEngine` yields 100% deterministic findings and risk assessments.

---

## 8. FUTURE ASYNCHRONOUS ARCHITECTURE ROADMAP

While `ScanEngine` runs synchronously in-memory for the MVP, future architecture will wrap `ScanEngine` inside background workers (e.g. Celery workers or async task queues) without modifying `ScanEngine` internal logic.
