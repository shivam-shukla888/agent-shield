# Evaluation Domain Contract & Specification

This document defines the architectural contract, design boundaries, and taxonomy for **AgentShield's Evaluation Layer** (`EvaluationResult`, `EvaluationVerdict`, `Evaluator`).

---

## 1. DATA FLOW & PIPELINE SEPARATION

AgentShield enforces a strict separation between executing security probes, capturing target behavior, evaluating policy adherence, and aggregating findings:

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐     ┌───────────┐     ┌─────────────────┐     ┌─────────┐
│SecurityProbe │ ──► │ AttackEngine  │ ──► │ TargetResult │ ──► │ Evaluator │ ──► │EvaluationResult │ ──► │ Finding │
└──────────────┘     └───────────────┘     └──────────────┘     └───────────┘     └─────────────────┘     └─────────┘
  (Test Input)         (Execution)          (Target Output)      (Policy Judge)    (Per-Run Verdict)     (Vulnerability)
```

### Key Domain Distinctions
* **`TargetResult`**: Describes **WHAT THE TARGET DID** (raw response text, status code, latency, transport error). Contains zero security policy evaluation.
* **`EvaluationResult`**: Describes **WHAT AGENTSHIELD CONCLUDED** about that specific test execution run (verdict, confidence, evidence).
* **`Finding`**: Aggregate vulnerability object (created in future layers) summarizing validated, persistent security issues across scan runs.

> [!IMPORTANT]
> **EvaluationResult is NOT a Finding**:
> An `EvaluationResult` with `verdict = VIOLATION` represents a single failed test execution. A `Finding` encapsulates additional context, such as asset impact, risk scoring, remediation instructions, and vulnerability lifecycle tracking.

---

## 2. EVALUATION VERDICTS (`EvaluationVerdict`)

The evaluation verdict summarizes whether the target maintained expected security behavior for a specific probe execution:

| Verdict | Meaning & Criteria | Example Scenario |
| :--- | :--- | :--- |
| **`SAFE`** | Evidence confirms target maintained expected security controls. | Target agent explicitly refused to disclose system instructions. |
| **`VIOLATION`** | Evidence confirms target breached the probe's security expectation. | Target agent leaked system prompt text or executed an unauthorized tool. |
| **`INCONCLUSIVE`** | Available evidence is insufficient, ambiguous, or truncated. | Target agent returned a generic error or ambiguous response text. |
| **`ERROR`** | Evaluation process could not complete (e.g. transport timeout). | Target request timed out at network layer before output could be retrieved. |

> [!NOTE]
> **`ERROR` Verdict $\neq$ Vulnerable**:
> An `ERROR` verdict indicates an operational failure (e.g., HTTP 504 Timeout or unparseable JSON). It does **NOT** imply that the target agent is vulnerable.

---

## 3. CONFIDENCE VS. SEVERITY

AgentShield explicitly distinguishes between **evaluator confidence** and **vulnerability severity**:

* **`confidence` (0.0 to 1.0)**: Represents the evaluator's certainty in its assigned verdict (e.g. `confidence = 1.0` for exact pattern matches; `confidence = 0.60` for heuristic regex matches).
* **`severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)**: Represents the potential asset impact of a confirmed vulnerability (calculated in downstream Finding/Risk layers).

> [!WARNING]
> **Do Not Confuse Confidence with Severity**:
> A high-confidence evaluation (`confidence = 0.99`) of a minor policy breach does not make it a `CRITICAL` vulnerability. Conversely, a medium-confidence evaluation of an unauthorized database wipe tool tested on production infrastructure represents a `CRITICAL` risk.

---

## 4. STRUCTURED EVIDENCE & UNTRUSTED DATA

Each `EvaluationResult` includes an `EvaluationEvidence` object:

```python
EvaluationEvidence(
    summary="Target output contained internal system instruction header",
    matched_indicators=["SYSTEM_INSTRUCTION_HEADER"],
    response_excerpt="SYSTEM_INSTRUCTION: You are a support assistant...",
)
```

### Safety & Storage Boundaries
1. **Target Output is Untrusted**: Response text received from external AI targets may contain malicious payloads, script tags, or terminal injection strings.
2. **Bounded Excerpts**: `response_excerpt` is automatically truncated to a maximum of 500 characters to prevent storing unbounded target output in memory or logs.
3. **No Automatic Secret Exposure**: Evaluators must mask sensitive headers and authorization tokens before writing evidence logs.

---

## 5. EVALUATOR TYPES & ARCHITECTURE

The `Evaluator` abstract interface (`app/evaluation/base.py`) operates purely on collected data (`SecurityProbe` and `ProbeExecution`):

```python
class Evaluator(ABC):
    @abstractmethod
    def evaluate(self, probe: SecurityProbe, execution: ProbeExecution) -> EvaluationResult:
        pass
```

### Evaluator Types
* **`DETERMINISTIC` (Week 1 Scope)**: High-speed, reproducible evaluation using exact string matching, regex rules, and structural parsing.
* **`LLM_JUDGE` (Future Scope)**: Semantic evaluation using secondary LLMs to judge complex conversational nuances.

### Why Evaluators Do Not Communicate With Targets
Evaluators are decoupled from network transport. They receive already-collected `ProbeExecution` records. This ensures that:
1. Re-evaluating past scan runs does not re-trigger target side effects.
2. Evaluation rules can be updated and re-run offline against historical target results.
