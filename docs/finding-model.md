# Finding Domain Contract & Specification (STEP 7A)

This document defines the architectural contract, design boundaries, taxonomy, and specification for **AgentShield's Finding Layer** (`Finding`, `FindingSeverity`, `FindingStatus`, `FindingEvidence`).

---

## 1. DATA FLOW & PIPELINE SEPARATION

AgentShield maintains strict pipeline isolation between executing tests, evaluating single probe runs, aggregating security findings, and downstream risk scoring:

```
SecurityProbe
      ↓
AttackEngine
      ↓
TargetResult
      ↓
EvaluationResult
      ↓
Finding
      ↓
Future Risk Engine
```

---

## 2. EVALUATIONRESULT VS FINDING

AgentShield explicitly distinguishes between an **`EvaluationResult`** and a **`Finding`**:

* **`EvaluationResult`**: Represents *"One executed probe's evaluation"*. It is an operational evaluation outcome for a single probe execution run (e.g. `PROMPT_LEAK_001` evaluated against execution `exec-123` producing verdict `VIOLATION`). It contains zero risk scores, final severities, or remediations.
* **`Finding`**: Represents *"A human-readable security issue derived from one or more evaluation results"*. It synthesizes confirmed security violations into an actionable security issue (e.g. `System Prompt Disclosure`) containing human-facing explanations, impact descriptions, remediation recommendations, and evidence references across multiple probes or runs.

---

## 3. WHAT A FINDING REPRESENTS

A `Finding` encapsulates actionable, human-facing security information:

1. **Vulnerability Identification**: Unique stable `finding_id` and descriptive `title`.
2. **Security Classification**: Reuses the core security `category` (`ProbeCategory`).
3. **Issue Classification**: Assigns final `severity` (`FindingSeverity`).
4. **Lifecycle Tracking**: Tracks operational status (`FindingStatus`).
5. **Human-Facing Guidance**: Detailed `description`, security `impact`, and `remediation`.
6. **Traceability**: References all `affected_probe_ids` and `affected_execution_ids` that discovered the issue, along with supporting `FindingEvidence`.

---

## 4. FINDING SEVERITY (`FindingSeverity`)

`FindingSeverity` represents the **FINAL ISSUE CLASSIFICATION** measuring how dangerous or impactful a confirmed security finding is:

| Value | Severity Level | Description |
| :--- | :--- | :--- |
| **`INFO`** | Informational | Security observation with no direct vulnerability risk. |
| **`LOW`** | Low | Minor security rule flaw with minimal asset impact. |
| **`MEDIUM`** | Medium | Moderate flaw potentially allowing limited unauthorized actions or disclosure. |
| **`HIGH`** | High | Significant security weakness leading to key instruction override or prompt leakage. |
| **`CRITICAL`** | Critical | Severe vulnerability exposing sensitive systems, credentials, or tool abuse. |

---

## 5. SEVERITY VS. CONFIDENCE

AgentShield enforces a clear conceptual boundary between **Severity** and **Confidence**:

* **Confidence (`0.0` to `1.0`)**: Measures *"How certain are we that this finding is real?"* (evaluator/finding detection certainty).
* **Severity (`FindingSeverity`)**: Measures *"How dangerous/important is the confirmed issue?"* (vulnerability potential impact).

### Concrete Example:
* **Finding A**: `severity = CRITICAL`, `confidence = 0.99` (Certain that target agent allows unauthorized arbitrary code execution).
* **Finding B**: `severity = LOW`, `confidence = 0.99` (Certain that target agent leaked a harmless non-sensitive model version string).

> [!IMPORTANT]
> **Do Not Combine Severity and Confidence**:
> Severity and confidence must NOT be combined into a single composite score at the Finding model layer. They represent orthogonal security dimensions.

---

## 6. PROBE SEVERITY HINT VS. FINAL SEVERITY

* **`SecurityProbe.severity_hint`**: An initial test-design priority/impact hint assigned to a probe specification.
* **`Finding.severity`**: The final, confirmed issue classification.

> [!WARNING]
> **No Automatic Copying**:
> `SecurityProbe.severity_hint` must NOT be automatically copied to `Finding.severity` unless explicitly justified by the Risk Engine or Finding creation logic. A probe with a `LOW` severity hint could uncover a `CRITICAL` finding depending on the target's contextual behavior and exposed data.

---

## 7. FINDING STATUS (`FindingStatus`)

`FindingStatus` models the lifecycle state of a security finding:

| Value | Status Name | Usage / MVP Behavior |
| :--- | :--- | :--- |
| **`OPEN`** | Open | **Default status for MVP.** Newly created findings from confirmed violations start here. |
| **`CONFIRMED`** | Confirmed | Validated by human security reviewer or automated verification. |
| **`RESOLVED`** | Resolved | Remediation implemented and verified by subsequent scan runs. |
| **`ACCEPTED_RISK`** | Accepted Risk | Risk reviewed and accepted by security team. |

*Note: Lifecycle transition logic is not implemented in STEP 7A.*

---

## 8. FINDING EVIDENCE & SAFETY BOUNDARIES

Each finding includes supporting evidence items (`FindingEvidence`):

```python
FindingEvidence(
    summary="Target output contained system instructions",
    indicators=["SYSTEM_PROMPT_DISCLOSURE_HEADER"],
    response_excerpt="SYSTEM INSTRUCTIONS: You are a customer support agent...",
    probe_id="PROMPT_LEAK_001",
    execution_id="exec-123",
)
```

### Safety & Storage Boundaries
1. **Untrusted Data Handling**: Target response text is untrusted external output.
2. **Excerpt Bounding**: `response_excerpt` is automatically capped at **500 characters maximum**.
3. **No Secret Storage**: Credentials, tokens, and authorization secrets must never be stored in evidence fields.

---

## 9. FINDING AGGREGATION

A single `Finding` can reference **multiple probe IDs** (`affected_probe_ids`) and **multiple execution IDs** (`affected_execution_ids`).

### Rationale
Multiple security probes (e.g. `PROMPT_LEAK_001`, `PROMPT_LEAK_002`, `PROMPT_LEAK_003`) may target different prompt syntax variations, yet all expose the same underlying root cause: **System Prompt Disclosure**. 

Aggregation allows AgentShield to present a single consolidated Finding to humans while maintaining full traceability back to every probe payload and execution run that triggered it.

*Note: Aggregation logic is deferred to subsequent steps.*

---

## 10. WHY RISK SCORING IS A SEPARATE FUTURE LAYER

`Finding` represents human-facing security information about a vulnerability. It intentionally does **NOT** compute composite risk scores or CVSS values:

* **Risk Scoring**: Requires environment context (e.g. network exposure, asset criticality, target deployment context) handled by the **Future Risk Engine**.
* **Remediation & Reporting**: Advanced report generation, PDF exports, and LLM-assisted remediation recommendations belong to the **Future Report Engine**.
