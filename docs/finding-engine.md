# Finding Engine Specification (STEP 7B)

This document defines the architectural contract, design boundaries, category mappings, and aggregation logic for **AgentShield's FindingEngine** (`FindingEngine`).

---

## 1. PURPOSE OF FINDINGENGINE

The `FindingEngine` is responsible for converting raw `EvaluationResult` objects into aggregated, human-facing `Finding` domain models.

### Data Flow Pipeline
```
EvaluationResult
       ↓
FindingEngine
       ↓
Category Mapping
       ↓
Aggregation
       ↓
Finding
       ↓
Future Risk Engine
```

---

## 2. EVALUATIONRESULT VS FINDING

AgentShield maintains a strict distinction between evaluation results and security findings:

* **`EvaluationResult`**: Operational evaluation of **one executed probe** (e.g. `PROMPT_LEAK_001` evaluated against execution `exec-101` returning verdict `VIOLATION`). It contains zero risk scores, final severities, or remediations.
* **`Finding`**: Aggregate, human-facing security issue (e.g. `System Prompt Disclosure`) summarizing confirmed vulnerabilities across one or more evaluation runs.

---

## 3. VERDICT HANDLING (VIOLATION-ONLY)

Only evaluation results with verdict **`EvaluationVerdict.VIOLATION`** produce a confirmed security `Finding`:

| Verdict | Finding Engine Action | Rationale |
| :--- | :--- | :--- |
| **`VIOLATION`** | **Converted to Finding** | Security control failed; target agent exhibited vulnerable behavior. |
| **`SAFE`** | Ignored (No Finding) | Target agent maintained expected security controls. |
| **`INCONCLUSIVE`** | Ignored (No Finding) | Evidence is ambiguous; cannot confirm a security vulnerability. |
| **`ERROR`** | Ignored (No Finding) | Transport/execution error (e.g. HTTP 504 Timeout). Operational error $\neq$ vulnerability. |

---

## 4. CATEGORY MAPPING & PROVISIONAL SEVERITY

`FindingEngine` applies deterministic category mappings for currently supported security categories:

| Category | Finding Title | Provisional Severity | Description & Impact |
| :--- | :--- | :--- | :--- |
| **`SYSTEM_PROMPT_DISCLOSURE`** | System Prompt Disclosure | `HIGH` | Exposes internal system instructions, boundaries, and system rules. |
| **`INSTRUCTION_OVERRIDE`** | Instruction Override | `HIGH` | Accepts adversarial user payloads overriding system prompt constraints. |
| **`TOOL_AUTHORIZATION`** | Unauthorized Tool Invocation | `CRITICAL` | Executes privileged agent tools/actions without proper authorization. |

> [!NOTE]
> **Provisional MVP Classification**:
> The severities above are static provisional classifications assigned at finding creation time. They do **NOT** represent final contextual risk scores.

---

## 5. CONFIDENCE & EVIDENCE PROPAGATION

### Confidence Propagation
`FindingEngine` derives finding confidence directly from `EvaluationResult.confidence` without transformation. Finding confidence represents certainty that the vulnerability is real.

### Evidence Propagation
`EvaluationEvidence` is converted into `FindingEvidence`:
* `summary` $\rightarrow$ `FindingEvidence.summary`
* `matched_indicators` $\rightarrow$ `FindingEvidence.indicators`
* `response_excerpt` $\rightarrow$ `FindingEvidence.response_excerpt` (automatically capped at 500 characters)
* `probe_id` $\rightarrow$ `FindingEvidence.probe_id`
* `execution_id` $\rightarrow$ `FindingEvidence.execution_id`

---

## 6. DETERMINISTIC FINDING IDS & AGGREGATION

### Deterministic Finding IDs
Finding IDs are generated deterministically based on security category (e.g., `FINDING_SYSTEM_PROMPT_DISCLOSURE`, `FINDING_INSTRUCTION_OVERRIDE`, `FINDING_TOOL_AUTHORIZATION`).

### Deduplication & Aggregation
When processing multiple `EvaluationResult` objects (e.g., across a scan run), `FindingEngine` groups `VIOLATION` results by security category into a single aggregated `Finding`:

```
EvaluationResult 1 (PROMPT_LEAK_001 -> VIOLATION) ┐
EvaluationResult 2 (PROMPT_LEAK_002 -> VIOLATION) ├─► ONE Finding ("System Prompt Disclosure")
EvaluationResult 3 (PROMPT_LEAK_003 -> VIOLATION) ┘     affected_probe_ids: [PROMPT_LEAK_001, 002, 003]
```

---

## 7. WHY RISK ENGINE REMAINS SEPARATE

`FindingEngine` constructs human-facing security findings. It intentionally does **NOT** compute numerical risk scores, CVSS vectors, or LLM-generated remediations:

1. **Risk Scoring Context**: Contextual risk calculation requires asset exposure, target environment context, tool capabilities, and blast radius (handled in the future **Risk Engine**).
2. **Deterministic & Offline**: `FindingEngine` operates purely in-memory on collected evaluation results without making external network calls or invoking LLMs.
