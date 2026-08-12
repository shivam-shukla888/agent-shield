# Risk Assessment Domain Contract & Specification (STEP 8A)

This document defines the architectural contract, design boundaries, taxonomy, and model specifications for **AgentShield's Risk Assessment Layer** (`RiskLevel`, `RiskFactors`, `RiskAssessment`).

---

## 1. DATA FLOW & PIPELINE SEPARATION

AgentShield maintains a strict separation between finding vulnerability issues, collecting contextual risk factors, and calculating quantitative risk scores:

```
Finding
   ↓
RiskFactors
   ↓
RiskAssessment
   ↓
Future RiskEngine
```

---

## 2. FINDING VS. RISKASSESSMENT

* **`Finding`**: Represents a validated security weakness discovered during test execution (e.g. `System Prompt Disclosure`). It describes *what vulnerability was found*.
* **`RiskAssessment`**: Represents the contextual danger of that finding in a specific target environment. It describes *how dangerous the vulnerability is for a specific target agent*.

---

## 3. FINDINGSEVERITY VS. RISKLEVEL

AgentShield explicitly distinguishes between vulnerability severity and contextual risk level:

* **`FindingSeverity`**: Classification of the vulnerability itself based on probe payload design and policy breach.
* **`RiskLevel`**: Contextual risk assigned after evaluating target environment factors (tool privileges, asset sensitivity, blast radius).

### Contextual Risk Example

Consider the exact same vulnerability finding (`FINDING_SYSTEM_PROMPT_DISCLOSURE`) evaluated across two different target agents:

#### Scenario A: Customer FAQ Chatbot
* **Finding**: `System Prompt Disclosure` (`FindingSeverity = HIGH`)
* **Context**: Public greeting instructions; no tools (`ToolPrivilege = NONE`), public data (`AssetSensitivity = PUBLIC`).
* **Risk Assessment**: `RiskLevel = MEDIUM`, `risk_score = 35.0`

#### Scenario B: Financial Transfer Agent
* **Finding**: `System Prompt Disclosure` (`FindingSeverity = HIGH`)
* **Context**: Wire transfer validation rules & internal API keys; bank transfer tool (`ToolPrivilege = DESTRUCTIVE`), highly sensitive PII (`AssetSensitivity = HIGHLY_SENSITIVE`).
* **Risk Assessment**: `RiskLevel = CRITICAL`, `risk_score = 95.0`

> [!IMPORTANT]
> **Risk is Contextual**:
> The exact same security vulnerability can present drastically different operational risks depending on the target agent's tool access, data sensitivity, and blast radius.

---

## 4. RISK FACTORS (`RiskFactors`)

`RiskFactors` models the contextual inputs evaluated when assessing target risk:

| Factor | Enum Type | Values | Description |
| :--- | :--- | :--- | :--- |
| **Impact** | `ImpactLevel` | `NEGLIGIBLE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Potential security damage if exploited. |
| **Exploitability** | `ExploitabilityLevel` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Ease and probability of successful exploitation. |
| **Blast Radius** | `BlastRadiusLevel` | `LIMITED`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Scope of downstream systems or assets affected. |
| **Asset Sensitivity** | `AssetSensitivity` | `PUBLIC`, `INTERNAL`, `PERSONAL`, `CONFIDENTIAL`, `HIGHLY_SENSITIVE` | Sensitivity of data accessible to the agent. |
| **Tool Privilege** | `ToolPrivilege` | `NONE`, `READ`, `WRITE`, `DESTRUCTIVE`, `ADMIN` | Highest privilege level of agent tools. |

---

## 5. RISK SCORE VS. CONFIDENCE

`RiskAssessment` separates numerical risk score from assessment confidence:

* **`risk_score` (`0.0` to `100.0`)**: Measures *"How dangerous is this issue?"*
* **`confidence` (`0.0` to `1.0`)**: Measures *"How certain are we about this risk assessment?"*

```python
RiskAssessment(
    risk_id="RISK_001",
    finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
    risk_level=RiskLevel.HIGH,
    risk_score=78.5,
    confidence=0.95,
    factors=RiskFactors(...),
    rationale="System prompt disclosure exposes internal guidelines and configuration rules.",
)
```

> [!NOTE]
> `risk_score` (0.0 to 100.0) and `confidence` (0.0 to 1.0) are orthogonal, independent dimensions.

---

## 6. WHY SCORING IS A SEPARATE FUTURE STEP

STEP 8A defines **ONLY** the domain contract and model boundaries. It intentionally contains:
- ❌ No scoring functions (`calculate_risk()`, `score()`, `rank()`)
- ❌ No CVSS vector calculations
- ❌ No LLM calls or automated heuristic algorithms

Quantitative scoring algorithms and environment profiling engines are implemented in subsequent Risk Engine steps.

---

## 7. SECURITY & STORAGE BOUNDARIES

`RiskAssessment` and `RiskFactors` models:
- Contain zero credentials, secrets, or API keys.
- Contain zero raw target response strings or unparsed prompts.
- Contain zero network or transport logic.
- Are strictly frozen in-memory domain models (`ConfigDict(frozen=True)`).
