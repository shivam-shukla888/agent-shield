# Risk Engine Specification (STEP 8B)

This document defines the architectural contract, numeric normalization algorithms, weighting model, score calculation formulas, and risk level mapping rules for **AgentShield's RiskEngine** (`RiskEngine`).

---

## 1. PURPOSE OF RISKENGINE

The `RiskEngine` calculates quantitative risk scores (`risk_score`) and assigns contextual risk levels (`RiskLevel`) by evaluating confirmed security findings (`Finding`) against target environment risk factors (`RiskFactors`).

### Data Flow Pipeline
```
Finding + RiskFactors
        ↓
    RiskEngine
        ↓
  RiskAssessment
```

> [!IMPORTANT]
> **Policy Defaults Notice**:
> The numeric factor mappings and category weights defined below are **AgentShield MVP policy defaults**, not industry-standard universal constants.

---

## 2. RISKFACTORS NUMERIC NORMALIZATION

`RiskEngine` normalizes qualitative risk factor enums into transparent numeric values from `0.0` to `100.0`:

### ImpactLevel Normalization
* `NEGLIGIBLE` = `0.0`
* `LOW` = `25.0`
* `MEDIUM` = `50.0`
* `HIGH` = `75.0`
* `CRITICAL` = `100.0`

### ExploitabilityLevel Normalization
* `LOW` = `25.0`
* `MEDIUM` = `50.0`
* `HIGH` = `75.0`
* `CRITICAL` = `100.0`

### BlastRadiusLevel Normalization
* `LIMITED` = `20.0`
* `LOW` = `40.0`
* `MEDIUM` = `60.0`
* `HIGH` = `80.0`
* `CRITICAL` = `100.0`

### AssetSensitivity Normalization
* `PUBLIC` = `10.0`
* `INTERNAL` = `30.0`
* `PERSONAL` = `55.0`
* `CONFIDENTIAL` = `80.0`
* `HIGHLY_SENSITIVE` = `100.0`

### ToolPrivilege Normalization
* `NONE` = `0.0`
* `READ` = `25.0`
* `WRITE` = `60.0`
* `DESTRUCTIVE` = `85.0`
* `ADMIN` = `100.0`

---

## 3. WEIGHTING MODEL & SCORE FORMULA

`RiskEngine` applies transparent baseline weights that sum to `1.0` (100%):

| Risk Dimension | Weight Parameter | Weight Percentage |
| :--- | :--- | :--- |
| **Impact** | `IMPACT_WEIGHT` | `30%` (`0.30`) |
| **Exploitability** | `EXPLOITABILITY_WEIGHT` | `25%` (`0.25`) |
| **Blast Radius** | `BLAST_RADIUS_WEIGHT` | `20%` (`0.20`) |
| **Asset Sensitivity** | `ASSET_SENSITIVITY_WEIGHT` | `15%` (`0.15`) |
| **Tool Privilege** | `TOOL_PRIVILEGE_WEIGHT` | `10%` (`0.10`) |

### Score Calculation Formula
$$\text{risk\_score} = \text{round}\Big(\min\big(100.0, \max(0.0, \sum \text{factor\_value} \times \text{weight})\big), 2\Big)$$

$$\begin{aligned}
\text{risk\_score} &= (\text{impact} \times 0.30) + (\text{exploitability} \times 0.25) \\
&+ (\text{blast\_radius} \times 0.20) + (\text{asset\_sensitivity} \times 0.15) \\
&+ (\text{tool\_privilege} \times 0.10)
\end{aligned}$$

---

## 4. RISK LEVEL THRESHOLDS

Calculated scores (0.00 to 100.00) map deterministically to `RiskLevel`:

| Score Range | Assigned RiskLevel | Risk Description |
| :--- | :--- | :--- |
| `0.00` – `19.99` | **`INFO`** | Minimal contextual risk. |
| `20.00` – `39.99` | **`LOW`** | Low risk requiring periodic monitoring. |
| `40.00` – `59.99` | **`MEDIUM`** | Moderate risk requiring planned remediation. |
| `60.00` – `79.99` | **`HIGH`** | High risk requiring prioritized intervention. |
| `80.00` – `100.0` | **`CRITICAL`** | Critical risk requiring immediate isolation or remediation. |

---

## 5. CONFIDENCE PROPAGATION

* `Finding.confidence` is propagated directly into `RiskAssessment.confidence` without transformation.
* **Confidence is NOT multiplied into risk_score**. Multiplying confidence into score would obscure high-risk vulnerabilities evaluated under lower confidence.

---

## 6. WHY FINDING SEVERITY DOES NOT EQUAL RISK LEVEL

`FindingSeverity` represents vulnerability classification, whereas `RiskLevel` represents contextual environment risk.

* A `HIGH` severity prompt leakage finding on a public chatbot with `NONE` tool privileges yields `RiskLevel = INFO` / `LOW`.
* The exact same `HIGH` severity prompt leakage finding on a financial agent with `ADMIN` tool privileges yields `RiskLevel = CRITICAL`.

---

## 7. DETERMINISTIC RISK IDS & EXPLAINABILITY

- **Risk ID**: Formatted deterministically as `RISK_<finding_id>` (e.g. `RISK_FINDING_TOOL_AUTHORIZATION`).
- **Explainability**: Formats a clear, deterministic rationale string explaining all factor values contributing to the score.

---

## 8. MVP LIMITATIONS & FUTURE EXTENSIONS

### MVP Scope Boundaries
- Operates purely in-memory on explicit `Finding` and `RiskFactors` inputs.
- Does NOT execute target tools, call LLMs, or invoke external networks.

### Future Roadmap Extensions
- Organization-specific risk policies & custom weight profiles
- CVSS v4 vector mapping & environmental metrics
- Automatic target asset discovery & tool privilege profiling
- Exploit-chain impact analysis
- Historical vulnerability trend scoring
