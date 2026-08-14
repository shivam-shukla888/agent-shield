# Security Report Domain Model Specification (STEP 16A)

## Executive Summary

The Security Report Domain Model defines strongly typed, immutable Data Transfer Objects (DTOs) representing sanitized security scan reports. Unlike internal execution traces or target adapter configurations, report domain models are designed strictly for public consumption, auditing, and human analysis.

---

## 1. Core Architectural Directives

1. **Strict Immutability**: All top-level report models use `model_config = ConfigDict(frozen=True)` to prevent field reassignment.
2. **Zero Credentials**: Report models NEVER store target passwords, bearer tokens, API keys, database URLs, or `TargetAuthConfig` objects.
3. **No Raw HTTP Headers or Bodies**: Raw target response bodies, internal adapter metadata, and raw HTTP headers are excluded.
4. **No CVSS Scoring**: AgentShield uses contextual AI agent risk scoring (`RiskAssessment`). Standard CVSS metrics are not used.
5. **Bounded Score Fields**: `confidence` is bounded within `[0.0, 1.0]` and `risk_score` is bounded within `[0.0, 100.0]`.

---

## 2. Domain Model Specifications (`app/domain/report.py`)

### ReportFormat
Enum defining supported export formats:
- `MARKDOWN` (`"markdown"`)
- `JSON` (`"json"`)

### ReportFinding
Sanitized summary representation of a confirmed security finding.

| Field | Type | Description |
|---|---|---|
| `finding_id` | `str` | Non-empty unique finding identifier |
| `category` | `str` | Vulnerability probe category identifier |
| `title` | `str` | Human-readable finding title |
| `severity` | `str` | Severity classification (`info`, `low`, `medium`, `high`, `critical`) |
| `confidence` | `float` | Verdict confidence score bounded in `[0.0, 1.0]` |
| `description` | `str` | Detailed vulnerability description |
| `evidence` | `Optional[str]` | Bounded evidence summary excerpt (max 500 chars) |
| `affected_probe_ids` | `List[str]` | List of probe IDs contributing to finding |
| `affected_execution_ids` | `List[str]` | List of execution IDs associated with finding |
| `remediation` | `str` | Actionable remediation guidance |

### ReportRisk
Sanitized summary representation of a contextual risk assessment.

| Field | Type | Description |
|---|---|---|
| `risk_id` | `str` | Non-empty unique risk assessment identifier |
| `finding_id` | `str` | Associated finding identifier |
| `risk_level` | `str` | Contextual risk level (`info`, `low`, `medium`, `high`, `critical`) |
| `risk_score` | `float` | Contextual risk score bounded in `[0.0, 100.0]` |
| `confidence` | `float` | Risk assessment confidence bounded in `[0.0, 1.0]` |
| `factors` | `Dict[str, str]` | Environmental risk factors map |
| `rationale` | `str` | Human-readable justification for risk level |

### SecurityReport
Complete immutable container for a security report.

| Field | Type | Description |
|---|---|---|
| `report_id` | `str` | Deterministic unique report identifier (`REPORT_<scan_id>`) |
| `scan_id` | `str` | Associated non-empty scan identifier |
| `target_name` | `str` | Target AI agent name |
| `status` | `str` | Scan execution lifecycle status (`completed`, `partial`, `failed`) |
| `generated_at` | `datetime` | UTC timestamp when report was generated |
| `executive_summary` | `str` | Concise human-readable executive summary string |
| `summary` | `Dict[str, int]` | Statistical summary counts map |
| `findings` | `List[ReportFinding]` | List of converted report findings |
| `risk_assessments` | `List[ReportRisk]` | List of converted risk assessments (sorted by score DESC) |
| `recommendations` | `List[str]` | Deduplicated remediation recommendations |
| `metadata` | `Dict[str, Any]` | Safe report operational metadata |

---

## 3. Data Integrity & Validation Rules

- `report_id`, `scan_id`, `target_name`, `status`, and `executive_summary` must be non-empty strings.
- Field values are validated on model instantiation via Pydantic field validators.
