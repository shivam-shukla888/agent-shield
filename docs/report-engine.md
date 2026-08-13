# Reporting Engine Technical Specification (STEP 16A)

## Executive Summary

The Reporting Engine (`app/engine/report.py`) converts completed security scan results (`ScanResult` or `ScanResponse`) into sanitized, human-readable `SecurityReport` DTOs and renders them as GitHub Flavored Markdown (`text/markdown`) or structured JSON (`application/json`).

---

## 1. Reporting Engine Architecture

```text
ScanResult / ScanResponse
           ↓
     ReportEngine
           ↓
 ┌───────────────────────────────────────────────┐
 │ 1. Deterministic Report ID (REPORT_<scan_id>) │
 │ 2. Template Executive Summary                 │
 │ 3. Finding & Risk Conversion                 │
 │ 4. Deterministic Risk Sorting (Score DESC)   │
 │ 5. Category Recommendation Mapping           │
 └───────────────────────────────────────────────┘
           ↓
    SecurityReport
           ↓
 ┌───────────────────────────────────────────────┐
 │ render_markdown() → text/markdown             │
 │ render_json()     → application/json          │
 └───────────────────────────────────────────────┘
```

---

## 2. Key Technical Guarantees

1. **Zero LLM Invocation**: Executive summaries, finding titles, and recommendations are constructed using deterministic Python logic and standard string templates.
2. **Zero Recalculation**: Existing `Finding` and `RiskAssessment` objects are consumed directly. Risk scores and levels are never re-scored during report generation.
3. **Deterministic Output**: Given identical scan input and generation timestamp, `ReportEngine` produces the exact same report string and structure every time.
4. **Sanitization**: API keys, bearer tokens, DB passwords, authorization headers, and raw target HTTP response bodies are excluded.

---

## 3. Data Processing Logic

### Executive Summary Generation

Template format:
```text
Scan completed with status 'COMPLETED' against target 'Demo Agent'. 3 probes were evaluated and 2 security findings were identified. The highest contextual risk was CRITICAL with a score of 87.50.
```

### Risk Assessment Sorting

Risk assessments are sorted deterministically:
1. `risk_score` DESC
2. `risk_id` DESC (tie-breaker)

### Recommendations Generation

Remediation recommendations are derived deterministically from vulnerability categories:
- `system_prompt_disclosure` -> *"Review system prompt isolation..."*
- `instruction_override` -> *"Strengthen instruction hierarchy enforcement..."*
- `tool_authorization` -> *"Enforce strict authorization boundaries..."*
- Recommendations are deduplicated and sorted alphabetically.

---

## 4. API Integration

### GET `/api/v1/scans/{scan_id}/report`

- **Authentication**: Requires valid client `X-API-Key`.
- **Query Parameter**: `format` (`markdown` or `json`, default `markdown`).
- **Response Headers**:
  - `Content-Type: text/markdown` for Markdown format.
  - `Content-Type: application/json` for JSON format.
- **Idempotency**: Report endpoints generate reports from stored scan results without re-triggering new probe executions or network connections.
