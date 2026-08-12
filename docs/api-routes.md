# REST API Endpoint Specification (STEP 10B)

This document defines the REST API endpoint specification, request/response payload examples, HTTP status codes, error handling rules, and security boundaries for **AgentShield's REST API** (`app/api/routes.py`).

---

## 1. ENDPOINT SPECIFICATION

### `POST /api/v1/scans`
Synchronously executes a suite of security probes against a target agent and returns a public `ScanResponse`.

- **Transport Protocol**: HTTP / HTTPS
- **Content-Type**: `application/json`
- **Execution Mode**: Synchronous in-memory execution

---

## 2. REQUEST & RESPONSE PAYLOAD EXAMPLES

### Example Request Body
```json
{
  "scan_id": "SCAN_2026_001",
  "target": {
    "target_name": "Customer Support Agent",
    "endpoint": "http://example.test/chat",
    "method": "POST",
    "request_template": {
      "message": "{{input}}"
    },
    "response_path": "response",
    "timeout_seconds": 30
  },
  "probes": {
    "probe_ids": [
      "PROMPT_LEAK_001",
      "INSTRUCTION_OVERRIDE_001",
      "TOOL_AUTH_001"
    ]
  },
  "risk_context": {
    "impact": "high",
    "exploitability": "high",
    "blast_radius": "medium",
    "asset_sensitivity": "confidential",
    "tool_privilege": "write"
  }
}
```

### Example Response Body (HTTP 200 OK)
```json
{
  "scan_id": "SCAN_2026_001",
  "target_name": "Customer Support Agent",
  "status": "completed",
  "started_at": "2026-08-12T23:45:00.000000Z",
  "completed_at": "2026-08-12T23:45:02.000000Z",
  "summary": {
    "total_probes": 3,
    "completed_executions": 3,
    "failed_executions": 0,
    "safe_evaluations": 0,
    "violation_evaluations": 3,
    "inconclusive_evaluations": 0,
    "error_evaluations": 0,
    "total_findings": 3,
    "info_risks": 0,
    "low_risks": 0,
    "medium_risks": 0,
    "high_risks": 3,
    "critical_risks": 0
  },
  "findings": [
    {
      "finding_id": "FINDING_SYSTEM_PROMPT_DISCLOSURE",
      "title": "System Prompt Disclosure",
      "category": "system_prompt_disclosure",
      "severity": "high",
      "status": "open",
      "confidence": 0.98,
      "description": "Target agent disclosed internal system prompt instructions.",
      "impact": "Disclosing system instructions exposes internal business rules.",
      "remediation": "Harden system prompt instructions with explicit refusal boundaries.",
      "affected_probe_ids": ["PROMPT_LEAK_001"],
      "affected_execution_ids": ["exec-101"],
      "evidence": [
        {
          "summary": "Prompt leak detected",
          "indicators": ["SYSTEM_INSTRUCTION:"],
          "response_excerpt": "SYSTEM_INSTRUCTION: secret prompt",
          "probe_id": "PROMPT_LEAK_001",
          "execution_id": "exec-101"
        }
      ]
    }
  ],
  "risk_assessments": [
    {
      "risk_id": "RISK_FINDING_SYSTEM_PROMPT_DISCLOSURE",
      "finding_id": "FINDING_SYSTEM_PROMPT_DISCLOSURE",
      "risk_level": "high",
      "risk_score": 75.0,
      "confidence": 0.98,
      "factors": {
        "impact": "high",
        "exploitability": "high",
        "blast_radius": "medium",
        "asset_sensitivity": "confidential",
        "tool_privilege": "write"
      },
      "rationale": "Risk score 75.0 was derived from impact=high, exploitability=high..."
    }
  ]
}
```

---

## 3. HTTP STATUS CODES & ERROR HANDLING

| HTTP Status | Trigger Condition | Error Payload Example |
| :--- | :--- | :--- |
| **`200 OK`** | Scan completed successfully. | Full `ScanResponse` JSON. |
| **`400 Bad Request`** | Requested probe ID is unknown or unrecognized. | `{"detail": "Unknown probe ID: PROMPT_LEAK_999"}` |
| **`422 Unprocessable Entity`** | Malformed JSON or invalid schema values (e.g. timeout > 300). | Standard FastAPI / Pydantic validation error details. |
| **`500 Internal Error`** | Unexpected application failure. | `{"detail": "Scan execution failed."}` *(Stack traces and credentials stripped)* |

---

## 4. SECURITY BOUNDARIES

- **Secret Non-Disclosure**: Public responses exclude raw HTTP headers, bearer tokens, API keys, `raw_response` bodies, and `TargetAuthConfig`.
- **Error Safety**: Application errors (HTTP 500) never leak Python tracebacks, filesystem paths, or internal connection parameters.
- **SSRF Boundary Notice**: Endpoint URLs undergo syntactic scheme (`http`/`https`) and hostname validation. Downstream transport IP blocking (loopback, private subnets) is enforced by `GenericHTTPAdapter`.

---

## 5. API VERSIONING & ROADMAP

- Current routes operate under `/api/v1/scans`.
- Future asynchronous scan dispatching (`POST /api/v1/scans/async`) and scan status queries (`GET /api/v1/scans/{id}`) will build on this route foundation.
