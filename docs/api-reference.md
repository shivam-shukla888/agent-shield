# AgentGuard — REST API Reference (v1)

Base URL: `/api/v1`

All endpoints (except public `/health` and `/health/ready`) require HTTP authentication header:
`X-API-Key: <YOUR_API_KEY>` or `Authorization: Bearer <YOUR_API_KEY>`

---

## Endpoint Summary

| Method | Endpoint | Summary | Auth Required? |
|---|---|---|---|
| `GET` | `/health` | Application liveness & version | No |
| `GET` | `/health/ready` | Service & storage readiness | No |
| `POST` | `/api/v1/scans` | Submit new scan run | **Yes** |
| `GET` | `/api/v1/scans` | List scan history (paginated) | **Yes** |
| `GET` | `/api/v1/scans/{scan_id}` | Get scan details by ID | **Yes** |
| `GET` | `/api/v1/scans/{scan_id}/report` | Download security report | **Yes** |

---

## API Details

### 1. Submit Scan Request
`POST /api/v1/scans`

**Headers:**
- `X-API-Key`: `<API_KEY>`
- `Idempotency-Key`: `[Optional]` Client key for request deduplication

**Request Body:**
```json
{
  "scan_id": "SCAN_CUSTOM_001",
  "target": {
    "target_name": "Customer Support Agent",
    "endpoint": "https://agent.example.com/chat",
    "request_template": {"prompt": "{{input}}"},
    "response_path": "response"
  },
  "probes": {
    "probe_ids": ["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"]
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

**Response (202 Accepted):**
```json
{
  "scan_id": "SCAN_CUSTOM_001",
  "target_name": "Customer Support Agent",
  "status": "created",
  "started_at": "2026-08-13T16:00:00Z",
  "completed_at": null,
  "summary": {
    "total_probes": 2,
    "completed_executions": 0,
    "failed_executions": 0,
    "safe_evaluations": 0,
    "violation_evaluations": 0,
    "inconclusive_evaluations": 0,
    "error_evaluations": 0,
    "total_findings": 0,
    "info_risks": 0,
    "low_risks": 0,
    "medium_risks": 0,
    "high_risks": 0,
    "critical_risks": 0
  },
  "findings": [],
  "risk_assessments": []
}
```

---

### 2. List Scan History
`GET /api/v1/scans?limit=50&offset=0`

**Query Parameters:**
- `limit` (int, optional): Number of scans to return (1-100, default None/50).
- `offset` (int, optional): Number of scans to skip (default 0).

---

### 3. Retrieve Scan Details
`GET /api/v1/scans/{scan_id}`

---

### 4. Download Security Report
`GET /api/v1/scans/{scan_id}/report?format=markdown`

**Query Parameters:**
- `format` (string, required): Report format (`markdown`, `json`, `html`, `pdf`).
