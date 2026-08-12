# API Contract Specification (STEP 10A)

This document defines the public Data Transfer Objects (DTOs), request/response schemas, secret boundaries, SSRF validation rules, and conversion functions for **AgentShield's API Contract Layer** (`app/api/schemas.py`).

---

## 1. PURPOSE OF THE API CONTRACT LAYER

The API contract layer establishes a clean architectural separation between external client data and internal domain models:

```text
Client
   ↓
ScanRequest (API DTO)
   ↓
API Validation & Conversion
   ↓
ScanEngine (Orchestrator)
   ↓
ScanResult (Internal Domain Container)
   ↓
Explicit Conversion (scan_result_to_response)
   ↓
ScanResponse (Public API DTO)
```

> [!IMPORTANT]
> **Domain Segregation**:
> Internal domain models (`ScanResult`, `ProbeExecution`, `TargetAuthConfig`) are **NEVER** exposed directly to external clients. The public API response (`ScanResponse`) is explicitly mapped and safe by default.

---

## 2. PUBLIC REQUEST SCHEMAS

### `ScanRequest`
Unified request payload sent by external clients to trigger a security scan:

```python
ScanRequest(
    scan_id="SCAN_2026_001",  # Optional
    target=TargetScanRequest(...),
    probes=ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"]),
    risk_context=RiskContextRequest(...),
)
```

### `TargetScanRequest`
Public representation of target agent configuration:
- `target_name` (str): Non-empty target name.
- `endpoint` (str): Target URL (syntactically validated for `http`/`https` and valid hostname).
- `method` (str): Normalized to uppercase (`POST`, `GET`).
- `headers` (Dict[str, str]): Optional headers (treated as sensitive input).
- `request_template` (Optional[Dict]): Optional JSON payload template.
- `response_path` (Optional[str]): Optional JSONPath response key extractor.
- `timeout_seconds` (float): Request timeout ($0.0 < \text{timeout} \le 300.0$).

### `ProbeSelectionRequest`
- `probe_ids` (List[str]): List of unique probe identifiers. Duplicate probe IDs raise a `ValidationError` to prevent unintentional scope drift.

### `RiskContextRequest`
Explicit environmental context provided by caller:
- `impact`, `exploitability`, `blast_radius`, `asset_sensitivity`, `tool_privilege` enums.

---

## 3. PUBLIC RESPONSE SCHEMAS

### `ScanResponse`
Clean public response container returned to clients:
- `scan_id` (str)
- `target_name` (str)
- `status` (`ScanStatus`)
- `started_at` & `completed_at` (timezone-aware UTC datetimes)
- `summary` (`ScanSummaryResponse`)
- `findings` (`List[ScanFindingResponse]`)
- `risk_assessments` (`List[ScanRiskResponse]`)

---

## 4. INTERNAL VS. PUBLIC DATA BOUNDARY & SECRET SAFETY

| Internal `ScanResult` Model | Public `ScanResponse` DTO | Rationale / Security Boundary |
| :--- | :--- | :--- |
| `executions` (`ProbeExecution`) | **EXCLUDED** | Prevents exposure of raw target output text and response bodies. |
| `raw_response` | **EXCLUDED** | Excludes raw HTTP response payloads and unparsed server data. |
| Target HTTP `headers` | **EXCLUDED** | Prevents accidental leakage of `Authorization: Bearer <token>` headers. |
| `TargetAuthConfig` | **EXCLUDED** | Prevents credential or API key disclosure. |
| `findings` (`Finding`) | `ScanFindingResponse` | Public DTO exposing category, title, severity, evidence excerpts, and remediation. |
| `risk_assessments` (`RiskAssessment`) | `ScanRiskResponse` | Public DTO exposing risk level, score, factors, and rationale. |

---

## 5. SSRF VALIDATION BOUNDARY

- **Syntactic Validation**: `TargetScanRequest.endpoint` enforces valid `http`/`https` schemes and non-empty netloc/hostname.
- **Network Boundary Notice**: Actual IP resolution, private subnet blocking (`127.0.0.1`, RFC 1918), and DNS rebinding protections are enforced downstream at the `TargetAdapter` level before sending network packets.

---

## 6. DETERMINISTIC CONVERSION FUNCTIONS

Explicit mapping helper functions perform DTO $\leftrightarrow$ Domain conversions:

1. `scan_request_to_target_config(request: TargetScanRequest) -> TargetConfig`
2. `risk_context_request_to_risk_factors(request: RiskContextRequest) -> RiskFactors`
3. `scan_result_to_response(scan_result: ScanResult) -> ScanResponse`

Conversion is 100% deterministic and contains zero business logic, network calls, or LLM interactions.

---

## 7. FUTURE INTEGRATION ROADMAP

- **STEP 10B (REST Endpoints)**: FastAPI routes (`POST /api/v1/scans`) will ingest `ScanRequest` DTOs and return `ScanResponse` DTOs.
- **Future CI/CD & n8n Automation**: Webhooks and CI pipelines will serialize standard `ScanResponse` JSON payloads.
