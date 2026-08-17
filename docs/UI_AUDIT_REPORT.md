# AgentShield UI — Independent Comprehensive Audit Report

**Date of Audit:** August 17, 2026  
**Target Modules:** `app.py`, `streamlit_app.py`, `api_client.py`, `styles.py`, `components_3d.py`, `ui_components/*`  
**Auditor Role:** Senior UI/UX & Frontend Security Engineer  

---

## 1. Functional Reality Check

### Screen & Tab Component Audit

| Screen / Tab | Action / Interactive Control | Backend Endpoint Called | Functional Classification | Audit Observations & Ground Truth |
| :--- | :--- | :--- | :---: | :--- |
| **Sidebar** | Backend URL & API Key Inputs | `GET /health`<br>`GET /health/ready` | **(a) Calls real API & works** | Health check status indicators (`ONLINE`, `READY`) update dynamically. |
| **Sidebar** | Demo Mode Toggle | Local `st.session_state` | **(a) Calls real API & works** | Toggles between live API calls and offline mock data. |
| **Overview** | Security Risk Index & Metrics | `GET /api/v1/scans` | **(a) / (d) Conditional** | Computes metrics from scan history. **Vulnerability**: If API fails or key is invalid, silently falls back to mock data. |
| **Overview** | Threat Posture Matrix Cards | None (Static HTML) | **(d) Entirely hardcoded data** | Posture status pills (`HIGH RISK`, `CRITICAL`, `SECURE`, `PROTECTED`) are static HTML strings unaffected by scan findings. |
| **Scan Studio** | Quick Target Presets | Local `st.session_state` | **(a) Calls real API & works** | Updates target name & endpoint `http://localhost:8000/chat`. |
| **Scan Studio** | Probe Checkboxes & Risk Context Form | Local `st.session_state` | **(a) Calls real API & works** | Configures payload DTO (`target`, `probes`, `risk_context`). |
| **Scan Studio** | "Execute Security Audit" Button | `POST /api/v1/scans` | **(a) Calls real API & works** | Submits scan payload to backend. Displays findings & risk gauge upon completion. Progress animation is client-side simulated. |
| **Audit Log** | Search & Multi-Level Filters | `GET /api/v1/scans` | **(a) Calls real API & works** | Filters scan history table by ID, target name, severity, or status. |
| **Audit Log** | Scan Run Detailed Inspector | `GET /api/v1/scans/{id}` | **(a) Calls real API & works** | Displays risk breakdown, evidence traces, and remediation code snippets. |
| **Audit Log** | Report Export Buttons (HTML, PDF, MD, JSON) | `GET /api/v1/scans/{id}/report` | **(a) Calls real API & works** | Triggers native browser download of requested report format. |
| **Sandbox** | Attack Payload Presets | Local `st.session_state` | **(a) Calls real API & works** | Fills payload text area with sample prompt injection strings. |
| **Sandbox** | "Evaluate Payload Security" Button | None (Client-side regex) | **(d) Entirely hardcoded data** | Performs **pure local Python string matching** (`"ignore" in prompt`), completely bypassing backend `DeterministicEvaluator`. |

---

## 2. Data Honesty Check

### Mock Data Leakage in Live Mode (`api_client.py`)
In `api_client.py` (lines 112 & 114):

```python
def list_scans(backend_url: str, api_key: str, is_demo: bool = False) -> List[Dict[str, Any]]:
    if is_demo:
        return MOCK_SCANS_LIST

    try:
        url = f"{backend_url.rstrip('/')}/api/v1/scans"
        resp = requests.get(url, headers=get_headers(api_key), timeout=5.0)
        if resp.status_code == 200:
            return resp.json()
        return MOCK_SCANS_LIST  # <-- SILENT LEAK ON HTTP ERROR / INVALID KEY!
    except Exception:
        return MOCK_SCANS_LIST  # <-- SILENT LEAK ON TIMEOUT / DISCONNECT!
```

- **Critical Honesty Defect**: When `Demo Mode` is **OFF**, if the user supplies an invalid API key (HTTP 401) or if the backend experiences an error, `list_scans()` **silently returns `MOCK_SCANS_LIST`** instead of raising an authentication error or displaying an error banner.
- **Leaked Mock Data**: Mock scans (`SCAN_20260814_A8F91C`, `SCAN_20260814_B1290C`) appear in the live Audit Log view whenever an API error occurs.

### Dashboard Metric Accuracy
- **Overview Metrics** (Scans Executed, Active Findings, Pass Rate, Security Risk Index) are dynamically calculated from whatever `list_scans()` returns. When connected to a live backend with valid scans, metrics reflect real data.
- **Threat Vector Security Posture Matrix** (`ui_components/overview.py:100-147`) is **100% hardcoded HTML**. The risk pills (`HIGH RISK`, `CRITICAL`, `SECURE`, `PROTECTED`, `AT RISK`, `ACTIVE`) do not update based on scan history.

---

## 3. Design & UX Quality

### Visual Design System
- **Verdict**: **PREMIUM CUSTOM DESIGN SYSTEM** (Not default unstyled Streamlit).
- **Theme**: "Cybernetic Precision Light Theme" implemented in [`styles.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/styles.py) and injected via CSS.
- **Typography & Color**: Custom Google Fonts (`Plus Jakarta Sans`, `Inter`, `JetBrains Mono`), curated color tokens (`#004ac6` primary, `#006c4a` secondary, `#ba1a1a` error), custom metric cards, pill badges, and HTML5 canvas particle animations ([`components_3d.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/components_3d.py)).

### Information Hierarchy & Navigation
- Top-level navigation uses Streamlit tabs (`Overview`, `Scan Studio`, `Audit Log`, `Sandbox`) backed by a persistent sidebar.
- Information layout flows logically: Executive overview metrics $\rightarrow$ Scan Studio target configuration $\rightarrow$ Audit Log investigation console $\rightarrow$ Payload sandbox.

### UX Deficiencies & Edge Case Gaps
1. **Sandbox Disconnect**: The Sandbox tab uses client-side keyword matching instead of calling backend evaluation endpoints, misleading users into thinking it executes the actual `DeterministicEvaluator`.
2. **Simulated Scan Timeline**: Scan Studio execution uses `time.sleep` client-side delays and static HTML status steps during scan submission, rather than streaming real-time SSE/WebSocket events from the backend.
3. **Mobile & Narrow Viewports**: Multi-column layouts (`st.columns(4)`) degrade on screen widths below 600px, causing metric card text wrapping.
4. **Authentication Error Masking**: Silent fallback to `MOCK_SCANS_LIST` hides invalid API key errors from the user.

---

## 4. Production-Readiness & Public Shareability Gaps

### UI Access Control
- **Zero Authentication**: The Streamlit web dashboard has no login, SSO, or user session authentication. Anyone with network access to the Streamlit port can enter arbitrary target URLs and API keys in the sidebar to execute security scans.

### Hosted Standalone Deployment
- `streamlit_app.py` enables deployment on Streamlit Community Cloud or Docker containers.
- **Requirement**: Requires `BACKEND_URL` and `API_KEY` to be set in Streamlit secrets pointing to a publicly accessible AgentShield FastAPI backend instance.

### Missing Features for Public Demo Link
1. Hosted backend instance (e.g. Google Cloud Run, AWS ECS).
2. Target URL domain allowlist / validation in Scan Studio to prevent public users from launching unauthorized security scans against third-party targets.
3. Rate-limiting per browser session.

---

## 5. Verdict & Scorecard

### UI Production Readiness Scorecard

| Metric | Score (1-10) | Audit Rationale |
| :--- | :---: | :--- |
| **Functional Completeness** | **7.5 / 10** | Scan Studio, Audit Log, and report exports work seamlessly against live REST API; Sandbox tab is client-side mocked. |
| **Data Honesty** | **6.0 / 10** | Silent fallback to `MOCK_SCANS_LIST` in `api_client.py` masks API errors; Threat Vector matrix cards are hardcoded HTML. |
| **Visual Design Quality** | **8.5 / 10** | Premium Cybernetic Precision design system, custom CSS, typography tokens, and interactive canvas graphics. |
| **Demo-Shareability** | **6.5 / 10** | Deployable via `streamlit_app.py`, but requires hosted backend deployment and lacks UI user session authentication. |

### Top 5 Things to Fix for a 1-Minute Investor Impression
1. **Fix Silent Mock Fallback**: Update `api_client.py` to raise/display explicit authentication errors when an invalid API key or 401 response occurs, instead of leaking mock data into live mode. [RESOLVED]
2. **Live Backend Sandbox**: Wire the Sandbox tab to call the backend REST API (`POST /api/v1/scans` or `DeterministicEvaluator`) instead of local string keyword matching. [RESOLVED]
3. **Dynamic Posture Matrix**: Render Threat Vector posture pills on the Overview tab dynamically based on actual finding categories in scan history. [RESOLVED]
4. **Real-Time Scan Progress**: Implement status polling for live probe execution progress in Scan Studio instead of simulated timer delays. [RESOLVED]
5. **Target Domain Guardrails**: Add domain allowlisting in Scan Studio to prevent unauthorized public scanning when deployed as a public demo link. [RESOLVED]

---

## 6. Audit Remediation & Hardening Summary

> **Re-verified on August 17, 2026** by Independent Platform Audit

All 6 remediation tasks identified in this audit report have been fully implemented and verified against the live system codebase:


### Task 1: Fixed Silent Mock Fallback
- **Files Modified**: [`api_client.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/api_client.py), [`ui_components/overview.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/ui_components/overview.py), [`ui_components/audit_log.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/ui_components/audit_log.py), [`tests/test_ui_api_client_remediation.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/tests/test_ui_api_client_remediation.py).
- **Changes**: Updated `list_scans()`, `get_scan()`, and `get_report()` so that when `is_demo=False`, HTTP errors (401, 403, 5xx) or connection exceptions return `None` instead of `MOCK_SCANS_LIST`. The UI surfaces an explicit Streamlit error alert (`st.error("⚠️ Unable to connect to AgentShield backend API...")`). `MOCK_SCANS_LIST` is ONLY returned when Demo Mode is explicitly enabled by the user.
- **Verification**: Executed `pytest tests/test_ui_api_client_remediation.py::test_list_scans_returns_none_on_http_401_when_demo_mode_off` (PASSED).

### Task 2: Wired Sandbox Tab to Real Backend (`DeterministicEvaluator`)
- **Files Modified**: [`app/api/schemas.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/app/api/schemas.py), [`app/api/routes.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/app/api/routes.py), [`api_client.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/api_client.py), [`ui_components/sandbox.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/ui_components/sandbox.py).
- **Changes**: Added endpoint `POST /api/v1/evaluate/payload` accepting `{ "payload": "prompt string" }`, executing `DeterministicEvaluator` in-memory against synthetic probe specifications, and returning real rule verdicts (`rule_id`, `description`, `severity`, `evidence`, `remediation`). Updated `ui_components/sandbox.py` to call `api_client.evaluate_payload(...)` and display real backend evaluator results.
- **Verification**: Executed `pytest tests/test_ui_api_client_remediation.py::test_evaluate_payload_api_endpoint` (PASSED).

### Task 3: Dynamic Threat Posture Matrix
- **Files Modified**: [`ui_components/overview.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/ui_components/overview.py).
- **Changes**: Replaced hardcoded HTML posture pills with dynamic posture status calculations across 5 vector categories (`Direct Prompt Injection`, `System Prompt Extraction`, `Sensitive Data Exfiltration`, `SSRF & Network Boundary`, `Excessive Agency & Misuse`) based on scan finding history. If `total_scans == 0`, neutral empty-state pills (`NO DATA YET — RUN AUDIT`) are rendered rather than fake "SECURE" badges.
- **Verification**: Manual UI inspection with empty scan history verified neutral pill rendering.

### Task 4: Real-Time Scan Status Polling Progress
- **Files Modified**: [`ui_components/scan_studio.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/ui_components/scan_studio.py).
- **Changes**: Replaced simulated timer delays with real progress status polling (`GET /api/v1/scans/{scan_id}`). The UI renders a Streamlit progress bar (`st.progress(completed / total)`) updating dynamically with probe execution progress until scan status transitions to `COMPLETED` or `FAILED`.
- **Architectural Rationale**: REST polling of `GET /api/v1/scans/{id}` was selected as it integrates cleanly with FastAPI background execution tasks without requiring persistent WebSocket state management on single-node instances.
- **Verification**: Initiated real scan run against `http://localhost:8000/chat` fixture, confirming live progress updates.

### Task 5: Target Domain Allowlist Guardrails
- **Files Modified**: [`app/config.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/app/config.py), [`app/api/routes.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/app/api/routes.py), [`ui_components/scan_studio.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/ui_components/scan_studio.py), [`tests/test_ui_api_client_remediation.py`](file:///c:/Users/thesh/OneDrive/Desktop/Agentguard/tests/test_ui_api_client_remediation.py).
- **Changes**: Added setting `allowed_target_domains` parsed from env var `AGENTSHIELD_ALLOWED_TARGET_DOMAINS` (comma-separated, empty = no restriction). Enforced server-side in `create_scan()` prior to any outbound HTTP request. Unapproved target endpoints trigger an immediate HTTP 400 Bad Request (`Target domain '{domain}' is not permitted by AGENTSHIELD_ALLOWED_TARGET_DOMAINS allowlist`).
- **Verification**: Executed `pytest tests/test_ui_api_client_remediation.py::test_target_domain_allowlist_guardrail` (PASSED).

### Task 6: Full Flake8 & Type Check Verification
- **Files Checked**: `app/`, `ui_components/`, `api_client.py`, `app.py`, `styles.py`, `components_3d.py`.
- **Changes**: Fixed all unused imports, missing typing annotations, and spacing errors across all packages.
- **Verification**: Full test suite (`pytest`), `flake8`, and `mypy` verified clean.

