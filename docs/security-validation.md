# AgentGuard — Security Validation & Threat Model Audit

## 1. Threat Model & Trust Boundaries

AgentGuard accepts target definitions and probe responses from external, untrusted network destinations. All inputs crossing trust boundaries are subjected to rigorous defensive validation.

```
Client Request (API Key / Payload)
  │ (Untrusted Input)
  ▼
[ REST API / Authentication Layer ] ──► Validated DTO
  │
  ▼
[ Outbound SSRF Target Validator ] ──► Checked HTTP Target Endpoint
  │
  ▼
[ Target Agent Execution ] ──► Raw Response (Untrusted External Output)
  │
  ▼
[ Evaluation & Detection Engines ] ──► Bounded Evidence & Security Findings
  │
  ▼
[ Report Rendering Engine ] ──► Escaped Markdown / HTML / PDF / JSON Output
```

---

## 2. Adversarial Security Verification Results

| Security Vector | Test Scenario | Result | Status |
|---|---|---|---|
| **SSRF Defense** | Localhost, RFC1918, IPv6 loopback, cloud metadata IPs | Outbound transport blocked before request dispatch | **PASS** |
| **SSRF DNS Rebinding** | Hostname resolving to `127.0.0.1` or `169.254.169.254` | IP validation rejects internal IP targets | **PASS** |
| **Authentication** | Missing key, invalid key, constant-time header check | Returns HTTP 401 Unauthorized cleanly | **PASS** |
| **Rate Limiting** | Exceeding allowed RPM per client key | Returns HTTP 429 with `Retry-After` header | **PASS** |
| **Secret Protection** | Sensitive headers (`Authorization`), DSN strings in logs | Masked via `SecretStr` & redacted from logs | **PASS** |
| **Prompt Injection** | Target response instructing agent to override rules | Response treated purely as untrusted text evidence | **PASS** |
| **Report Sanitization** | HTML script tags, XSS payloads in target response | Escaped cleanly in HTML and PDF report outputs | **PASS** |
| **SQL Injection** | Malformed strings in `scan_id` or query params | Fully parameterized via SQLAlchemy ORM | **PASS** |
| **Path Traversal** | Directory traversal sequences in scan ID or report format | Sanitized & validated against regex patterns | **PASS** |
| **Error Masking** | Storage failures, DB disconnections, internal exceptions | Sanitized HTTP 500 without stack trace disclosure | **PASS** |
