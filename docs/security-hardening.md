# AgentShield Security Hardening & Threat-Model Specification (STEP 17A)

This document specifies the production security hardening architecture, threat surface, trust boundaries, mitigations, and residual risk assessment implemented across the AgentShield platform.

---

## 1. Threat Surface & Trust Boundaries

```
[ External Client ]  ──── Request ───►  [ API Boundary: Auth & Rate Limiter ]
                                                     │ (Sanitized Inputs)
                                                     ▼
                                        [ Security Headers Middleware ]
                                                     │
                                                     ▼
[ Target AI Agent ]  ◄── Outbound ───   [ SSRF Validator & HTTP Adapter ]
                                                     │ (Isolated Credentials)
                                                     ▼
[ LLM Judge Provider ] ◄─ Evaluation ─── [ Attack & Finding Engine ]
                                                     │ (Parameterization)
                                                     ▼
                                        [ PostgreSQL / In-Memory Repo ]
```

---

## 2. API Input Hardening

All public API request payloads, path parameters, and query parameters undergo strict syntactic and semantic validation:

- **Scan ID (`scan_id`)**: Must match `^[A-Za-z0-9_\-]{1,128}$`. Control characters (`\r`, `\n`, `\0`), path traversal sequences (`..`, `/`), and spaces are strictly rejected.
- **Target Name (`target_name`)**: Non-empty, max 128 characters, whitespace-trimmed, no control characters.
- **Endpoint URL (`endpoint`)**: Must use `http` or `https` schemes. Must contain a valid hostname. Embedded userinfo (`http://user:pass@host/`) is rejected to prevent credential leakage. Max length 2048 characters.
- **HTTP Method (`method`)**: Restricted to standard uppercase methods (`POST`, `GET`, `PUT`, `PATCH`, `DELETE`).
- **Probe IDs (`probe_ids`)**: Maximum of 50 probes per request. Each probe ID must be non-empty and max 64 characters.
- **Timeout (`timeout_seconds`)**: Bounded between `0.1` and `300.0` seconds.

---

## 3. SSRF & Redirect Defense

Outbound target communication is strictly validated prior to network socket dispatch:

- **Loopback & Private Address Blocking**: Rejects `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (IPv6 unique local), `169.254.0.0/16` (link-local), `0.0.0.0/8`, and Carrier-Grade NAT (`100.64.0.0/10`).
- **Cloud Metadata Protection**: Explicitly blocks `169.254.169.254` and IPv4-mapped IPv6 representations (`::ffff:169.254.169.254`).
- **Redirect Security**: Automatic HTTP redirects are explicitly disabled (`follow_redirects=False`) to eliminate redirect-based SSRF bypass attacks.

---

## 4. Secret Redaction & Isolation

- **Secret Redaction**: Structured JSON logging automatically redacts API keys (`sk-*`), Bearer tokens, database connection strings (`postgresql://...`), and sensitive dictionary keys (`authorization`, `api_key`, `bearer`, `password`, `secret`, `db_url`).
- **Credential Isolation**: Target authentication tokens and LLM judge API keys are isolated in separate `SecretStr` containers and are never cross-contaminated or exposed in `TargetResult` or `ScanResponse` DTOs.
- **Header Injection Defense**: Custom target request headers strip control characters (`\r`, `\n`) and disallow sensitive hop-by-hop headers (`Authorization`, `Host`, `X-API-Key`).

---

## 5. Security Response Headers

All API HTTP responses include defense-in-depth HTTP security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store, max-age=0`

---

## 6. Residual Risks

- **DNS Rebinding**: In environments without a pinning proxy, rapid DNS IP change between validation and connection remains a theoretical vector. Mitigated by short connection timeouts.
- **Target Latency Exhaustion**: Slow target responses can consume worker connections up to `timeout_seconds` (bounded to max 300s).
