# Server-Side Request Forgery (SSRF) Security Boundary & Safe Transport (STEP 10C)

This document defines the architecture, threat model, policy rules, DNS validation, redirect protection, and error mapping for **AgentShield's outbound SSRF security boundary** (`app/security/ssrf.py` and `app/adapters/http.py`).

---

## 1. THREAT MODEL & RISK STATEMENT

In AgentShield, user requests supply a target agent endpoint URL (`TargetScanRequest.endpoint`). Because target URLs are **untrusted user-controlled input**, an attacker could attempt to specify internal infrastructure endpoints:

- Localhost & Loopback Services (`http://127.0.0.1:8000`, `http://localhost:6379`)
- Internal RFC1918 Private Microservices (`http://10.0.0.5/admin`, `http://192.168.1.100`)
- Cloud Instance Metadata Services (`http://169.254.169.254/latest/meta-data`)
- Protocol Smuggling Schemes (`file:///etc/passwd`, `gopher://`, `ftp://`)

Without a dedicated outbound SSRF security boundary, security probing tools would become vectors for internal network discovery, data exfiltration, or cloud credential theft.

---

## 2. ARCHITECTURAL PLACEMENT & INVARIANTS

The SSRF security boundary is placed **at the network boundary immediately prior to HTTP transport dispatch**:

```text
User Request
    │
    ▼
TargetScanRequest (Public API DTO)
    │
    ▼
ScanService ──► ScanEngine ──► AttackEngine
                                   │
                                   ▼
                            GenericHTTPAdapter
                                   │
                         [ SSRF Security Boundary ] ──► (ssrf.py)
                                   │
                    ┌──────────────┴──────────────┐
                 BLOCKED                        ALLOWED
                    │                             │
                    ▼                             ▼
        TargetResult (SSRF_REJECTION)    HTTP Transport (httpx.Client)
        (Zero Network Connection)                 │
                                                  ▼
                                             Target Agent
```

### Architectural Invariants
1. **TargetAdapter Boundary**: Outbound target safety is enforced inside `GenericHTTPAdapter` before any network socket connection is attempted.
2. **Layer Isolation**: FastAPI routes, `ScanEngine`, `FindingEngine`, and `RiskEngine` do NOT implement SSRF validation logic.
3. **Pre-Transport Blocking**: Blocked targets yield `TargetResult(success=False, error=TargetError(code=TargetErrorCode.SSRF_REJECTION, ...))` without creating HTTP transport connections or dispatching packets.

---

## 3. POLICY SPECIFICATION

### Allowed Schemes
- `http`
- `https`

All other schemes (`file://`, `ftp://`, `gopher://`, `data://`, `javascript://`, `ws://`, `wss://`) are rejected.

### Blocked Hostnames & IP Ranges
- **Hostnames**: `localhost`, `localhost.localdomain`, `loopback`, empty or whitespace-only hostnames.
- **IPv4 Loopback**: `127.0.0.0/8`
- **IPv6 Loopback**: `::1`
- **RFC1918 Private IPv4**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **IPv6 Unique-Local**: `fc00::/7`
- **Link-Local Addresses**: `169.254.0.0/16`, `fe80::/10`
- **Cloud Metadata Address**: `169.254.169.254`
- **Unspecified / Special**: `0.0.0.0`, `::`, Multicast (`224.0.0.0/4`), Reserved (`240.0.0.0/4`).

---

## 4. DNS RESOLUTION & DNS REBINDING

1. **Pre-Connection Resolution**: Hostname destinations undergo DNS resolution (`socket.getaddrinfo`).
2. **Multi-IP Validation**: Every IP address returned by DNS is evaluated against `SSRFPolicy`. If any IP belongs to a blocked range, the target is REJECTED.
3. **DNS Rebinding Protection**: Automatic HTTP redirects are explicitly disabled (`follow_redirects=False`) in `GenericHTTPAdapter` to prevent redirect-based rebinding to private IPs.
4. **TOCTOU / Rebinding Pinning (IMPLEMENTED)**: `SSRFValidator.resolve_and_validate()` returns the exact hostname + IP(s) checked against policy, and `pinned_dns_resolution(hostname, ip)` forces the outbound `httpx` connection to use that same IP — closing the gap where a malicious DNS record could resolve to a different (blocked) IP between validation and connection. See `app/adapters/http.py::GenericHTTPAdapter.send()`.

---

## 5. ERROR SEMANTICS & SECRET SAFETY

- **Normalized Error Code**: `TargetErrorCode.SSRF_REJECTION`
- **Error Message**: `"Target URL rejected by SSRF security policy."`
- **Credential Protection**: Userinfo in URLs (`http://user:pass@example.com`) and target authentication headers are stripped/masked and NEVER exposed in error messages or representations.

---

## 6. CURRENT LIMITATIONS & FUTURE HARDENING

- **DNS Rebinding Pinning — Concurrency Scope**: Pinned IP binding (see §4) is implemented via a process-wide `socket.getaddrinfo` patch scoped to the request. This is safe for AgentShield's current sequential (one target request at a time) scan execution model. If scan execution is parallelized to fire concurrent outbound target requests from multiple threads, this should be upgraded to a per-connection transport-level pin (e.g. a custom `httpx` transport) instead of a global monkeypatch.
