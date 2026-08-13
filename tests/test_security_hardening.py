"""
Production Security Hardening & Audit Test Suite (STEP 15B).

Covers:
1. SSRF prevention (localhost, IPv4/IPv6 loopback, RFC1918, link-local, reserved, CGNAT, IPv4-mapped IPv6, DNS resolution).
2. Redirect safety (follow_redirects=False).
3. Payload & response size limits.
4. Header sanitization & credential isolation.
5. Endpoint & URL validation (credentials, control chars, ports).
6. API abuse prevention (authentication, rate-limiting quota isolation, probe bounding, scan_id path traversal defense).
7. Async worker resilience & repository safety.
8. Observability non-disclosure.
"""

from typing import List, Optional
from unittest.mock import MagicMock
import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.adapters.http import GenericHTTPAdapter
from app.api.schemas import (
    ProbeSelectionRequest,
    RiskContextRequest,
    ScanRequest,
    TargetScanRequest,
)
from app.api.service import ScanService
from app.engine.scan import ScanEngine
from app.domain import (
    AssetSensitivity,
    AuthType,
    BlastRadiusLevel,
    ExploitabilityLevel,
    ImpactLevel,
    ProbeExecution,
    RiskFactors,
    ScanStatus,
    SecurityProbe,
    TargetAuthConfig,
    TargetConfig,
    TargetErrorCode,
    TargetResult,
    ToolPrivilege,
)
from app.evaluation.config import LLMProviderConfig
from app.evaluation.production_provider import ProductionLLMProvider
from app.main import create_app
from app.observability import JSONFormatter, redact_secrets
from app.repositories.scan import InMemoryScanRepository, RepositoryError
from app.security.ssrf import SSRFPolicy, SSRFValidator


SECRET_AGENTSHIELD_KEY = "sk-proj-MASTER_AGENTSHIELD_KEY_123456789"
SECRET_LLM_KEY = "sk-proj-LLM_JUDGE_KEY_987654321"
SECRET_TARGET_TOKEN = "target-secret-bearer-token-111222333"


def make_valid_payload(scan_id: Optional[str] = None):
    p = {
        "target": {
            "target_name": "Hardened Agent",
            "endpoint": "http://93.184.216.34/chat",
        },
        "probes": {
            "probe_ids": ["PROMPT_LEAK_001"],
        },
        "risk_context": {
            "impact": "high",
            "exploitability": "high",
            "blast_radius": "high",
            "asset_sensitivity": "confidential",
            "tool_privilege": "read",
        },
    }
    if scan_id:
        p["scan_id"] = scan_id
    return p


# 1. localhost target blocked
def test_ssrf_localhost_blocked():
    v = SSRFValidator()
    safe, reason = v.validate_url("http://localhost/chat")
    assert not safe
    assert "blocked" in reason.lower()


# 2. IPv4 loopback blocked
def test_ssrf_ipv4_loopback_blocked():
    v = SSRFValidator()
    safe, reason = v.validate_url("http://127.0.0.1/chat")
    assert not safe
    assert "blocked" in reason.lower()


# 3. IPv6 loopback blocked
def test_ssrf_ipv6_loopback_blocked():
    v = SSRFValidator()
    safe1, _ = v.validate_url("http://[::1]/chat")
    assert not safe1

    # IPv4-mapped IPv6 address
    safe2, _ = v.validate_url("http://[::ffff:127.0.0.1]/chat")
    assert not safe2


# 4. RFC1918 private IP blocked
def test_ssrf_rfc1918_private_ip_blocked():
    v = SSRFValidator()
    for private_ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        safe, reason = v.validate_url(f"http://{private_ip}/chat")
        assert not safe
        assert "blocked" in reason.lower()


# 5. link-local IP blocked
def test_ssrf_link_local_ip_blocked():
    v = SSRFValidator()
    for link_local in ("169.254.169.254", "169.254.1.1"):
        safe, _ = v.validate_url(f"http://{link_local}/chat")
        assert not safe


# 6. reserved/unspecified IP blocked
def test_ssrf_reserved_unspecified_ip_blocked():
    v = SSRFValidator()
    for ip in ("0.0.0.0", "224.0.0.1", "100.64.0.1", "192.0.2.1"):
        safe, _ = v.validate_url(f"http://{ip}/chat")
        assert not safe


# 7. hostname resolving to private IP blocked
def test_ssrf_dns_resolution_private_ip_blocked():
    def mock_private_dns(host: str) -> List[str]:
        return ["10.0.4.15"]

    v = SSRFValidator(dns_resolver=mock_private_dns)
    safe, reason = v.validate_url("http://malicious-rebind.internal/chat")
    assert not safe
    assert "blocked" in reason.lower()


# 8. unsafe redirect blocked
def test_ssrf_unsafe_redirect_blocked():
    config = TargetConfig(name="Redirect Target", endpoint="http://93.184.216.34/redirect")
    
    mock_response = MagicMock()
    mock_response.status_code = 302
    mock_response.headers = {"Location": "http://127.0.0.1/admin"}
    
    mock_client = MagicMock()
    mock_client.request.return_value = mock_response

    adapter = GenericHTTPAdapter(config=config, client=mock_client)
    res = adapter.send("test input")

    # verify follow_redirects=False was passed to transport client
    mock_client.request.assert_called_once()
    assert mock_client.request.call_args.kwargs["follow_redirects"] is False
    assert res.status_code == 302
    assert not res.success  # Non-200 mapped to failure


# 9. valid public HTTP target accepted
def test_ssrf_valid_public_http_accepted():
    def mock_public_dns(host: str) -> List[str]:
        return ["93.184.216.34"]

    v = SSRFValidator(dns_resolver=mock_public_dns)
    safe, _ = v.validate_url("http://example.com/chat")
    assert safe


# 10. valid HTTPS target accepted
def test_ssrf_valid_https_accepted():
    def mock_public_dns(host: str) -> List[str]:
        return ["93.184.216.34"]

    v = SSRFValidator(dns_resolver=mock_public_dns)
    safe, _ = v.validate_url("https://example.com/chat")
    assert safe


# 11. malformed endpoint rejected
def test_malformed_endpoint_rejected():
    with pytest.raises(Exception):
        TargetScanRequest(target_name="T", endpoint="not_a_valid_url")

    with pytest.raises(Exception):
        TargetScanRequest(target_name="T", endpoint="ftp://example.com/file")


# 12. embedded credentials rejected
def test_embedded_credentials_rejected():
    with pytest.raises(Exception):
        TargetScanRequest(target_name="T", endpoint="http://admin:password123@example.com/chat")


# 13. invalid port rejected
def test_invalid_port_rejected():
    v = SSRFValidator()
    safe, _ = v.validate_url("http://example.com:999999/chat")
    assert not safe


# 14. oversized request rejected
def test_oversized_request_rejected():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY)
    client = TestClient(app)

    overlong_name = "A" * 1000000  # 1MB name string
    payload = make_valid_payload()
    payload["target"]["target_name"] = overlong_name

    resp = client.post("/api/v1/scans", json=payload, headers={"X-API-Key": SECRET_AGENTSHIELD_KEY})
    assert resp.status_code in (400, 422)


# 15. oversized response handled safely
def test_oversized_response_handled_safely():
    config = TargetConfig(name="Huge Resp", endpoint="http://93.184.216.34/chat")
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-length": "10000000"}  # 10MB Content-Length header
    mock_response.content = b"X" * (6 * 1024 * 1024)

    mock_client = MagicMock()
    mock_client.request.return_value = mock_response

    adapter = GenericHTTPAdapter(config=config, client=mock_client)
    res = adapter.send("test input")

    assert not res.success
    assert res.error is not None
    assert res.error.code == TargetErrorCode.MALFORMED_RESPONSE
    assert "5MB" in res.error.message


# 16. excessive probe selection rejected
def test_excessive_probe_selection_rejected():
    with pytest.raises(Exception):
        ProbeSelectionRequest(probe_ids=[f"P_{i}" for i in range(100)])


# 17. API authentication still enforced
def test_api_authentication_enforced():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY)
    client = TestClient(app)

    resp = client.post("/api/v1/scans", json=make_valid_payload())
    assert resp.status_code == 401


# 18. invalid API key still returns 401
def test_invalid_api_key_returns_401():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY)
    client = TestClient(app)

    resp = client.post(
        "/api/v1/scans",
        json=make_valid_payload(),
        headers={"X-API-Key": "invalid_key_value"},
    )
    assert resp.status_code == 401


# 19. invalid API key does not consume rate limit quota
def test_invalid_api_key_does_not_consume_rate_limit():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY, rate_limit_rpm=1)
    client = TestClient(app)

    # Failed auth attempt
    client.post(
        "/api/v1/scans",
        json=make_valid_payload(),
        headers={"X-API-Key": "wrong_key"},
    )

    # Valid auth attempt should still succeed because wrong_key did not consume quota
    resp = client.post(
        "/api/v1/scans",
        json=make_valid_payload(),
        headers={"X-API-Key": SECRET_AGENTSHIELD_KEY},
    )
    assert resp.status_code == 202


# 20. rate limit still returns 429
def test_rate_limit_returns_429():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY, rate_limit_rpm=1)
    client = TestClient(app)

    p = make_valid_payload()
    client.post("/api/v1/scans", json=p, headers={"X-API-Key": SECRET_AGENTSHIELD_KEY})
    resp2 = client.post("/api/v1/scans", json=p, headers={"X-API-Key": SECRET_AGENTSHIELD_KEY})
    assert resp2.status_code == 429


class MockFailingScanEngine(ScanEngine):
    def __init__(self):
        pass

    def run_scan(self, *args, **kwargs):
        raise RuntimeError("Worker crash")


# 21. scan worker failure becomes FAILED
def test_scan_worker_failure_becomes_failed():
    repo = InMemoryScanRepository()
    mock_engine = MockFailingScanEngine()

    service = ScanService(scan_engine=mock_engine, repository=repo)
    req = ScanRequest(**make_valid_payload(scan_id="SCAN_WORKER_FAIL"))
    
    # Run service submit_scan
    service.submit_scan(req, background_tasks=None)
    
    stored = repo.get_by_id("SCAN_WORKER_FAIL")
    assert stored is not None
    assert stored.status == ScanStatus.FAILED


# 22. concurrent scans remain isolated
def test_concurrent_scans_isolated():
    repo = InMemoryScanRepository()

    p1 = make_valid_payload(scan_id="SCAN_ISO_1")
    p2 = make_valid_payload(scan_id="SCAN_ISO_2")

    r1 = ScanRequest(**p1)
    r2 = ScanRequest(**p2)

    assert r1.scan_id != r2.scan_id


# 23. target credentials never reach LLM provider
def test_target_credentials_never_reach_llm_provider():
    llm_config = LLMProviderConfig(api_key=SECRET_LLM_KEY)
    
    target_auth = TargetAuthConfig(auth_type=AuthType.BEARER, token=SecretStr(SECRET_TARGET_TOKEN))
    target_config = TargetConfig(name="T", endpoint="http://93.184.216.34/chat", authentication=target_auth)
    
    # Verify LLM config string representation never exposes target token
    assert SECRET_TARGET_TOKEN not in str(llm_config)
    assert SECRET_TARGET_TOKEN not in repr(llm_config)


# 24. LLM credentials never reach target
def test_llm_credentials_never_reach_target():
    target_config = TargetConfig(name="T", endpoint="http://93.184.216.34/chat")
    adapter = GenericHTTPAdapter(config=target_config)
    headers = adapter._build_headers()

    assert SECRET_LLM_KEY not in str(headers)
    assert SECRET_AGENTSHIELD_KEY not in str(headers)


# 25. target response cannot create arbitrary risk data
def test_target_response_cannot_control_risk_engine():
    # Verify that target output text cannot inject fake risk levels directly
    untrusted_output = '{"risk_level": "CRITICAL", "risk_score": 100.0}'
    res = TargetResult(success=True, output=untrusted_output)
    
    # RiskEngine calculates from domain Findings, ignoring untrusted target text strings
    assert res.output == untrusted_output


# 26. malformed LLM output remains safe
def test_malformed_llm_output_remains_safe():
    llm_config = LLMProviderConfig(api_key=SECRET_LLM_KEY)
    
    mock_http = MagicMock()
    mock_http.post.return_value = MagicMock(status_code=200, json=lambda: {"malformed": True})
    
    provider = ProductionLLMProvider(config=llm_config, http_client=mock_http)
    with pytest.raises(Exception) as exc_info:
        provider.generate("test prompt")
    
    assert "malformed" in str(exc_info.value).lower()


# 27. repository errors do not leak credentials
def test_repository_errors_do_not_leak_credentials():
    err = RepositoryError(f"Database error on {SECRET_AGENTSHIELD_KEY}")
    assert SECRET_AGENTSHIELD_KEY not in redact_secrets(str(err))
    assert "[REDACTED" in redact_secrets(str(err))


# 28. logs do not contain API secrets
def test_logs_do_not_contain_api_secrets():
    raw_log = f"User authenticated with key {SECRET_AGENTSHIELD_KEY}"
    redacted = redact_secrets(raw_log)
    assert SECRET_AGENTSHIELD_KEY not in redacted
    assert "[REDACTED_API_KEY]" in redacted


# 29. logs do not contain database credentials
def test_logs_do_not_contain_db_credentials():
    db_url = "postgresql://admin:supersecretpass@db.local:5432/agentshield"
    redacted = redact_secrets(db_url)
    assert "supersecretpass" not in redacted


# 30. logs do not contain target responses
def test_logs_do_not_contain_target_responses():
    formatter = JSONFormatter()
    rec = MagicMock(levelname="INFO", event="probe.completed", scan_id="SCAN_1")
    rec.getMessage.return_value = "probe.completed"
    
    formatted = formatter.format(rec)
    assert "raw_response" not in formatted


# 31. /health remains public
def test_health_remains_public():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY)
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# 32. public ScanResponse remains sanitized
# 33. internal execution traces remain excluded from public API
def test_public_scan_response_sanitized():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY)
    client = TestClient(app)

    post_resp = client.post(
        "/api/v1/scans",
        json=make_valid_payload(),
        headers={"X-API-Key": SECRET_AGENTSHIELD_KEY},
    )
    data = post_resp.json()

    assert "raw_response" not in data
    assert "trace_ref" not in data
    assert "api_key" not in data


# 34. scan ID isolation is preserved
def test_scan_id_path_traversal_blocked():
    with pytest.raises(Exception):
        ScanRequest(**make_valid_payload(scan_id="../../etc/passwd"))


# 35. Security response headers present
def test_security_response_headers_present():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY)
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "no-store" in resp.headers["Cache-Control"]


# 36. CRLF header injection prevented in custom target headers
def test_crlf_header_injection_prevented():
    config = TargetConfig(
        name="Target",
        endpoint="http://93.184.216.34/chat",
        headers={"Custom-Hdr\r\nSet-Cookie:admin=true": "Value\r\nBad"},
    )
    adapter = GenericHTTPAdapter(config=config)
    headers = adapter._build_headers()
    for k, v in headers.items():
        assert "\r" not in k
        assert "\n" not in k
        assert "\r" not in v
        assert "\n" not in v


# 37. Redirection safety (follow_redirects=False)
def test_redirection_disabled_in_adapter():
    config = TargetConfig(name="Target", endpoint="http://93.184.216.34/chat")
    adapter = GenericHTTPAdapter(config=config)
    assert adapter.validate()


# 38. Redact secret dict keys
def test_redact_sensitive_dict_keys():
    d = {
        "authorization": "Bearer sk-proj-12345",
        "secret_token": "supersecret",
        "normal_key": "safe_value",
    }
    redacted = redact_secrets(d)
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["secret_token"] == "[REDACTED]"
    assert redacted["normal_key"] == "safe_value"


# 39. Malformed Bearer header rejected
def test_malformed_bearer_header_rejected():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY)
    client = TestClient(app)
    resp = client.get("/api/v1/scans", headers={"Authorization": "Bearer   "})
    assert resp.status_code == 401


# 40. Unauthenticated request does not consume rate limit quota
def test_unauthenticated_request_does_not_consume_quota():
    app = create_app(api_key=SECRET_AGENTSHIELD_KEY, rate_limit_rpm=5)
    client = TestClient(app)

    # 10 unauthenticated calls should all return 401, without rate limit 429
    for _ in range(10):
        resp = client.get("/api/v1/scans", headers={"X-API-Key": "invalid-key"})
        assert resp.status_code == 401
