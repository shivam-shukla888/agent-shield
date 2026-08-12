import json
import pytest
import httpx
from pydantic import SecretStr

from app.adapters.http import GenericHTTPAdapter
from app.domain.target import (
    AuthType,
    TargetAuthConfig,
    TargetConfig,
    TargetErrorCode,
    TargetResult,
)


def test_adapter_sends_json_request_successfully() -> None:
    """Test 1: GenericHTTPAdapter successfully dispatches JSON request and extracts output."""
    captured_request = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_request["method"] = request.method
        captured_request["url"] = str(request.url)
        captured_request["body"] = json.loads(request.content)
        return httpx.Response(200, json={"response": "Hello world!"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        request_template={"prompt": "{{input}}"},
        response_path="response",
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Hello AI")

    assert result.success is True
    assert result.output == "Hello world!"
    assert result.status_code == 200
    assert captured_request["body"] == {"prompt": "Hello AI"}


def test_input_placeholder_substituted() -> None:
    """Test 2: {{input}} is correctly substituted in complex template structure."""
    captured_body = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_body.update(json.loads(request.content))
        return httpx.Response(200, json={"output": "Substituted ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        request_template={"messages": [{"role": "user", "content": "{{input}}"}]},
        response_path="output",
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Inject test payload")

    assert result.success is True
    assert captured_body == {"messages": [{"role": "user", "content": "Inject test payload"}]}


def test_default_request_template_works() -> None:
    """Test 3: Default request template {"prompt": "{{input}}"} works when template is None."""
    captured_body = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_body.update(json.loads(request.content))
        return httpx.Response(200, json={"response": "Default response"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        request_template=None,  # Should default to {"prompt": "{{input}}"}
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Default prompt payload")

    assert result.success is True
    assert captured_body == {"prompt": "Default prompt payload"}


def test_configured_response_path_works() -> None:
    """Test 4: Configured simple response_path extracts field value."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answer": "The answer is 42."})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        response_path="answer",
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("What is the answer?")

    assert result.success is True
    assert result.output == "The answer is 42."


def test_nested_response_path_works() -> None:
    """Test 5: Configured nested dot-notation response_path extracts field value."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"output": {"text": "Nested response string"}}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        response_path="data.output.text",
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Test nested extraction")

    assert result.success is True
    assert result.output == "Nested response string"


def test_missing_response_field_returns_extraction_error() -> None:
    """Test 6: Missing response field path returns RESPONSE_EXTRACTION_ERROR."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"wrong_key": "No target path here"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        response_path="data.expected_response",
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Test missing path")

    assert result.success is False
    assert result.error is not None
    assert result.error.code == TargetErrorCode.RESPONSE_EXTRACTION_ERROR


def test_malformed_json_returns_malformed_response_error() -> None:
    """Test 7: Malformed non-JSON body returns MALFORMED_RESPONSE."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>500 Internal Server Error Page</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Test malformed response")

    assert result.success is False
    assert result.error is not None
    assert result.error.code == TargetErrorCode.MALFORMED_RESPONSE


def test_http_401_403_maps_to_authentication_error() -> None:
    """Test 8: HTTP 401 and 403 status codes map to AUTHENTICATION_ERROR."""
    def handler_401(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Unauthorized"})

    client_401 = httpx.Client(transport=httpx.MockTransport(handler_401))
    config = TargetConfig(name="Test Agent", endpoint="https://agent.example.com/chat")
    adapter_401 = GenericHTTPAdapter(config=config, client=client_401)

    result_401 = adapter_401.send("Test auth error")

    assert result_401.success is False
    assert result_401.status_code == 401
    assert result_401.error is not None
    assert result_401.error.code == TargetErrorCode.AUTHENTICATION_ERROR

    def handler_403(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "Forbidden"})

    client_403 = httpx.Client(transport=httpx.MockTransport(handler_403))
    adapter_403 = GenericHTTPAdapter(config=config, client=client_403)
    result_403 = adapter_403.send("Test forbidden error")

    assert result_403.success is False
    assert result_403.status_code == 403
    assert result_403.error.code == TargetErrorCode.AUTHENTICATION_ERROR


def test_http_5xx_maps_to_target_server_error() -> None:
    """Test 9: HTTP 500 status code maps to TARGET_SERVER_ERROR."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "Internal server crash"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Test Agent", endpoint="https://agent.example.com/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Test 500 error")

    assert result.success is False
    assert result.status_code == 500
    assert result.error is not None
    assert result.error.code == TargetErrorCode.TARGET_SERVER_ERROR


def test_timeout_maps_to_timeout_error() -> None:
    """Test 10: Transport timeout maps to TIMEOUT error."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Connection timed out")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Test Agent", endpoint="https://agent.example.com/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Test timeout")

    assert result.success is False
    assert result.error is not None
    assert result.error.code == TargetErrorCode.TIMEOUT
    assert result.error.retryable is False


def test_network_error_maps_to_network_error() -> None:
    """Test 11: Network connection failure maps to NETWORK_ERROR."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.NetworkError("Failed to connect to host")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Test Agent", endpoint="https://agent.example.com/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Test network error")

    assert result.success is False
    assert result.error is not None
    assert result.error.code == TargetErrorCode.NETWORK_ERROR


def test_latency_is_populated() -> None:
    """Test 12: Latency is accurately populated in milliseconds using monotonic time."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "Speed check"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Test Agent", endpoint="https://agent.example.com/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Latency test")

    assert result.success is True
    assert result.latency_ms is not None
    assert result.latency_ms >= 0.0


def test_bearer_authentication_applied_without_leak() -> None:
    """Test 13: Bearer token is applied to request headers and not leaked in TargetResult."""
    captured_auth_header = None
    secret_token = "secret-bearer-token-999"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_auth_header
        captured_auth_header = request.headers.get("Authorization")
        return httpx.Response(200, json={"response": "Authenticated response"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth_config = TargetAuthConfig(auth_type=AuthType.BEARER, token=SecretStr(secret_token))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        authentication=auth_config,
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Auth check")

    assert result.success is True
    assert captured_auth_header == f"Bearer {secret_token}"
    assert secret_token not in str(result)
    assert secret_token not in repr(result)


def test_api_key_authentication_applied_without_leak() -> None:
    """Test 14: API key header authentication is applied without leaking in TargetResult."""
    captured_api_key = None
    secret_api_key = "secret-api-key-88888"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_api_key
        captured_api_key = request.headers.get("X-API-Key")
        return httpx.Response(200, json={"response": "API Key auth ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth_config = TargetAuthConfig(
        auth_type=AuthType.API_KEY,
        header_name="X-API-Key",
        token=SecretStr(secret_api_key),
    )
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        authentication=auth_config,
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("API key test")

    assert result.success is True
    assert captured_api_key == secret_api_key
    assert secret_api_key not in str(result)
    assert secret_api_key not in repr(result)


def test_adapter_returns_target_result_no_findings() -> None:
    """Test 15: TargetAdapter returns TargetResult instance and produces zero security findings."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "Target execution complete"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Test Agent", endpoint="https://agent.example.com/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Attack probe text")

    assert isinstance(result, TargetResult)
    # TargetResult describes target behavior, not security findings
    assert not hasattr(result, "findings")
    assert not hasattr(result, "vulnerabilities")


def test_security_secret_non_disclosure_in_errors_and_logs() -> None:
    """Test 16 & Security Requirement: Secret values do not appear in TargetResult or TargetError messages."""
    secret_value = "SUPER_SECRET_TOKEN_VALUE_XYZ_777"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection failed to secure gateway")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth_config = TargetAuthConfig(auth_type=AuthType.BEARER, token=SecretStr(secret_value))
    config = TargetConfig(
        name="Test Agent",
        endpoint="https://agent.example.com/chat",
        authentication=auth_config,
    )
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Secret leak security test")

    assert result.success is False
    assert result.error is not None
    # Verify secret value is never present in error messages or TargetResult representations
    assert secret_value not in result.error.message
    assert secret_value not in str(result)
    assert secret_value not in repr(result)


def test_adapter_validates_ssrf_before_http_transport() -> None:
    """Test 31: GenericHTTPAdapter validates SSRF before attempting transport dispatch."""
    transport_called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200, json={"response": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Blocked Target", endpoint="http://127.0.0.1:8000/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("SSRF test")

    assert result.success is False
    assert result.error is not None
    assert result.error.code == TargetErrorCode.SSRF_REJECTION
    assert transport_called is False  # CRITICAL INVARIANT: Transport MUST NOT be called!


def test_blocked_destination_produces_target_result_failure() -> None:
    """Test 32: Blocked SSRF destination produces TargetResult with success=False."""
    config = TargetConfig(name="Blocked Target", endpoint="http://169.254.169.254/latest/meta-data")
    adapter = GenericHTTPAdapter(config=config)

    result = adapter.send("SSRF test")
    assert result.success is False


def test_blocked_destination_produces_ssrf_rejection() -> None:
    """Test 33: Blocked SSRF destination produces TargetErrorCode.SSRF_REJECTION."""
    config = TargetConfig(name="Blocked Target", endpoint="http://10.0.0.1/chat")
    adapter = GenericHTTPAdapter(config=config)

    result = adapter.send("SSRF test")
    assert result.error is not None
    assert result.error.code == TargetErrorCode.SSRF_REJECTION


def test_blocked_destination_does_not_invoke_transport() -> None:
    """Test 34 (Requirement 19): Blocked 127.0.0.1 destination results in transport call count == 0."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"response": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Blocked Target", endpoint="http://127.0.0.1/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("SSRF test")
    assert result.success is False
    assert call_count == 0


def test_allowed_destination_reaches_mock_transport() -> None:
    """Test 35: Allowed destination passes SSRF validation and reaches mock transport."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"response": "Allowed response"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Allowed Target", endpoint="http://public-agent.local/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Allowed test")
    assert result.success is True
    assert call_count == 1


def test_redirects_cannot_bypass_ssrf_policy() -> None:
    """Test 36 (Requirement 20): Automatic HTTP redirects are disabled (follow_redirects=False)."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/secret"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Redirect Target", endpoint="http://public-agent.local/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("Redirect test")
    # Adapter receives 302 response without automatically following redirect to loopback
    assert result.status_code == 302


def test_no_automatic_retries_occur() -> None:
    """Test 37: SSRF failures are not retried automatically."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"response": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    config = TargetConfig(name="Blocked Target", endpoint="http://192.168.1.1/chat")
    adapter = GenericHTTPAdapter(config=config, client=client)

    result = adapter.send("No retry test")
    assert result.success is False
    assert call_count == 0


def test_credentials_remain_undisclosed_on_ssrf_failure() -> None:
    """Test 38: Credentials in authentication config or userinfo are not disclosed in SSRF error messages."""
    secret_token = "SECRET_BEARER_TOKEN_99999"
    auth_config = TargetAuthConfig(auth_type=AuthType.BEARER, token=SecretStr(secret_token))
    config = TargetConfig(
        name="Blocked Auth Target",
        endpoint="http://admin_secret:PASS@127.0.0.1/chat",
        authentication=auth_config,
    )
    adapter = GenericHTTPAdapter(config=config)

    result = adapter.send("SSRF auth test")
    assert result.success is False
    assert result.error is not None
    assert secret_token not in result.error.message
    assert "PASS" not in result.error.message
    assert secret_token not in str(result)

