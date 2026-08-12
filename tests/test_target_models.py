import pytest
from pydantic import ValidationError

from app.domain.target import (
    AuthType,
    TargetAuthConfig,
    TargetConfig,
    TargetError,
    TargetErrorCode,
    TargetResult,
)


def test_valid_target_config_creation() -> None:
    """Test 1: Valid TargetConfig creation with all default and custom fields."""
    config = TargetConfig(
        name="Customer Support Agent",
        endpoint="https://agent.example.com/chat",
        method="post",
        headers={"Content-Type": "application/json"},
        timeout_seconds=15.0,
        request_template={"prompt": "{{input}}"},
        response_path="response.text",
    )
    assert config.name == "Customer Support Agent"
    assert config.endpoint == "https://agent.example.com/chat"
    assert config.method == "POST"  # Normalized to uppercase
    assert config.headers == {"Content-Type": "application/json"}
    assert config.timeout_seconds == 15.0
    assert config.request_template == {"prompt": "{{input}}"}
    assert config.response_path == "response.text"


def test_empty_target_name_rejected() -> None:
    """Test 2: Empty or whitespace-only target name is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        TargetConfig(name="", endpoint="https://agent.example.com/chat")
    assert "name" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        TargetConfig(name="   ", endpoint="https://agent.example.com/chat")
    assert "name" in str(exc_info.value)


def test_empty_target_endpoint_rejected() -> None:
    """Test 3: Empty or whitespace-only target endpoint is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        TargetConfig(name="Agent A", endpoint="")
    assert "endpoint" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        TargetConfig(name="Agent A", endpoint="   ")
    assert "endpoint" in str(exc_info.value)


def test_invalid_timeout_rejected() -> None:
    """Test 4: Negative or zero timeout_seconds is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        TargetConfig(name="Agent A", endpoint="https://agent.example.com", timeout_seconds=0)
    assert "timeout_seconds" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        TargetConfig(name="Agent A", endpoint="https://agent.example.com", timeout_seconds=-5.0)
    assert "timeout_seconds" in str(exc_info.value)


def test_valid_target_result_creation() -> None:
    """Test 5: Valid TargetResult creation."""
    result = TargetResult(
        success=True,
        output="Hello! How can I assist you today?",
        status_code=200,
        latency_ms=145.2,
    )
    assert result.success is True
    assert result.output == "Hello! How can I assist you today?"
    assert result.status_code == 200
    assert result.latency_ms == 145.2
    assert result.error is None


def test_target_result_successful_response() -> None:
    """Test 6: TargetResult represents a successful response with raw payload & metadata."""
    result = TargetResult(
        success=True,
        output="I cannot fulfill this request.",
        status_code=200,
        latency_ms=210.5,
        metadata={"server": "uvicorn", "model": "gpt-4o"},
        raw_response={"choices": [{"message": {"content": "I cannot fulfill this request."}}]},
        trace_ref="trace-abc-123",
    )
    assert result.success is True
    assert result.output == "I cannot fulfill this request."
    assert result.metadata["model"] == "gpt-4o"
    assert result.raw_response is not None
    assert result.trace_ref == "trace-abc-123"


def test_target_result_error_representation() -> None:
    """Test 7: TargetResult represents a network/transport error."""
    error = TargetError(
        code=TargetErrorCode.TIMEOUT,
        message="Request to target agent timed out after 30 seconds",
        retryable=False,
        details={"endpoint": "https://agent.example.com/chat"},
    )
    result = TargetResult(
        success=False,
        status_code=504,
        latency_ms=30005.0,
        error=error,
    )
    assert result.success is False
    assert result.output is None
    assert result.error is not None
    assert result.error.code == TargetErrorCode.TIMEOUT
    assert result.error.retryable is False


def test_target_error_uses_normalized_code() -> None:
    """Test 8: TargetError uses normalized error code Enum."""
    error = TargetError(
        code=TargetErrorCode.SSRF_REJECTION,
        message="Destination IP 127.0.0.1 is blocked by SSRF security policy",
    )
    assert isinstance(error.code, TargetErrorCode)
    assert error.code == TargetErrorCode.SSRF_REJECTION
    assert error.code.value == "ssrf_rejection"


def test_auth_config_masks_credentials() -> None:
    """Test 9: TargetAuthConfig represents primary credentials using SecretStr."""
    auth = TargetAuthConfig(
        auth_type=AuthType.BEARER,
        token="secret-bearer-token-12345",
        custom_headers={"X-Custom-Env": "staging"},
    )
    assert auth.auth_type == AuthType.BEARER
    assert auth.token is not None
    # SecretStr masks string in repr and str representations
    assert "secret-bearer-token-12345" not in repr(auth)
    assert "secret-bearer-token-12345" not in str(auth)
    assert auth.token.get_secret_value() == "secret-bearer-token-12345"
    assert auth.custom_headers == {"X-Custom-Env": "staging"}


def test_target_result_does_not_contain_security_verdict() -> None:
    """Test 10: TargetResult model has no security verdict, risk score, or finding attributes."""
    result = TargetResult(
        success=True,
        output="System prompt: You are a helpful assistant.",
        status_code=200,
    )
    # Verify architectural decoupling: TargetResult has no security evaluation fields
    assert not hasattr(result, "is_vulnerable")
    assert not hasattr(result, "risk_score")
    assert not hasattr(result, "finding_severity")
    assert not hasattr(result, "security_verdict")


def test_frozen_model_reassignment_prevented() -> None:
    """Test 11: Pydantic frozen=True prevents field reassignment."""
    config = TargetConfig(name="Agent A", endpoint="https://agent.example.com")
    with pytest.raises(ValidationError):
        config.endpoint = "https://malicious.example.com"  # type: ignore[misc]
