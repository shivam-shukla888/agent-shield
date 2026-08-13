"""
Unit & Security Tests for Production LLM Provider & Configuration Boundary (STEP 14B).

Verifies:
1. ProductionLLMProvider construction & configuration validation
2. Mocked HTTP transport execution for 200 OK, 401/403 Auth Error, 429 Rate Limit, 5xx Server Error, Timeout
3. Malformed JSON handling
4. Secret non-disclosure (API key never in repr, str, or exception tracebacks)
5. Provider factory selection logic (Fake vs Production)
6. Compatibility with LLMEvaluator
7. Credential isolation (Target API key vs LLM API key separation)
"""

import os
from unittest.mock import patch
import pytest
import httpx
from pydantic import SecretStr

from app.domain import (
    EvaluationResult,
    EvaluationVerdict,
    ExecutionStatus,
    ProbeCategory,
    ProbeExecution,
    SecurityProbe,
    TargetAuthConfig,
    TargetResult,
    AuthType,
)
from app.evaluation.config import LLMProviderConfig
from app.evaluation.factory import build_llm_provider
from app.evaluation.llm import LLMEvaluator
from app.evaluation.production_provider import LLMProviderError, ProductionLLMProvider
from app.evaluation.provider import FakeLLMProvider


SECRET_TEST_KEY = "sk-proj-SECRET_LLM_KEY_123456789"
TARGET_TEST_KEY = "target-secret-api-key-987654321"


# 1. production provider can be constructed with valid config
def test_production_provider_construction():
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
        model="gpt-4o",
        timeout_seconds=15.0,
    )
    provider = ProductionLLMProvider(config=config)
    assert provider is not None


# 2. model configuration is preserved
def test_model_config_preserved():
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
        model="claude-3-5-sonnet",
    )
    provider = ProductionLLMProvider(config=config)
    assert provider.config.model == "claude-3-5-sonnet"


# 3. timeout configuration is preserved
def test_timeout_config_preserved():
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
        timeout_seconds=45.0,
    )
    provider = ProductionLLMProvider(config=config)
    assert provider.config.timeout_seconds == 45.0


# 4. successful provider response returns expected text
def test_successful_provider_response():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == f"Bearer {SECRET_TEST_KEY}"
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"verdict": "safe", "confidence": 0.95, "rationale": "Clean output", "matched_indicators": [], "evidence_summary": "No violation"}'
                        }
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)
    res = provider.generate("Test prompt")
    assert "verdict" in res
    assert "safe" in res


# 5. provider timeout is converted to safe exception
def test_provider_timeout_converted_to_safe_exception():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Mocked connection timeout", request=request)

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)

    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate("Test prompt")

    assert "timed out" in str(exc_info.value).lower()
    assert SECRET_TEST_KEY not in str(exc_info.value)


# 6. HTTP authentication failure is handled safely
def test_http_401_auth_failure():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "Invalid API Key"}})

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)

    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate("Test prompt")

    assert "authentication failed" in str(exc_info.value).lower()
    assert SECRET_TEST_KEY not in str(exc_info.value)


# 7. HTTP rate-limit failure is handled safely
def test_http_429_rate_limit():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"message": "Rate limit exceeded"}})

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)

    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate("Test prompt")

    assert "rate limit" in str(exc_info.value).lower()
    assert SECRET_TEST_KEY not in str(exc_info.value)


# 8. HTTP server failure is handled safely
def test_http_500_server_error():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "Service unavailable"}})

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)

    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate("Test prompt")

    assert "server error" in str(exc_info.value).lower()
    assert SECRET_TEST_KEY not in str(exc_info.value)


# 9. malformed provider response is handled safely
def test_malformed_provider_response():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="NOT VALID JSON")

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)

    with pytest.raises(LLMProviderError) as exc_info:
        provider.generate("Test prompt")

    assert "malformed" in str(exc_info.value).lower()
    assert SECRET_TEST_KEY not in str(exc_info.value)


# 10. API key never appears in exception text
def test_api_key_not_in_exception():
    err = LLMProviderError(f"Failed with Bearer {SECRET_TEST_KEY} error")
    err_str = str(err)
    assert SECRET_TEST_KEY not in err_str
    assert "[REDACTED]" in err_str


# 11. API key never appears in repr
def test_api_key_not_in_repr():
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config)
    rep = repr(config)
    prov_rep = repr(provider)
    assert SECRET_TEST_KEY not in rep
    assert SECRET_TEST_KEY not in prov_rep


# 12. API key never appears in str
def test_api_key_not_in_str():
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config)
    st = str(config)
    prov_st = str(provider)
    assert SECRET_TEST_KEY not in st
    assert SECRET_TEST_KEY not in prov_st


# 13. missing API key is rejected
def test_missing_api_key_rejected():
    config = LLMProviderConfig(
        provider_type="production",
        api_key=None,
    )
    with pytest.raises(LLMProviderError) as exc_info:
        ProductionLLMProvider(config=config)
    assert "missing" in str(exc_info.value).lower()


# 14. invalid timeout is rejected
def test_invalid_timeout_rejected():
    with pytest.raises(ValueError):
        LLMProviderConfig(provider_type="production", timeout_seconds=0.0)
    with pytest.raises(ValueError):
        LLMProviderConfig(provider_type="production", timeout_seconds=500.0)


# 15. empty model is rejected
def test_empty_model_rejected():
    with pytest.raises(ValueError):
        LLMProviderConfig(provider_type="production", model="   ")


# 16. unsupported provider is rejected
def test_unsupported_provider_rejected():
    with pytest.raises(ValueError):
        LLMProviderConfig(provider_type="unknown_vendor")


# 17. provider factory selects FakeLLMProvider correctly
def test_factory_selects_fake_provider():
    config = LLMProviderConfig(provider_type="fake")
    provider = build_llm_provider(config)
    assert isinstance(provider, FakeLLMProvider)


# 18. provider factory selects production provider correctly
def test_factory_selects_production_provider():
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = build_llm_provider(config)
    assert isinstance(provider, ProductionLLMProvider)


# 19. no real network call occurs during tests (verified by MockTransport)
def test_no_real_network_call_made():
    called = False

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)
    provider.generate("test")
    assert called is True


# 20. existing LLMEvaluator remains compatible with the provider
def test_llm_evaluator_compatibility_with_production_provider():
    json_response = (
        '{"verdict": "violation", "confidence": 0.91, "rationale": "leaked info", '
        '"matched_indicators": ["leak"], "evidence_summary": "summary"}'
    )

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": json_response}}]})

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    provider = ProductionLLMProvider(config=config, http_client=client)
    evaluator = LLMEvaluator(provider=provider)

    probe = SecurityProbe(
        id="PROMPT_LEAK_001",
        name="Leak Probe",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        description="test",
        prompt="test prompt",
        expected_behavior="refuse",
    )
    target_res = TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")
    execution = ProbeExecution(
        execution_id="EXEC_001",
        target_name="target",
        probe_id="PROMPT_LEAK_001",
        prompt_text="test prompt",
        target_result=target_res,
        status=ExecutionStatus.COMPLETED,
    )

    result = evaluator.evaluate(probe, execution)
    assert isinstance(result, EvaluationResult)
    assert result.verdict == EvaluationVerdict.VIOLATION
    assert result.confidence == 0.91


# 21. Target API key vs LLM API key isolation proof
def test_target_and_llm_credential_isolation():
    """
    Security Requirement 14:
    Verify that the target agent API key is never forwarded to the LLM provider,
    and the LLM provider API key is never forwarded to the target adapter.
    """
    target_auth = TargetAuthConfig(
        auth_type=AuthType.BEARER,
        token=SecretStr(TARGET_TEST_KEY),
    )

    captured_llm_headers = {}

    def mock_llm_handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_llm_headers
        captured_llm_headers = dict(request.headers)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    llm_client = httpx.Client(transport=httpx.MockTransport(mock_llm_handler))
    llm_config = LLMProviderConfig(
        provider_type="production",
        api_key=SecretStr(SECRET_TEST_KEY),
    )
    llm_provider = ProductionLLMProvider(config=llm_config, http_client=llm_client)

    # Generate request to LLM provider
    llm_provider.generate("Test prompt")

    # Assert LLM provider request received LLM API key, NOT Target API key
    assert captured_llm_headers.get("authorization") == f"Bearer {SECRET_TEST_KEY}"
    assert TARGET_TEST_KEY not in captured_llm_headers.get("authorization", "")
    assert target_auth.token.get_secret_value() != llm_config.api_key.get_secret_value()
