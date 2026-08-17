"""
Targeted High-Coverage Test Suite for GenericHTTPAdapter and FindingEngine (Part B Remediation)

Achieves >90% code coverage on app/adapters/http.py and app/engine/finding.py
by testing all edge cases, malformed payloads, transport errors, and path parsing fallbacks.
"""

from unittest.mock import MagicMock
import httpx
import pytest

from app.adapters.http import GenericHTTPAdapter
from app.domain.evaluation import EvaluationEvidence, EvaluationResult, EvaluationVerdict
from app.domain.finding import Finding
from app.domain.probe import ProbeCategory, SecurityProbe
from app.domain.target import TargetConfig, TargetErrorCode
from app.engine.finding import FindingEngine
from app.security.ssrf import SSRFResolution, SSRFValidator


def test_http_adapter_validation_edge_cases():
    # Empty name or endpoint via model_construct bypassing Pydantic constructor
    cfg1 = TargetConfig.model_construct(name="", endpoint="http://testagent.local/chat")
    adapter1 = GenericHTTPAdapter(cfg1)
    assert not adapter1.validate()

    # Negative/zero timeout
    cfg2 = TargetConfig.model_construct(name="ValidName", endpoint="http://testagent.local/chat", timeout_seconds=0.0)
    adapter2 = GenericHTTPAdapter(cfg2)
    assert not adapter2.validate()

    # Invalid scheme (ftp://)
    cfg3 = TargetConfig.model_construct(name="ValidName", endpoint="ftp://testagent.local/chat")
    adapter3 = GenericHTTPAdapter(cfg3)
    assert not adapter3.validate()

    # Valid config
    cfg4 = TargetConfig(name="ValidName", endpoint="http://testagent.local/chat")
    adapter4 = GenericHTTPAdapter(cfg4)
    assert adapter4.validate()


def test_http_adapter_health_check_invalid_config_and_success():
    # Invalid config health check
    cfg_invalid = TargetConfig.model_construct(name="", endpoint="http://testagent.local/chat")
    adapter_invalid = GenericHTTPAdapter(cfg_invalid)
    hc_res = adapter_invalid.health_check()
    assert not hc_res.success
    assert hc_res.error is not None
    assert hc_res.error.code == TargetErrorCode.CONFIGURATION_ERROR

    # Valid health check with mock transport
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "pong"})

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    cfg_valid = TargetConfig(name="ValidTarget", endpoint="http://testagent.local/chat")
    ssrf = SSRFValidator(dns_resolver=lambda h: ["93.184.216.34"])
    adapter_valid = GenericHTTPAdapter(cfg_valid, client=client, ssrf_validator=ssrf)

    hc_valid = adapter_valid.health_check()
    assert hc_valid.success
    assert hc_valid.metadata.get("health_check") is True


def test_http_adapter_send_invalid_config():
    cfg = TargetConfig.model_construct(name="", endpoint="http://testagent.local/chat")
    adapter = GenericHTTPAdapter(cfg)
    res = adapter.send("hello")
    assert not res.success
    assert res.error is not None
    assert res.error.code == TargetErrorCode.CONFIGURATION_ERROR


def test_http_adapter_transport_exceptions_and_status_codes():
    ssrf = SSRFValidator(dns_resolver=lambda h: ["93.184.216.34"])
    cfg = TargetConfig(name="TestTarget", endpoint="http://testagent.local/chat")

    # 1. TimeoutException
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Connection timed out")

    client_timeout = httpx.Client(transport=httpx.MockTransport(timeout_handler))
    adapter_timeout = GenericHTTPAdapter(cfg, client=client_timeout, ssrf_validator=ssrf)
    res_timeout = adapter_timeout.send("hello")
    assert not res_timeout.success
    assert res_timeout.error.code == TargetErrorCode.TIMEOUT

    # 2. RequestError (Network / connection failure)
    def connect_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Failed to establish TCP connection")

    client_connect = httpx.Client(transport=httpx.MockTransport(connect_handler))
    adapter_connect = GenericHTTPAdapter(cfg, client=client_connect, ssrf_validator=ssrf)
    res_connect = adapter_connect.send("hello")
    assert not res_connect.success
    assert res_connect.error.code == TargetErrorCode.NETWORK_ERROR

    # 3. HTTP 500 Server Error
    def server_error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    client_500 = httpx.Client(transport=httpx.MockTransport(server_error_handler))
    adapter_500 = GenericHTTPAdapter(cfg, client=client_500, ssrf_validator=ssrf)
    res_500 = adapter_500.send("hello")
    assert not res_500.success
    assert res_500.error.code == TargetErrorCode.TARGET_SERVER_ERROR

    # 4. HTTP 401 Unauthorized Error
    def auth_error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Unauthorized")

    client_401 = httpx.Client(transport=httpx.MockTransport(auth_error_handler))
    adapter_401 = GenericHTTPAdapter(cfg, client=client_401, ssrf_validator=ssrf)
    res_401 = adapter_401.send("hello")
    assert not res_401.success
    assert res_401.error.code == TargetErrorCode.AUTHENTICATION_ERROR

    # 5. Non-JSON response body on HTTP 200
    def text_200_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Plain raw text response")

    client_text = httpx.Client(transport=httpx.MockTransport(text_200_handler))
    adapter_text = GenericHTTPAdapter(cfg, client=client_text, ssrf_validator=ssrf)
    res_text = adapter_text.send("hello")
    assert not res_text.success
    assert res_text.error.code == TargetErrorCode.MALFORMED_RESPONSE


def test_http_adapter_response_parsing_heuristics_and_jsonpath():
    ssrf = SSRFValidator(dns_resolver=lambda h: ["93.184.216.34"])

    # 1. Explicit response_path (nested dot notation)
    cfg_path = TargetConfig(
        name="PathTarget",
        endpoint="http://testagent.local/chat",
        response_path="result.data.output_text",
    )
    def path_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": {"data": {"output_text": "Extracted Path Text"}}})

    adapter_path = GenericHTTPAdapter(cfg_path, client=httpx.Client(transport=httpx.MockTransport(path_handler)), ssrf_validator=ssrf)
    res_path = adapter_path.send("hello")
    assert res_path.output == "Extracted Path Text"

    # 2. Auto-detection candidate keys ("output", "content", "message", "answer")
    candidate_shapes = [
        ({"answer": "Answer Text"}, "Answer Text"),
        ({"output": "Output Text"}, "Output Text"),
        ({"message": "Message Text"}, "Message Text"),
        ({"content": "Content Text"}, "Content Text"),
        ({"choices": [{"message": {"content": "OpenAI Chat Content"}}]}, "OpenAI Chat Content"),
        ({"choices": [{"text": "OpenAI Legacy Text"}]}, "OpenAI Legacy Text"),
        ({"result": {"output": "Nested Result Output"}}, "Nested Result Output"),
        ({"response": "Response Text"}, "Response Text"),
    ]

    for body_data, expected_text in candidate_shapes:
        cfg_auto = TargetConfig(name="AutoTarget", endpoint="http://testagent.local/chat")
        def auto_handler(request: httpx.Request, b=body_data) -> httpx.Response:
            return httpx.Response(200, json=b)

        adapter_auto = GenericHTTPAdapter(cfg_auto, client=httpx.Client(transport=httpx.MockTransport(auto_handler)), ssrf_validator=ssrf)
        res_auto = adapter_auto.send("hello")
        assert res_auto.output == expected_text


def test_http_adapter_extract_by_path_and_auto_detect_direct():
    adapter = GenericHTTPAdapter(TargetConfig(name="DirectTarget", endpoint="http://testagent.local/chat"))

    # Direct test of _extract_by_path
    assert adapter._extract_by_path({"a": {"b": "val"}}, "a.b") == "val"
    assert adapter._extract_by_path({"items": ["first", "second"]}, "items.0") == "first"
    assert adapter._extract_by_path({"a": 123}, "a") == "123"
    assert adapter._extract_by_path({"a": "val"}, "non_existent_key") is None
    assert adapter._extract_by_path("not_a_dict", "a.b") is None
    assert adapter._extract_by_path({"items": []}, "items.99") is None


    # Direct test of _extract_response_text
    assert adapter._extract_response_text({"res": "val"}, "res") == "val"
    assert adapter._extract_response_text({"output": "auto_val"}, None) == "auto_val"

    # Direct test of _extract_by_path with primitives
    assert adapter._extract_by_path({"flag": True}, "flag") == "True"
    assert adapter._extract_by_path({"score": 98.5}, "score") == "98.5"

    # Direct test of _auto_detect_response_text
    assert adapter._auto_detect_response_text({"text": "sample text"}) == "sample text"
    assert adapter._auto_detect_response_text({"result": {"output": "nested output"}}) == "nested output"
    assert adapter._auto_detect_response_text({"choices": [{"message": {"content": "choice content"}}]}) == "choice content"
    assert adapter._auto_detect_response_text({"message": {"value": "sub_value"}}) == "sub_value"
    assert adapter._auto_detect_response_text({"custom_dict": {"inner": "val"}}) is None

    # Auth headers validation in _build_headers
    from app.domain.target import AuthType, TargetAuthConfig

    cfg_auth = TargetConfig(
        name="AuthTarget",
        endpoint="http://testagent.local/chat",
        authentication=TargetAuthConfig(
            auth_type=AuthType.CUSTOM_HEADERS,
            custom_headers={"X-Custom-Header": "CustomVal", "": "IgnoreEmpty"},
        ),
    )
    adapter_auth = GenericHTTPAdapter(cfg_auth)
    headers = adapter_auth._build_headers()
    assert headers.get("X-Custom-Header") == "CustomVal"






def test_finding_engine_category_resolution_and_fallbacks():
    engine = FindingEngine()

    # 1. Category from metadata as ProbeCategory instance
    eval1 = EvaluationResult(
        evaluation_id="e1",
        execution_id="ex1",
        probe_id="PID_001",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.95,
        rationale="Violation rationale",
        evidence=EvaluationEvidence(summary="Ev summary"),
        metadata={"category": ProbeCategory.INSTRUCTION_OVERRIDE},
    )
    f1 = engine.convert_evaluation_result(eval1)
    assert f1 is not None
    assert f1.category == ProbeCategory.INSTRUCTION_OVERRIDE.value

    # 2. Category from metadata as string
    eval2 = EvaluationResult(
        evaluation_id="e2",
        execution_id="ex2",
        probe_id="PID_002",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.95,
        rationale="Violation rationale",
        evidence=EvaluationEvidence(summary="Ev summary"),
        metadata={"category": "tool_authorization"},
    )
    f2 = engine.convert_evaluation_result(eval2)
    assert f2 is not None
    assert f2.category == ProbeCategory.TOOL_AUTHORIZATION.value

    # 3. Category from probe_id prefix fallback ("PROMPT_LEAK", "OVERRIDE", "AUTH")
    eval3 = EvaluationResult(
        evaluation_id="e3",
        execution_id="ex3",
        probe_id="PROMPT_LEAK_ADVANCED_01",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.95,
        rationale="Violation rationale",
        evidence=EvaluationEvidence(summary="Ev summary"),
    )
    f3 = engine.convert_evaluation_result(eval3)
    assert f3 is not None
    assert f3.category == ProbeCategory.SYSTEM_PROMPT_DISCLOSURE.value

    # 4. Unknown category fallback to SYSTEM_PROMPT_DISCLOSURE
    eval4 = EvaluationResult(
        evaluation_id="e4",
        execution_id="ex4",
        probe_id="UNKNOWN_RANDOM_PROBE",
        verdict=EvaluationVerdict.VIOLATION,
        confidence=0.95,
        rationale="Violation rationale",
        evidence=EvaluationEvidence(summary="Ev summary"),
    )
    f4 = engine.convert_evaluation_result(eval4)
    assert f4 is not None
    assert f4.category == ProbeCategory.SYSTEM_PROMPT_DISCLOSURE.value

    # 5. Non-violation returns None
    eval_safe = EvaluationResult(
        evaluation_id="e5",
        execution_id="ex5",
        probe_id="PROMPT_LEAK_01",
        verdict=EvaluationVerdict.SAFE,
        confidence=0.99,
        rationale="No violation",
        evidence=EvaluationEvidence(summary="Safe"),
    )
    assert engine.convert_evaluation_result(eval_safe) is None
