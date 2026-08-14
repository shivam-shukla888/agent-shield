"""
Generic HTTP Target Adapter Implementation

This module implements the GenericHTTPAdapter class for communicating with REST/HTTP AI agents.
It handles template substitution, header/auth injection, SSRF security validation, HTTP transport,
latency measurement, JSON response parsing, response extraction, and deterministic error mapping.

SECURITY & ARCHITECTURAL DIRECTIVES:
- Does NOT evaluate security policy, generate attacks, calculate risk, or produce findings.
- Enforces SSRF security validation BEFORE outbound network connection establishment.
- Disables automatic redirects (follow_redirects=False) to prevent redirect-based SSRF bypasses.
- Secret tokens are extracted safely via SecretStr and MUST NOT be logged or exposed in TargetResult.
- Target response payloads are treated as UNTRUSTED external data.
"""

import time
from typing import Any, Dict, Optional

import httpx

from app.adapters.base import TargetAdapter
from app.domain.target import (
    AuthType,
    TargetConfig,
    TargetError,
    TargetErrorCode,
    TargetResult,
)
from app.security.ssrf import SSRFValidator

MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB limit

DISALLOWED_TARGET_HEADERS = {
    "x-api-key",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class GenericHTTPAdapter(TargetAdapter):
    """
    Adapter for communicating with generic HTTP REST AI agents.

    Dataflow:
    Attack Engine Payload ──► Template Substitution ──► SSRF Validation ──► HTTP Request
                                                                              │
    TargetResult ◄── Response Extraction ◄── HTTP Response ◄──────────────────┘
    """

    def __init__(
        self,
        config: TargetConfig,
        client: Optional[httpx.Client] = None,
        ssrf_validator: Optional[SSRFValidator] = None,
    ) -> None:
        super().__init__(config)
        self._client = client
        self._ssrf_validator = ssrf_validator or SSRFValidator()

    def validate(self) -> bool:
        """
        Validate that the target configuration is structurally valid for HTTP execution.
        """
        if not self.config.name or not self.config.endpoint:
            return False
        if self.config.timeout_seconds <= 0:
            return False
        endpoint_lower = self.config.endpoint.lower()
        if not (endpoint_lower.startswith("http://") or endpoint_lower.startswith("https://")):
            return False
        return True

    def health_check(self) -> TargetResult:
        """
        Perform a minimal availability check on the target agent endpoint.
        """
        if not self.validate():
            return TargetResult(
                success=False,
                error=TargetError(
                    code=TargetErrorCode.CONFIGURATION_ERROR,
                    message="Target configuration is invalid for HTTP communication",
                ),
                metadata={"health_check": True},
            )

        # Execute test payload to verify target reachability
        result = self.send("ping")
        metadata = dict(result.metadata)
        metadata["health_check"] = True
        return TargetResult(
            success=result.success,
            output=result.output,
            status_code=result.status_code,
            latency_ms=result.latency_ms,
            error=result.error,
            metadata=metadata,
            raw_response=result.raw_response,
            trace_ref=result.trace_ref,
        )

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        """
        Dispatch input text payload to the target HTTP agent and return a normalized TargetResult.
        Enforces SSRF security validation BEFORE outbound transport dispatch.
        """
        # 1. Structural Validation
        if not self.validate():
            return TargetResult(
                success=False,
                error=TargetError(
                    code=TargetErrorCode.CONFIGURATION_ERROR,
                    message="Invalid target configuration",
                ),
            )

        # 2. SSRF Security Boundary Validation BEFORE outbound transport connection
        is_safe, ssrf_reason = self._ssrf_validator.validate_url(self.config.endpoint)
        if not is_safe:
            return TargetResult(
                success=False,
                error=TargetError(
                    code=TargetErrorCode.SSRF_REJECTION,
                    message="Target URL rejected by SSRF security policy.",
                    retryable=False,
                ),
            )

        headers = self._build_headers()
        body = self._build_request_body(input_text)

        start_time = time.monotonic()

        # 3. Execute HTTP request using injected or ephemeral client (follow_redirects=False)
        try:
            if self._client is not None:
                response = self._client.request(
                    method=self.config.method,
                    url=self.config.endpoint,
                    json=body,
                    headers=headers,
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                )
            else:
                with httpx.Client(timeout=self.config.timeout_seconds, follow_redirects=False) as client:
                    response = client.request(
                        method=self.config.method,
                        url=self.config.endpoint,
                        json=body,
                        headers=headers,
                        follow_redirects=False,
                    )
        except httpx.TimeoutException:
            latency_ms = (time.monotonic() - start_time) * 1000.0
            return TargetResult(
                success=False,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.TIMEOUT,
                    message=f"Request to target timed out after {self.config.timeout_seconds} seconds",
                    retryable=False,
                ),
            )
        except (httpx.NetworkError, httpx.RequestError) as exc:
            latency_ms = (time.monotonic() - start_time) * 1000.0
            return TargetResult(
                success=False,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.NETWORK_ERROR,
                    message=f"Network error connecting to target endpoint: {type(exc).__name__}",
                    retryable=False,
                ),
            )
        except Exception as exc:
            latency_ms = (time.monotonic() - start_time) * 1000.0
            return TargetResult(
                success=False,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.UNKNOWN_ERROR,
                    message=f"Unexpected transport error: {type(exc).__name__}",
                    retryable=False,
                ),
            )

        latency_ms = (time.monotonic() - start_time) * 1000.0
        status_code = response.status_code

        # Check response content size limits before parsing
        content_length_hdr = response.headers.get("content-length")
        if content_length_hdr and content_length_hdr.isdigit() and int(content_length_hdr) > MAX_RESPONSE_BYTES:
            return TargetResult(
                success=False,
                status_code=status_code,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.MALFORMED_RESPONSE,
                    message="Target response payload exceeded maximum allowed size limit of 5MB",
                    retryable=False,
                ),
            )

        if len(response.content) > MAX_RESPONSE_BYTES:
            return TargetResult(
                success=False,
                status_code=status_code,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.MALFORMED_RESPONSE,
                    message="Target response payload exceeded maximum allowed size limit of 5MB",
                    retryable=False,
                ),
            )

        # HTTP Status Code Error Mapping
        if status_code in (401, 403):
            return TargetResult(
                success=False,
                status_code=status_code,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.AUTHENTICATION_ERROR,
                    message=f"Authentication failed with target HTTP status {status_code}",
                    retryable=False,
                ),
            )
        elif status_code >= 400:
            return TargetResult(
                success=False,
                status_code=status_code,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.TARGET_SERVER_ERROR,
                    message=f"Target agent returned error HTTP status {status_code}",
                    retryable=False,
                ),
            )

        # JSON Response Parsing
        try:
            raw_json = response.json()
        except Exception:
            return TargetResult(
                success=False,
                status_code=status_code,
                latency_ms=latency_ms,
                error=TargetError(
                    code=TargetErrorCode.MALFORMED_RESPONSE,
                    message="Target agent returned unparseable non-JSON response body",
                    retryable=False,
                ),
            )

        # Response Path Extraction
        extracted_output = self._extract_response_text(raw_json, self.config.response_path)
        if extracted_output is None:
            return TargetResult(
                success=False,
                status_code=status_code,
                latency_ms=latency_ms,
                raw_response=raw_json,
                error=TargetError(
                    code=TargetErrorCode.RESPONSE_EXTRACTION_ERROR,
                    message=(
                        f"Could not extract response from target JSON using path '{self.config.response_path}'"
                        if self.config.response_path
                        else "Could not extract text response from target JSON"
                    ),
                    retryable=False,
                ),
            )

        metadata = {"content_type": response.headers.get("content-type", "")}
        return TargetResult(
            success=True,
            output=extracted_output,
            status_code=status_code,
            latency_ms=latency_ms,
            raw_response=raw_json,
            metadata=metadata,
        )

    def _build_headers(self) -> Dict[str, str]:
        """
        Construct HTTP headers applying static and authentication headers.
        Credentials are read safely via SecretStr without logging.
        Strips dangerous hop-by-hop and AgentShield internal auth headers, and cleans CRLF characters.
        """
        headers: Dict[str, str] = {}
        for k, v in self.config.headers.items():
            clean_k = str(k).replace("\r", "").replace("\n", "").strip()
            clean_v = str(v).replace("\r", "").replace("\n", "").strip()
            if clean_k and clean_k.lower() not in DISALLOWED_TARGET_HEADERS:
                headers[clean_k] = clean_v

        if "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = "application/json"

        if self.config.authentication:
            auth = self.config.authentication
            if auth.auth_type == AuthType.BEARER and auth.token:
                headers["Authorization"] = f"Bearer {auth.token.get_secret_value()}"
            elif auth.auth_type == AuthType.API_KEY and auth.token:
                header_name = auth.header_name or "X-API-Key"
                clean_hdr_name = str(header_name).replace("\r", "").replace("\n", "").strip()
                headers[clean_hdr_name] = auth.token.get_secret_value()
            elif auth.auth_type == AuthType.CUSTOM_HEADERS:
                for ck, cv in auth.custom_headers.items():
                    clean_ck = str(ck).replace("\r", "").replace("\n", "").strip()
                    clean_cv = str(cv).replace("\r", "").replace("\n", "").strip()
                    if clean_ck:
                        headers[clean_ck] = clean_cv

        return headers

    def _build_request_body(self, input_text: str) -> Dict[str, Any]:
        """
        Construct JSON request payload by substituting {{input}} in the request_template.
        Defaults to {"prompt": "{{input}}"} if no template is configured.
        """
        template = self.config.request_template or {"prompt": "{{input}}"}

        def _substitute(data: Any) -> Any:
            if isinstance(data, str):
                return data.replace("{{input}}", input_text)
            elif isinstance(data, dict):
                return {k: _substitute(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [_substitute(item) for item in data]
            return data

        result = _substitute(template)
        if isinstance(result, dict):
            return result
        return {"prompt": input_text}

    def _extract_response_text(self, data: Any, path: Optional[str]) -> Optional[str]:
        """
        Extract textual response from target JSON payload using path or default key fallbacks.
        """
        if path:
            current = data
            parts = path.split(".")
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                    current = current[int(part)]
                else:
                    return None

            if isinstance(current, str):
                return current
            elif isinstance(current, (int, float, bool)):
                return str(current)
            return None

        # Default fallback key resolution if no response_path is configured
        if isinstance(data, str):
            return data
        elif isinstance(data, dict):
            for fallback_key in ("response", "answer", "output", "text", "message", "content"):
                if fallback_key in data:
                    val = data[fallback_key]
                    if isinstance(val, str):
                        return val
                    elif isinstance(val, (int, float, bool)):
                        return str(val)
        return None
