"""
Target Contract Domain Models

This module defines strongly typed domain models for target agent configuration,
authentication specs, normalized execution results, and communication errors.

These models correspond to the specification defined in docs/target-contract.md.

DEVELOPER NOTE ON IMMUTABILITY:
The Pydantic models in this module use `ConfigDict(frozen=True)`. This configuration
prevents top-level field reassignment (e.g. `config.endpoint = "new"` will raise an error),
but it does NOT guarantee deep immutability of nested mutable Python objects such as
dictionaries or lists contained within field values.
"""

from enum import StrEnum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class TargetErrorCode(StrEnum):
    """Normalized target error classification codes."""

    CONFIGURATION_ERROR = "configuration_error"
    AUTHENTICATION_ERROR = "authentication_error"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    TARGET_SERVER_ERROR = "target_server_error"
    MALFORMED_RESPONSE = "malformed_response"
    RESPONSE_EXTRACTION_ERROR = "response_extraction_error"
    SSRF_REJECTION = "ssrf_rejection"
    UNKNOWN_ERROR = "unknown_error"


class AuthType(StrEnum):
    """Supported target authentication patterns."""

    BEARER = "bearer"
    API_KEY = "api_key"
    CUSTOM_HEADERS = "custom_headers"


class TargetAuthConfig(BaseModel):
    """
    Declarative target authentication configuration.
    
    IMMUTABILITY NOTE:
    `frozen=True` prevents field reassignment, but does not guarantee deep immutability
    of nested mutable structures (e.g. custom_headers dict).

    SECRET HANDLING NOTE:
    - Primary authentication token is represented using `SecretStr` to prevent accidental
      exposure in raw string or representation outputs.
    - `custom_headers` values are treated as configuration data and MUST NOT be logged.
    - Real secret-bearing custom headers should not be committed to source control.
    - Future production secret management and header redaction will be enforced at the
      adapter and security boundary.
    """

    model_config = ConfigDict(frozen=True)

    auth_type: AuthType
    token: Optional[SecretStr] = Field(
        default=None,
        description="Bearer token or API key value represented via SecretStr"
    )
    header_name: Optional[str] = Field(
        default=None,
        description="Custom header name for API key authentication (e.g. X-API-Key)"
    )
    custom_headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary key-value headers (configuration data; must not be logged)"
    )


class TargetError(BaseModel):
    """
    Normalized error detail returned when target communication fails.
    
    Decouples core scanning from target-specific runtime exceptions.
    Error messages must never include raw authorization secrets or credentials.

    IMMUTABILITY NOTE:
    `frozen=True` prevents field reassignment, but does not guarantee deep immutability
    of nested mutable structures (e.g. details dict).
    """

    model_config = ConfigDict(frozen=True)

    code: TargetErrorCode = Field(..., description="Machine-readable normalized error code")
    message: str = Field(..., description="Human-readable error description")
    retryable: bool = Field(default=False, description="Indicates whether the error is transient")
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Safe debug metadata (credentials stripped)"
    )


class TargetConfig(BaseModel):
    """
    Declarative configuration defining how AgentShield communicates with a target AI agent.
    
    Decoupled from any specific agent framework or HTTP request/response JSON schema.

    IMMUTABILITY NOTE:
    `frozen=True` prevents field reassignment, but does not guarantee deep immutability
    of nested mutable structures (e.g. headers, request_template dicts).
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Human-readable target identifier")
    endpoint: str = Field(..., description="Target endpoint URI / URL")
    method: str = Field(default="POST", description="HTTP method (GET, POST, etc.)")
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Static non-sensitive HTTP headers"
    )
    timeout_seconds: float = Field(
        default=30.0,
        description="Hard ceiling on target request duration in seconds"
    )
    request_template: Optional[Dict[str, Any]] = Field(
        default=None,
        description="JSON body template for payload mapping"
    )
    response_path: Optional[str] = Field(
        default=None,
        description="JSONPath or key path for isolating textual response"
    )
    authentication: Optional[TargetAuthConfig] = Field(
        default=None,
        description="Optional target authentication configuration"
    )

    @field_validator("name")
    @classmethod
    def validate_name_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Target name must not be empty or whitespace-only")
        return stripped

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Target endpoint must not be empty or whitespace-only")
        return stripped

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        return v

    @field_validator("method")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        stripped = v.strip().upper()
        if not stripped:
            raise ValueError("HTTP method must not be empty")
        return stripped


class TargetResult(BaseModel):
    """
    Normalized representation of a target agent execution output.
    
    IMMUTABILITY NOTE:
    `frozen=True` prevents field reassignment, but does not guarantee deep immutability
    of nested mutable structures (e.g. metadata dict, raw_response payload).

    IMPORTANT ARCHITECTURAL DIRECTIVE:
    - Target responses (output, raw_response) MUST be treated as UNTRUSTED external data.
    - TargetResult describes WHAT HAPPENED during target communication.
    - TargetResult MUST NOT contain security verdicts, vulnerability severity, findings,
      or risk scores. Downstream Detection & Risk engines handle all security evaluation.
    """

    model_config = ConfigDict(frozen=True)

    success: bool = Field(..., description="True if target communication succeeded without transport/adapter error")
    output: Optional[str] = Field(
        default=None,
        description="Extracted textual output response from target agent (untrusted external data)"
    )
    status_code: Optional[int] = Field(
        default=None,
        description="HTTP status code or protocol execution status"
    )
    latency_ms: Optional[float] = Field(
        default=None,
        description="Round-trip execution latency in milliseconds"
    )
    error: Optional[TargetError] = Field(
        default=None,
        description="Normalized error details if success is False"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Protocol headers, model identifiers, or operational metadata"
    )
    raw_response: Optional[Any] = Field(
        default=None,
        description="Reference or raw response payload (untrusted external data)"
    )
    trace_ref: Optional[str] = Field(
        default=None,
        description="Optional telemetry trace identifier for glass-box integration"
    )
