"""
LLM Provider Configuration Boundary Model (STEP 14B)

This module defines LLMProviderConfig, an immutable Pydantic configuration model
for LLM provider credentials, model selection, timeouts, and endpoint URLs.

SECURITY DIRECTIVES:
1. API keys are wrapped in Pydantic `SecretStr` to prevent secret leakage in logs or representations.
2. Credentials MUST NOT have hardcoded production secret defaults.
3. No credentials appear in repr() or str() outputs.
"""

import os
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class LLMProviderConfig(BaseModel):
    """
    Configuration model for LLM provider adapters.

    IMMUTABILITY NOTE:
    Uses `ConfigDict(frozen=True)` to prevent field reassignment after instantiation.
    """

    model_config = ConfigDict(frozen=True)

    provider_type: str = Field(
        default="fake",
        description="Type of LLM provider engine ('fake', 'cloud', 'production', 'openai', 'ollama')"
    )
    api_key: Optional[SecretStr] = Field(
        default=None,
        description="Vendor API authorization key (represented via SecretStr)"
    )
    model: str = Field(
        default="gpt-4o",
        description="Model name/version string (e.g. gpt-4o, claude-3-5-sonnet, llama3)"
    )
    timeout_seconds: float = Field(
        default=30.0,
        description="Hard timeout ceiling for provider requests in seconds"
    )
    endpoint: str = Field(
        default="https://api.openai.com/v1/chat/completions",
        description="Vendor REST API endpoint URL"
    )

    @field_validator("provider_type")
    @classmethod
    def validate_provider_type(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("provider_type must not be empty")
        valid_providers = {"fake", "production", "openai", "cloud", "ollama"}
        if clean not in valid_providers:
            raise ValueError(f"Unsupported provider_type '{v}'. Supported options: {sorted(valid_providers)}")
        return clean


    @field_validator("model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("model must not be empty or whitespace-only")
        return clean

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if v < 0.1 or v > 300.0:
            raise ValueError("timeout_seconds must be between 0.1 and 300.0 seconds")
        return v

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("endpoint must not be empty")
        if not (clean.startswith("http://") or clean.startswith("https://")):
            raise ValueError("endpoint must start with http:// or https://")
        return clean

    @classmethod
    def from_env(cls) -> "LLMProviderConfig":
        """
        Construct LLMProviderConfig from environment variables.

        Environment variables:
            AGENTSHIELD_LLM_PROVIDER / LLM_PROVIDER
            AGENTSHIELD_LLM_API_KEY / LLM_API_KEY
            AGENTSHIELD_LLM_MODEL / LLM_MODEL
            AGENTSHIELD_LLM_TIMEOUT / LLM_TIMEOUT
            AGENTSHIELD_LLM_ENDPOINT / LLM_ENDPOINT

        Returns:
            LLMProviderConfig: Instantiated configuration model.
        """
        provider_type = (
            os.getenv("AGENTSHIELD_LLM_PROVIDER")
            or os.getenv("LLM_PROVIDER")
            or "fake"
        )
        api_key_str = (
            os.getenv("AGENTSHIELD_LLM_API_KEY")
            or os.getenv("LLM_API_KEY")
        )
        api_key = SecretStr(api_key_str.strip()) if api_key_str and api_key_str.strip() else None

        default_model = "llama3" if provider_type.lower() == "ollama" else "gpt-4o"
        model = (
            os.getenv("AGENTSHIELD_LLM_MODEL")
            or os.getenv("LLM_MODEL")
            or default_model
        )
        env_timeout = os.getenv("AGENTSHIELD_LLM_TIMEOUT") or os.getenv("LLM_TIMEOUT")
        timeout = float(env_timeout) if env_timeout and env_timeout.strip() else 30.0

        default_endpoint = (
            "http://localhost:11434/v1/chat/completions"
            if provider_type.lower() == "ollama"
            else "https://api.openai.com/v1/chat/completions"
        )
        endpoint = (
            os.getenv("AGENTSHIELD_LLM_ENDPOINT")
            or os.getenv("LLM_ENDPOINT")
            or default_endpoint
        )

        return cls(
            provider_type=provider_type,
            api_key=api_key,
            model=model,
            timeout_seconds=timeout,
            endpoint=endpoint,
        )

    def __repr__(self) -> str:
        """Sanitized string representation hiding API keys."""
        key_status = "set" if self.api_key else "none"
        return (
            f"LLMProviderConfig(provider_type={self.provider_type!r}, model={self.model!r}, "
            f"timeout_seconds={self.timeout_seconds}, api_key=SecretStr('***{key_status}***'), "
            f"endpoint={self.endpoint!r})"
        )

    def __str__(self) -> str:
        """Sanitized string output."""
        return self.__repr__()
