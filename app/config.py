"""
Production Configuration & Environment Settings (STEP 18A)

This module defines AppConfig to parse, validate, and manage production environment
configuration parameters deterministically during application startup.

SECURITY & ARCHITECTURAL DIRECTIVES:
1. Environment secrets (API keys, DB connection strings, LLM keys) are wrapped in SecretStr.
2. Secret values MUST NEVER be printed in logs, tracebacks, or string representations (__repr__ / __str__).
3. Rejects invalid configuration parameters (ports outside 1..65535, non-positive rate limits or timeouts,
   missing LLM API keys for production providers) deterministically during startup.
"""

import os
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


VALID_LOG_LEVELS: Set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
VALID_LLM_PROVIDERS: Set[str] = {"fake", "openai", "anthropic", "groq", "ollama", "custom", "none"}
CLOUD_LLM_PROVIDERS: Set[str] = {"openai", "anthropic", "groq"}


class AppConfig(BaseModel):
    """
    Application Configuration Schema & Environment Validator.
    """

    host: str = Field(default="0.0.0.0", description="ASGI server binding host address")
    port: int = Field(default=8000, description="ASGI server binding TCP port number (1..65535)")
    log_level: str = Field(default="INFO", description="Logging verbosity level")

    api_key: Optional[SecretStr] = Field(default=None, description="Master API Key for endpoint authentication")
    rate_limit_rpm: int = Field(default=60, description="Requests per minute rate limit quota")

    database_url: Optional[SecretStr] = Field(default=None, description="PostgreSQL or SQL storage connection URL")

    llm_provider: str = Field(default="fake", description="LLM provider backend type")
    llm_api_key: Optional[SecretStr] = Field(default=None, description="LLM provider authentication API key")
    llm_model: Optional[str] = Field(default=None, description="LLM provider model identifier")
    llm_timeout: float = Field(default=30.0, description="LLM request timeout in seconds")
    llm_endpoint: Optional[str] = Field(default=None, description="Custom LLM provider HTTP API endpoint")

    allowed_target_domains: List[str] = Field(
        default_factory=list,
        description="Allowed target domain hostnames for security scanning (empty = no restriction)",
    )


    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("APP_HOST must be a non-empty string")
        if any(c in stripped for c in ("\r", "\n", "\t", "\0", " ")):
            raise ValueError("APP_HOST contains invalid control characters or spaces")
        return stripped

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError(f"APP_PORT must be between 1 and 65535 (got {v})")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        upper = v.strip().upper()
        if upper not in VALID_LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)} (got '{v}')")
        return upper

    @field_validator("rate_limit_rpm")
    @classmethod
    def validate_rate_limit_rpm(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("AGENTSHIELD_RATE_LIMIT_RPM must be a positive integer > 0")
        return v

    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, v: str) -> str:
        lower = v.strip().lower()
        if lower not in VALID_LLM_PROVIDERS:
            raise ValueError(f"AGENTSHIELD_LLM_PROVIDER must be one of {sorted(VALID_LLM_PROVIDERS)} (got '{v}')")
        return lower

    @field_validator("llm_timeout")
    @classmethod
    def validate_llm_timeout(cls, v: float) -> float:
        if v <= 0.0 or v > 300.0:
            raise ValueError("AGENTSHIELD_LLM_TIMEOUT must be between 0.0 and 300.0 seconds")
        return v

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: Optional[SecretStr]) -> Optional[SecretStr]:
        if v is None:
            return None
        raw = v.get_secret_value().strip()
        if not raw:
            return None
        lower = raw.lower()
        if not (lower.startswith("postgresql://") or lower.startswith("postgres://") or lower.startswith("sqlite://")):
            raise ValueError("DATABASE_URL must start with 'postgresql://', 'postgres://', or 'sqlite://'")
        return v

    @model_validator(mode="after")
    def validate_cloud_llm_credentials(self) -> "AppConfig":
        if self.llm_provider in CLOUD_LLM_PROVIDERS:
            if self.llm_api_key is None or not self.llm_api_key.get_secret_value().strip():
                raise ValueError(
                    f"AGENTSHIELD_LLM_API_KEY is required when AGENTSHIELD_LLM_PROVIDER is set to '{self.llm_provider}'"
                )
        return self

    @classmethod
    def from_env(cls) -> "AppConfig":
        """
        Construct AppConfig by reading environment variables safely.
        """
        host = os.getenv("APP_HOST") or "0.0.0.0"

        raw_port = os.getenv("APP_PORT") or "8000"
        try:
            port = int(raw_port)
        except ValueError:
            raise ValueError(f"APP_PORT must be a valid integer, got '{raw_port}'")

        log_level = os.getenv("LOG_LEVEL") or "INFO"

        raw_api_key = os.getenv("AGENTSHIELD_API_KEY") or os.getenv("API_KEY")
        api_key = SecretStr(raw_api_key.strip()) if raw_api_key and raw_api_key.strip() else None

        raw_rpm = os.getenv("AGENTSHIELD_RATE_LIMIT_RPM") or os.getenv("RATE_LIMIT_RPM") or "60"
        try:
            rpm = int(raw_rpm)
        except ValueError:
            raise ValueError(f"AGENTSHIELD_RATE_LIMIT_RPM must be an integer, got '{raw_rpm}'")

        raw_db_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
        database_url = SecretStr(raw_db_url.strip()) if raw_db_url and raw_db_url.strip() else None

        llm_provider = os.getenv("AGENTSHIELD_LLM_PROVIDER") or "fake"

        raw_llm_key = os.getenv("AGENTSHIELD_LLM_API_KEY") or os.getenv("LLM_API_KEY")
        llm_api_key = SecretStr(raw_llm_key.strip()) if raw_llm_key and raw_llm_key.strip() else None

        llm_model = os.getenv("AGENTSHIELD_LLM_MODEL") or None

        raw_llm_timeout = os.getenv("AGENTSHIELD_LLM_TIMEOUT") or "30.0"
        try:
            llm_timeout = float(raw_llm_timeout)
        except ValueError:
            raise ValueError(f"AGENTSHIELD_LLM_TIMEOUT must be a float, got '{raw_llm_timeout}'")

        llm_endpoint = os.getenv("AGENTSHIELD_LLM_ENDPOINT") or None

        raw_allowed = os.getenv("AGENTSHIELD_ALLOWED_TARGET_DOMAINS")
        if raw_allowed is not None and raw_allowed.strip():
            allowed_target_domains = [d.strip().lower() for d in raw_allowed.split(",") if d.strip()]
        else:
            demo_guardrails = os.getenv("AGENTSHIELD_DEMO_GUARDRAILS", "false").lower() in ("true", "1", "yes")
            if demo_guardrails:
                allowed_target_domains = ["localhost", "127.0.0.1", "testagent.local", "test_target"]
            else:
                allowed_target_domains = []


        return cls(
            host=host,
            port=port,
            log_level=log_level,
            api_key=api_key,
            rate_limit_rpm=rpm,
            database_url=database_url,
            llm_provider=llm_provider,
            llm_api_key=llm_api_key,
            llm_model=llm_model,
            llm_timeout=llm_timeout,
            llm_endpoint=llm_endpoint,
            allowed_target_domains=allowed_target_domains,
        )

    def safe_dict(self) -> Dict[str, Any]:
        """
        Return a safe non-sensitive representation for status endpoints or logging.
        Redacts all SecretStr fields.
        """
        return {
            "host": self.host,
            "port": self.port,
            "log_level": self.log_level,
            "api_key_configured": self.api_key is not None,
            "rate_limit_rpm": self.rate_limit_rpm,
            "database_configured": self.database_url is not None,
            "llm_provider": self.llm_provider,
            "llm_key_configured": self.llm_api_key is not None,
            "llm_model": self.llm_model,
            "llm_timeout": self.llm_timeout,
            "llm_endpoint": self.llm_endpoint,
            "allowed_target_domains": self.allowed_target_domains,
        }

