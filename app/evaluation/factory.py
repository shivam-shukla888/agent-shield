"""
LLM Provider Factory / Selector (STEP 14B)

This module defines build_llm_provider, a factory function for instantiating
LLMProvider instances based on explicit configuration.

ARCHITECTURAL DIRECTIVES:
1. Returns FakeLLMProvider for test/dev mode (default).
2. Instantiates ProductionLLMProvider when explicitly configured.
3. Fails safely with LLMProviderError if production configuration is incomplete,
   without leaking secrets or dumping raw tracebacks.
"""

from typing import Optional

from app.evaluation.config import LLMProviderConfig
from app.evaluation.production_provider import LLMProviderError, ProductionLLMProvider
from app.evaluation.provider import FakeLLMProvider, LLMProvider


def build_llm_provider(config: Optional[LLMProviderConfig] = None) -> LLMProvider:
    """
    Build and return an LLMProvider instance based on configuration.

    Args:
        config (Optional[LLMProviderConfig]): Provider configuration instance.
            If omitted, loads configuration from environment variables via LLMProviderConfig.from_env().

    Returns:
        LLMProvider: Configured provider instance (FakeLLMProvider or ProductionLLMProvider).

    Raises:
        LLMProviderError: If production provider configuration is incomplete or invalid.
    """
    if config is None:
        config = LLMProviderConfig.from_env()

    provider_type = config.provider_type.lower()

    if provider_type == "fake":
        return FakeLLMProvider()

    if provider_type in ("production", "openai"):
        if config.api_key is None or not config.api_key.get_secret_value().strip():
            raise LLMProviderError("Missing required API key for production LLM provider configuration")
        return ProductionLLMProvider(config=config)

    raise LLMProviderError(f"Unsupported LLM provider_type '{config.provider_type}'")
