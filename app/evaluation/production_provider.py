"""
Production LLM Provider Adapter (STEP 14B)

This module implements ProductionLLMProvider, a production-ready HTTP vendor adapter
subclassing LLMProvider.

ARCHITECTURAL & SECURITY DIRECTIVES:
1. Vendor-agnostic HTTP adapter communicating via standard REST endpoints (e.g. OpenAI / OpenAI-compatible).
2. Does NOT import vendor SDKs (openai, anthropic).
3. API key is wrapped in SecretStr and NEVER exposed in logs, repr(), str(), or exceptions.
4. Transport & provider failures (timeout, HTTP 401/403/429/5xx, malformed response) are converted
   into safe LLMProviderError exceptions without revealing secrets.
5. Target credentials and LLM provider credentials are fully isolated.
"""

from typing import Any, Dict, Optional
import httpx

from app.evaluation.config import LLMProviderConfig
from app.evaluation.provider import LLMProvider


import time
from app.observability import emit_event, get_logger

logger = get_logger("agentshield.evaluation.llm_provider")


class LLMProviderError(Exception):
    """
    Safe exception raised when LLM provider communication or parsing fails.

    Guarantees secret non-disclosure: message strings are sanitized to ensure
    raw API keys or Authorization headers are never included in exception tracebacks.
    """

    def __init__(self, message: str) -> None:
        sanitized_message = self._sanitize_message(message)
        super().__init__(sanitized_message)
        self.message = sanitized_message

    @staticmethod
    def _sanitize_message(msg: str) -> str:
        """Strip bearer tokens or authorization patterns from error messages."""
        clean = str(msg)
        if "Bearer" in clean:
            import re
            clean = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", clean)
        return clean


class ProductionLLMProvider(LLMProvider):
    """
    Production-ready LLM Provider communicating with OpenAI-compatible REST endpoints via HTTP.
    """

    def __init__(
        self,
        config: LLMProviderConfig,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        """
        Initialize ProductionLLMProvider with explicit configuration.

        Args:
            config (LLMProviderConfig): Instantiated provider configuration model.
            http_client (Optional[httpx.Client]): Optional pre-configured httpx Client for dependency injection / mocking.

        Raises:
            LLMProviderError: If required API key configuration is missing.
        """
        if not isinstance(config, LLMProviderConfig):
            raise ValueError("config must be a valid LLMProviderConfig instance")

        if config.provider_type.lower() != "ollama":
            if config.api_key is None or not config.api_key.get_secret_value().strip():
                raise LLMProviderError("Missing required API key for production LLM provider")

        self.config = config
        self._http_client = http_client

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Send text generation request to the LLM provider API.

        Args:
            prompt (str): Main input prompt text.
            system_prompt (Optional[str]): System instruction prompt.

        Returns:
            str: Extracted textual completion from LLM.

        Raises:
            LLMProviderError: On timeout, authentication failure, rate limit, server error, or malformed output.
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.0,
        }

        headers = {"Content-Type": "application/json"}
        if self.config.api_key and self.config.api_key.get_secret_value().strip():
            api_key_str = self.config.api_key.get_secret_value().strip()
            headers["Authorization"] = f"Bearer {api_key_str}"


        start_perf = time.perf_counter()
        emit_event(
            logger,
            "llm.request.started",
            provider=self.config.provider_type,
            model=self.config.model,
        )

        try:
            if self._http_client is not None:
                response = self._http_client.post(
                    self.config.endpoint,
                    json=payload,
                    headers=headers,
                    timeout=self.config.timeout_seconds,
                )
            else:
                with httpx.Client(timeout=self.config.timeout_seconds) as client:
                    response = client.post(
                        self.config.endpoint,
                        json=payload,
                        headers=headers,
                    )
        except httpx.TimeoutException:
            dur = round((time.perf_counter() - start_perf) * 1000, 2)
            emit_event(
                logger,
                "llm.request.failed",
                level=30,
                provider=self.config.provider_type,
                model=self.config.model,
                status="failed",
                error_type="TimeoutException",
                duration_ms=dur,
            )
            raise LLMProviderError(f"LLM provider request timed out ({self.config.timeout_seconds}s)")
        except httpx.RequestError as exc:
            dur = round((time.perf_counter() - start_perf) * 1000, 2)
            emit_event(
                logger,
                "llm.request.failed",
                level=30,
                provider=self.config.provider_type,
                model=self.config.model,
                status="failed",
                error_type=type(exc).__name__,
                duration_ms=dur,
            )
            raise LLMProviderError("LLM provider network request failed")
        except Exception as exc:
            dur = round((time.perf_counter() - start_perf) * 1000, 2)
            emit_event(
                logger,
                "llm.request.failed",
                level=30,
                provider=self.config.provider_type,
                model=self.config.model,
                status="failed",
                error_type=type(exc).__name__,
                duration_ms=dur,
            )
            raise LLMProviderError("LLM provider communication failure")

        dur = round((time.perf_counter() - start_perf) * 1000, 2)

        # Handle HTTP status codes safely without leaking headers
        if response.status_code == 401 or response.status_code == 403:
            emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="AuthError", duration_ms=dur)
            raise LLMProviderError(f"LLM provider authentication failed (HTTP {response.status_code})")
        elif response.status_code == 429:
            emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="RateLimitError", duration_ms=dur)
            raise LLMProviderError("LLM provider rate limit exceeded (HTTP 429)")
        elif response.status_code >= 500:
            emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="ServerError", duration_ms=dur)
            raise LLMProviderError(f"LLM provider server error (HTTP {response.status_code})")
        elif response.status_code >= 400:
            emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="HTTPError", duration_ms=dur)
            raise LLMProviderError(f"LLM provider request failed (HTTP {response.status_code})")

        # Parse JSON response
        try:
            data: Dict[str, Any] = response.json()
        except Exception:
            emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="MalformedJSON", duration_ms=dur)
            raise LLMProviderError("Malformed LLM provider response: non-JSON body")

        try:
            choices = data.get("choices")
            if not isinstance(choices, list) or len(choices) == 0:
                emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="MalformedJSON", duration_ms=dur)
                raise LLMProviderError("Malformed LLM provider response: missing choices array")
            
            message_obj = choices[0].get("message")
            if not isinstance(message_obj, dict):
                emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="MalformedJSON", duration_ms=dur)
                raise LLMProviderError("Malformed LLM provider response: missing message object")

            content = message_obj.get("content")
            if content is None or not isinstance(content, str):
                emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="MalformedJSON", duration_ms=dur)
                raise LLMProviderError("Malformed LLM provider response: missing text content")

            emit_event(
                logger,
                "llm.request.completed",
                provider=self.config.provider_type,
                model=self.config.model,
                status="completed",
                duration_ms=dur,
            )
            return content
        except LLMProviderError:
            raise
        except Exception:
            emit_event(logger, "llm.request.failed", level=30, provider=self.config.provider_type, model=self.config.model, status="failed", error_type="MalformedSchema", duration_ms=dur)
            raise LLMProviderError("Malformed LLM provider response structure")

    def __repr__(self) -> str:
        """Sanitized string representation hiding API keys."""
        return f"ProductionLLMProvider(config={self.config!r})"

    def __str__(self) -> str:
        """Sanitized string representation hiding API keys."""
        return self.__repr__()
