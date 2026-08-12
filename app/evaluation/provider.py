"""
LLM Provider Abstraction Layer (STEP 13B)

This module defines:
1. LLMProvider: Abstract interface decoupling LLM evaluators from specific vendor APIs.
2. FakeLLMProvider: Configurable mock provider for unit testing and offline execution.
"""

from abc import ABC, abstractmethod
from typing import Callable, Dict, Optional


class LLMProvider(ABC):
    """
    Abstract interface for LLM text generation providers.
    """

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate text completion from LLM given prompt and optional system prompt.

        Args:
            prompt (str): Main input prompt.
            system_prompt (Optional[str]): Optional system instruction prompt.

        Returns:
            str: Raw text output from LLM.
        """
        pass


class FakeLLMProvider(LLMProvider):
    """
    Fake/Mock LLM provider for unit tests and local execution.
    """

    def __init__(
        self,
        default_response: str = '{"verdict": "safe", "confidence": 0.9, "rationale": "Default safe fake verdict", "matched_indicators": [], "evidence_summary": "Clean output"}',
        response_map: Optional[Dict[str, str]] = None,
        exception_to_raise: Optional[Exception] = None,
        custom_handler: Optional[Callable[[str, Optional[str]], str]] = None,
    ) -> None:
        """
        Initialize FakeLLMProvider.

        Args:
            default_response (str): Fallback JSON string response.
            response_map (Optional[Dict[str, str]]): Mapping of keyword substrings in prompt to response strings.
            exception_to_raise (Optional[Exception]): Exception to simulate provider failure.
            custom_handler (Optional[Callable[[str, Optional[str]], str]]): Custom dynamic handler function.
        """
        self.default_response = default_response
        self.response_map = response_map or {}
        self.exception_to_raise = exception_to_raise
        self.custom_handler = custom_handler
        self.call_history = []

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate mock response or raise configured exception.
        """
        self.call_history.append({"prompt": prompt, "system_prompt": system_prompt})

        if self.exception_to_raise is not None:
            raise self.exception_to_raise

        if self.custom_handler is not None:
            return self.custom_handler(prompt, system_prompt)

        for keyword, response in self.response_map.items():
            if keyword.lower() in prompt.lower():
                return response

        return self.default_response
