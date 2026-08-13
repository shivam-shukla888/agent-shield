"""
AgentShield Evaluation Package (Deterministic & LLM Evaluator Engines)
"""

from app.evaluation.base import Evaluator
from app.evaluation.config import LLMProviderConfig
from app.evaluation.deterministic import (
    DetectionRule,
    DeterministicEvaluator,
    InstructionOverrideRule,
    SystemPromptDisclosureRule,
    ToolAuthorizationRule,
)
from app.evaluation.factory import build_llm_provider
from app.evaluation.hybrid import HybridEvaluationStrategy
from app.evaluation.llm import LLMEvaluator
from app.evaluation.production_provider import LLMProviderError, ProductionLLMProvider
from app.evaluation.provider import FakeLLMProvider, LLMProvider

__all__ = [
    "Evaluator",
    "DeterministicEvaluator",
    "DetectionRule",
    "SystemPromptDisclosureRule",
    "InstructionOverrideRule",
    "ToolAuthorizationRule",
    "LLMEvaluator",
    "LLMProvider",
    "FakeLLMProvider",
    "HybridEvaluationStrategy",
    "LLMProviderConfig",
    "LLMProviderError",
    "ProductionLLMProvider",
    "build_llm_provider",
]
