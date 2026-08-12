"""
Evaluator Abstract Base Interface

This module defines the Evaluator abstract base class.
All evaluation implementations (Deterministic, heuristic, rule-based, or future LLM judges)
must inherit from this interface.

ARCHITECTURAL DIRECTIVES:
1. Evaluator operates strictly on already collected data (SecurityProbe and ProbeExecution).
2. Evaluator MUST NOT communicate directly with target agents or make external network calls.
3. Evaluator evaluates security policy adherence and produces an EvaluationResult.
"""

from abc import ABC, abstractmethod

from app.domain.evaluation import EvaluationResult
from app.domain.execution import ProbeExecution
from app.domain.probe import SecurityProbe


class Evaluator(ABC):
    """
    Abstract interface for evaluating security probe execution outcomes.

    Dataflow Architecture:
    SecurityProbe + ProbeExecution ──► Evaluator.evaluate() ──► EvaluationResult
    """

    @abstractmethod
    def evaluate(self, probe: SecurityProbe, execution: ProbeExecution) -> EvaluationResult:
        """
        Evaluate a probe execution outcome and return a normalized EvaluationResult.

        Args:
            probe (SecurityProbe): The security probe specification that was run.
            execution (ProbeExecution): The recorded execution outcome including TargetResult.

        Returns:
            EvaluationResult: The normalized evaluation verdict, confidence, and evidence.
        """
        pass
