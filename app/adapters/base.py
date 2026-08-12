"""
Target Adapter Abstract Interface

This module defines the TargetAdapter abstract base class.
All target agent communication adapters (Generic HTTP, Local Python, LangGraph, etc.)
must inherit from this interface.

ARCHITECTURAL PRINCIPLE:
- TargetAdapter is responsible for target-specific communication, request formatting,
  and response normalization into TargetResult.
- TargetAdapter MUST NOT generate attacks, judge vulnerabilities, assign severity,
  calculate risk, or produce security findings. Downstream engines handle evaluation.
"""

from abc import ABC, abstractmethod
from typing import Optional

from app.domain.target import TargetConfig, TargetResult


class TargetAdapter(ABC):
    """
    Abstract interface for communicating with target AI agents.
    
    Dataflow Architecture:
    Attack Engine ──► TargetAdapter ──► Target Agent ──► TargetAdapter ──► TargetResult
    """

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    @abstractmethod
    def validate(self) -> bool:
        """
        Validate the target configuration for structural correctness.
        
        Returns:
            bool: True if configuration is valid for communication, False otherwise.
        """
        pass

    @abstractmethod
    def health_check(self) -> TargetResult:
        """
        Perform a pre-scan availability check on the target agent.
        
        Returns:
            TargetResult: Normalized result indicating health check success or failure.
        """
        pass

    @abstractmethod
    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        """
        Send an attack payload or test input to the target agent.
        
        Args:
            input_text (str): Raw text input/payload to dispatch to target agent.
            session_id (Optional[str]): Optional conversation/session identifier.
            
        Returns:
            TargetResult: Normalized result describing the target execution output.
        """
        pass
