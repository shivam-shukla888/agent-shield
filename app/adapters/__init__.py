"""
AgentShield Target Adapters Package
"""

from app.adapters.base import TargetAdapter
from app.adapters.http import GenericHTTPAdapter

__all__ = ["TargetAdapter", "GenericHTTPAdapter"]
