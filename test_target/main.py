"""
FastAPI HTTP Endpoint for Local Security Test Target

Exposes local POST /chat and GET /health endpoints for local security testing.

SECURITY WARNING:
- For local development and test environment usage ONLY.
- DO NOT deploy this application to public networks or production environments.
"""

from typing import Any, Dict, List
from fastapi import FastAPI
from pydantic import BaseModel

from test_target.agent import TestAgentEngine
from test_target.tools import get_tool_events, reset_test_state

local_target_app = FastAPI(
    title="AgentShield Local Security Test Target",
    description="Deterministic local AI agent test fixture for AgentShield development",
    version="0.1.0",
)

agent_engine = TestAgentEngine()


class ChatRequest(BaseModel):
    prompt: str


class ChatResponse(BaseModel):
    response: str


@local_target_app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check for local test target."""
    return {"status": "ok", "target": "test_agent"}


@local_target_app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    """
    Primary chat endpoint for local security test agent.
    """
    output_text = agent_engine.process_prompt(request.prompt)
    return ChatResponse(response=output_text)


@local_target_app.get("/debug/tool_events")
def debug_tool_events() -> Dict[str, List[Dict[str, Any]]]:
    """Debug endpoint returning in-memory tool execution event log."""
    return {"tool_events": get_tool_events()}


@local_target_app.post("/debug/reset")
def debug_reset() -> Dict[str, str]:
    """Debug endpoint resetting synthetic database and tool execution log."""
    reset_test_state()
    return {"status": "reset_complete"}
