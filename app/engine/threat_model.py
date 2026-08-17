"""
Threat Model Generator (STEP 23A)

Rule-based Threat Model Generator mapping target agent declared tools, capabilities,
and prompt directives to structured ThreatCategory risk assessments.

ARCHITECTURAL DIRECTIVES:
1. Pure rule-based mapping (zero external ML/LLM network dependency).
2. Deterministic output: input tool definitions produce exact same ThreatModel.
3. Plugs into ScanEngine to enrich initial security scan contextual analysis.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from app.domain.risk import RiskLevel


class ThreatCategory(str, Enum):
    """Categories of tool abuse threats for AI agent target security."""

    FINANCIAL_ABUSE = "financial_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_FILE_ACCESS = "unauthorized_file_access"
    ARBITRARY_COMMAND_EXECUTION = "arbitrary_command_execution"
    PHISHING_SPAM = "phishing_spam"
    UNAUTHORIZED_SYSTEM_MODIFICATION = "unauthorized_system_modification"
    GENERAL_TOOL_MISUSE = "general_tool_misuse"


class ThreatAssessment(BaseModel):
    """Individual threat assessment for a declared agent tool or capability."""

    tool_name: str = Field(..., description="Declared tool or function name")
    threat_category: ThreatCategory = Field(..., description="Mapped threat category")
    risk_level: RiskLevel = Field(..., description="Estimated intrinsic risk level")
    description: str = Field(..., description="Deterministic description of abuse vector")
    mitigation: str = Field(..., description="Recommended security control mitigation")


class ThreatModel(BaseModel):
    """Structured threat model output for a target agent."""

    target_name: str = Field(..., description="Target application name")
    assessments: List[ThreatAssessment] = Field(default_factory=list)
    summary_by_level: Dict[str, int] = Field(default_factory=dict)


# Rule table mapping keyword substrings to ThreatCategory & RiskLevel
_TOOL_RULE_TABLE = [
    (
        ["refund", "payment", "transfer", "billing", "credit", "money", "transaction", "balance"],
        ThreatCategory.FINANCIAL_ABUSE,
        RiskLevel.CRITICAL,
        "Tool allows financial state mutation. Unbounded LLM execution could allow unauthorized refunds or fraudulent transfers.",
        "Enforce strict out-of-band human authorization (2FA/approval gate) and explicit amount transaction limits.",
    ),
    (
        ["query", "select", "database", "db", "sql", "search", "customer", "pii", "user_data"],
        ThreatCategory.DATA_EXFILTRATION,
        RiskLevel.HIGH,
        "Tool provides access to internal databases or PII data store. Indirect prompt injection could leak sensitive records.",
        "Implement row-level security, column masking, and read-only parameterized query execution contexts.",
    ),
    (
        ["file", "read", "fetch", "get_file", "download", "document", "path"],
        ThreatCategory.UNAUTHORIZED_FILE_ACCESS,
        RiskLevel.HIGH,
        "Tool accesses local or cloud filesystem documents. Path traversal attacks could expose internal system credentials.",
        "Enforce strict path chroot/sandbox constraints and block access to sensitive system paths (/etc, .env, credentials).",
    ),
    (
        ["exec", "shell", "bash", "command", "run_script", "terminal", "eval", "code"],
        ThreatCategory.ARBITRARY_COMMAND_EXECUTION,
        RiskLevel.CRITICAL,
        "Tool executes arbitrary code or shell commands. Prompt injection could allow full remote code execution (RCE).",
        "Restrict tool execution to isolated, ephemeral Docker containers without host network or volume access.",
    ),
    (
        ["email", "mail", "send", "notify", "slack", "webhook", "sms"],
        ThreatCategory.PHISHING_SPAM,
        RiskLevel.MEDIUM,
        "Tool dispatches outbound communications. Unaligned prompt handling could be leveraged to send spam or phishing messages.",
        "Require user confirmation before dispatching outbound external messages and enforce recipient domain allowlists.",
    ),
    (
        ["delete", "remove", "update", "cancel", "reset", "write", "modify", "patch"],
        ThreatCategory.UNAUTHORIZED_SYSTEM_MODIFICATION,
        RiskLevel.HIGH,
        "Tool modifies state or deletes resources. Prompt override could trigger unauthorized data destruction or service cancellation.",
        "Enforce role-based access control (RBAC) and require explicit secondary token confirmation for destructive actions.",
    ),
]


class ThreatModelGenerator:
    """
    Deterministic Threat Model Generator for AI agent security targets.
    """

    def generate_threat_model(
        self,
        target_name: str,
        declared_tools: Optional[List[str]] = None,
        system_prompt: Optional[str] = None,
    ) -> ThreatModel:
        """
        Generate a structured ThreatModel based on declared target tools and prompt directives.

        Args:
            target_name (str): Name of target agent.
            declared_tools (Optional[List[str]]): List of declared tool/function names.
            system_prompt (Optional[str]): Target system prompt text for keyword scanning.

        Returns:
            ThreatModel: Structured threat model mapping tools to threat categories and mitigations.
        """
        tools = list(declared_tools) if declared_tools else []

        # If system_prompt is provided, extract potential tool names/keywords
        if system_prompt and not tools:
            prompt_lower = system_prompt.lower()
            for keywords, _, _, _, _ in _TOOL_RULE_TABLE:
                for kw in keywords:
                    if kw in prompt_lower and kw not in tools:
                        tools.append(f"implied_{kw}_tool")

        # Fallback default if no tools specified
        if not tools:
            tools = ["generic_assistant_chat"]

        assessments: List[ThreatAssessment] = []
        summary_counts: Dict[str, int] = {
            RiskLevel.CRITICAL.value: 0,
            RiskLevel.HIGH.value: 0,
            RiskLevel.MEDIUM.value: 0,
            RiskLevel.LOW.value: 0,
            RiskLevel.INFO.value: 0,
        }

        for tool in tools:
            tool_clean = tool.strip()
            tool_lower = tool_clean.lower()
            matched = False

            for keywords, category, risk_lvl, desc, mitig in _TOOL_RULE_TABLE:
                if any(kw in tool_lower for kw in keywords):
                    assessment = ThreatAssessment(
                        tool_name=tool_clean,
                        threat_category=category,
                        risk_level=risk_lvl,
                        description=desc,
                        mitigation=mitig,
                    )
                    assessments.append(assessment)
                    summary_counts[risk_lvl.value] += 1
                    matched = True
                    break

            if not matched:
                assessment = ThreatAssessment(
                    tool_name=tool_clean,
                    threat_category=ThreatCategory.GENERAL_TOOL_MISUSE,
                    risk_level=RiskLevel.LOW,
                    description="General purpose assistant tool. Subject to standard prompt injection and safety bypass.",
                    mitigation="Monitor execution logs and enforce output sanitization boundaries.",
                )
                assessments.append(assessment)
                summary_counts[RiskLevel.LOW.value] += 1

        return ThreatModel(
            target_name=target_name,
            assessments=assessments,
            summary_by_level=summary_counts,
        )
