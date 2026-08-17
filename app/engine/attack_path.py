"""
Attack Path Engine (STEP 23B)

Deterministic correlation engine that chains related scan findings into multi-stage attack paths
(e.g. System Prompt Disclosure -> Instruction Override -> Tool Authorization Bypass).

ARCHITECTURAL DIRECTIVES:
1. Consumes validated Finding DTOs from scan execution.
2. Applies rule-based correlation heuristics to construct ordered AttackPath sequences.
3. Pure code logic (zero ML / zero external network calls).
"""

from typing import Dict, List
from pydantic import BaseModel, Field

from app.domain.finding import Finding, FindingSeverity
from app.domain.probe import ProbeCategory



class AttackStep(BaseModel):
    """Single step within a multi-stage attack path."""

    step_index: int = Field(..., ge=1, description="1-indexed sequence order in attack path")
    finding_id: str = Field(..., description="Correlated finding ID")
    category: str = Field(..., description="Probe/Finding category name")
    description: str = Field(..., description="Summary of vulnerability step")
    severity: FindingSeverity = Field(..., description="Finding severity level")


class AttackPath(BaseModel):
    """Correlated multi-stage attack path representing vulnerability chaining."""

    path_id: str = Field(..., description="Unique attack path identifier")
    title: str = Field(..., description="Descriptive title of attack path")
    description: str = Field(..., description="Overview of attack chain progression")
    steps: List[AttackStep] = Field(default_factory=list)
    overall_severity: FindingSeverity = Field(..., description="Highest severity in chain")
    risk_score_multiplier: float = Field(1.0, ge=1.0, le=2.0, description="Risk multiplier for chained vectors")



# Category priority ordering for multi-stage sequence construction
_CATEGORY_SEQUENCE_ORDER = {
    ProbeCategory.SYSTEM_PROMPT_DISCLOSURE.value: 1,
    ProbeCategory.INSTRUCTION_OVERRIDE.value: 2,
    ProbeCategory.TOOL_AUTHORIZATION.value: 3,
}


class AttackPathEngine:
    """
    Deterministic correlation engine for building AttackPath chains from Finding results.
    """

    def correlate_attack_paths(self, findings: List[Finding]) -> List[AttackPath]:
        """
        Analyze a collection of Findings and generate correlated AttackPath instances.

        Args:
            findings (List[Finding]): Finding instances produced during a scan.

        Returns:
            List[AttackPath]: Ordered list of identified attack path chains.
        """
        if not findings:
            return []

        categories_present = {f.category for f in findings}


        paths: List[AttackPath] = []

        # Check for full multi-stage chain: System Prompt Disclosure -> Instruction Override -> Tool Authorization
        has_prompt_leak = ProbeCategory.SYSTEM_PROMPT_DISCLOSURE.value in categories_present
        has_override = ProbeCategory.INSTRUCTION_OVERRIDE.value in categories_present
        has_tool_auth = ProbeCategory.TOOL_AUTHORIZATION.value in categories_present

        if has_prompt_leak and has_override and has_tool_auth:
            chain_findings = sorted(
                findings,
                key=lambda f: _CATEGORY_SEQUENCE_ORDER.get(f.category, 99),
            )
            steps: List[AttackStep] = []
            for idx, f in enumerate(chain_findings, start=1):
                steps.append(
                    AttackStep(
                        step_index=idx,
                        finding_id=f.finding_id,
                        category=f.category,
                        description=f.description,
                        severity=f.severity,
                    )
                )

            paths.append(
                AttackPath(
                    path_id="PATH_FULL_COMPROMISE_CHAIN",
                    title="Full Agent Compromise Chain (Reconnaissance -> Override -> Privilege Escalation)",
                    description=(
                        "Attacker first extracts hidden system prompt instructions, uses revealed context to execute an "
                        "instruction override, and ultimately bypasses tool authorization control boundaries."
                    ),
                    steps=steps,
                    overall_severity=FindingSeverity.CRITICAL,
                    risk_score_multiplier=1.5,
                )
            )
        elif has_prompt_leak and has_override:
            chain_findings = [
                f for f in findings if f.category in (
                    ProbeCategory.SYSTEM_PROMPT_DISCLOSURE.value,
                    ProbeCategory.INSTRUCTION_OVERRIDE.value,
                )
            ]
            chain_findings.sort(key=lambda f: _CATEGORY_SEQUENCE_ORDER.get(f.category, 99))
            steps = [
                AttackStep(
                    step_index=idx,
                    finding_id=f.finding_id,
                    category=f.category,
                    description=f.description,
                    severity=f.severity,
                )
                for idx, f in enumerate(chain_findings, start=1)
            ]
            paths.append(
                AttackPath(
                    path_id="PATH_RECON_AND_OVERRIDE",
                    title="System Reconnaissance & Alignment Override Chain",
                    description="Attacker extracts system prompt directives and bypasses system instruction boundaries.",
                    steps=steps,
                    overall_severity=FindingSeverity.HIGH,
                    risk_score_multiplier=1.25,
                )
            )

        # Generate standalone fallback paths for any unchained finding
        chained_finding_ids = {step.finding_id for p in paths for step in p.steps}

        for f in findings:
            if f.finding_id not in chained_finding_ids:
                step = AttackStep(
                    step_index=1,
                    finding_id=f.finding_id,
                    category=f.category,
                    description=f.description,
                    severity=f.severity,
                )
                paths.append(
                    AttackPath(
                        path_id=f"PATH_SINGLE_{f.finding_id}",
                        title=f"Direct Vector: {f.title}",
                        description=f.description,
                        steps=[step],
                        overall_severity=f.severity,
                        risk_score_multiplier=1.0,
                    )
                )

        return paths
