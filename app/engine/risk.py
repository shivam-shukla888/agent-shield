"""
Risk Engine Implementation

This module defines the RiskEngine class, which evaluates Finding domain models
against contextual RiskFactors to calculate quantitative risk scores and assign RiskLevels.

ARCHITECTURAL DIRECTIVES:
1. RiskEngine is 100% deterministic, transparent, and in-memory.
2. It MUST NOT contact targets, execute probes, call external APIs/LLMs, or modify Finding objects.
3. Numerical mappings and weights are AgentShield MVP policy defaults, not universal security standards.
4. Finding confidence is propagated directly without modifying the risk score.
5. FindingSeverity does NOT directly determine RiskLevel; RiskLevel is calculated solely from contextual RiskFactors.
"""

from typing import Dict

from app.domain.finding import Finding
from app.domain.risk import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    ImpactLevel,
    RiskAssessment,
    RiskFactors,
    RiskLevel,
    ToolPrivilege,
)

# -----------------------------------------------------------------------------
# MVP Policy Baseline Weights (Sum = 1.0 / 100%)
# -----------------------------------------------------------------------------
IMPACT_WEIGHT: float = 0.30
EXPLOITABILITY_WEIGHT: float = 0.25
BLAST_RADIUS_WEIGHT: float = 0.20
ASSET_SENSITIVITY_WEIGHT: float = 0.15
TOOL_PRIVILEGE_WEIGHT: float = 0.10

# Verify weight sum invariant at module load
_TOTAL_WEIGHT = (
    IMPACT_WEIGHT
    + EXPLOITABILITY_WEIGHT
    + BLAST_RADIUS_WEIGHT
    + ASSET_SENSITIVITY_WEIGHT
    + TOOL_PRIVILEGE_WEIGHT
)
assert abs(_TOTAL_WEIGHT - 1.0) < 1e-6, "RiskEngine weights must sum to exactly 1.0"

# -----------------------------------------------------------------------------
# MVP Numeric Factor Mappings (0 to 100)
# -----------------------------------------------------------------------------
IMPACT_MAP: Dict[ImpactLevel, float] = {
    ImpactLevel.NEGLIGIBLE: 0.0,
    ImpactLevel.LOW: 25.0,
    ImpactLevel.MEDIUM: 50.0,
    ImpactLevel.HIGH: 75.0,
    ImpactLevel.CRITICAL: 100.0,
}

EXPLOITABILITY_MAP: Dict[ExploitabilityLevel, float] = {
    ExploitabilityLevel.LOW: 25.0,
    ExploitabilityLevel.MEDIUM: 50.0,
    ExploitabilityLevel.HIGH: 75.0,
    ExploitabilityLevel.CRITICAL: 100.0,
}

BLAST_RADIUS_MAP: Dict[BlastRadiusLevel, float] = {
    BlastRadiusLevel.LIMITED: 20.0,
    BlastRadiusLevel.LOW: 40.0,
    BlastRadiusLevel.MEDIUM: 60.0,
    BlastRadiusLevel.HIGH: 80.0,
    BlastRadiusLevel.CRITICAL: 100.0,
}

ASSET_SENSITIVITY_MAP: Dict[AssetSensitivity, float] = {
    AssetSensitivity.PUBLIC: 10.0,
    AssetSensitivity.INTERNAL: 30.0,
    AssetSensitivity.PERSONAL: 55.0,
    AssetSensitivity.CONFIDENTIAL: 80.0,
    AssetSensitivity.HIGHLY_SENSITIVE: 100.0,
}

TOOL_PRIVILEGE_MAP: Dict[ToolPrivilege, float] = {
    ToolPrivilege.NONE: 0.0,
    ToolPrivilege.READ: 25.0,
    ToolPrivilege.WRITE: 60.0,
    ToolPrivilege.DESTRUCTIVE: 85.0,
    ToolPrivilege.ADMIN: 100.0,
}


def score_to_risk_level(score: float) -> RiskLevel:
    """
    Deterministically convert a numerical risk score (0.0 to 100.0) into a RiskLevel.

    Thresholds:
    0.00  - 19.99 -> INFO
    20.00 - 39.99 -> LOW
    40.00 - 59.99 -> MEDIUM
    60.00 - 79.99 -> HIGH
    80.00 - 100.0 -> CRITICAL

    Args:
        score (float): Bounded risk score between 0.0 and 100.0.

    Returns:
        RiskLevel: Corresponding RiskLevel enum value.
    """
    if score < 20.0:
        return RiskLevel.INFO
    elif score < 40.0:
        return RiskLevel.LOW
    elif score < 60.0:
        return RiskLevel.MEDIUM
    elif score < 80.0:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


class RiskEngine:
    """
    Engine for evaluating security Findings against target RiskFactors to construct RiskAssessments.

    Dataflow:
    Finding + RiskFactors ──► RiskEngine ──► Score & Factor Calculation ──► RiskAssessment
    """

    def assess_risk(self, finding: Finding, factors: RiskFactors) -> RiskAssessment:
        """
        Evaluate a Finding and contextual RiskFactors to produce a RiskAssessment.

        Args:
            finding (Finding): The validated security finding.
            factors (RiskFactors): Contextual environment risk factors.

        Returns:
            RiskAssessment: Immutable risk assessment domain object.

        Raises:
            ValueError: If finding or factors are invalid or missing.
        """
        if not isinstance(finding, Finding):
            raise ValueError("finding must be a valid Finding instance")
        if not isinstance(factors, RiskFactors):
            raise ValueError("factors must be a valid RiskFactors instance")

        # 1. Normalize factors to numeric values (0 - 100)
        impact_val = IMPACT_MAP[factors.impact]
        exploitability_val = EXPLOITABILITY_MAP[factors.exploitability]
        blast_radius_val = BLAST_RADIUS_MAP[factors.blast_radius]
        asset_sensitivity_val = ASSET_SENSITIVITY_MAP[factors.asset_sensitivity]
        tool_privilege_val = TOOL_PRIVILEGE_MAP[factors.tool_privilege]

        # 2. Weighted score calculation
        raw_score = (
            impact_val * IMPACT_WEIGHT
            + exploitability_val * EXPLOITABILITY_WEIGHT
            + blast_radius_val * BLAST_RADIUS_WEIGHT
            + asset_sensitivity_val * ASSET_SENSITIVITY_WEIGHT
            + tool_privilege_val * TOOL_PRIVILEGE_WEIGHT
        )

        # 3. Bound and round score
        bounded_score = max(0.0, min(100.0, raw_score))
        final_score = round(bounded_score, 2)

        # 4. Derive risk level
        risk_level = score_to_risk_level(final_score)

        # 5. Deterministic risk_id
        risk_id = f"RISK_{finding.finding_id}"

        # 6. Deterministic human-readable rationale
        rationale = (
            f"Risk score {final_score:.2f} was derived from impact={factors.impact.value}, "
            f"exploitability={factors.exploitability.value}, blast_radius={factors.blast_radius.value}, "
            f"asset_sensitivity={factors.asset_sensitivity.value}, and tool_privilege={factors.tool_privilege.value}."
        )

        # 7. Construct RiskAssessment (confidence propagated directly from finding)
        return RiskAssessment(
            risk_id=risk_id,
            finding_id=finding.finding_id,
            risk_level=risk_level,
            risk_score=final_score,
            confidence=finding.confidence,
            factors=factors,
            rationale=rationale,
            metadata={
                "finding_severity": finding.severity.value,
                "finding_category": finding.category.value,
            },
        )
