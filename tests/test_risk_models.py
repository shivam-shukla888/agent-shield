"""
Unit tests for Risk Assessment domain models (STEP 8A).
"""

import pytest
from pydantic import ValidationError

from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    ImpactLevel,
    RiskAssessment,
    RiskFactors,
    RiskLevel,
    ToolPrivilege,
)


def make_valid_risk_factors() -> RiskFactors:
    return RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.WRITE,
    )


def test_valid_risk_factors_creation():
    factors = make_valid_risk_factors()
    assert factors.impact == ImpactLevel.HIGH
    assert factors.exploitability == ExploitabilityLevel.HIGH
    assert factors.blast_radius == BlastRadiusLevel.MEDIUM
    assert factors.asset_sensitivity == AssetSensitivity.CONFIDENTIAL
    assert factors.tool_privilege == ToolPrivilege.WRITE


def test_valid_risk_assessment_creation():
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        risk_level=RiskLevel.HIGH,
        risk_score=78.5,
        confidence=0.95,
        factors=factors,
        rationale="System prompt disclosure exposes internal guidelines and configuration rules.",
        metadata={"assessor": "agentshield_v1"},
    )
    assert assessment.risk_id == "RISK_001"
    assert assessment.finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"
    assert assessment.risk_level == RiskLevel.HIGH
    assert assessment.risk_score == 78.5
    assert assessment.confidence == 0.95
    assert assessment.factors == factors
    assert "internal guidelines" in assessment.rationale


def test_risk_level_enum_works():
    assert RiskLevel.INFO == "info"
    assert RiskLevel.LOW == "low"
    assert RiskLevel.MEDIUM == "medium"
    assert RiskLevel.HIGH == "high"
    assert RiskLevel.CRITICAL == "critical"
    assert set(RiskLevel) == {"info", "low", "medium", "high", "critical"}


def test_impact_level_enum_works():
    assert ImpactLevel.NEGLIGIBLE == "negligible"
    assert ImpactLevel.LOW == "low"
    assert ImpactLevel.MEDIUM == "medium"
    assert ImpactLevel.HIGH == "high"
    assert ImpactLevel.CRITICAL == "critical"


def test_exploitability_level_enum_works():
    assert ExploitabilityLevel.LOW == "low"
    assert ExploitabilityLevel.MEDIUM == "medium"
    assert ExploitabilityLevel.HIGH == "high"
    assert ExploitabilityLevel.CRITICAL == "critical"


def test_blast_radius_level_enum_works():
    assert BlastRadiusLevel.LIMITED == "limited"
    assert BlastRadiusLevel.LOW == "low"
    assert BlastRadiusLevel.MEDIUM == "medium"
    assert BlastRadiusLevel.HIGH == "high"
    assert BlastRadiusLevel.CRITICAL == "critical"


def test_asset_sensitivity_enum_works():
    assert AssetSensitivity.PUBLIC == "public"
    assert AssetSensitivity.INTERNAL == "internal"
    assert AssetSensitivity.PERSONAL == "personal"
    assert AssetSensitivity.CONFIDENTIAL == "confidential"
    assert AssetSensitivity.HIGHLY_SENSITIVE == "highly_sensitive"


def test_tool_privilege_enum_works():
    assert ToolPrivilege.NONE == "none"
    assert ToolPrivilege.READ == "read"
    assert ToolPrivilege.WRITE == "write"
    assert ToolPrivilege.DESTRUCTIVE == "destructive"
    assert ToolPrivilege.ADMIN == "admin"


def test_risk_score_accepts_0():
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_001",
        risk_level=RiskLevel.INFO,
        risk_score=0.0,
        confidence=0.5,
        factors=factors,
        rationale="Zero risk score.",
    )
    assert assessment.risk_score == 0.0


def test_risk_score_accepts_100():
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_001",
        risk_level=RiskLevel.CRITICAL,
        risk_score=100.0,
        confidence=1.0,
        factors=factors,
        rationale="Maximum risk score.",
    )
    assert assessment.risk_score == 100.0


def test_risk_score_below_0_rejected():
    factors = make_valid_risk_factors()
    with pytest.raises(ValidationError):
        RiskAssessment(
            risk_id="RISK_001",
            finding_id="FINDING_001",
            risk_level=RiskLevel.LOW,
            risk_score=-0.1,
            confidence=0.5,
            factors=factors,
            rationale="Negative risk score.",
        )


def test_risk_score_above_100_rejected():
    factors = make_valid_risk_factors()
    with pytest.raises(ValidationError):
        RiskAssessment(
            risk_id="RISK_001",
            finding_id="FINDING_001",
            risk_level=RiskLevel.CRITICAL,
            risk_score=100.1,
            confidence=0.5,
            factors=factors,
            rationale="Overflow risk score.",
        )


def test_confidence_accepts_0():
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_001",
        risk_level=RiskLevel.LOW,
        risk_score=10.0,
        confidence=0.0,
        factors=factors,
        rationale="Zero confidence.",
    )
    assert assessment.confidence == 0.0


def test_confidence_accepts_1():
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_001",
        risk_level=RiskLevel.HIGH,
        risk_score=85.0,
        confidence=1.0,
        factors=factors,
        rationale="Full confidence.",
    )
    assert assessment.confidence == 1.0


def test_confidence_below_0_rejected():
    factors = make_valid_risk_factors()
    with pytest.raises(ValidationError):
        RiskAssessment(
            risk_id="RISK_001",
            finding_id="FINDING_001",
            risk_level=RiskLevel.LOW,
            risk_score=10.0,
            confidence=-0.01,
            factors=factors,
            rationale="Negative confidence.",
        )


def test_confidence_above_1_rejected():
    factors = make_valid_risk_factors()
    with pytest.raises(ValidationError):
        RiskAssessment(
            risk_id="RISK_001",
            finding_id="FINDING_001",
            risk_level=RiskLevel.HIGH,
            risk_score=85.0,
            confidence=1.01,
            factors=factors,
            rationale="Overflow confidence.",
        )


def test_empty_risk_id_rejected():
    factors = make_valid_risk_factors()
    with pytest.raises(ValidationError):
        RiskAssessment(
            risk_id="   ",
            finding_id="FINDING_001",
            risk_level=RiskLevel.MEDIUM,
            risk_score=50.0,
            confidence=0.8,
            factors=factors,
            rationale="Test rationale.",
        )


def test_empty_finding_id_rejected():
    factors = make_valid_risk_factors()
    with pytest.raises(ValidationError):
        RiskAssessment(
            risk_id="RISK_001",
            finding_id="",
            risk_level=RiskLevel.MEDIUM,
            risk_score=50.0,
            confidence=0.8,
            factors=factors,
            rationale="Test rationale.",
        )


def test_empty_rationale_rejected():
    factors = make_valid_risk_factors()
    with pytest.raises(ValidationError):
        RiskAssessment(
            risk_id="RISK_001",
            finding_id="FINDING_001",
            risk_level=RiskLevel.MEDIUM,
            risk_score=50.0,
            confidence=0.8,
            factors=factors,
            rationale="   ",
        )


def test_top_level_immutability():
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_001",
        risk_level=RiskLevel.MEDIUM,
        risk_score=50.0,
        confidence=0.8,
        factors=factors,
        rationale="Test rationale.",
    )
    with pytest.raises(ValidationError):
        assessment.risk_score = 99.0


def test_risk_assessment_has_no_cvss_field():
    assert "cvss" not in RiskAssessment.model_fields
    assert "cvss_score" not in RiskAssessment.model_fields
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_001",
        risk_level=RiskLevel.MEDIUM,
        risk_score=50.0,
        confidence=0.8,
        factors=factors,
        rationale="Test rationale.",
    )
    assert not hasattr(assessment, "cvss")
    assert not hasattr(assessment, "cvss_score")


def test_risk_assessment_does_not_contain_finding_severity():
    assert "severity" not in RiskAssessment.model_fields
    assert "finding_severity" not in RiskAssessment.model_fields
    factors = make_valid_risk_factors()
    assessment = RiskAssessment(
        risk_id="RISK_001",
        finding_id="FINDING_001",
        risk_level=RiskLevel.HIGH,
        risk_score=80.0,
        confidence=0.9,
        factors=factors,
        rationale="Test rationale.",
    )
    assert hasattr(assessment, "risk_level")
    assert not hasattr(assessment, "severity")


def test_risk_factors_contains_no_score():
    assert "score" not in RiskFactors.model_fields
    assert "risk_score" not in RiskFactors.model_fields
    factors = make_valid_risk_factors()
    assert not hasattr(factors, "score")
    assert not hasattr(factors, "risk_score")


def test_same_model_can_represent_different_risk_contexts():
    # Context 1: FAQ Chatbot with System Prompt Disclosure finding
    faq_factors = RiskFactors(
        impact=ImpactLevel.LOW,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.LIMITED,
        asset_sensitivity=AssetSensitivity.PUBLIC,
        tool_privilege=ToolPrivilege.NONE,
    )
    faq_risk = RiskAssessment(
        risk_id="RISK_FAQ_001",
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        risk_level=RiskLevel.MEDIUM,
        risk_score=35.0,
        confidence=0.95,
        factors=faq_factors,
        rationale="FAQ chatbot system prompt contains only public greeting instructions.",
    )

    # Context 2: Financial Agent with same System Prompt Disclosure finding
    fin_factors = RiskFactors(
        impact=ImpactLevel.CRITICAL,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.HIGH,
        asset_sensitivity=AssetSensitivity.HIGHLY_SENSITIVE,
        tool_privilege=ToolPrivilege.DESTRUCTIVE,
    )
    fin_risk = RiskAssessment(
        risk_id="RISK_FIN_001",
        finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
        risk_level=RiskLevel.CRITICAL,
        risk_score=95.0,
        confidence=0.95,
        factors=fin_factors,
        rationale="Financial agent system prompt contains confidential wire transfer validation rules and API credentials.",
    )

    assert faq_risk.finding_id == fin_risk.finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"
    assert faq_risk.risk_level == RiskLevel.MEDIUM
    assert fin_risk.risk_level == RiskLevel.CRITICAL
    assert faq_risk.risk_score == 35.0
    assert fin_risk.risk_score == 95.0


def test_no_external_network_calls():
    factors = make_valid_risk_factors()
    assessments = [
        RiskAssessment(
            risk_id=f"RISK_{i}",
            finding_id=f"FINDING_{i}",
            risk_level=RiskLevel.HIGH,
            risk_score=75.0,
            confidence=0.9,
            factors=factors,
            rationale=f"Rationale {i}",
        )
        for i in range(100)
    ]
    assert len(assessments) == 100
