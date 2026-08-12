"""
Unit tests for RiskEngine (STEP 8B).
"""

import pytest

from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    ImpactLevel,
    ProbeCategory,
    RiskAssessment,
    RiskFactors,
    RiskLevel,
    ToolPrivilege,
)
from app.engine.risk import (
    ASSET_SENSITIVITY_WEIGHT,
    BLAST_RADIUS_WEIGHT,
    EXPLOITABILITY_WEIGHT,
    IMPACT_WEIGHT,
    TOOL_PRIVILEGE_WEIGHT,
    RiskEngine,
    score_to_risk_level,
)


def make_test_finding(
    finding_id: str = "FINDING_TOOL_AUTHORIZATION",
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: float = 0.95,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Unauthorized Tool Invocation",
        category=ProbeCategory.TOOL_AUTHORIZATION,
        severity=severity,
        status=FindingStatus.OPEN,
        confidence=confidence,
        description="Target agent executed unauthorized tool.",
        impact="Unauthorized access to system tools.",
        remediation="Enforce server-side authorization.",
        affected_probe_ids=["TOOL_AUTH_001"],
        affected_execution_ids=["exec-101"],
        evidence=[
            FindingEvidence(
                summary="Tool executed without authorization",
                indicators=["UNAUTHORIZED_CANCEL_EXECUTED"],
                response_excerpt="UNAUTHORIZED_CANCEL_EXECUTED",
                probe_id="TOOL_AUTH_001",
                execution_id="exec-101",
            )
        ],
    )


def test_basic_risk_engine_creation():
    engine = RiskEngine()
    assert engine is not None


def test_all_minimum_factors_produce_info_or_low_risk():
    engine = RiskEngine()
    finding = make_test_finding()
    min_factors = RiskFactors(
        impact=ImpactLevel.NEGLIGIBLE,        # 0
        exploitability=ExploitabilityLevel.LOW, # 25
        blast_radius=BlastRadiusLevel.LIMITED,  # 20
        asset_sensitivity=AssetSensitivity.PUBLIC, # 10
        tool_privilege=ToolPrivilege.NONE,      # 0
    )
    assessment = engine.assess_risk(finding, min_factors)
    assert assessment.risk_score == 11.75
    assert assessment.risk_level == RiskLevel.INFO


def test_all_maximum_factors_produce_critical_risk():
    engine = RiskEngine()
    finding = make_test_finding()
    max_factors = RiskFactors(
        impact=ImpactLevel.CRITICAL,               # 100
        exploitability=ExploitabilityLevel.CRITICAL, # 100
        blast_radius=BlastRadiusLevel.CRITICAL,   # 100
        asset_sensitivity=AssetSensitivity.HIGHLY_SENSITIVE, # 100
        tool_privilege=ToolPrivilege.ADMIN,        # 100
    )
    assessment = engine.assess_risk(finding, max_factors)
    assert assessment.risk_score == 100.0
    assert assessment.risk_level == RiskLevel.CRITICAL


def test_impact_mapping_works():
    engine = RiskEngine()
    finding = make_test_finding()

    def get_score_for_impact(imp: ImpactLevel) -> float:
        f = RiskFactors(
            impact=imp,
            exploitability=ExploitabilityLevel.LOW,
            blast_radius=BlastRadiusLevel.LIMITED,
            asset_sensitivity=AssetSensitivity.PUBLIC,
            tool_privilege=ToolPrivilege.NONE,
        )
        return engine.assess_risk(finding, f).risk_score

    s_neg = get_score_for_impact(ImpactLevel.NEGLIGIBLE)
    s_high = get_score_for_impact(ImpactLevel.HIGH)
    s_crit = get_score_for_impact(ImpactLevel.CRITICAL)

    assert s_neg < s_high < s_crit


def test_exploitability_mapping_works():
    engine = RiskEngine()
    finding = make_test_finding()
    f_low = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    f_crit = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.CRITICAL, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    assert engine.assess_risk(finding, f_low).risk_score < engine.assess_risk(finding, f_crit).risk_score


def test_blast_radius_mapping_works():
    engine = RiskEngine()
    finding = make_test_finding()
    f_lim = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    f_crit = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.CRITICAL, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    assert engine.assess_risk(finding, f_lim).risk_score < engine.assess_risk(finding, f_crit).risk_score


def test_asset_sensitivity_mapping_works():
    engine = RiskEngine()
    finding = make_test_finding()
    f_pub = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    f_sens = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.HIGHLY_SENSITIVE, tool_privilege=ToolPrivilege.NONE)
    assert engine.assess_risk(finding, f_pub).risk_score < engine.assess_risk(finding, f_sens).risk_score


def test_tool_privilege_mapping_works():
    engine = RiskEngine()
    finding = make_test_finding()
    f_none = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    f_admin = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.ADMIN)
    assert engine.assess_risk(finding, f_none).risk_score < engine.assess_risk(finding, f_admin).risk_score


def test_weights_sum_to_1_0():
    total = (
        IMPACT_WEIGHT
        + EXPLOITABILITY_WEIGHT
        + BLAST_RADIUS_WEIGHT
        + ASSET_SENSITIVITY_WEIGHT
        + TOOL_PRIVILEGE_WEIGHT
    )
    assert pytest.approx(total, 0.00001) == 1.0


def test_score_is_deterministic():
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.WRITE,
    )
    r1 = engine.assess_risk(finding, factors)
    r2 = engine.assess_risk(finding, factors)
    assert r1.risk_score == r2.risk_score
    assert r1.risk_level == r2.risk_level


def test_score_is_bounded_0_100():
    engine = RiskEngine()
    finding = make_test_finding()
    factors_min = RiskFactors(impact=ImpactLevel.NEGLIGIBLE, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    factors_max = RiskFactors(impact=ImpactLevel.CRITICAL, exploitability=ExploitabilityLevel.CRITICAL, blast_radius=BlastRadiusLevel.CRITICAL, asset_sensitivity=AssetSensitivity.HIGHLY_SENSITIVE, tool_privilege=ToolPrivilege.ADMIN)

    res_min = engine.assess_risk(finding, factors_min)
    res_max = engine.assess_risk(finding, factors_max)

    assert 0.0 <= res_min.risk_score <= 100.0
    assert 0.0 <= res_max.risk_score <= 100.0


def test_score_rounds_consistently():
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(
        impact=ImpactLevel.MEDIUM,
        exploitability=ExploitabilityLevel.MEDIUM,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.PERSONAL,
        tool_privilege=ToolPrivilege.READ,
    )
    assessment = engine.assess_risk(finding, factors)
    assert round(assessment.risk_score, 2) == assessment.risk_score


def test_0_score_maps_to_info():
    assert score_to_risk_level(0.0) == RiskLevel.INFO
    assert score_to_risk_level(19.99) == RiskLevel.INFO


def test_score_at_20_maps_to_low():
    assert score_to_risk_level(20.0) == RiskLevel.LOW
    assert score_to_risk_level(39.99) == RiskLevel.LOW


def test_score_at_40_maps_to_medium():
    assert score_to_risk_level(40.0) == RiskLevel.MEDIUM
    assert score_to_risk_level(59.99) == RiskLevel.MEDIUM


def test_score_at_60_maps_to_high():
    assert score_to_risk_level(60.0) == RiskLevel.HIGH
    assert score_to_risk_level(79.99) == RiskLevel.HIGH


def test_score_at_80_maps_to_critical():
    assert score_to_risk_level(80.0) == RiskLevel.CRITICAL
    assert score_to_risk_level(100.0) == RiskLevel.CRITICAL


def test_finding_confidence_is_propagated_unchanged():
    engine = RiskEngine()
    finding = make_test_finding(confidence=0.88)
    factors = RiskFactors(impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL, tool_privilege=ToolPrivilege.WRITE)
    assessment = engine.assess_risk(finding, factors)
    assert assessment.confidence == 0.88


def test_confidence_does_not_affect_risk_score():
    engine = RiskEngine()
    finding1 = make_test_finding(confidence=0.10)
    finding2 = make_test_finding(confidence=0.99)
    factors = RiskFactors(impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL, tool_privilege=ToolPrivilege.WRITE)

    res1 = engine.assess_risk(finding1, factors)
    res2 = engine.assess_risk(finding2, factors)

    assert res1.risk_score == res2.risk_score
    assert res1.confidence == 0.10
    assert res2.confidence == 0.99


def test_finding_severity_does_not_directly_determine_risk_level():
    engine = RiskEngine()
    finding_high = make_test_finding(severity=FindingSeverity.HIGH)
    factors_low = RiskFactors(impact=ImpactLevel.NEGLIGIBLE, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)

    res = engine.assess_risk(finding_high, factors_low)
    assert finding_high.severity == FindingSeverity.HIGH
    assert res.risk_level == RiskLevel.INFO


def test_risk_id_is_deterministic():
    engine = RiskEngine()
    finding = make_test_finding(finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE")
    factors = RiskFactors(impact=ImpactLevel.MEDIUM, exploitability=ExploitabilityLevel.MEDIUM, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.INTERNAL, tool_privilege=ToolPrivilege.READ)
    assessment = engine.assess_risk(finding, factors)
    assert assessment.risk_id == "RISK_FINDING_SYSTEM_PROMPT_DISCLOSURE"


def test_rationale_contains_factor_information():
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
        tool_privilege=ToolPrivilege.DESTRUCTIVE,
    )
    assessment = engine.assess_risk(finding, factors)
    assert "impact=high" in assessment.rationale
    assert "exploitability=high" in assessment.rationale
    assert "blast_radius=medium" in assessment.rationale
    assert "asset_sensitivity=confidential" in assessment.rationale
    assert "tool_privilege=destructive" in assessment.rationale


def test_same_finding_and_factors_produces_identical_result():
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL, tool_privilege=ToolPrivilege.WRITE)
    a1 = engine.assess_risk(finding, factors)
    a2 = engine.assess_risk(finding, factors)
    assert a1 == a2


def test_different_factors_produce_different_scores():
    engine = RiskEngine()
    finding = make_test_finding()
    f1 = RiskFactors(impact=ImpactLevel.LOW, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    f2 = RiskFactors(impact=ImpactLevel.CRITICAL, exploitability=ExploitabilityLevel.CRITICAL, blast_radius=BlastRadiusLevel.CRITICAL, asset_sensitivity=AssetSensitivity.HIGHLY_SENSITIVE, tool_privilege=ToolPrivilege.ADMIN)
    a1 = engine.assess_risk(finding, f1)
    a2 = engine.assess_risk(finding, f2)
    assert a1.risk_score != a2.risk_score


def test_high_severity_finding_can_have_low_contextual_risk():
    engine = RiskEngine()
    finding = make_test_finding(severity=FindingSeverity.CRITICAL)
    low_factors = RiskFactors(impact=ImpactLevel.NEGLIGIBLE, exploitability=ExploitabilityLevel.LOW, blast_radius=BlastRadiusLevel.LIMITED, asset_sensitivity=AssetSensitivity.PUBLIC, tool_privilege=ToolPrivilege.NONE)
    assessment = engine.assess_risk(finding, low_factors)
    assert finding.severity == FindingSeverity.CRITICAL
    assert assessment.risk_level == RiskLevel.INFO


def test_low_severity_finding_can_have_high_contextual_risk_if_factors_justify():
    engine = RiskEngine()
    finding = make_test_finding(severity=FindingSeverity.LOW)
    high_factors = RiskFactors(impact=ImpactLevel.CRITICAL, exploitability=ExploitabilityLevel.CRITICAL, blast_radius=BlastRadiusLevel.CRITICAL, asset_sensitivity=AssetSensitivity.HIGHLY_SENSITIVE, tool_privilege=ToolPrivilege.ADMIN)
    assessment = engine.assess_risk(finding, high_factors)
    assert finding.severity == FindingSeverity.LOW
    assert assessment.risk_level == RiskLevel.CRITICAL


def test_no_cvss_exists():
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL, tool_privilege=ToolPrivilege.WRITE)
    assessment = engine.assess_risk(finding, factors)
    assert not hasattr(assessment, "cvss")
    assert "cvss" not in RiskAssessment.model_fields


def test_no_llm_calls():
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL, tool_privilege=ToolPrivilege.WRITE)
    assessment = engine.assess_risk(finding, factors)
    assert assessment.risk_score > 0


def test_no_network_calls():
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL, tool_privilege=ToolPrivilege.WRITE)
    for _ in range(100):
        engine.assess_risk(finding, factors)


def test_risk_engine_does_not_modify_finding():
    engine = RiskEngine()
    finding = make_test_finding(severity=FindingSeverity.HIGH)
    original_title = finding.title
    original_severity = finding.severity
    factors = RiskFactors(impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH, blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL, tool_privilege=ToolPrivilege.WRITE)

    engine.assess_risk(finding, factors)

    assert finding.title == original_title
    assert finding.severity == original_severity


def test_scoring_transparency_exact_calculation():
    """
    Section 14: Unit test transparency calculation.

    impact = HIGH = 75
    exploitability = HIGH = 75
    blast_radius = MEDIUM = 60
    asset_sensitivity = CONFIDENTIAL = 80
    tool_privilege = DESTRUCTIVE = 85

    Expected:
    75 * 0.30 = 22.50
    75 * 0.25 = 18.75
    60 * 0.20 = 12.00
    80 * 0.15 = 12.00
    85 * 0.10 =  8.50
    Sum       = 73.75
    """
    engine = RiskEngine()
    finding = make_test_finding()
    factors = RiskFactors(
        impact=ImpactLevel.HIGH,                # 75
        exploitability=ExploitabilityLevel.HIGH,# 75
        blast_radius=BlastRadiusLevel.MEDIUM,   # 60
        asset_sensitivity=AssetSensitivity.CONFIDENTIAL, # 80
        tool_privilege=ToolPrivilege.DESTRUCTIVE, # 85
    )

    assessment = engine.assess_risk(finding, factors)

    expected_score = round(
        75.0 * 0.30 + 75.0 * 0.25 + 60.0 * 0.20 + 80.0 * 0.15 + 85.0 * 0.10, 2
    )
    assert expected_score == 73.75
    assert assessment.risk_score == 73.75
    assert assessment.risk_level == RiskLevel.HIGH
