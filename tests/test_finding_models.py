"""
Unit tests for Finding domain models (STEP 7A).
"""

import pytest
from pydantic import ValidationError

from app.domain import (
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    ProbeCategory,
    ProbeSeverityHint,
    SecurityProbe,
)


def test_valid_finding_creation():
    evidence = FindingEvidence(
        summary="Matched system prompt header",
        indicators=["SYSTEM_PROMPT_HEADER"],
        response_excerpt="System prompt text excerpt",
        probe_id="PROMPT_LEAK_001",
        execution_id="exec-123",
    )
    finding = Finding(
        finding_id="FINDING_001",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        confidence=0.95,
        description="The target agent disclosed its system instructions.",
        impact="Attackers can discover sensitive prompt rules and instructions.",
        remediation="Implement strict system prompt instructions refusing leak requests.",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-123"],
        evidence=[evidence],
        metadata={"scanner": "agentshield_v1"},
    )
    assert finding.finding_id == "FINDING_001"
    assert finding.title == "System Prompt Disclosure"
    assert finding.category == ProbeCategory.SYSTEM_PROMPT_DISCLOSURE
    assert finding.severity == FindingSeverity.HIGH
    assert finding.status == FindingStatus.OPEN
    assert finding.confidence == 0.95
    assert len(finding.affected_probe_ids) == 1
    assert len(finding.affected_execution_ids) == 1
    assert len(finding.evidence) == 1


def test_empty_finding_id_rejected():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="   ",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
            confidence=0.9,
            description="Desc",
            impact="Impact",
            remediation="Remediation",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec-123"],
        )


def test_empty_title_rejected():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=0.9,
            description="Desc",
            impact="Impact",
            remediation="Remediation",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec-123"],
        )


def test_empty_description_rejected():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=0.9,
            description="",
            impact="Impact",
            remediation="Remediation",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec-123"],
        )


def test_empty_impact_rejected():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=0.9,
            description="Desc",
            impact="   ",
            remediation="Remediation",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec-123"],
        )


def test_empty_remediation_rejected():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=0.9,
            description="Desc",
            impact="Impact",
            remediation="",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec-123"],
        )


def test_confidence_accepts_0_0():
    finding = Finding(
        finding_id="FINDING_001",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.LOW,
        confidence=0.0,
        description="Desc",
        impact="Impact",
        remediation="Remediation",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-123"],
    )
    assert finding.confidence == 0.0


def test_confidence_accepts_1_0():
    finding = Finding(
        finding_id="FINDING_001",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.CRITICAL,
        confidence=1.0,
        description="Desc",
        impact="Impact",
        remediation="Remediation",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-123"],
    )
    assert finding.confidence == 1.0


def test_confidence_below_zero_rejected():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=-0.1,
            description="Desc",
            impact="Impact",
            remediation="Remediation",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec-123"],
        )


def test_confidence_above_one_rejected():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=1.05,
            description="Desc",
            impact="Impact",
            remediation="Remediation",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec-123"],
        )


def test_at_least_one_probe_id_required():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=0.9,
            description="Desc",
            impact="Impact",
            remediation="Remediation",
            affected_probe_ids=[],
            affected_execution_ids=["exec-123"],
        )


def test_at_least_one_execution_id_required():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="FINDING_001",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=0.9,
            description="Desc",
            impact="Impact",
            remediation="Remediation",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=[],
        )


def test_evidence_excerpt_bounded_500_chars():
    long_response = "A" * 600
    evidence = FindingEvidence(
        summary="Test summary",
        response_excerpt=long_response,
    )
    assert len(evidence.response_excerpt) <= 500
    assert evidence.response_excerpt.endswith("...")


def test_severity_enum_works():
    assert FindingSeverity.INFO == "info"
    assert FindingSeverity.LOW == "low"
    assert FindingSeverity.MEDIUM == "medium"
    assert FindingSeverity.HIGH == "high"
    assert FindingSeverity.CRITICAL == "critical"
    assert set(FindingSeverity) == {"info", "low", "medium", "high", "critical"}


def test_status_enum_works():
    assert FindingStatus.OPEN == "open"
    assert FindingStatus.CONFIRMED == "confirmed"
    assert FindingStatus.RESOLVED == "resolved"
    assert FindingStatus.ACCEPTED_RISK == "accepted_risk"
    assert set(FindingStatus) == {"open", "confirmed", "resolved", "accepted_risk"}


def test_top_level_immutability():
    finding = Finding(
        finding_id="FINDING_001",
        title="Original Title",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.MEDIUM,
        confidence=0.8,
        description="Desc",
        impact="Impact",
        remediation="Remediation",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-123"],
    )
    with pytest.raises(ValidationError):
        finding.title = "Modified Title"


def test_finding_has_no_risk_score_field():
    assert "risk_score" not in Finding.model_fields
    finding = Finding(
        finding_id="FINDING_001",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        confidence=0.9,
        description="Desc",
        impact="Impact",
        remediation="Remediation",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-123"],
    )
    assert not hasattr(finding, "risk_score")


def test_finding_does_not_contain_cvss_field():
    assert "cvss" not in Finding.model_fields
    assert "cvss_score" not in Finding.model_fields
    finding = Finding(
        finding_id="FINDING_001",
        title="System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        confidence=0.9,
        description="Desc",
        impact="Impact",
        remediation="Remediation",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-123"],
    )
    assert not hasattr(finding, "cvss")
    assert not hasattr(finding, "cvss_score")


def test_probe_severity_hint_is_not_automatically_part_of_finding():
    probe = SecurityProbe(
        id="PROMPT_LEAK_001",
        name="Leak System Prompt",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        description="Tests prompt leak",
        prompt="Disclose instructions",
        expected_behavior="Refuse disclosure",
        severity_hint=ProbeSeverityHint.LOW,
    )
    finding = Finding(
        finding_id="FINDING_001",
        title="System Prompt Disclosure",
        category=probe.category,
        severity=FindingSeverity.CRITICAL,
        confidence=0.99,
        description="System prompt disclosed completely.",
        impact="High disclosure impact.",
        remediation="Harden system prompt.",
        affected_probe_ids=[probe.id],
        affected_execution_ids=["exec-101"],
    )
    assert probe.severity_hint == ProbeSeverityHint.LOW
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.severity != probe.severity_hint


def test_multiple_probe_ids_can_be_represented():
    finding = Finding(
        finding_id="FINDING_002",
        title="Aggregated System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        confidence=0.95,
        description="Multiple probe variations triggered prompt disclosure.",
        impact="System prompt exposed under multiple attack vectors.",
        remediation="Harden system instruction boundary.",
        affected_probe_ids=["PROMPT_LEAK_001", "PROMPT_LEAK_002", "PROMPT_LEAK_003"],
        affected_execution_ids=["exec-201"],
    )
    assert len(finding.affected_probe_ids) == 3
    assert finding.affected_probe_ids == ["PROMPT_LEAK_001", "PROMPT_LEAK_002", "PROMPT_LEAK_003"]


def test_multiple_execution_ids_can_be_represented():
    finding = Finding(
        finding_id="FINDING_003",
        title="Repeated System Prompt Disclosure",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        severity=FindingSeverity.HIGH,
        confidence=0.99,
        description="Probe succeeded across multiple test execution runs.",
        impact="Consistent prompt exposure across scan runs.",
        remediation="Enforce prompt boundary controls.",
        affected_probe_ids=["PROMPT_LEAK_001"],
        affected_execution_ids=["exec-301", "exec-302", "exec-303"],
    )
    assert len(finding.affected_execution_ids) == 3
    assert finding.affected_execution_ids == ["exec-301", "exec-302", "exec-303"]
