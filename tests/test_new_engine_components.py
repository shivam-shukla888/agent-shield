"""
Unit Test Suite for ThreatModelGenerator, AttackPathEngine, and AgentShieldTracer (STEP 23D)
"""

import pytest
from app.domain.finding import Finding
from app.domain.probe import ProbeCategory
from app.domain.risk import RiskLevel
from app.engine.attack_path import AttackPathEngine
from app.engine.threat_model import ThreatCategory, ThreatModelGenerator
from app.observability.tracing import AgentShieldTracer


def test_threat_model_generator_with_declared_tools():
    generator = ThreatModelGenerator()
    tools = ["refund_order", "query_customer_db", "read_file", "run_bash_script", "send_email", "delete_account", "custom_tool"]
    model = generator.generate_threat_model(target_name="TestTarget", declared_tools=tools)

    assert model.target_name == "TestTarget"
    assert len(model.assessments) == 7

    cats = {a.threat_category for a in model.assessments}
    assert ThreatCategory.FINANCIAL_ABUSE in cats
    assert ThreatCategory.DATA_EXFILTRATION in cats
    assert ThreatCategory.UNAUTHORIZED_FILE_ACCESS in cats
    assert ThreatCategory.ARBITRARY_COMMAND_EXECUTION in cats
    assert ThreatCategory.PHISHING_SPAM in cats
    assert ThreatCategory.UNAUTHORIZED_SYSTEM_MODIFICATION in cats
    assert ThreatCategory.GENERAL_TOOL_MISUSE in cats

    assert model.summary_by_level[RiskLevel.CRITICAL.value] == 2  # refund & bash
    assert model.summary_by_level[RiskLevel.HIGH.value] == 3      # db, file, delete


def test_threat_model_generator_fallback_and_system_prompt():
    generator = ThreatModelGenerator()
    # Test with system prompt keyword scanning
    model_prompt = generator.generate_threat_model(target_name="PromptTarget", system_prompt="This agent can execute bash commands and refund customer orders.")
    assert len(model_prompt.assessments) >= 2

    # Test complete fallback
    model_empty = generator.generate_threat_model(target_name="EmptyTarget")
    assert len(model_empty.assessments) == 1
    assert model_empty.assessments[0].tool_name == "generic_assistant_chat"


def test_attack_path_engine_full_compromise_chain():
    engine = AttackPathEngine()
    findings = [
        Finding(
            finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE.value,
            severity=RiskLevel.HIGH,
            title="System Prompt Disclosure",
            description="Leaked prompt",
            impact="Exposes directives",
            confidence=0.9,
            remediation="Remediate prompt",
            affected_probe_ids=["p1"],
            affected_execution_ids=["e1"],
        ),
        Finding(
            finding_id="FINDING_INSTRUCTION_OVERRIDE",
            category=ProbeCategory.INSTRUCTION_OVERRIDE.value,
            severity=RiskLevel.HIGH,
            title="Instruction Override",
            description="Bypassed instructions",
            impact="Bypasses constraints",
            confidence=0.9,
            remediation="Remediate override",
            affected_probe_ids=["p2"],
            affected_execution_ids=["e2"],
        ),
        Finding(
            finding_id="FINDING_TOOL_AUTHORIZATION",
            category=ProbeCategory.TOOL_AUTHORIZATION.value,
            severity=RiskLevel.CRITICAL,
            title="Tool Authorization Bypass",
            description="Unauthorized tool run",
            impact="Executes unauthorized action",
            confidence=0.9,
            remediation="Remediate tool auth",
            affected_probe_ids=["p3"],
            affected_execution_ids=["e3"],
        ),
    ]

    paths = engine.correlate_attack_paths(findings)
    assert len(paths) == 1
    p = paths[0]
    assert p.path_id == "PATH_FULL_COMPROMISE_CHAIN"
    assert p.overall_severity == RiskLevel.CRITICAL
    assert len(p.steps) == 3
    assert p.steps[0].finding_id == "FINDING_SYSTEM_PROMPT_DISCLOSURE"
    assert p.steps[1].finding_id == "FINDING_INSTRUCTION_OVERRIDE"
    assert p.steps[2].finding_id == "FINDING_TOOL_AUTHORIZATION"


def test_attack_path_engine_partial_and_standalone():
    engine = AttackPathEngine()
    findings = [
        Finding(
            finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE.value,
            severity=RiskLevel.HIGH,
            title="System Prompt Disclosure",
            description="Leaked prompt",
            impact="Exposes directives",
            confidence=0.9,
            remediation="Remediate prompt",
            affected_probe_ids=["p1"],
            affected_execution_ids=["e1"],
        ),
        Finding(
            finding_id="FINDING_INSTRUCTION_OVERRIDE",
            category=ProbeCategory.INSTRUCTION_OVERRIDE.value,
            severity=RiskLevel.HIGH,
            title="Instruction Override",
            description="Bypassed instructions",
            impact="Bypasses constraints",
            confidence=0.9,
            remediation="Remediate override",
            affected_probe_ids=["p2"],
            affected_execution_ids=["e2"],
        ),
    ]

    paths = engine.correlate_attack_paths(findings)
    assert len(paths) == 1
    assert paths[0].path_id == "PATH_RECON_AND_OVERRIDE"
    assert len(paths[0].steps) == 2

    # Single finding standalone case
    standalone_findings = [
        Finding(
            finding_id="FINDING_ISOLATED",
            category=ProbeCategory.TOOL_AUTHORIZATION.value,
            severity=RiskLevel.MEDIUM,
            title="Isolated Vulnerability",
            description="Isolated finding description",
            impact="Minor impact",
            confidence=0.8,
            remediation="Fix it",
            affected_probe_ids=["p1"],
            affected_execution_ids=["e1"],
        )
    ]
    s_paths = engine.correlate_attack_paths(standalone_findings)
    assert len(s_paths) == 1
    assert s_paths[0].path_id == "PATH_SINGLE_FINDING_ISOLATED"

    # Empty case
    assert engine.correlate_attack_paths([]) == []



def test_agentshield_tracer_span_context():
    tracer = AgentShieldTracer()
    with tracer.span("test.operation", scan_id="SCAN_TEST_123", attributes={"env": "unit_test"}) as span:
        pass
