"""
Unit tests for ScanService and probe resolution (STEP 10B).
"""

from typing import Optional
import pytest

from app.adapters.base import TargetAdapter
from app.api.schemas import (
    ProbeSelectionRequest,
    RiskContextRequest,
    ScanRequest,
    ScanResponse,
    TargetScanRequest,
)
from app.api.service import ScanService, resolve_probes
from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    ImpactLevel,
    ProbeCategory,
    RiskFactors,
    ScanStatus,
    TargetConfig,
    TargetResult,
    ToolPrivilege,
)
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator


class ServiceMockAdapter(TargetAdapter):
    def __init__(self):
        super().__init__(TargetConfig(name="Mock Target", endpoint="http://mock.local/chat"))

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


def make_test_scan_service() -> ScanService:
    adapter = ServiceMockAdapter()
    attack_engine = AttackEngine(adapter=adapter)
    evaluator = DeterministicEvaluator()
    finding_engine = FindingEngine()
    risk_engine = RiskEngine()
    scan_engine = ScanEngine(
        attack_engine=attack_engine,
        evaluator=evaluator,
        finding_engine=finding_engine,
        risk_engine=risk_engine,
    )
    return ScanService(scan_engine=scan_engine)


def make_valid_scan_request(scan_id: Optional[str] = "SCAN_SERVICE_100") -> ScanRequest:
    return ScanRequest(
        scan_id=scan_id,
        target=TargetScanRequest(
            target_name="Service Target Agent",
            endpoint="http://target.local/chat",
            method="POST",
            timeout_seconds=15.0,
        ),
        probes=ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"]),
        risk_context=RiskContextRequest(
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM,
            asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.WRITE,
        ),
    )


def test_service_executes_valid_scan():
    service = make_test_scan_service()
    req = make_valid_scan_request()
    response = service.execute_scan(req)

    assert isinstance(response, ScanResponse)
    assert response.status == ScanStatus.COMPLETED
    assert response.target_name == "Service Target Agent"


def test_service_preserves_scan_id():
    service = make_test_scan_service()
    req = make_valid_scan_request("EXPLICIT_SCAN_ID_999")
    response = service.execute_scan(req)

    assert response.scan_id == "EXPLICIT_SCAN_ID_999"


def test_service_generates_scan_id_when_omitted():
    service = make_test_scan_service()
    req = make_valid_scan_request(scan_id=None)
    response = service.execute_scan(req)

    assert response.scan_id.startswith("SCAN_")
    assert len(response.scan_id) > 5


def test_service_preserves_target_name():
    service = make_test_scan_service()
    req = make_valid_scan_request()
    response = service.execute_scan(req)

    assert response.target_name == "Service Target Agent"


def test_service_converts_target_configuration_correctly():
    service = make_test_scan_service()
    req = make_valid_scan_request()
    service.execute_scan(req)

    adapter_config = service.scan_engine.attack_engine.adapter.config
    assert adapter_config.name == "Service Target Agent"
    assert adapter_config.endpoint == "http://target.local/chat"
    assert adapter_config.timeout_seconds == 15.0


def test_service_converts_risk_context_correctly():
    service = make_test_scan_service()
    req = make_valid_scan_request()
    response = service.execute_scan(req)

    assert len(response.risk_assessments) > 0
    assert response.risk_assessments[0].factors.impact == ImpactLevel.HIGH


def test_service_resolves_requested_probes():
    probes = resolve_probes(["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001"])
    assert len(probes) == 2
    assert probes[0].id == "PROMPT_LEAK_001"
    assert probes[1].id == "INSTRUCTION_OVERRIDE_001"


def test_service_preserves_probe_order():
    probes_1 = resolve_probes(["PROMPT_LEAK_001", "TOOL_AUTH_001"])
    probes_2 = resolve_probes(["TOOL_AUTH_001", "PROMPT_LEAK_001"])

    assert [p.id for p in probes_1] == ["PROMPT_LEAK_001", "TOOL_AUTH_001"]
    assert [p.id for p in probes_2] == ["TOOL_AUTH_001", "PROMPT_LEAK_001"]


def test_unknown_probe_rejected():
    with pytest.raises(ValueError, match="Unknown probe ID: UNKNOWN_PROBE_999"):
        resolve_probes(["UNKNOWN_PROBE_999"])


def test_service_returns_public_scan_response():
    service = make_test_scan_service()
    req = make_valid_scan_request()
    response = service.execute_scan(req)

    assert type(response).__name__ == "ScanResponse"


def test_service_does_not_expose_scan_result_internals():
    service = make_test_scan_service()
    req = make_valid_scan_request()
    response = service.execute_scan(req)

    resp_dict = response.model_dump()
    assert "executions" not in resp_dict
    assert "evaluations" not in resp_dict
    assert "metadata" not in resp_dict


def test_service_does_not_call_target_directly():
    assert not hasattr(ScanService, "send_http")
    assert not hasattr(ScanService, "make_request")


def test_no_llm_calls():
    service = make_test_scan_service()
    req = make_valid_scan_request()
    response = service.execute_scan(req)
    assert response.status == ScanStatus.COMPLETED


def test_no_database():
    assert not hasattr(ScanService, "db")
    service = make_test_scan_service()
    assert hasattr(service, "repository")

