from typing import List, Optional
import pytest

from app.adapters.base import TargetAdapter
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.probe import ProbeCategory, ProbeSeverityHint, SecurityProbe
from app.domain.target import (
    TargetConfig,
    TargetError,
    TargetErrorCode,
    TargetResult,
)
from app.engine.attack import AttackEngine
from app.probes.basic import get_basic_probes


class FakeAdapter(TargetAdapter):
    """Fake TargetAdapter implementation for unit testing without HTTP or network access."""

    def __init__(self, config: TargetConfig, return_error: bool = False, raise_exception: bool = False) -> None:
        super().__init__(config)
        self.return_error = return_error
        self.raise_exception = raise_exception
        self.received_prompts: List[str] = []
        self.call_count = 0

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="healthy")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        self.call_count += 1
        self.received_prompts.append(input_text)

        if self.raise_exception:
            raise RuntimeError("Simulated unhandled transport crash")

        if self.return_error:
            return TargetResult(
                success=False,
                status_code=504,
                latency_ms=10.0,
                error=TargetError(
                    code=TargetErrorCode.TIMEOUT,
                    message="Target timed out",
                    retryable=False,
                ),
            )

        return TargetResult(
            success=True,
            output=f"Echo: {input_text}",
            status_code=200,
            latency_ms=15.0,
            raw_response={"echo": input_text},
        )


@pytest.fixture
def sample_probe() -> SecurityProbe:
    return SecurityProbe(
        id="TEST_PROBE_001",
        name="Test Security Probe",
        category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
        description="Testing single probe execution",
        prompt="Sample attack payload",
        expected_behavior="Refuse disclosure",
        severity_hint=ProbeSeverityHint.HIGH,
    )


@pytest.fixture
def target_config() -> TargetConfig:
    return TargetConfig(name="Fake In-Memory Target Agent", endpoint="fake://in-memory")


def test_single_probe_execution_success(sample_probe: SecurityProbe, target_config: TargetConfig) -> None:
    """Test 1, 3, 4, 5: Single probe executes successfully and preserves TargetResult."""
    adapter = FakeAdapter(target_config)
    engine = AttackEngine(adapter=adapter)

    execution: ProbeExecution = engine.execute_probe(sample_probe)

    assert execution.execution_id is not None
    assert len(execution.execution_id) > 0
    assert execution.probe_id == "TEST_PROBE_001"
    assert execution.status == ExecutionStatus.COMPLETED
    assert execution.target_name == "Fake In-Memory Target Agent"
    assert execution.started_at is not None
    assert execution.completed_at is not None
    assert execution.target_result is not None
    assert execution.target_result.success is True
    assert execution.target_result.output == "Echo: Sample attack payload"


def test_probe_prompt_passed_to_adapter(sample_probe: SecurityProbe, target_config: TargetConfig) -> None:
    """Test 2: Probe prompt is passed directly to TargetAdapter.send()."""
    adapter = FakeAdapter(target_config)
    engine = AttackEngine(adapter=adapter)

    engine.execute_probe(sample_probe)

    assert len(adapter.received_prompts) == 1
    assert adapter.received_prompts[0] == "Sample attack payload"


def test_multiple_probes_execute_sequentially(target_config: TargetConfig) -> None:
    """Test 6 & 7: Multiple probes execute sequentially in deterministic order."""
    adapter = FakeAdapter(target_config)
    engine = AttackEngine(adapter=adapter)
    probes = get_basic_probes()

    executions = engine.execute_probes(probes)

    assert len(executions) == 3
    assert [e.probe_id for e in executions] == ["PROMPT_LEAK_001", "INSTRUCTION_OVERRIDE_001", "TOOL_AUTH_001"]
    assert [e.status for e in executions] == [ExecutionStatus.COMPLETED] * 3
    assert adapter.call_count == 3
    assert adapter.received_prompts == [p.prompt for p in probes]


def test_adapter_exception_does_not_halt_subsequent_probes(target_config: TargetConfig, sample_probe: SecurityProbe) -> None:
    """Test 8: One adapter exception produces status=ERROR but does not halt scan execution."""
    class FlakyAdapter(FakeAdapter):
        def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
            self.call_count += 1
            if input_text == "CRASH":
                raise RuntimeError("Adapter crashed")
            return super().send(input_text, session_id)

    adapter = FlakyAdapter(target_config)
    engine = AttackEngine(adapter=adapter)

    probe_crash = SecurityProbe(
        id="CRASH_PROBE",
        name="Crash Probe",
        category=ProbeCategory.INSTRUCTION_OVERRIDE,
        description="Desc",
        prompt="CRASH",
        expected_behavior="Refuse",
    )

    executions = engine.execute_probes([probe_crash, sample_probe])

    assert len(executions) == 2
    assert executions[0].status == ExecutionStatus.ERROR
    assert "Unhandled adapter execution error" in (executions[0].error_message or "")
    assert executions[1].status == ExecutionStatus.COMPLETED
    assert executions[1].target_result is not None
    assert executions[1].target_result.success is True


def test_adapter_transport_errors_preserved(sample_probe: SecurityProbe, target_config: TargetConfig) -> None:
    """Test 9: Normalized transport errors in TargetResult leave execution status COMPLETED."""
    adapter = FakeAdapter(target_config, return_error=True)
    engine = AttackEngine(adapter=adapter)

    execution = engine.execute_probe(sample_probe)

    # Transport error is captured inside target_result, execution itself finished
    assert execution.status == ExecutionStatus.COMPLETED
    assert execution.target_result is not None
    assert execution.target_result.success is False
    assert execution.target_result.error is not None
    assert execution.target_result.error.code == TargetErrorCode.TIMEOUT


def test_no_automatic_retries(sample_probe: SecurityProbe, target_config: TargetConfig) -> None:
    """Test 10: AttackEngine calls adapter exactly once per probe (no automatic retries)."""
    adapter = FakeAdapter(target_config, return_error=True)
    engine = AttackEngine(adapter=adapter)

    engine.execute_probe(sample_probe)

    assert adapter.call_count == 1


def test_engine_produces_no_vulnerability_findings(sample_probe: SecurityProbe, target_config: TargetConfig) -> None:
    """Test 11: ProbeExecution and AttackEngine produce zero vulnerability findings or security verdicts."""
    adapter = FakeAdapter(target_config)
    engine = AttackEngine(adapter=adapter)

    execution = engine.execute_probe(sample_probe)

    assert not hasattr(execution, "findings")
    assert not hasattr(execution, "is_vulnerable")
    assert not hasattr(execution, "risk_score")


def test_engine_works_with_fake_adapter_no_http(sample_probe: SecurityProbe, target_config: TargetConfig) -> None:
    """Test 12 & 13: AttackEngine works via dependency injection with FakeAdapter without HTTP or GenericHTTPAdapter."""
    adapter = FakeAdapter(target_config)
    engine = AttackEngine(adapter=adapter)

    assert isinstance(engine.adapter, FakeAdapter)
    execution = engine.execute_probe(sample_probe)
    assert execution.status == ExecutionStatus.COMPLETED
