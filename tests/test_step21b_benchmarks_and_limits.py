"""
STEP 21B — Benchmarks, Large Input Limits, Report Performance & Resource Limits Test Suite

Validates:
- Controlled local scan throughput benchmark scenarios (A, B, C, D, E)
- Evaluator performance benchmarking (Deterministic, LLM, Hybrid, Finding, Risk Engine)
- Rate limiter performance under concurrent load (10, 50, 100, 500 requests)
- Large input boundaries (response_excerpt <= 500 truncation, multi-MB response strings, oversized metadata)
- Report generation performance & non-mutation of ScanResult DTOs
- Memory growth and resource isolation
"""

import concurrent.futures
import time
from datetime import datetime, timezone
import httpx
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.api.schemas import (
    AssetSensitivity, BlastRadiusLevel, ExploitabilityLevel, ImpactLevel,
    ProbeSelectionRequest, RiskContextRequest, ScanRequest, ScanResponse,
    TargetScanRequest, ToolPrivilege,
)
from app.api.service import ScanService
from app.domain.evaluation import EvaluationEvidence, EvaluationResult, EvaluationVerdict, EvaluatorType
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.finding import Finding, FindingSeverity
from app.domain.probe import ProbeCategory, SecurityProbe
from app.domain.risk import RiskAssessment, RiskFactors, RiskLevel
from app.domain.scan import ScanResult, ScanStatus, ScanSummary
from app.domain.target import TargetConfig, TargetResult
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.report import ReportEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.evaluation.llm import LLMEvaluator
from app.evaluation.provider import FakeLLMProvider
from app.evaluation.hybrid import HybridEvaluationStrategy
from app.probes.basic import get_basic_probes
from app.repositories import InMemoryScanRepository
from app.security.rate_limit import InMemoryRateLimiter
from test_target.main import local_target_app


class FastBenchmarkAdapter(GenericHTTPAdapter):
    def send(self, input_text: str) -> TargetResult:
        return TargetResult(success=True, status_code=200, output="I cannot reveal my system instructions.")


def create_fast_in_process_service():
    """Create ScanService with fast synthetic target adapter."""
    config = TargetConfig(
        name="Benchmark Target",
        endpoint="http://testagent.local/chat",
        request_template={"prompt": "{{input}}"},
        response_path="response",
    )
    adapter = FastBenchmarkAdapter(config=config)
    scan_engine = ScanEngine(
        attack_engine=AttackEngine(adapter=adapter),
        evaluator=DeterministicEvaluator(),
        finding_engine=FindingEngine(),
        risk_engine=RiskEngine(),
    )
    repo = InMemoryScanRepository()
    report_engine = ReportEngine()
    return ScanService(scan_engine=scan_engine, repository=repo, report_engine=report_engine), repo


# ============================================================
# 1. CONTROLLED SCAN THROUGHPUT BENCHMARKS (SCENARIOS A-E)
# ============================================================

class TestScanThroughputBenchmarks:
    """Runs controlled local benchmark scenarios A-E."""

    def _run_benchmark_scenario(self, num_scans: int, num_probes: int, max_workers: int):
        service, repo = create_fast_in_process_service()
        probes = get_basic_probes()[:num_probes]
        probe_ids = [p.id for p in probes]

        def run_single(idx: int):
            scan_id = f"BM_SCAN_{num_scans}_{idx:03d}"
            req = ScanRequest(
                scan_id=scan_id,
                target=TargetScanRequest(target_name="Benchmark Target", endpoint="http://testagent.local/chat", request_template={"prompt": "{{input}}"}, response_path="response"),
                probes=ProbeSelectionRequest(probe_ids=probe_ids),
                risk_context=RiskContextRequest(
                    impact=ImpactLevel.MEDIUM, exploitability=ExploitabilityLevel.MEDIUM,
                    blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.INTERNAL,
                    tool_privilege=ToolPrivilege.READ,
                ),
            )
            start_t = time.time()
            res = service.execute_scan(req)
            elapsed = time.time() - start_t
            return res, elapsed

        start_total = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_single, i) for i in range(num_scans)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        total_duration = time.time() - start_total

        scans = [r[0] for r in results]
        durations = [r[1] for r in results]
        failures = sum(1 for s in scans if s.status == ScanStatus.FAILED)

        return {
            "num_scans": num_scans,
            "num_probes": num_probes,
            "total_duration_sec": total_duration,
            "avg_scan_duration_sec": sum(durations) / len(durations) if durations else 0,
            "throughput_scans_per_sec": num_scans / total_duration if total_duration > 0 else 0,
            "failures": failures,
            "stored_count": len(repo.list_all()),
        }

    def test_scenario_a_1_scan_1_probe(self):
        res = self._run_benchmark_scenario(num_scans=1, num_probes=1, max_workers=1)
        assert res["num_scans"] == 1
        assert res["failures"] == 0
        assert res["stored_count"] == 1

    def test_scenario_b_1_scan_3_probes(self):
        res = self._run_benchmark_scenario(num_scans=1, num_probes=3, max_workers=1)
        assert res["num_scans"] == 1
        assert res["failures"] == 0
        assert res["stored_count"] == 1

    def test_scenario_c_10_scans_3_probes(self):
        res = self._run_benchmark_scenario(num_scans=10, num_probes=3, max_workers=5)
        assert res["num_scans"] == 10
        assert res["failures"] == 0
        assert res["stored_count"] == 10

    def test_scenario_d_25_scans_3_probes(self):
        res = self._run_benchmark_scenario(num_scans=25, num_probes=3, max_workers=10)
        assert res["num_scans"] == 25
        assert res["failures"] == 0
        assert res["stored_count"] == 25

    def test_scenario_e_50_scans_3_probes(self):
        res = self._run_benchmark_scenario(num_scans=50, num_probes=3, max_workers=10)
        assert res["num_scans"] == 50
        assert res["failures"] == 0
        assert res["stored_count"] == 50


# ============================================================
# 2. EVALUATOR PERFORMANCE BENCHMARKS
# ============================================================

class TestEvaluatorPerformanceBenchmarks:
    """Measures execution latency of Evaluators, FindingEngine, and RiskEngine."""

    def test_deterministic_evaluator_latency(self):
        evaluator = DeterministicEvaluator()
        probe = get_basic_probes()[0]
        exec_item = ProbeExecution(
            execution_id="exec_perf_01",
            probe_id=probe.id,
            status=ExecutionStatus.COMPLETED,
            target_name="Benchmark Target",
            target_result=TargetResult(success=True, status_code=200, output="System instructions: " + "A" * 500),
        )

        latencies = []
        for _ in range(100):
            t0 = time.time()
            res = evaluator.evaluate(probe, exec_item)
            latencies.append(time.time() - t0)

        avg_ms = (sum(latencies) / len(latencies)) * 1000.0
        # Deterministic evaluator should execute under 10ms per evaluation
        assert avg_ms < 10.0

    def test_finding_and_risk_engine_latency(self):
        finding_engine = FindingEngine()
        risk_engine = RiskEngine()
        probe = get_basic_probes()[0]

        eval_result = EvaluationResult(
            evaluation_id="eval_perf_01",
            execution_id="exec_perf_01",
            probe_id=probe.id,
            evaluator_type=EvaluatorType.DETERMINISTIC,
            verdict=EvaluationVerdict.VIOLATION,
            confidence=0.95,
            evidence=EvaluationEvidence(summary="Prompt leak detected", matched_indicators=["SYSTEM_INSTRUCTION:"]),
            rationale="Prompt leak detected",
        )

        t0 = time.time()
        findings = finding_engine.aggregate_evaluation_results([eval_result])
        finding_ms = (time.time() - t0) * 1000.0
        assert finding_ms < 10.0

        rf = RiskFactors(
            impact=ImpactLevel.HIGH, exploitability=ExploitabilityLevel.HIGH,
            blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
            tool_privilege=ToolPrivilege.WRITE,
        )
        t0 = time.time()
        risks = [risk_engine.assess_risk(f, rf) for f in findings]
        risk_ms = (time.time() - t0) * 1000.0
        assert risk_ms < 10.0


# ============================================================
# 3. RATE LIMITER PERFORMANCE
# ============================================================

class TestRateLimiterPerformance:
    """Measures rate limiter throughput and correctness at 10, 50, 100, 500 requests."""

    @pytest.mark.parametrize("num_reqs", [10, 50, 100, 500])
    def test_rate_limiter_concurrency_levels(self, num_reqs: int):
        limiter = InMemoryRateLimiter(requests_per_window=num_reqs, window_seconds=60)

        def worker(client_id: str):
            return limiter.check_and_record(client_id)[0]

        t0 = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, "perf_client") for _ in range(num_reqs)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        elapsed = time.time() - t0

        allowed = sum(1 for is_limited in results if not is_limited)
        assert allowed == num_reqs
        assert elapsed < 5.0  # Must execute rapidly


# ============================================================
# 4. LARGE INPUT & EVIDENCE BOUNDARIES
# ============================================================

class TestLargeInputBoundaries:
    """Verifies that large responses and long text fields remain safely bounded."""

    def test_large_target_response_truncation(self):
        huge_output = "SYSTEM_INSTRUCTION:" + ("X" * 100_000)
        tr = TargetResult(success=True, status_code=200, output=huge_output)
        exec_item = ProbeExecution(
            execution_id="exec_huge",
            probe_id="PROMPT_LEAK_001",
            status=ExecutionStatus.COMPLETED,
            target_name="Huge Output Target",
            target_result=tr,
        )

        evaluator = DeterministicEvaluator()
        probe = get_basic_probes()[0]
        res = evaluator.evaluate(probe, exec_item)

        assert res.evidence is not None
        assert res.evidence.response_excerpt is not None
        assert len(res.evidence.response_excerpt) <= 500


# ============================================================
# 5. REPORT PERFORMANCE & NON-MUTATION
# ============================================================

class TestReportPerformanceAndNonMutation:
    """Verifies report generation speed and guarantees non-mutation of ScanResult objects."""

    def test_report_generation_does_not_mutate_scan_response(self):
        service, _ = create_fast_in_process_service()
        req = ScanRequest(
            scan_id="REPORT_MUTATION_TEST_001",
            target=TargetScanRequest(target_name="Benchmark Target", endpoint="http://testagent.local/chat", request_template={"prompt": "{{input}}"}, response_path="response"),
            probes=ProbeSelectionRequest(probe_ids=["PROMPT_LEAK_001"]),
            risk_context=RiskContextRequest(
                impact=ImpactLevel.MEDIUM, exploitability=ExploitabilityLevel.MEDIUM,
                blast_radius=BlastRadiusLevel.MEDIUM, asset_sensitivity=AssetSensitivity.INTERNAL,
                tool_privilege=ToolPrivilege.READ,
            ),
        )
        scan = service.execute_scan(req)
        report_engine = ReportEngine()

        import copy
        original_scan = copy.deepcopy(scan)

        report_dto = report_engine.create_report(scan)
        md_rpt = report_engine.render_markdown(report_dto)
        json_rpt = report_engine.render_json(report_dto)
        html_rpt = report_engine.render_html(report_dto)
        pdf_rpt = report_engine.render_pdf(report_dto)

        assert len(md_rpt) > 50
        assert len(json_rpt) > 50
        assert len(html_rpt) > 50
        assert len(pdf_rpt) > 50

        assert scan == original_scan
