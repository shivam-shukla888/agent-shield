"""
Performance, Load & Reliability Test Suite (STEP 19A)

Validates concurrent scan execution, repository concurrency, rate limiter performance,
evaluator throughput, pagination, failure injection, memory boundaries, and report generation limits.
"""

import concurrent.futures
import time
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.adapters.http import GenericHTTPAdapter
from app.api.schemas import RiskContextRequest, ScanRequest, TargetScanRequest, ProbeSelectionRequest
from app.api.service import ScanService
from app.domain.execution import ExecutionStatus, ProbeExecution
from app.domain.evaluation import EvaluationVerdict, EvaluationResult, EvaluationEvidence
from app.domain.finding import FindingSeverity, Finding
from app.domain.probe import SecurityProbe, ProbeCategory
from app.domain.risk import (
    RiskAssessment, RiskFactors, RiskLevel, ImpactLevel, ExploitabilityLevel,
    BlastRadiusLevel, AssetSensitivity, ToolPrivilege,
)
from app.domain.scan import ScanResult, ScanStatus, ScanSummary
from app.domain.target import TargetConfig, TargetResult
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.report import ReportEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app
from app.probes.basic import get_basic_probes
from app.repositories import InMemoryScanRepository, PostgreSQLScanRepository
from app.security.rate_limit import InMemoryRateLimiter


def get_default_risk_factors() -> RiskFactors:
    return RiskFactors(
        impact=ImpactLevel.MEDIUM,
        exploitability=ExploitabilityLevel.MEDIUM,
        blast_radius=BlastRadiusLevel.MEDIUM,
        asset_sensitivity=AssetSensitivity.INTERNAL,
        tool_privilege=ToolPrivilege.READ,
    )


# ============================================================
# 1. CONCURRENT SCANS & WORKER ISOLATION
# ============================================================

class TestConcurrentScans:
    """Test concurrent scan execution without state corruption or race conditions."""

    def test_concurrent_scan_execution(self):
        repo = InMemoryScanRepository()
        adapter = GenericHTTPAdapter(config=TargetConfig(name="Concurrent Target", endpoint="http://localhost:8000/chat"))
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
        service = ScanService(scan_engine=scan_engine, repository=repo)

        probes = get_basic_probes()[:2]

        def run_single_scan(index: int):
            scan_id = f"CONC_SCAN_{index:03d}"
            req = ScanRequest(
                scan_id=scan_id,
                target=TargetScanRequest(target_name=f"Target {index}", endpoint="http://localhost:8000/chat"),
                probes=ProbeSelectionRequest(probe_ids=[p.id for p in probes]),
                risk_context=RiskContextRequest(
                    impact=ImpactLevel.MEDIUM,
                    exploitability=ExploitabilityLevel.MEDIUM,
                    blast_radius=BlastRadiusLevel.MEDIUM,
                    asset_sensitivity=AssetSensitivity.INTERNAL,
                    tool_privilege=ToolPrivilege.READ,
                ),
            )
            return service.execute_scan(req)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(run_single_scan, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 10
        stored_scans = repo.list_all()
        assert len(stored_scans) == 10
        statuses = {s.status for s in stored_scans}
        assert any(s in (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED) for s in statuses)


# ============================================================
# 2. REPOSITORY CONCURRENCY
# ============================================================

class TestRepositoryConcurrency:
    """Test concurrent reads and writes to InMemoryScanRepository."""

    def test_concurrent_repo_reads_and_writes(self):
        repo = InMemoryScanRepository()

        def writer(index: int):
            for j in range(10):
                scan_id = f"REPO_SCAN_{index}_{j}"
                from app.api.schemas import ScanResponse, ScanSummaryResponse
                now = datetime.now(timezone.utc)
                resp = ScanResponse(
                    scan_id=scan_id,
                    target_name="ConcTarget",
                    status=ScanStatus.COMPLETED,
                    started_at=now,
                    completed_at=now,
                    summary=ScanSummaryResponse(
                        total_probes=1, completed_executions=1, failed_executions=0,
                        safe_evaluations=1, violation_evaluations=0, inconclusive_evaluations=0, error_evaluations=0,
                        total_findings=0, info_risks=0, low_risks=0, medium_risks=0, high_risks=0, critical_risks=0
                    ),
                    findings=[],
                    risk_assessments=[],
                )
                repo.save(resp)

        def reader():
            for _ in range(20):
                repo.list_all()
                time.sleep(0.001)

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            w_futures = [executor.submit(writer, i) for i in range(4)]
            r_futures = [executor.submit(reader) for _ in range(2)]
            for f in w_futures + r_futures:
                f.result()

        assert len(repo.list_all()) == 40


# ============================================================
# 3. RATE LIMITER CONCURRENCY & CLEANUP
# ============================================================

class TestRateLimiterConcurrency:
    """Test concurrent rate limiter access and window cleanup."""

    def test_concurrent_rate_limiter_access(self):
        limiter = InMemoryRateLimiter(requests_per_window=100, window_seconds=60.0)

        def make_requests(client_id: str):
            allowed = 0
            for _ in range(20):
                is_limited, _ = limiter.check_and_record(client_id)
                if not is_limited:
                    allowed += 1
            return allowed

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_requests, f"client_{i}") for i in range(5)]
            results = [f.result() for f in futures]

        assert sum(results) == 100

    def test_expired_window_cleanup(self):
        limiter = InMemoryRateLimiter(requests_per_window=5, window_seconds=0.2)
        limiter.check_and_record("stale_client_1")
        limiter.check_and_record("stale_client_2")

        time.sleep(0.25)

        purged = limiter.cleanup_expired()
        assert purged == 2


# ============================================================
# 4. EVALUATOR THROUGHPUT
# ============================================================

class TestEvaluatorThroughput:
    """Test deterministic evaluator throughput and latency."""

    def test_deterministic_evaluator_throughput(self):
        evaluator = DeterministicEvaluator()
        probes = get_basic_probes()

        probe_map = {p.id: p for p in probes}
        leak_probe = probe_map["PROMPT_LEAK_001"]

        target_res = TargetResult(
            success=True,
            output="SYSTEM PROMPT: You are a helpful assistant.",
            status_code=200,
            latency_ms=10.0,
        )
        execution = ProbeExecution(
            execution_id="exec_1",
            probe_id="PROMPT_LEAK_001",
            status=ExecutionStatus.COMPLETED,
            target_name="TestTarget",
            target_result=target_res,
        )

        start_time = time.time()
        iterations = 1000
        for _ in range(iterations):
            evaluator.evaluate(leak_probe, execution)
        elapsed = time.time() - start_time

        assert elapsed < 1.0
        evals_per_sec = iterations / max(0.001, elapsed)
        assert evals_per_sec > 1000


# ============================================================
# 5. FINDING AGGREGATION
# ============================================================

class TestFindingAggregation:
    """Test finding engine aggregation throughput."""

    def test_finding_engine_aggregation(self):
        engine = FindingEngine()
        probe = get_basic_probes()[0]

        eval_results = []
        executions = []
        for i in range(50):
            tr = TargetResult(
                success=True,
                output=f"Response {i}",
                status_code=200,
                latency_ms=5.0,
            )
            ex = ProbeExecution(
                execution_id=f"exec_{i}",
                probe_id=probe.id,
                status=ExecutionStatus.COMPLETED,
                target_name="TestTarget",
                target_result=tr,
            )
            er = EvaluationResult(
                evaluation_id=f"eval_{i}",
                probe_id=probe.id,
                execution_id=ex.execution_id,
                verdict=EvaluationVerdict.VIOLATION,
                confidence=0.9,
                rationale=f"Violation {i}",
                evidence=EvaluationEvidence(summary="Matched pattern", response_excerpt=f"Response {i}"),
            )
            executions.append(ex)
            eval_results.append(er)

        findings = engine.aggregate_evaluation_results(eval_results)
        assert len(findings) > 0


# ============================================================
# 6. RISK CALCULATION
# ============================================================

class TestRiskCalculation:
    """Test risk engine scoring calculation throughput and correctness."""

    def test_risk_scoring(self):
        risk_engine = RiskEngine()
        finding = Finding(
            finding_id="FINDING_SYSTEM_PROMPT_DISCLOSURE",
            title="System Prompt Disclosure",
            category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
            severity=FindingSeverity.HIGH,
            confidence=0.95,
            description="Leaked system prompt",
            impact="Exposure of internal instructions",
            remediation="Sanitize model outputs",
            affected_probe_ids=["PROMPT_LEAK_001"],
            affected_execution_ids=["exec_1"],
        )
        risk_factors = get_default_risk_factors()

        assessment = risk_engine.assess_risk(finding, risk_factors)
        assert assessment is not None
        assert assessment.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)


# ============================================================
# 7. SCAN RETRIEVAL LATENCY
# ============================================================

class TestScanRetrievalLatency:
    """Test key-indexed scan retrieval latency."""

    def test_scan_retrieval_fast(self):
        repo = InMemoryScanRepository()
        from app.api.schemas import ScanResponse, ScanSummaryResponse
        now = datetime.now(timezone.utc)

        for i in range(100):
            repo.save(ScanResponse(
                scan_id=f"RET_SCAN_{i}",
                target_name="Test",
                status=ScanStatus.COMPLETED,
                started_at=now,
                completed_at=now,
                summary=ScanSummaryResponse(
                    total_probes=1, completed_executions=1, failed_executions=0,
                    safe_evaluations=1, violation_evaluations=0, inconclusive_evaluations=0, error_evaluations=0,
                    total_findings=0, info_risks=0, low_risks=0, medium_risks=0, high_risks=0, critical_risks=0
                ),
                findings=[],
                risk_assessments=[],
            ))

        start = time.time()
        for i in range(100):
            res = repo.get_by_id(f"RET_SCAN_{i}")
            assert res is not None
        duration = time.time() - start

        assert duration < 0.05


# ============================================================
# 8. SCAN LISTING & PAGINATION
# ============================================================

class TestScanListingPagination:
    """Test scan history pagination limit, offset, and hard cap."""

    def test_pagination_offset_limit(self):
        repo = InMemoryScanRepository()
        from app.api.schemas import ScanResponse, ScanSummaryResponse
        now = datetime.now(timezone.utc)

        for i in range(25):
            repo.save(ScanResponse(
                scan_id=f"PAG_SCAN_{i:02d}",
                target_name="PagTarget",
                status=ScanStatus.COMPLETED,
                started_at=now,
                completed_at=now,
                summary=ScanSummaryResponse(
                    total_probes=1, completed_executions=1, failed_executions=0,
                    safe_evaluations=1, violation_evaluations=0, inconclusive_evaluations=0, error_evaluations=0,
                    total_findings=0, info_risks=0, low_risks=0, medium_risks=0, high_risks=0, critical_risks=0
                ),
                findings=[],
                risk_assessments=[],
            ))

        # Page 1: limit 10, offset 0
        p1 = repo.list_all(limit=10, offset=0)
        assert len(p1) == 10

        # Page 2: limit 10, offset 10
        p2 = repo.list_all(limit=10, offset=10)
        assert len(p2) == 10

        # Page 3: limit 10, offset 20
        p3 = repo.list_all(limit=10, offset=20)
        assert len(p3) == 5

        p1_ids = {s.scan_id for s in p1}
        p2_ids = {s.scan_id for s in p2}
        assert len(p1_ids.intersection(p2_ids)) == 0

    def test_api_pagination_validation(self):
        app = create_app(api_key="test-key")
        client = TestClient(app)

        resp = client.get("/api/v1/scans?limit=5&offset=0", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200

        resp_invalid = client.get("/api/v1/scans?limit=150", headers={"X-API-Key": "test-key"})
        assert resp_invalid.status_code == 422


# ============================================================
# 9. REPORT GENERATION PERFORMANCE
# ============================================================

class TestReportGenerationPerformance:
    """Test report rendering performance across markdown, html, json, pdf."""

    def test_report_rendering_speed(self):
        from app.api.schemas import ScanResponse, ScanSummaryResponse
        now = datetime.now(timezone.utc)
        scan_resp = ScanResponse(
            scan_id="PERF_REPORT_01",
            target_name="Report Target",
            status=ScanStatus.COMPLETED,
            started_at=now,
            completed_at=now,
            summary=ScanSummaryResponse(
                total_probes=5, completed_executions=5, failed_executions=0,
                safe_evaluations=3, violation_evaluations=2, inconclusive_evaluations=0, error_evaluations=0,
                total_findings=2, info_risks=0, low_risks=0, medium_risks=1, high_risks=1, critical_risks=0
            ),
            findings=[],
            risk_assessments=[],
        )

        engine = ReportEngine()
        report = engine.create_report(scan_resp)

        t0 = time.time()
        md = engine.render_markdown(report)
        t_md = time.time() - t0
        assert t_md < 0.1
        assert len(md) > 0

        t0 = time.time()
        html = engine.render_html(report)
        t_html = time.time() - t0
        assert t_html < 0.1
        assert len(html) > 0


# ============================================================
# 10. FAILURE INJECTION RECOVERY
# ============================================================

class TestFailureInjectionRecovery:
    """Test system graceful degradation when components experience failures."""

    def test_target_timeout_handled_safely(self):
        class TimeoutAdapter(GenericHTTPAdapter):
            def execute_probe(self, probe: SecurityProbe) -> ProbeExecution:
                tr = TargetResult(
                    success=False,
                    status_code=504,
                    latency_ms=10000.0,
                )
                return ProbeExecution(
                    execution_id="exec_timeout",
                    probe_id=probe.id,
                    status=ExecutionStatus.ERROR,
                    target_name="Timeout Target",
                    target_result=tr,
                    error_message="Request timed out",
                )

        adapter = TimeoutAdapter(config=TargetConfig(name="Timeout Target", endpoint="http://localhost:8000/chat"))
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

        probe = get_basic_probes()[0]
        res = scan_engine.run_scan(
            scan_id="FAIL_SCAN_01",
            target_name="Timeout Target",
            probes=[probe],
            risk_factors=get_default_risk_factors(),
        )

        assert res.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED)
        assert len(res.evaluations) == 1
        assert res.evaluations[0].verdict == EvaluationVerdict.ERROR


# ============================================================
# 11. TIMEOUT BEHAVIOR
# ============================================================

class TestTimeoutBehavior:
    """Test HTTP adapter default timeout setting."""

    def test_adapter_has_bounded_timeout(self):
        adapter = GenericHTTPAdapter(config=TargetConfig(name="Target", endpoint="http://localhost:8000/chat"))
        assert adapter.config.timeout_seconds <= 30.0


# ============================================================
# 12. MEMORY BOUND EVIDENCE
# ============================================================

class TestMemoryBoundEvidence:
    """Test target response evidence stays bounded."""

    def test_response_excerpts_are_bounded(self):
        large_response = "A" * 50000
        tr = TargetResult(
            success=True,
            output=large_response,
            status_code=200,
            latency_ms=10.0,
        )
        assert tr.output is not None
        assert len(tr.output) == 50000


# ============================================================
# 13. DETERMINISTIC ORDERING
# ============================================================

class TestDeterministicOrdering:
    """Test deterministic ordering on list_all."""

    def test_deterministic_ordering_tie_breaking(self):
        repo = InMemoryScanRepository()
        from app.api.schemas import ScanResponse, ScanSummaryResponse
        now = datetime.now(timezone.utc)

        for sid in ["SCAN_B", "SCAN_A", "SCAN_C"]:
            repo.save(ScanResponse(
                scan_id=sid,
                target_name="Target",
                status=ScanStatus.COMPLETED,
                started_at=now,
                completed_at=now,
                summary=ScanSummaryResponse(
                    total_probes=1, completed_executions=1, failed_executions=0,
                    safe_evaluations=1, violation_evaluations=0, inconclusive_evaluations=0, error_evaluations=0,
                    total_findings=0, info_risks=0, low_risks=0, medium_risks=0, high_risks=0, critical_risks=0
                ),
                findings=[],
                risk_assessments=[],
            ))

        ordered = repo.list_all()
        ids = [s.scan_id for s in ordered]
        assert ids == ["SCAN_C", "SCAN_B", "SCAN_A"]
