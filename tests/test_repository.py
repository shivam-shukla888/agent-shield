"""
Unit tests for ScanRepository abstraction and InMemoryScanRepository (STEP 11A).
"""

from datetime import datetime, timezone, timedelta
import threading
import pytest

from app.api.schemas import (
    ScanFindingResponse,
    ScanResponse,
    ScanRiskResponse,
    ScanSummaryResponse,
)
from app.domain import (
    AssetSensitivity,
    BlastRadiusLevel,
    ExploitabilityLevel,
    FindingSeverity,
    FindingStatus,
    ImpactLevel,
    ProbeCategory,
    RiskFactors,
    RiskLevel,
    ScanStatus,
    ToolPrivilege,
)
from app.repositories.scan import InMemoryScanRepository, ScanRepository


def make_test_scan_response(
    scan_id: str = "SCAN_TEST_001",
    target_name: str = "Test Target",
    started_at: datetime = None,
) -> ScanResponse:
    if started_at is None:
        started_at = datetime.now(timezone.utc)
    return ScanResponse(
        scan_id=scan_id,
        target_name=target_name,
        status=ScanStatus.COMPLETED,
        started_at=started_at,
        completed_at=started_at + timedelta(seconds=2),
        summary=ScanSummaryResponse(
            total_probes=1,
            completed_executions=1,
            failed_executions=0,
            safe_evaluations=0,
            violation_evaluations=1,
            inconclusive_evaluations=0,
            error_evaluations=0,
            total_findings=1,
            info_risks=0,
            low_risks=0,
            medium_risks=0,
            high_risks=1,
            critical_risks=0,
        ),
        findings=[
            ScanFindingResponse(
                finding_id="FINDING_001",
                title="Prompt Leak",
                category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
                severity=FindingSeverity.HIGH,
                status=FindingStatus.OPEN,
                confidence=0.95,
                description="System prompt leak detected",
                impact="Discloses rules",
                remediation="Harden prompt",
                affected_probe_ids=["PROMPT_LEAK_001"],
                affected_execution_ids=["exec-001"],
                evidence=[],
            )
        ],
        risk_assessments=[
            ScanRiskResponse(
                risk_id="RISK_001",
                finding_id="FINDING_001",
                risk_level=RiskLevel.HIGH,
                risk_score=75.0,
                confidence=0.95,
                factors=RiskFactors(
                    impact=ImpactLevel.HIGH,
                    exploitability=ExploitabilityLevel.HIGH,
                    blast_radius=BlastRadiusLevel.MEDIUM,
                    asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
                    tool_privilege=ToolPrivilege.WRITE,
                ),
                rationale="High risk score derived",
            )
        ],
    )


def test_repository_interface_abstract():
    with pytest.raises(TypeError):
        ScanRepository()  # Cannot instantiate abstract class


def test_save_and_get_by_id():
    repo = InMemoryScanRepository()
    scan = make_test_scan_response("SCAN_001")
    saved = repo.save(scan)
    assert saved == scan

    retrieved = repo.get_by_id("SCAN_001")
    assert retrieved is not None
    assert retrieved.scan_id == "SCAN_001"
    assert retrieved.target_name == "Test Target"


def test_save_invalid_type_raises():
    repo = InMemoryScanRepository()
    with pytest.raises(ValueError, match="scan must be a valid ScanResponse instance"):
        repo.save({"scan_id": "INVALID"})  # type: ignore


def test_get_by_id_non_existent_returns_none():
    repo = InMemoryScanRepository()
    assert repo.get_by_id("NON_EXISTENT") is None


def test_get_by_id_strips_whitespace():
    repo = InMemoryScanRepository()
    scan = make_test_scan_response("SCAN_SPACE_001")
    repo.save(scan)

    assert repo.get_by_id("  SCAN_SPACE_001  ") is not None
    assert repo.get_by_id("  SCAN_SPACE_001  ").scan_id == "SCAN_SPACE_001"


def test_get_by_id_empty_or_none_returns_none():
    repo = InMemoryScanRepository()
    assert repo.get_by_id("") is None
    assert repo.get_by_id("   ") is None


def test_list_all_empty():
    repo = InMemoryScanRepository()
    assert repo.list_all() == []


def test_list_all_deterministic_ordering():
    repo = InMemoryScanRepository()
    base_time = datetime(2026, 8, 13, 0, 0, 0, tzinfo=timezone.utc)

    scan_old = make_test_scan_response("SCAN_OLD", started_at=base_time)
    scan_mid1 = make_test_scan_response("SCAN_MID_B", started_at=base_time + timedelta(seconds=10))
    scan_mid2 = make_test_scan_response("SCAN_MID_A", started_at=base_time + timedelta(seconds=10))
    scan_new = make_test_scan_response("SCAN_NEW", started_at=base_time + timedelta(seconds=20))

    repo.save(scan_old)
    repo.save(scan_mid1)
    repo.save(scan_mid2)
    repo.save(scan_new)

    all_scans = repo.list_all()
    assert len(all_scans) == 4

    # Expected order: newest first (SCAN_NEW), then tie-broken deterministically by scan_id (SCAN_MID_B before SCAN_MID_A), then oldest (SCAN_OLD)
    ids = [s.scan_id for s in all_scans]
    assert ids == ["SCAN_NEW", "SCAN_MID_B", "SCAN_MID_A", "SCAN_OLD"]


def test_clear_and_count():
    repo = InMemoryScanRepository()
    assert repo.count() == 0
    assert len(repo) == 0

    repo.save(make_test_scan_response("SCAN_1"))
    repo.save(make_test_scan_response("SCAN_2"))
    assert repo.count() == 2
    assert len(repo) == 2

    repo.clear()
    assert repo.count() == 0
    assert repo.get_by_id("SCAN_1") is None


def test_thread_safety_concurrent_saves():
    repo = InMemoryScanRepository()
    errors = []

    def worker(worker_id: int):
        try:
            for i in range(10):
                scan = make_test_scan_response(f"SCAN_W{worker_id}_{i}")
                repo.save(scan)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert repo.count() == 50
