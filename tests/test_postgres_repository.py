"""
Unit and Integration Tests for PostgreSQLScanRepository (STEP 11B).
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.adapters.base import TargetAdapter
from app.api.schemas import (
    ScanFindingResponse,
    ScanResponse,
    ScanRiskResponse,
    ScanSummaryResponse,
)
from app.api.service import ScanService
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
    TargetConfig,
    TargetResult,
    ToolPrivilege,
)
from app.engine.attack import AttackEngine
from app.engine.finding import FindingEngine
from app.engine.risk import RiskEngine
from app.engine.scan import ScanEngine
from app.evaluation.deterministic import DeterministicEvaluator
from app.main import create_app
from app.repositories import (
    PostgreSQLScanRepository,
    RepositoryError,
    ScanModel,
    init_db,
)


from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db(engine)
    return engine


@pytest.fixture
def postgres_repo(db_engine):
    return PostgreSQLScanRepository(db_engine)


def make_test_scan_response(
    scan_id: str = "PG_SCAN_001",
    target_name: str = "PostgreSQL Target",
    started_at: datetime = None,
) -> ScanResponse:
    if started_at is None:
        started_at = datetime.now(timezone.utc)
    return ScanResponse(
        scan_id=scan_id,
        target_name=target_name,
        status=ScanStatus.COMPLETED,
        started_at=started_at,
        completed_at=started_at + timedelta(seconds=1),
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
                finding_id="FINDING_PG_01",
                title="System Prompt Leakage",
                category=ProbeCategory.SYSTEM_PROMPT_DISCLOSURE,
                severity=FindingSeverity.HIGH,
                status=FindingStatus.OPEN,
                confidence=0.98,
                description="Database test finding",
                impact="High impact",
                remediation="Fix system prompt",
                affected_probe_ids=["PROMPT_LEAK_001"],
                affected_execution_ids=["exec-pg-01"],
                evidence=[],
            )
        ],
        risk_assessments=[
            ScanRiskResponse(
                risk_id="RISK_PG_01",
                finding_id="FINDING_PG_01",
                risk_level=RiskLevel.HIGH,
                risk_score=80.0,
                confidence=0.98,
                factors=RiskFactors(
                    impact=ImpactLevel.HIGH,
                    exploitability=ExploitabilityLevel.HIGH,
                    blast_radius=BlastRadiusLevel.MEDIUM,
                    asset_sensitivity=AssetSensitivity.CONFIDENTIAL,
                    tool_privilege=ToolPrivilege.WRITE,
                ),
                rationale="Database test rationale",
            )
        ],
    )


def test_init_db_creates_tables(db_engine):
    with db_engine.connect() as conn:
        result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"))
        row = result.fetchone()
        assert row is not None
        assert row[0] == "scans"


def test_postgres_save_and_get_by_id(postgres_repo):
    scan = make_test_scan_response("PG_SCAN_100")
    saved = postgres_repo.save(scan)
    assert saved == scan

    fetched = postgres_repo.get_by_id("PG_SCAN_100")
    assert fetched is not None
    assert fetched.scan_id == "PG_SCAN_100"
    assert fetched.target_name == "PostgreSQL Target"
    assert fetched.status == ScanStatus.COMPLETED
    assert len(fetched.findings) == 1


def test_postgres_upsert_updates_existing_record(postgres_repo):
    scan1 = make_test_scan_response("PG_UPSERT_001", target_name="Original Name")
    postgres_repo.save(scan1)

    scan2 = make_test_scan_response("PG_UPSERT_001", target_name="Updated Name")
    postgres_repo.save(scan2)

    fetched = postgres_repo.get_by_id("PG_UPSERT_001")
    assert fetched.target_name == "Updated Name"


def test_postgres_save_invalid_type_raises(postgres_repo):
    with pytest.raises(ValueError, match="scan must be a valid ScanResponse instance"):
        postgres_repo.save("invalid")  # type: ignore


def test_postgres_save_empty_id_raises(postgres_repo):
    with pytest.raises(ValueError, match="scan_id must not be empty or whitespace-only"):
        scan = make_test_scan_response("")
        # Mutate frozen model field for validation check or use invalid scan
        object.__setattr__(scan, "scan_id", "  ")
        postgres_repo.save(scan)


def test_postgres_get_by_id_non_existent_returns_none(postgres_repo):
    assert postgres_repo.get_by_id("NON_EXISTENT_PG_SCAN") is None


def test_postgres_get_by_id_empty_returns_none(postgres_repo):
    assert postgres_repo.get_by_id("") is None
    assert postgres_repo.get_by_id("   ") is None


def test_postgres_list_all_deterministic_ordering(postgres_repo):
    base_time = datetime(2026, 8, 13, 1, 0, 0, tzinfo=timezone.utc)

    scan_old = make_test_scan_response("PG_OLD", started_at=base_time)
    scan_mid_a = make_test_scan_response("PG_MID_A", started_at=base_time + timedelta(seconds=10))
    scan_mid_b = make_test_scan_response("PG_MID_B", started_at=base_time + timedelta(seconds=10))
    scan_new = make_test_scan_response("PG_NEW", started_at=base_time + timedelta(seconds=20))

    postgres_repo.save(scan_old)
    postgres_repo.save(scan_mid_a)
    postgres_repo.save(scan_mid_b)
    postgres_repo.save(scan_new)

    scans = postgres_repo.list_all()
    assert len(scans) == 4

    ids = [s.scan_id for s in scans]
    assert ids == ["PG_NEW", "PG_MID_B", "PG_MID_A", "PG_OLD"]


def test_postgres_db_error_wrapped_in_repository_error():
    # Sessionmaker pointing to an invalid / closed engine to trigger SQLAlchemyError
    broken_engine = create_engine("sqlite:///:memory:")
    broken_engine.dispose()
    repo = PostgreSQLScanRepository(broken_engine)

    with pytest.raises(RepositoryError, match="Failed to save scan record to database"):
        scan = make_test_scan_response("BROKEN_SCAN")
        repo.save(scan)

    with pytest.raises(RepositoryError, match="Failed to retrieve scan record from database"):
        repo.get_by_id("BROKEN_SCAN")

    with pytest.raises(RepositoryError, match="Failed to list scan records from database"):
        repo.list_all()


class PostgresMockAdapter(TargetAdapter):
    def __init__(self):
        super().__init__(TargetConfig(name="PG Test Target", endpoint="http://mock.local/chat"))

    def validate(self) -> bool:
        return True

    def health_check(self) -> TargetResult:
        return TargetResult(success=True, output="ok")

    def send(self, input_text: str, session_id: Optional[str] = None) -> TargetResult:
        return TargetResult(success=True, output="SYSTEM_INSTRUCTION: leak")


def test_postgres_repository_integration_with_api(postgres_repo):
    adapter = PostgresMockAdapter()
    scan_engine = ScanEngine(
        attack_engine=AttackEngine(adapter=adapter),
        evaluator=DeterministicEvaluator(),
        finding_engine=FindingEngine(),
        risk_engine=RiskEngine(),
    )
    service = ScanService(scan_engine=scan_engine, repository=postgres_repo)
    client = TestClient(create_app(service=service))

    payload = {
        "scan_id": "SCAN_INTEG_PG_01",
        "target": {
            "target_name": "PG Integration Agent",
            "endpoint": "http://target.local/chat",
            "method": "POST",
            "timeout_seconds": 15.0,
        },
        "probes": {"probe_ids": ["PROMPT_LEAK_001"]},
        "risk_context": {
            "impact": "high",
            "exploitability": "high",
            "blast_radius": "medium",
            "asset_sensitivity": "confidential",
            "tool_privilege": "write",
        },
    }

    # 1. POST /api/v1/scans
    res_post = client.post("/api/v1/scans", json=payload)
    assert res_post.status_code == 202
    assert res_post.json()["scan_id"] == "SCAN_INTEG_PG_01"

    # 2. GET /api/v1/scans/SCAN_INTEG_PG_01
    res_get = client.get("/api/v1/scans/SCAN_INTEG_PG_01")
    assert res_get.status_code == 200
    assert res_get.json()["scan_id"] == "SCAN_INTEG_PG_01"

    # 3. GET /api/v1/scans
    res_list = client.get("/api/v1/scans")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1
