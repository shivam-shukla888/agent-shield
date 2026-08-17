"""
PostgreSQL Scan Repository Implementation (STEP 11B)

This module defines:
1. RepositoryError: Domain exception wrapper for database infrastructure failures.
2. ScanModel: Declarative SQLAlchemy ORM mapping for scans table.
3. init_db: Database DDL initialization / migration execution function.
4. PostgreSQLScanRepository: ScanRepository implementation backed by SQL database engine.

SECURITY & ARCHITECTURAL INVARIANTS:
1. Stored records retain public ScanResponse DTO structures (zero credentials or raw execution traces).
2. Database driver/SQL errors are caught and wrapped in RepositoryError to prevent exposing DB passwords, hostnames, or raw SQL tracebacks.
3. Deterministic scan ordering (started_at DESC, scan_id DESC) matches InMemoryScanRepository.
"""

from datetime import datetime, timezone
import json
from typing import List, Optional, Union

from sqlalchemy import Column, DateTime, Engine, String, Text, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.api.schemas import ScanResponse
from app.repositories.scan import RepositoryError, ScanRepository


class Base(DeclarativeBase):
    """SQLAlchemy Declarative Base."""
    pass


class ScanModel(Base):
    """
    SQLAlchemy ORM table mapping for security scans.
    """

    __tablename__ = "scans"

    scan_id = Column(String(255), primary_key=True, index=True, nullable=False)
    target_name = Column(String(255), nullable=False, index=True)
    status = Column(String(50), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=False, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    summary_json = Column(Text, nullable=False)
    findings_json = Column(Text, nullable=False)
    risk_assessments_json = Column(Text, nullable=False)
    payload_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


def init_db(engine: Engine) -> None:
    """
    Execute DDL table and index creation migrations.

    Args:
        engine (Engine): SQLAlchemy engine instance.

    Raises:
        RepositoryError: If table creation fails.
    """
    try:
        Base.metadata.create_all(bind=engine)
    except SQLAlchemyError as exc:
        raise RepositoryError("Failed to initialize database schema") from exc


class PostgreSQLScanRepository(ScanRepository):
    """
    PostgreSQL-backed implementation of ScanRepository abstraction.
    """

    def __init__(self, engine_or_sessionmaker: Union[Engine, sessionmaker]) -> None:
        """
        Initialize PostgreSQLScanRepository with an Engine or sessionmaker.

        Args:
            engine_or_sessionmaker: Configured SQLAlchemy Engine or sessionmaker factory.
        """
        if isinstance(engine_or_sessionmaker, Engine):
            self.session_factory = sessionmaker(bind=engine_or_sessionmaker, expire_on_commit=False)
        elif isinstance(engine_or_sessionmaker, sessionmaker):
            self.session_factory = engine_or_sessionmaker
        else:
            raise ValueError("Must provide a valid SQLAlchemy Engine or sessionmaker instance")

    def save(self, scan: ScanResponse) -> ScanResponse:
        """
        Persist or update a ScanResponse object in database.

        Args:
            scan (ScanResponse): The public scan response DTO to store.

        Returns:
            ScanResponse: The stored scan response DTO.

        Raises:
            ValueError: If scan is invalid or scan_id is empty.
            RepositoryError: If a database operation fails.
        """
        if not isinstance(scan, ScanResponse):
            raise ValueError("scan must be a valid ScanResponse instance")

        clean_id = scan.scan_id.strip() if scan.scan_id else ""
        if not clean_id:
            raise ValueError("scan_id must not be empty or whitespace-only")

        serialized_payload = scan.model_dump_json()
        summary_json = scan.summary.model_dump_json()
        findings_json = json.dumps([f.model_dump(mode="json") for f in scan.findings])
        risk_assessments_json = json.dumps([r.model_dump(mode="json") for r in scan.risk_assessments])

        try:
            with self.session_factory.begin() as session:
                db_record = session.get(ScanModel, clean_id)
                if db_record is None:
                    db_record = ScanModel(
                        scan_id=clean_id,
                        target_name=scan.target_name,
                        status=str(scan.status),
                        started_at=scan.started_at,
                        completed_at=scan.completed_at,
                        summary_json=summary_json,
                        findings_json=findings_json,
                        risk_assessments_json=risk_assessments_json,
                        payload_json=serialized_payload,
                    )
                    session.add(db_record)
                else:
                    db_record.target_name = scan.target_name  # type: ignore[assignment]
                    db_record.status = str(scan.status)  # type: ignore[assignment]
                    db_record.started_at = scan.started_at  # type: ignore[assignment]
                    db_record.completed_at = scan.completed_at  # type: ignore[assignment]
                    db_record.summary_json = summary_json  # type: ignore[assignment]
                    db_record.findings_json = findings_json  # type: ignore[assignment]
                    db_record.risk_assessments_json = risk_assessments_json  # type: ignore[assignment]
                    db_record.payload_json = serialized_payload  # type: ignore[assignment]

            return scan
        except SQLAlchemyError as exc:
            raise RepositoryError("Failed to save scan record to database") from exc

    def get_by_id(self, scan_id: str) -> Optional[ScanResponse]:
        """
        Retrieve a single scan record by ID and reconstruct its public ScanResponse DTO.

        Args:
            scan_id (str): Unique scan identifier.

        Returns:
            Optional[ScanResponse]: Reconstructed ScanResponse DTO if found, else None.

        Raises:
            RepositoryError: If a database error occurs.
        """
        clean_id = scan_id.strip() if scan_id else ""
        if not clean_id:
            return None

        try:
            with self.session_factory() as session:
                record = session.get(ScanModel, clean_id)
                if record is None:
                    return None
                return ScanResponse.model_validate_json(str(record.payload_json))
        except SQLAlchemyError as exc:
            raise RepositoryError("Failed to retrieve scan record from database") from exc

    def list_all(self, limit: Optional[int] = None, offset: int = 0) -> List[ScanResponse]:
        """
        Retrieve stored scans in deterministic order (started_at DESC, scan_id DESC) with pagination.

        Args:
            limit (Optional[int]): Maximum records to return.
            offset (int): Number of records to skip.

        Returns:
            List[ScanResponse]: Collection of reconstructed ScanResponse DTOs.

        Raises:
            RepositoryError: If a database query error occurs.
        """
        try:
            with self.session_factory() as session:
                stmt = select(ScanModel).order_by(ScanModel.started_at.desc(), ScanModel.scan_id.desc())
                if offset > 0:
                    stmt = stmt.offset(offset)
                if limit is not None and limit >= 0:
                    stmt = stmt.limit(limit)
                records = session.scalars(stmt).all()
                return [ScanResponse.model_validate_json(str(r.payload_json)) for r in records]
        except SQLAlchemyError as exc:
            raise RepositoryError("Failed to list scan records from database") from exc
