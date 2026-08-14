"""
Scan Repository Abstraction and In-Memory Implementation (STEP 11A)

This module defines:
1. ScanRepository: Abstract interface for scan history persistence.
2. InMemoryScanRepository: Deterministic in-memory repository implementation.

ARCHITECTURAL DIRECTIVES:
1. ScanRepository handles persistence of public ScanResponse DTOs.
2. Preserves all security boundaries (no credentials or raw execution traces).
3. Enforces deterministic ordering in scan listing (newest scans first, tie-broken by scan_id).
"""

from abc import ABC, abstractmethod
import threading
from typing import Dict, List, Optional

from app.api.schemas import ScanResponse
from app.observability import emit_event, get_logger

logger = get_logger("agentshield.repository.in_memory")


class RepositoryError(Exception):
    """Domain exception raised when a database or storage operational error occurs."""
    pass


class ScanRepository(ABC):
    """
    Abstract interface for security scan history persistence.
    """

    @abstractmethod
    def save(self, scan: ScanResponse) -> ScanResponse:
        """
        Persist a ScanResponse object.

        Args:
            scan (ScanResponse): The scan response DTO to store.

        Returns:
            ScanResponse: The stored scan response.
        """
        pass

    @abstractmethod
    def get_by_id(self, scan_id: str) -> Optional[ScanResponse]:
        """
        Retrieve a stored scan by its unique scan_id.

        Args:
            scan_id (str): The unique scan identifier.

        Returns:
            Optional[ScanResponse]: The scan response if found, else None.
        """
        pass

    @abstractmethod
    def list_all(self, limit: Optional[int] = None, offset: int = 0) -> List[ScanResponse]:
        """
        Retrieve stored scans ordered deterministically, with optional pagination.

        Args:
            limit (Optional[int]): Maximum number of scans to return.
            offset (int): Number of scans to skip.

        Returns:
            List[ScanResponse]: Collection of stored scans.
        """
        pass


class InMemoryScanRepository(ScanRepository):
    """
    Thread-safe in-memory implementation of ScanRepository.
    """

    def __init__(self) -> None:
        self._scans: Dict[str, ScanResponse] = {}
        self._lock = threading.Lock()

    def save(self, scan: ScanResponse) -> ScanResponse:
        """
        Persist a ScanResponse object in memory.

        Args:
            scan (ScanResponse): The scan response DTO to store.

        Returns:
            ScanResponse: The stored scan response.

        Raises:
            ValueError: If scan is invalid or scan_id is empty.
        """
        if not isinstance(scan, ScanResponse):
            raise ValueError("scan must be a valid ScanResponse instance")

        clean_id = scan.scan_id.strip() if scan.scan_id else ""
        if not clean_id:
            raise ValueError("scan_id must not be empty or whitespace-only")

        with self._lock:
            self._scans[clean_id] = scan

        emit_event(logger, "repository.save", repository_type="in_memory", operation="save", scan_id=clean_id)
        return scan

    def get_by_id(self, scan_id: str) -> Optional[ScanResponse]:
        """
        Retrieve a stored scan by scan_id.

        Args:
            scan_id (str): The unique scan identifier.

        Returns:
            Optional[ScanResponse]: Stored scan response if present, else None.
        """
        if not scan_id:
            return None

        clean_id = scan_id.strip()
        if not clean_id:
            return None

        with self._lock:
            res = self._scans.get(clean_id)

        emit_event(logger, "repository.get", repository_type="in_memory", operation="get_by_id", scan_id=clean_id, found=res is not None)
        return res

    def list_all(self, limit: Optional[int] = None, offset: int = 0) -> List[ScanResponse]:
        """
        Retrieve all stored scans in deterministic order.
        Scans are ordered by started_at descending (newest first),
        with scan_id descending as a deterministic tie-breaker.
        Supports pagination via offset and limit.

        Args:
            limit (Optional[int]): Maximum records to return (None for all).
            offset (int): Number of records to skip.

        Returns:
            List[ScanResponse]: Collection of stored scans.
        """
        with self._lock:
            scans = list(self._scans.values())

        # Deterministic sorting: started_at descending, scan_id descending
        scans.sort(key=lambda s: (s.started_at, s.scan_id), reverse=True)

        start = max(0, offset)
        end = start + limit if limit is not None and limit >= 0 else len(scans)
        paginated = scans[start:end]

        emit_event(logger, "repository.list", repository_type="in_memory", operation="list_all", total_scans=len(scans), returned_scans=len(paginated))
        return paginated

    def clear(self) -> None:
        """
        Clear all stored scans from memory (testing utility).
        """
        with self._lock:
            self._scans.clear()

    def count(self) -> int:
        """
        Return total number of stored scans.
        """
        with self._lock:
            return len(self._scans)

    def __len__(self) -> int:
        return self.count()
