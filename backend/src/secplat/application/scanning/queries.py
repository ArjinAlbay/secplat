from __future__ import annotations

from secplat.domain.scanning.errors import ScanNotFound
from secplat.domain.scanning.ports import ScanRepository
from secplat.domain.scanning.records import FindingView, ScanResultView
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import ProjectId, ScanId, Severity


class GetScan:
    def __init__(self, scans: ScanRepository) -> None:
        self._scans = scans

    def __call__(self, scan_id: ScanId) -> Scan:
        scan = self._scans.get(scan_id)
        if scan is None:
            raise ScanNotFound(str(scan_id))
        return scan


class ListProjectScans:
    def __init__(self, scans: ScanRepository) -> None:
        self._scans = scans

    def __call__(self, project_id: ProjectId) -> list[Scan]:
        return self._scans.list_by_project(project_id)


class ListRecentScans:
    def __init__(self, scans: ScanRepository) -> None:
        self._scans = scans

    def __call__(self, limit: int) -> list[Scan]:
        return self._scans.list_recent(limit)


class ListScanResults:
    def __init__(self, scans: ScanRepository) -> None:
        self._scans = scans

    def __call__(self, scan_id: ScanId, limit: int, offset: int) -> list[ScanResultView]:
        return self._scans.list_results(scan_id, limit, offset)


class ListScanFindings:
    def __init__(self, scans: ScanRepository) -> None:
        self._scans = scans

    def __call__(
        self, scan_id: ScanId, severity: Severity | None, limit: int, offset: int
    ) -> list[FindingView]:
        return self._scans.list_findings(scan_id, severity, limit, offset)
