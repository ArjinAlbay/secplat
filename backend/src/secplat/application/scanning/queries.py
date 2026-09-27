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


class CompareScans:
    def __init__(self, scans: ScanRepository) -> None:
        self._scans = scans

    def __call__(
        self, base_scan_id: ScanId, target_scan_id: ScanId | None = None
    ) -> dict[str, object]:
        base_scan = self._scans.get(base_scan_id)
        if base_scan is None:
            raise ScanNotFound(str(base_scan_id))

        if target_scan_id is None:
            # Find the immediately preceding completed scan for the same project & target
            project_scans = self._scans.list_by_project(base_scan.project_id)
            matching_previous = [
                s
                for s in project_scans
                if s.id != base_scan.id
                and s.status.is_terminal
                and s.target == base_scan.target
                and s.tool == base_scan.tool
                and (
                    (
                        s.finished_at
                        and base_scan.finished_at
                        and s.finished_at <= base_scan.finished_at
                    )
                    or s.created_at <= base_scan.created_at
                )
            ]
            if matching_previous:
                target_scan_id = matching_previous[0].id

        base_findings = self._scans.list_findings(
            base_scan_id, severity=None, limit=500, offset=0
        )
        base_map = {f.fingerprint: f for f in base_findings}

        target_findings: list[FindingView] = []
        target_map: dict[str, FindingView] = {}
        if target_scan_id is not None:
            target_findings = self._scans.list_findings(
                target_scan_id, severity=None, limit=500, offset=0
            )
            target_map = {f.fingerprint: f for f in target_findings}

        new_fingerprints = set(base_map.keys()) - set(target_map.keys())
        fixed_fingerprints = set(target_map.keys()) - set(base_map.keys())
        unchanged_fingerprints = set(base_map.keys()) & set(target_map.keys())

        return {
            "base_scan_id": base_scan_id,
            "target_scan_id": target_scan_id,
            "summary": {
                "new_count": len(new_fingerprints),
                "fixed_count": len(fixed_fingerprints),
                "unchanged_count": len(unchanged_fingerprints),
                "current_total": len(base_findings),
                "previous_total": len(target_findings),
            },
            "new_findings": [base_map[fp] for fp in new_fingerprints],
            "fixed_findings": [target_map[fp] for fp in fixed_fingerprints],
            "unchanged_findings": [base_map[fp] for fp in unchanged_fingerprints],
        }

