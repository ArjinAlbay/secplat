from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from secplat.domain.scanning.ports import ProjectRepository, ScanRepository
from secplat.domain.scanning.project import Project, Target
from secplat.domain.scanning.records import FindingRecord, FindingView, ScanResultView
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import (
    ProjectId,
    ScanId,
    ScanStatus,
    Severity,
    TargetId,
    ToolName,
)
from secplat.infrastructure.persistence.mappers import (
    apply_project,
    apply_scan,
    orm_to_project,
    orm_to_scan,
    orm_to_target,
    project_to_orm,
    scan_to_orm,
    target_to_orm,
)
from secplat.infrastructure.persistence.orm import (
    FindingORM,
    ProjectORM,
    ScanORM,
    ScanResultORM,
    TargetORM,
)


def _commit(session: Session) -> None:
    try:
        session.commit()
    except Exception:
        session.rollback()
        raise


class SqlAlchemyProjectRepository(ProjectRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, project: Project) -> None:
        row = self._session.get(ProjectORM, project.id)
        if row is None:
            self._session.add(project_to_orm(project))
        else:
            apply_project(row, project)
        _commit(self._session)

    def get(self, project_id: ProjectId) -> Project | None:
        row = self._session.get(ProjectORM, project_id)
        return orm_to_project(row) if row else None

    def list(self) -> list[Project]:
        rows = self._session.scalars(
            select(ProjectORM).order_by(ProjectORM.created_at.desc())
        ).all()
        return [orm_to_project(row) for row in rows]

    def delete(self, project_id: ProjectId) -> None:
        project_scan_ids = select(ScanORM.id).where(ScanORM.project_id == project_id)
        self._session.execute(delete(FindingORM).where(FindingORM.project_id == project_id))
        self._session.execute(
            delete(ScanResultORM).where(ScanResultORM.scan_id.in_(project_scan_ids))
        )
        self._session.execute(delete(ScanORM).where(ScanORM.project_id == project_id))
        self._session.execute(delete(TargetORM).where(TargetORM.project_id == project_id))
        self._session.execute(delete(ProjectORM).where(ProjectORM.id == project_id))
        _commit(self._session)

    def add_target(self, target: Target) -> Target:
        existing = self._session.scalars(
            select(TargetORM).where(
                TargetORM.project_id == target.project_id,
                TargetORM.kind == target.ref.kind,
                TargetORM.value == target.ref.value,
            )
        ).first()
        if existing is not None:
            return orm_to_target(existing)
        row = target_to_orm(target)
        self._session.add(row)
        _commit(self._session)
        return orm_to_target(row)

    def get_target(self, project_id: ProjectId, target_id: TargetId) -> Target | None:
        row = self._session.get(TargetORM, target_id)
        if row is None or row.project_id != project_id:
            return None
        return orm_to_target(row)

    def list_targets(self, project_id: ProjectId) -> list[Target]:
        rows = self._session.scalars(
            select(TargetORM)
            .where(TargetORM.project_id == project_id)
            .order_by(TargetORM.created_at.desc())
        ).all()
        return [orm_to_target(row) for row in rows]

    def delete_target(self, project_id: ProjectId, target_id: TargetId) -> None:
        self._session.execute(
            delete(TargetORM).where(
                TargetORM.project_id == project_id,
                TargetORM.id == target_id,
            )
        )
        _commit(self._session)


class SqlAlchemyScanRepository(ScanRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, scan: Scan) -> None:
        row = self._session.get(ScanORM, scan.id)
        if row is None:
            self._session.add(scan_to_orm(scan))
        else:
            apply_scan(row, scan)
        _commit(self._session)

    def get(self, scan_id: ScanId) -> Scan | None:
        row = self._session.get(ScanORM, scan_id)
        return orm_to_scan(row) if row else None

    def list_by_project(self, project_id: ProjectId) -> list[Scan]:
        rows = self._session.scalars(
            select(ScanORM)
            .where(ScanORM.project_id == project_id)
            .order_by(ScanORM.created_at.desc())
        ).all()
        return [orm_to_scan(row) for row in rows]

    def delete(self, scan_id: ScanId) -> None:
        self._session.execute(delete(FindingORM).where(FindingORM.scan_id == scan_id))
        self._session.execute(delete(ScanResultORM).where(ScanResultORM.scan_id == scan_id))
        self._session.execute(delete(ScanORM).where(ScanORM.id == scan_id))
        _commit(self._session)

    def delete_by_project(self, project_id: ProjectId) -> None:
        project_scan_ids = select(ScanORM.id).where(ScanORM.project_id == project_id)
        self._session.execute(
            delete(FindingORM).where(FindingORM.project_id == project_id)
        )
        self._session.execute(
            delete(ScanResultORM).where(ScanResultORM.scan_id.in_(project_scan_ids))
        )
        self._session.execute(delete(ScanORM).where(ScanORM.project_id == project_id))
        _commit(self._session)

    def list_recent(self, limit: int) -> list[Scan]:
        rows = self._session.scalars(
            select(ScanORM).order_by(ScanORM.created_at.desc()).limit(limit)
        ).all()
        return [orm_to_scan(row) for row in rows]

    def update_stats(self, scan_id: ScanId, stats: Mapping[str, Any]) -> None:
        row = self._session.get(ScanORM, scan_id)
        if row is None:
            return
        row.stats = dict(stats)
        _commit(self._session)

    def add_results(
        self, scan_id: ScanId, tool: ToolName, raw_lines: Sequence[Mapping[str, Any]]
    ) -> None:
        self._session.add_all(
            ScanResultORM(scan_id=scan_id, tool=tool.value, raw=dict(raw)) for raw in raw_lines
        )
        _commit(self._session)

    def upsert_findings(
        self, scan_id: ScanId, project_id: ProjectId, findings: Sequence[FindingRecord]
    ) -> None:
        now = datetime.now(UTC)
        for record in findings:
            row = self._session.scalars(
                select(FindingORM).where(
                    FindingORM.scan_id == scan_id,
                    FindingORM.fingerprint == record.fingerprint,
                )
            ).first()
            if row is None:
                self._session.add(
                    FindingORM(
                        id=uuid.uuid4(),
                        project_id=project_id,
                        scan_id=scan_id,
                        severity=record.severity,
                        template_id=record.template_id,
                        name=record.name,
                        matched_at=record.matched_at,
                        host=record.host,
                        extracted=list(record.extracted) or None,
                        fingerprint=record.fingerprint,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
            else:
                row.last_seen_at = now
                row.extracted = list(record.extracted) or None
        _commit(self._session)

    def list_results(self, scan_id: ScanId, limit: int, offset: int) -> list[ScanResultView]:
        rows = self._session.scalars(
            select(ScanResultORM)
            .where(ScanResultORM.scan_id == scan_id)
            .order_by(ScanResultORM.id.asc())
            .limit(limit)
            .offset(offset)
        ).all()
        return [
            ScanResultView(tool=row.tool, raw=dict(row.raw), created_at=row.created_at)
            for row in rows
        ]

    def list_findings(
        self, scan_id: ScanId, severity: Severity | None, limit: int, offset: int
    ) -> list[FindingView]:
        stmt = select(FindingORM).where(FindingORM.scan_id == scan_id)
        if severity is not None:
            stmt = stmt.where(FindingORM.severity == severity)
        rows = self._session.scalars(
            stmt.order_by(FindingORM.last_seen_at.desc()).limit(limit).offset(offset)
        ).all()
        return [
            FindingView(
                severity=row.severity,
                template_id=row.template_id,
                name=row.name,
                matched_at=row.matched_at,
                host=row.host,
                extracted=tuple(row.extracted or ()),
                status=row.status,
                first_seen_at=row.first_seen_at,
                last_seen_at=row.last_seen_at,
            )
            for row in rows
        ]

    def list_by_status(self, status: ScanStatus, updated_before: datetime) -> list[Scan]:
        rows = self._session.scalars(
            select(ScanORM).where(
                ScanORM.status == status,
                ScanORM.updated_at < updated_before,
            )
        ).all()
        return [orm_to_scan(row) for row in rows]
