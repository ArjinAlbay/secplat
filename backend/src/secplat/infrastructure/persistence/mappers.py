from __future__ import annotations

from secplat.domain.scanning.project import Project, Target
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import ProjectId, ScanId, TargetId, TargetRef
from secplat.infrastructure.persistence.orm import ProjectORM, ScanORM, TargetORM


def apply_scan(row: ScanORM, scan: Scan) -> None:
    row.id = scan.id
    row.project_id = scan.project_id
    row.target_id = scan.target_id
    row.parent_scan_id = None
    row.target_kind = scan.target.kind
    row.target_value = scan.target.value
    row.tool = scan.tool
    row.status = scan.status
    row.task_id = scan.task_id
    row.config = dict(scan.config)
    row.stats = scan.stats
    row.error = scan.error
    row.started_at = scan.started_at
    row.finished_at = scan.finished_at
    row.created_at = scan.created_at


def scan_to_orm(scan: Scan) -> ScanORM:
    row = ScanORM()
    apply_scan(row, scan)
    return row


def orm_to_scan(row: ScanORM) -> Scan:
    return Scan(
        id=ScanId(row.id),
        project_id=ProjectId(row.project_id),
        target_id=TargetId(row.target_id) if row.target_id else None,
        target=TargetRef(kind=row.target_kind, value=row.target_value),
        tool=row.tool,
        config=dict(row.config or {}),
        status=row.status,
        task_id=row.task_id,
        stats=dict(row.stats) if row.stats else None,
        error=row.error,
        started_at=row.started_at,
        finished_at=row.finished_at,
        created_at=row.created_at,
    )


def apply_project(row: ProjectORM, project: Project) -> None:
    row.id = project.id
    row.name = project.name
    row.description = project.description
    row.created_at = project.created_at


def project_to_orm(project: Project) -> ProjectORM:
    row = ProjectORM()
    apply_project(row, project)
    return row


def orm_to_project(row: ProjectORM) -> Project:
    return Project(
        id=ProjectId(row.id),
        name=row.name,
        description=row.description,
        created_at=row.created_at,
    )


def apply_target(row: TargetORM, target: Target) -> None:
    row.id = target.id
    row.project_id = target.project_id
    row.kind = target.ref.kind
    row.value = target.ref.value
    row.is_active = target.is_active
    row.created_at = target.created_at


def target_to_orm(target: Target) -> TargetORM:
    row = TargetORM()
    apply_target(row, target)
    return row


def orm_to_target(row: TargetORM) -> Target:
    return Target(
        id=TargetId(row.id),
        project_id=ProjectId(row.project_id),
        ref=TargetRef(kind=row.kind, value=row.value),
        is_active=row.is_active,
        created_at=row.created_at,
    )
