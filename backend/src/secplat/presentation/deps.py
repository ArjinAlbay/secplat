from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends
from sqlalchemy.orm import Session

from secplat.application.projects.handlers import (
    AddTarget,
    CreateProject,
    DeleteProject,
    DeleteTarget,
    GetProject,
    ListProjects,
    ListTargets,
)
from secplat.application.reports.builders import BuildProjectOverview, BuildProjectSecurityScore
from secplat.application.scanning.commands import (
    CancelScan,
    DeleteScan,
    StartCodebasePipeline,
    StartReconPipeline,
    StartScan,
)
from secplat.application.scanning.queries import (
    GetScan,
    ListProjectScans,
    ListRecentScans,
    ListScanFindings,
    ListScanResults,
)
from secplat.domain.scanning.ports import ProjectRepository, ScanRepository, TaskQueue
from secplat.infrastructure.persistence.repositories import (
    SqlAlchemyProjectRepository,
    SqlAlchemyScanRepository,
)
from secplat.infrastructure.persistence.session import session_factory
from secplat.infrastructure.queue.celery_queue import CeleryTaskQueue
from secplat.infrastructure.reporting.renderers import (
    OverviewHtmlRenderer,
    OverviewPdfRenderer,
)

_sessions = session_factory()


def get_db() -> Iterator[Session]:
    session = _sessions()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_project_repo(db: Session = Depends(get_db)) -> ProjectRepository:
    return SqlAlchemyProjectRepository(db)


def get_scan_repo(db: Session = Depends(get_db)) -> ScanRepository:
    return SqlAlchemyScanRepository(db)


def get_task_queue() -> TaskQueue:
    return CeleryTaskQueue()


def get_start_scan(
    scans: ScanRepository = Depends(get_scan_repo),
    projects: ProjectRepository = Depends(get_project_repo),
    queue: TaskQueue = Depends(get_task_queue),
) -> StartScan:
    return StartScan(scans, projects, queue)


def get_start_recon_pipeline(
    projects: ProjectRepository = Depends(get_project_repo),
    queue: TaskQueue = Depends(get_task_queue),
) -> StartReconPipeline:
    return StartReconPipeline(projects, queue)


def get_start_codebase_pipeline(
    projects: ProjectRepository = Depends(get_project_repo),
    queue: TaskQueue = Depends(get_task_queue),
) -> StartCodebasePipeline:
    return StartCodebasePipeline(projects, queue)


def get_cancel_scan(
    scans: ScanRepository = Depends(get_scan_repo),
    queue: TaskQueue = Depends(get_task_queue),
) -> CancelScan:
    return CancelScan(scans, queue)


def get_delete_scan(
    scans: ScanRepository = Depends(get_scan_repo),
    queue: TaskQueue = Depends(get_task_queue),
) -> DeleteScan:
    return DeleteScan(scans, queue)


def get_get_scan(scans: ScanRepository = Depends(get_scan_repo)) -> GetScan:
    return GetScan(scans)


def get_list_project_scans(scans: ScanRepository = Depends(get_scan_repo)) -> ListProjectScans:
    return ListProjectScans(scans)


def get_list_recent_scans(scans: ScanRepository = Depends(get_scan_repo)) -> ListRecentScans:
    return ListRecentScans(scans)


def get_list_scan_results(scans: ScanRepository = Depends(get_scan_repo)) -> ListScanResults:
    return ListScanResults(scans)


def get_list_scan_findings(scans: ScanRepository = Depends(get_scan_repo)) -> ListScanFindings:
    return ListScanFindings(scans)


def get_build_project_overview() -> BuildProjectOverview:
    return BuildProjectOverview()


def get_build_project_security_score() -> BuildProjectSecurityScore:
    return BuildProjectSecurityScore()


def get_overview_html_report_renderer() -> OverviewHtmlRenderer:
    return OverviewHtmlRenderer()


def get_overview_pdf_report_renderer() -> OverviewPdfRenderer:
    return OverviewPdfRenderer()


def get_create_project(projects: ProjectRepository = Depends(get_project_repo)) -> CreateProject:
    return CreateProject(projects)


def get_get_project(projects: ProjectRepository = Depends(get_project_repo)) -> GetProject:
    return GetProject(projects)


def get_list_projects(projects: ProjectRepository = Depends(get_project_repo)) -> ListProjects:
    return ListProjects(projects)


def get_add_target(projects: ProjectRepository = Depends(get_project_repo)) -> AddTarget:
    return AddTarget(projects)


def get_list_targets(projects: ProjectRepository = Depends(get_project_repo)) -> ListTargets:
    return ListTargets(projects)


def get_delete_project(
    projects: ProjectRepository = Depends(get_project_repo),
    scans: ScanRepository = Depends(get_scan_repo),
) -> DeleteProject:
    return DeleteProject(projects, scans)


def get_delete_target(
    projects: ProjectRepository = Depends(get_project_repo),
) -> DeleteTarget:
    return DeleteTarget(projects)
