from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, Response

from secplat.application.projects.dto import TargetIn
from secplat.application.reports.builders import (
    BuildProjectOverview,
    BuildProjectSecurityScore,
)
from secplat.application.reports.dto import OverviewOut
from secplat.application.scanning.commands import (
    CancelScan,
    DeleteScan,
    StartCodebasePipeline,
    StartReconPipeline,
    StartScan,
)
from secplat.application.scanning.dto import (
    BatchScanCreate,
    CodebasePipelineRequest,
    CodebasePipelineResponse,
    FindingOut,
    ReconPipelineRequest,
    ReconPipelineResponse,
    ScanCreate,
    ScanOut,
    ScanResultOut,
    SecurityScoreOut,
    TargetRefOut,
)
from secplat.application.scanning.queries import (
    GetScan,
    ListProjectScans,
    ListRecentScans,
    ListScanFindings,
    ListScanResults,
)
from secplat.domain.scanning.ports import ProjectRepository, ScanRepository
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import ProjectId, ScanId, Severity, TargetKind
from secplat.infrastructure.config import Settings, get_settings
from secplat.infrastructure.reporting.renderers import (
    OverviewHtmlRenderer,
    OverviewPdfRenderer,
)
from secplat.presentation.deps import (
    get_build_project_overview,
    get_build_project_security_score,
    get_cancel_scan,
    get_delete_scan,
    get_get_scan,
    get_list_project_scans,
    get_list_recent_scans,
    get_list_scan_findings,
    get_list_scan_results,
    get_overview_html_report_renderer,
    get_overview_pdf_report_renderer,
    get_project_repo,
    get_scan_repo,
    get_start_codebase_pipeline,
    get_start_recon_pipeline,
    get_start_scan,
)
from secplat.presentation.target_values import resolve_target_value

router = APIRouter(tags=["scans"])


@router.get("/scans", response_model=list[ScanOut])
def list_recent_scans(
    handler: ListRecentScans = Depends(get_list_recent_scans),
    limit: int = Query(10, ge=1, le=100),
) -> list[ScanOut]:
    scans = handler(limit)
    return [ScanOut.from_domain(scan) for scan in scans]


@router.post("/projects/{project_id}/scans", status_code=202, response_model=ScanOut)
def start_scan(
    project_id: uuid.UUID,
    payload: ScanCreate,
    handler: StartScan = Depends(get_start_scan),
    settings: Settings = Depends(get_settings),
) -> ScanOut:
    if payload.target is not None:
        kind = TargetKind(payload.target.kind)
        resolved_val = resolve_target_value(kind, payload.target.value, settings.workspace_root)
        payload = payload.model_copy(
            update={
                "target": TargetIn(
                    kind=payload.target.kind,
                    value=resolved_val,
                )
            }
        )
    scan = handler(ProjectId(project_id), payload)
    return ScanOut.from_domain(scan)


@router.post("/projects/{project_id}/scans/batch", status_code=202, response_model=list[ScanOut])
def start_batch_scans(
    project_id: uuid.UUID,
    payload: BatchScanCreate,
    handler: StartScan = Depends(get_start_scan),
    settings: Settings = Depends(get_settings),
) -> list[ScanOut]:
    results: list[ScanOut] = []
    for item in payload.scans:
        if item.target is not None:
            kind = TargetKind(item.target.kind)
            resolved_val = resolve_target_value(kind, item.target.value, settings.workspace_root)
            item = item.model_copy(
                update={
                    "target": TargetIn(
                        kind=item.target.kind,
                        value=resolved_val,
                    )
                }
            )
        scan = handler(ProjectId(project_id), item)
        results.append(ScanOut.from_domain(scan))
    return results


@router.post(
    "/projects/{project_id}/pipelines/recon",
    status_code=202,
    response_model=ReconPipelineResponse,
)
def start_recon_pipeline_endpoint(
    project_id: uuid.UUID,
    payload: ReconPipelineRequest,
    handler: StartReconPipeline = Depends(get_start_recon_pipeline),
    settings: Settings = Depends(get_settings),
) -> ReconPipelineResponse:
    if payload.target is not None:
        kind = TargetKind(payload.target.kind)
        resolved_val = resolve_target_value(kind, payload.target.value, settings.workspace_root)
        payload = payload.model_copy(
            update={
                "target": TargetIn(
                    kind=payload.target.kind,
                    value=resolved_val,
                )
            }
        )
    pipeline_id, target_ref = handler(ProjectId(project_id), payload)
    return ReconPipelineResponse(
        pipeline_id=pipeline_id,
        project_id=project_id,
        target=TargetRefOut(kind=target_ref.kind, value=target_ref.value),
        status="queued",
        message="Recon & DAST pipeline queued (Subfinder -> HTTPx -> Nuclei)",
    )


@router.post(
    "/projects/{project_id}/pipelines/codebase",
    status_code=202,
    response_model=CodebasePipelineResponse,
)
def start_codebase_pipeline_endpoint(
    project_id: uuid.UUID,
    payload: CodebasePipelineRequest,
    handler: StartCodebasePipeline = Depends(get_start_codebase_pipeline),
    settings: Settings = Depends(get_settings),
) -> CodebasePipelineResponse:
    if payload.target is not None:
        kind = TargetKind(payload.target.kind)
        resolved_val = resolve_target_value(kind, payload.target.value, settings.workspace_root)
        payload = payload.model_copy(
            update={
                "target": TargetIn(
                    kind=payload.target.kind,
                    value=resolved_val,
                )
            }
        )
    pipeline_id, target_ref = handler(ProjectId(project_id), payload)
    return CodebasePipelineResponse(
        pipeline_id=pipeline_id,
        project_id=project_id,
        target=TargetRefOut(kind=target_ref.kind, value=target_ref.value),
        status="queued",
        message="Full Codebase Audit queued (Gitleaks -> Semgrep -> Trivy -> Checkov)",
    )


@router.get("/projects/{project_id}/security-score", response_model=SecurityScoreOut)
def get_project_security_score_endpoint(
    project_id: uuid.UUID,
    list_scans: ListProjectScans = Depends(get_list_project_scans),
    score_builder: BuildProjectSecurityScore = Depends(get_build_project_security_score),
) -> SecurityScoreOut:
    scans = list_scans(ProjectId(project_id))
    score = score_builder(scans)
    return SecurityScoreOut.from_domain(score)


@router.get("/projects/{project_id}/scans", response_model=list[ScanOut])
def list_project_scans(
    project_id: uuid.UUID, handler: ListProjectScans = Depends(get_list_project_scans)
) -> list[ScanOut]:
    scans = handler(ProjectId(project_id))
    return [ScanOut.from_domain(scan) for scan in scans]


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: uuid.UUID, handler: GetScan = Depends(get_get_scan)) -> ScanOut:
    scan: Scan = handler(ScanId(scan_id))
    return ScanOut.from_domain(scan)


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: uuid.UUID, handler: CancelScan = Depends(get_cancel_scan)) -> ScanOut:
    scan: Scan = handler(ScanId(scan_id))
    return ScanOut.from_domain(scan)


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: uuid.UUID, handler: DeleteScan = Depends(get_delete_scan)
) -> None:
    handler(ScanId(scan_id))


@router.get("/scans/{scan_id}/results", response_model=list[ScanResultOut])
def list_scan_results(
    scan_id: uuid.UUID,
    handler: ListScanResults = Depends(get_list_scan_results),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[ScanResultOut]:
    views = handler(ScanId(scan_id), limit, offset)
    return [ScanResultOut.from_view(view) for view in views]


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_scan_findings(
    scan_id: uuid.UUID,
    handler: ListScanFindings = Depends(get_list_scan_findings),
    severity: Severity | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[FindingOut]:
    views = handler(ScanId(scan_id), severity, limit, offset)
    return [FindingOut.from_view(view) for view in views]


@router.get("/reports/overview")
def get_overview_report(
    projects: ProjectRepository = Depends(get_project_repo),
    scans: ScanRepository = Depends(get_scan_repo),
    build_overview: BuildProjectOverview = Depends(get_build_project_overview),
    html_renderer: OverviewHtmlRenderer = Depends(get_overview_html_report_renderer),
    pdf_renderer: OverviewPdfRenderer = Depends(get_overview_pdf_report_renderer),
    format: str = Query("pdf", pattern="^(pdf|html|json)$"),
) -> Response:
    scans_by_project: list[tuple[str, list[Scan]]] = []
    for project in projects.list():
        project_scans = scans.list_by_project(project.id)
        if project_scans:
            scans_by_project.append((project.name, project_scans))
    model = build_overview(scans_by_project)
    if format == "json":
        return JSONResponse(content=OverviewOut.from_model(model).model_dump(mode="json"))
    if format == "html":
        return Response(
            content=html_renderer.render(model),
            media_type=html_renderer.media_type,
            headers={"Content-Disposition": "inline"},
        )
    return Response(
        content=pdf_renderer.render(model),
        media_type=pdf_renderer.media_type,
        headers={
            "Content-Disposition": 'attachment; filename="secplat-overview.pdf"'
        },
    )
