from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends

from secplat.application.projects.dto import ProjectCreate, TargetIn
from secplat.application.projects.handlers import (
    AddTarget,
    CreateProject,
    DeleteProject,
    DeleteTarget,
    GetProject,
    ListProjects,
    ListTargets,
)
from secplat.application.scanning.dto import ProjectOut, TargetOut
from secplat.domain.scanning.value_objects import ProjectId, TargetId, TargetKind
from secplat.infrastructure.config import Settings, get_settings
from secplat.presentation.deps import (
    get_add_target,
    get_create_project,
    get_delete_project,
    get_delete_target,
    get_get_project,
    get_list_projects,
    get_list_targets,
)
from secplat.presentation.target_values import resolve_target_value

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", status_code=201, response_model=ProjectOut)
def create_project(
    payload: ProjectCreate,
    handler: CreateProject = Depends(get_create_project),
) -> ProjectOut:
    project = handler(payload)
    return ProjectOut.from_domain(project)


@router.get("", response_model=list[ProjectOut])
def list_projects(handler: ListProjects = Depends(get_list_projects)) -> list[ProjectOut]:
    projects = handler()
    return [ProjectOut.from_domain(project) for project in projects]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: uuid.UUID, handler: GetProject = Depends(get_get_project)
) -> ProjectOut:
    project = handler(ProjectId(project_id))
    return ProjectOut.from_domain(project)


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: uuid.UUID, handler: DeleteProject = Depends(get_delete_project)
) -> None:
    handler(ProjectId(project_id))


@router.post("/{project_id}/targets", status_code=201, response_model=TargetOut)
def add_target(
    project_id: uuid.UUID,
    payload: TargetIn,
    handler: AddTarget = Depends(get_add_target),
    settings: Settings = Depends(get_settings),
) -> TargetOut:
    kind = TargetKind(payload.kind)
    value = resolve_target_value(kind, payload.value, settings.workspace_root)
    target = handler(ProjectId(project_id), kind, value)
    return TargetOut.from_domain(target)


@router.get("/{project_id}/targets", response_model=list[TargetOut])
def list_targets(
    project_id: uuid.UUID, handler: ListTargets = Depends(get_list_targets)
) -> list[TargetOut]:
    targets = handler(ProjectId(project_id))
    return [TargetOut.from_domain(target) for target in targets]


@router.delete("/{project_id}/targets/{target_id}", status_code=204)
def delete_target(
    project_id: uuid.UUID,
    target_id: uuid.UUID,
    handler: DeleteTarget = Depends(get_delete_target),
) -> None:
    handler(ProjectId(project_id), TargetId(target_id))
