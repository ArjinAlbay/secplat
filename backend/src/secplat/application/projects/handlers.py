from __future__ import annotations

import uuid

from secplat.application.projects.dto import ProjectCreate
from secplat.domain.scanning.errors import ProjectHasActiveScans, ProjectNotFound
from secplat.domain.scanning.ports import ProjectRepository, ScanRepository
from secplat.domain.scanning.project import Project, Target
from secplat.domain.scanning.value_objects import ProjectId, TargetId, TargetKind, TargetRef


class CreateProject:
    def __init__(self, projects: ProjectRepository) -> None:
        self._projects = projects

    def __call__(self, request: ProjectCreate) -> Project:
        project = Project(
            id=ProjectId(uuid.uuid4()),
            name=request.name,
            description=request.description,
        )
        self._projects.save(project)
        return project


class GetProject:
    def __init__(self, projects: ProjectRepository) -> None:
        self._projects = projects

    def __call__(self, project_id: ProjectId) -> Project:
        project = self._projects.get(project_id)
        if project is None:
            raise ProjectNotFound(str(project_id))
        return project


class ListProjects:
    def __init__(self, projects: ProjectRepository) -> None:
        self._projects = projects

    def __call__(self) -> list[Project]:
        return self._projects.list()


class AddTarget:
    def __init__(self, projects: ProjectRepository) -> None:
        self._projects = projects

    def __call__(self, project_id: ProjectId, kind: TargetKind, value: str) -> Target:
        if self._projects.get(project_id) is None:
            raise ProjectNotFound(str(project_id))
        ref = TargetRef(kind=kind, value=value)
        target = Target(id=TargetId(uuid.uuid4()), project_id=project_id, ref=ref)
        return self._projects.add_target(target)


class ListTargets:
    def __init__(self, projects: ProjectRepository) -> None:
        self._projects = projects

    def __call__(self, project_id: ProjectId) -> list[Target]:
        return self._projects.list_targets(project_id)


class DeleteProject:
    def __init__(self, projects: ProjectRepository, scans: ScanRepository) -> None:
        self._projects = projects
        self._scans = scans

    def __call__(self, project_id: ProjectId) -> None:
        if self._projects.get(project_id) is None:
            raise ProjectNotFound(str(project_id))
        for scan in self._scans.list_by_project(project_id):
            if not scan.status.is_terminal:
                raise ProjectHasActiveScans(str(project_id))
        self._scans.delete_by_project(project_id)
        self._projects.delete(project_id)


class DeleteTarget:
    def __init__(self, projects: ProjectRepository) -> None:
        self._projects = projects

    def __call__(self, project_id: ProjectId, target_id: TargetId) -> None:
        if self._projects.get(project_id) is None:
            raise ProjectNotFound(str(project_id))
        self._projects.delete_target(project_id, target_id)
