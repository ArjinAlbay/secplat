from __future__ import annotations

import os

from fastapi import APIRouter
from pydantic import BaseModel

from secplat.infrastructure.config import get_settings

router = APIRouter(prefix="/workspace", tags=["workspace"])


class WorkspaceEntry(BaseModel):
    name: str
    path: str
    full_path: str


class WorkspaceResponse(BaseModel):
    root: str
    available: bool
    entries: list[WorkspaceEntry]


@router.get("", response_model=WorkspaceResponse)
def get_workspace() -> WorkspaceResponse:
    settings = get_settings()
    root = settings.workspace_root

    if not os.path.isdir(root):
        return WorkspaceResponse(root=root, available=False, entries=[])

    entries: list[WorkspaceEntry] = []
    try:
        for entry in sorted(os.scandir(root), key=lambda e: e.name.lower()):
            if entry.is_dir(follow_symlinks=True):
                entries.append(
                    WorkspaceEntry(
                        name=entry.name,
                        path=entry.name,
                        full_path=entry.path,
                    )
                )
    except PermissionError:
        pass

    return WorkspaceResponse(root=root, available=True, entries=entries)
