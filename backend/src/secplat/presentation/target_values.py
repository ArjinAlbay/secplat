from __future__ import annotations

import os

from secplat.domain.scanning.value_objects import TargetKind


def resolve_target_value(kind: TargetKind, value: str, workspace_root: str) -> str:
    resolved = value.strip()
    if kind is TargetKind.PATH and resolved:
        resolved = os.path.expanduser(resolved).replace("\x00", "")
        if not os.path.isabs(resolved):
            return os.path.join(workspace_root, resolved)
    return resolved
