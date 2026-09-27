from __future__ import annotations


class DomainError(Exception):
    pass


class InvalidTransition(DomainError):
    def __init__(self, current: str, attempted: str) -> None:
        super().__init__(f"invalid status transition: {current} -> {attempted}")
        self.current = current
        self.attempted = attempted


class InvalidTargetValue(DomainError):
    pass


class UnknownTool(DomainError):
    def __init__(self, tool: str) -> None:
        super().__init__(f"unknown tool: {tool}")
        self.tool = tool


class ConfigNotAllowed(DomainError):
    pass


class MissingTargetInput(DomainError):
    def __init__(self) -> None:
        super().__init__("either target_id or target is required")


class ProjectNotFound(DomainError):
    def __init__(self, project_id: str) -> None:
        super().__init__(f"project not found: {project_id}")
        self.project_id = project_id


class TargetNotFound(DomainError):
    def __init__(self, target_id: str) -> None:
        super().__init__(f"target not found: {target_id}")
        self.target_id = target_id


class ScanNotFound(DomainError):
    def __init__(self, scan_id: str) -> None:
        super().__init__(f"scan not found: {scan_id}")
        self.scan_id = scan_id


class ProjectHasActiveScans(DomainError):
    def __init__(self, project_id: str) -> None:
        super().__init__(
            f"project has running or queued scans, cancel them first: {project_id}"
        )
        self.project_id = project_id
