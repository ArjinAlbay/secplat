from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from secplat.domain.scanning.errors import (
    ConfigNotAllowed,
    DomainError,
    InvalidTargetValue,
    InvalidTransition,
    ProjectHasActiveScans,
    ProjectNotFound,
    ScanNotFound,
    TargetNotFound,
    UnknownTool,
)
from secplat.infrastructure.config import get_settings
from secplat.presentation.routes import projects, scans, workspace

_NOT_FOUND_ERRORS = (ProjectNotFound, ScanNotFound, TargetNotFound)
_CONFLICT_ERRORS = (InvalidTransition, ProjectHasActiveScans)
_BAD_REQUEST_ERRORS = (
    ConfigNotAllowed,
    UnknownTool,
    InvalidTargetValue,
)


def create_app() -> FastAPI:
    application = FastAPI(title="SecPlat", version="0.1.0")
    settings = get_settings()
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(projects.router, prefix="/api/v1")
    application.include_router(scans.router, prefix="/api/v1")
    application.include_router(workspace.router, prefix="/api/v1")

    @application.exception_handler(DomainError)
    async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
        if isinstance(exc, _NOT_FOUND_ERRORS):
            status_code = 404
        elif isinstance(exc, _CONFLICT_ERRORS):
            status_code = 409
        elif isinstance(exc, _BAD_REQUEST_ERRORS):
            status_code = 400
        else:
            status_code = 400
        return JSONResponse(status_code=status_code, content={"detail": str(exc)})

    @application.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
