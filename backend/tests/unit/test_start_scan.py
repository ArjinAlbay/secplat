from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from secplat.application.scanning.commands import StartScan
from secplat.application.scanning.dto import ScanCreate
from secplat.domain.scanning.ports import TaskQueue
from secplat.domain.scanning.project import Project
from secplat.domain.scanning.value_objects import ProjectId, ScanId, ScanStatus, TargetRef
from secplat.infrastructure.persistence.orm import Base
from secplat.infrastructure.persistence.repositories import (
    SqlAlchemyProjectRepository,
    SqlAlchemyScanRepository,
)
from tests.conftest import FakeTaskQueue


class SnapshotQueue(FakeTaskQueue):
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        super().__init__()
        self._sessions = sessions
        self.status_at_publish: list[ScanStatus] = []

    def enqueue_scan(self, scan_id: ScanId, task_id: str) -> None:
        session = self._sessions()
        try:
            scan = SqlAlchemyScanRepository(session).get(scan_id)
            assert scan is not None
            self.status_at_publish.append(scan.status)
        finally:
            session.close()
        super().enqueue_scan(scan_id, task_id)


class FailingQueue(TaskQueue):
    def enqueue_scan(self, scan_id: ScanId, task_id: str) -> None:
        raise ConnectionError("broker down")

    def enqueue_recon_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        nuclei_severity: list[str] | None = None,
    ) -> None:
        raise ConnectionError("broker down")

    def enqueue_codebase_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        tools: list[str] | None = None,
    ) -> None:
        raise ConnectionError("broker down")

    def revoke(self, task_id: str) -> None:
        raise AssertionError("unreachable")


def _setup(tmp_path: Path) -> tuple[sessionmaker[Session], ProjectId]:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    session = sessions()
    try:
        project_id = ProjectId(uuid.uuid4())
        SqlAlchemyProjectRepository(session).save(Project(id=project_id, name="P"))
        return sessions, project_id
    finally:
        session.close()


def _request() -> ScanCreate:
    return ScanCreate(
        tool="nuclei",
        target={"kind": "url", "value": "https://example.com"},
    )


def test_scan_is_queued_before_publish(tmp_path: Path) -> None:
    sessions, project_id = _setup(tmp_path)
    queue = SnapshotQueue(sessions)
    session = sessions()
    try:
        handler = StartScan(
            scans=SqlAlchemyScanRepository(session),
            projects=SqlAlchemyProjectRepository(session),
            queue=queue,
        )
        scan = handler(project_id, _request())
    finally:
        session.close()
    assert scan.status is ScanStatus.QUEUED
    assert uuid.UUID(scan.task_id or "")
    assert queue.status_at_publish == [ScanStatus.QUEUED]
    assert queue.task_ids == [scan.task_id]


def test_publish_failure_fails_scan(tmp_path: Path) -> None:
    sessions, project_id = _setup(tmp_path)
    session = sessions()
    try:
        handler = StartScan(
            scans=SqlAlchemyScanRepository(session),
            projects=SqlAlchemyProjectRepository(session),
            queue=FailingQueue(),
        )
        with pytest.raises(ConnectionError):
            handler(project_id, _request())
    finally:
        session.close()
    check = sessions()
    try:
        scans = SqlAlchemyScanRepository(check).list_recent(10)
    finally:
        check.close()
    assert len(scans) == 1
    assert scans[0].status is ScanStatus.FAILED
    assert scans[0].error is not None and "queue publish failed" in scans[0].error
