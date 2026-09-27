from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from secplat.domain.scanning.ports import TaskQueue
from secplat.domain.scanning.value_objects import ProjectId, ScanId, TargetRef
from secplat.infrastructure.persistence.orm import Base
from secplat.presentation.deps import get_db, get_task_queue
from secplat.presentation.main import app

type SessionFactory = sessionmaker[Session]


class FakeTaskQueue(TaskQueue):
    def __init__(self) -> None:
        self.enqueued: list[str] = []
        self.task_ids: list[str] = []
        self.revoked: list[str] = []

    def enqueue_scan(self, scan_id: ScanId, task_id: str) -> None:
        self.enqueued.append(str(scan_id))
        self.task_ids.append(task_id)

    def enqueue_recon_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        nuclei_severity: list[str] | None = None,
    ) -> None:
        self.enqueued.append(f"pipeline:{pipeline_id}")
        self.task_ids.append(pipeline_id)

    def enqueue_codebase_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        tools: list[str] | None = None,
    ) -> None:
        self.enqueued.append(f"codebase:{pipeline_id}")
        self.task_ids.append(pipeline_id)

    def revoke(self, task_id: str) -> None:
        self.revoked.append(task_id)


@pytest.fixture()
def sessions(tmp_path: Path) -> SessionFactory:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture()
def fake_queue() -> FakeTaskQueue:
    return FakeTaskQueue()


@pytest.fixture()
def client(sessions: SessionFactory, fake_queue: FakeTaskQueue) -> Iterator[TestClient]:
    def override_db() -> Iterator[Session]:
        session = sessions()
        try:
            yield session
            session.commit()
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_task_queue] = lambda: fake_queue
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
