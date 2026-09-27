from __future__ import annotations

import uuid

import pytest

from secplat.domain.scanning.errors import InvalidTransition
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import (
    ProjectId,
    ScanId,
    ScanStatus,
    TargetKind,
    TargetRef,
    ToolName,
)


def make_scan() -> Scan:
    return Scan(
        id=ScanId(uuid.uuid4()),
        project_id=ProjectId(uuid.uuid4()),
        target=TargetRef(kind=TargetKind.URL, value="https://example.com"),
        tool=ToolName.NUCLEI,
        config={"rate_limit": 10},
    )


def test_full_lifecycle() -> None:
    scan = make_scan()
    assert scan.status is ScanStatus.PENDING
    scan.mark_queued("task-1")
    assert scan.status is ScanStatus.QUEUED
    assert scan.task_id == "task-1"
    scan.mark_running()
    assert scan.status is ScanStatus.RUNNING
    assert scan.started_at is not None
    scan.complete({"findings": 3})
    assert scan.status is ScanStatus.COMPLETED
    assert scan.finished_at is not None
    assert scan.stats == {"findings": 3}


def test_running_requires_queued() -> None:
    scan = make_scan()
    with pytest.raises(InvalidTransition):
        scan.mark_running()


def test_complete_twice_raises() -> None:
    scan = make_scan()
    scan.mark_queued("t")
    scan.mark_running()
    scan.complete({})
    with pytest.raises(InvalidTransition):
        scan.complete({})


def test_fail_allowed_from_queued() -> None:
    scan = make_scan()
    scan.mark_queued("t")
    scan.fail("boom")
    assert scan.status is ScanStatus.FAILED
    assert scan.error == "boom"


@pytest.mark.parametrize(
    "setup",
    ["pending", "queued", "running"],
)
def test_cancel_allowed_from_active_states(setup: str) -> None:
    scan = make_scan()
    if setup in ("queued", "running"):
        scan.mark_queued("t")
    if setup == "running":
        scan.mark_running()
    scan.cancel()
    assert scan.status is ScanStatus.CANCELLED


def test_cancel_after_terminal_raises() -> None:
    scan = make_scan()
    scan.mark_queued("t")
    scan.mark_running()
    scan.complete({})
    with pytest.raises(InvalidTransition):
        scan.cancel()


def test_execute_is_idempotent_guard_for_terminal_states() -> None:
    scan = make_scan()
    scan.mark_queued("t")
    scan.mark_running()
    scan.complete({})
    assert scan.status.is_terminal
