from __future__ import annotations

import json
import time
import uuid
from typing import Any

from secplat.application.scanning.dto import (
    CodebasePipelineRequest,
    ReconPipelineRequest,
    ScanCreate,
)
from secplat.domain.scanning.errors import (
    MissingTargetInput,
    ProjectNotFound,
    ScanNotFound,
    TargetNotFound,
)
from secplat.domain.scanning.ports import (
    ProjectRepository,
    ScanRepository,
    TaskQueue,
    ToolAdapterFactory,
    ToolRunner,
)
from secplat.domain.scanning.project import Target
from secplat.domain.scanning.records import FindingRecord
from secplat.domain.scanning.scan import Scan
from secplat.domain.scanning.value_objects import (
    ProjectId,
    ScanId,
    ScanStatus,
    TargetId,
    TargetKind,
    TargetRef,
    ToolName,
)

BATCH_LINES = 50
BATCH_SECONDS = 2.0
MAX_PENDING_JSON_BYTES = 64 * 1024 * 1024


class _JsonDocuments:
    __slots__ = ("_chunks", "_depth", "_escaped", "_in_str", "_started")

    def __init__(self) -> None:
        self._chunks: list[str] = []
        self._depth = 0
        self._escaped = False
        self._in_str = False
        self._started = False

    def feed(self, line: str) -> list[Any]:
        if not self._started:
            try:
                return [json.loads(line)]
            except json.JSONDecodeError:
                pass
        docs: list[Any] = []
        pos = 0
        while pos < len(line):
            if not self._started:
                opener = _leading_opener(line, pos)
                if opener is None:
                    return docs
                pos = opener
                self._started = True
            end = self._scan(line, pos)
            if end is None:
                self._chunks.append(line[pos:])
                self._check_overflow()
                return docs
            doc = "".join((*self._chunks, line[pos:end]))
            self._reset()
            try:
                docs.append(json.loads(doc))
            except json.JSONDecodeError:
                pass
            pos = end
        return docs

    def _scan(self, line: str, pos: int) -> int | None:
        depth = self._depth
        in_str = self._in_str
        escaped = self._escaped
        for i in range(pos, len(line)):
            ch = line[i]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
                if depth <= 0:
                    self._depth, self._in_str, self._escaped = depth, in_str, escaped
                    return i + 1
        self._depth, self._in_str, self._escaped = depth, in_str, escaped
        return None

    def _reset(self) -> None:
        self._chunks = []
        self._depth = 0
        self._escaped = False
        self._in_str = False
        self._started = False

    def _check_overflow(self) -> None:
        if sum(map(len, self._chunks)) > MAX_PENDING_JSON_BYTES:
            self._reset()


def _leading_opener(line: str, pos: int) -> int | None:
    for i in range(pos, len(line)):
        ch = line[i]
        if ch in " \t":
            continue
        if ch in "{[":
            return i
        return None
    return None


class StartScan:
    def __init__(
        self,
        scans: ScanRepository,
        projects: ProjectRepository,
        queue: TaskQueue,
    ) -> None:
        self._scans = scans
        self._projects = projects
        self._queue = queue

    def __call__(self, project_id: ProjectId, request: ScanCreate) -> Scan:
        if self._projects.get(project_id) is None:
            raise ProjectNotFound(str(project_id))

        if request.target_id is not None:
            target = self._projects.get_target(project_id, TargetId(request.target_id))
            if target is None:
                raise TargetNotFound(str(request.target_id))
            ref, target_id = target.ref, target.id
        elif request.target is not None:
            ref = TargetRef(kind=TargetKind(request.target.kind), value=request.target.value)
            new_target = Target(id=TargetId(uuid.uuid4()), project_id=project_id, ref=ref)
            target_id = self._projects.add_target(new_target).id
        else:
            raise MissingTargetInput

        scan = Scan(
            id=ScanId(uuid.uuid4()),
            project_id=project_id,
            target_id=target_id,
            target=ref,
            tool=ToolName(request.tool),
            config=request.config.model_dump(),
        )
        self._scans.save(scan)
        task_id = str(uuid.uuid4())
        scan.mark_queued(task_id)
        self._scans.save(scan)
        try:
            self._queue.enqueue_scan(scan.id, task_id)
        except Exception as exc:
            scan.fail(f"queue publish failed: {type(exc).__name__}: {exc}"[:4000])
            self._scans.save(scan)
            raise
        return scan


class StartReconPipeline:
    def __init__(
        self,
        projects: ProjectRepository,
        queue: TaskQueue,
    ) -> None:
        self._projects = projects
        self._queue = queue

    def __call__(
        self, project_id: ProjectId, request: ReconPipelineRequest
    ) -> tuple[str, TargetRef]:
        if self._projects.get(project_id) is None:
            raise ProjectNotFound(str(project_id))

        if request.target_id is not None:
            target = self._projects.get_target(project_id, TargetId(request.target_id))
            if target is None:
                raise TargetNotFound(str(request.target_id))
            ref = target.ref
        elif request.target is not None:
            ref = TargetRef(kind=TargetKind(request.target.kind), value=request.target.value)
            new_target = Target(id=TargetId(uuid.uuid4()), project_id=project_id, ref=ref)
            self._projects.add_target(new_target)
        else:
            raise MissingTargetInput

        pipeline_id = str(uuid.uuid4())
        self._queue.enqueue_recon_pipeline(
            project_id=project_id,
            target_ref=ref,
            pipeline_id=pipeline_id,
            nuclei_severity=list(request.nuclei_severity) if request.nuclei_severity else None,
        )
        return pipeline_id, ref


class StartCodebasePipeline:
    def __init__(
        self,
        projects: ProjectRepository,
        queue: TaskQueue,
    ) -> None:
        self._projects = projects
        self._queue = queue

    def __call__(
        self, project_id: ProjectId, request: CodebasePipelineRequest
    ) -> tuple[str, TargetRef]:
        if self._projects.get(project_id) is None:
            raise ProjectNotFound(str(project_id))

        if request.target_id is not None:
            target = self._projects.get_target(project_id, TargetId(request.target_id))
            if target is None:
                raise TargetNotFound(str(request.target_id))
            ref = target.ref
        elif request.target is not None:
            ref = TargetRef(kind=TargetKind(request.target.kind), value=request.target.value)
            new_target = Target(id=TargetId(uuid.uuid4()), project_id=project_id, ref=ref)
            self._projects.add_target(new_target)
        else:
            raise MissingTargetInput

        pipeline_id = str(uuid.uuid4())
        self._queue.enqueue_codebase_pipeline(
            project_id=project_id,
            target_ref=ref,
            pipeline_id=pipeline_id,
            tools=list(request.tools) if request.tools else None,
        )
        return pipeline_id, ref



class ExecuteScan:
    def __init__(
        self,
        scans: ScanRepository,
        adapters: ToolAdapterFactory,
        runner: ToolRunner,
        timeout_s: int,
    ) -> None:
        self._scans = scans
        self._adapters = adapters
        self._runner = runner
        self._timeout_s = timeout_s

    def __call__(self, scan_id: ScanId) -> Scan:
        scan = self._scans.get(scan_id)
        if scan is None:
            raise ScanNotFound(str(scan_id))
        if scan.status is not ScanStatus.QUEUED:
            return scan
        scan.mark_running()
        self._scans.save(scan)
        try:
            self._execute(scan)
        except Exception as exc:
            scan.fail(f"{type(exc).__name__}: {exc}"[:4000])
            self._scans.save(scan)
        return scan

    def _execute(self, scan: Scan) -> None:
        adapter = self._adapters(scan.tool)
        argv = adapter.build_args(scan.target, scan.config)

        raws: list[dict[str, Any]] = []
        findings: list[FindingRecord] = []
        seen: set[str] = set()
        counts: dict[str, int] = {}
        counters = {"dirty": False}
        last_flush = time.monotonic()
        documents = _JsonDocuments()

        def flush() -> None:
            if raws:
                self._scans.add_results(scan.id, scan.tool, list(raws))
            if findings:
                self._scans.upsert_findings(scan.id, scan.project_id, list(findings))
            if counters["dirty"]:
                self._scans.update_stats(scan.id, _stats(counts))
            raws.clear()
            findings.clear()
            counters["dirty"] = False

        def on_line(line: str) -> None:
            nonlocal last_flush
            for data in documents.feed(line):
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    records = adapter.parse_report(item)
                    raws.append(item)
                    for record in records:
                        if record.fingerprint not in seen:
                            seen.add(record.fingerprint)
                            findings.append(record)
                            counts["findings"] = counts.get("findings", 0) + 1
                            counts[record.severity.value] = counts.get(record.severity.value, 0) + 1
                            counters["dirty"] = True
                if len(raws) >= BATCH_LINES or time.monotonic() - last_flush >= BATCH_SECONDS:
                    flush()
                    last_flush = time.monotonic()

        outcome = self._runner.run(argv, self._timeout_s, on_line)
        flush()

        if outcome.timed_out:
            tail = outcome.stderr_tail[-500:]
            scan.fail(f"tool timed out after {self._timeout_s}s; stderr: {tail}")
        elif outcome.ok:
            scan.complete(_stats(counts))
        else:
            tail = outcome.stderr_tail[-2000:]
            scan.fail(f"tool exited with code {outcome.returncode}; stderr: {tail}")
        self._scans.save(scan)


def _stats(counts: dict[str, int]) -> dict[str, Any]:
    return {
        "findings": counts.get("findings", 0),
        "by_severity": {k: v for k, v in counts.items() if k != "findings"},
    }


class CancelScan:
    def __init__(self, scans: ScanRepository, queue: TaskQueue) -> None:
        self._scans = scans
        self._queue = queue

    def __call__(self, scan_id: ScanId) -> Scan:
        scan = self._scans.get(scan_id)
        if scan is None:
            raise ScanNotFound(str(scan_id))
        if scan.status.is_terminal:
            return scan
        if scan.task_id:
            self._queue.revoke(scan.task_id)
        scan.cancel()
        self._scans.save(scan)
        return scan


class DeleteScan:
    def __init__(self, scans: ScanRepository, queue: TaskQueue) -> None:
        self._scans = scans
        self._queue = queue

    def __call__(self, scan_id: ScanId) -> None:
        scan = self._scans.get(scan_id)
        if scan is None:
            raise ScanNotFound(str(scan_id))
        if not scan.status.is_terminal and scan.task_id:
            self._queue.revoke(scan.task_id)
        self._scans.delete(scan_id)
