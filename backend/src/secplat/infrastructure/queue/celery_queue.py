from __future__ import annotations

from secplat.domain.scanning.ports import TaskQueue
from secplat.domain.scanning.value_objects import ProjectId, ScanId, TargetRef
from secplat.infrastructure.queue.app import app


class CeleryTaskQueue(TaskQueue):
    def enqueue_scan(self, scan_id: ScanId, task_id: str) -> None:
        app.send_task(
            "secplat.scan.run", args=[str(scan_id)], queue="scans", task_id=task_id
        )

    def enqueue_recon_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        nuclei_severity: list[str] | None = None,
    ) -> None:
        app.send_task(
            "secplat.recon.pipeline",
            kwargs={
                "project_id": str(project_id),
                "target_kind": target_ref.kind.value,
                "target_value": target_ref.value,
                "pipeline_id": pipeline_id,
                "nuclei_severity": nuclei_severity or ["critical", "high", "medium"],
            },
            queue="scans",
            task_id=pipeline_id,
        )

    def enqueue_codebase_pipeline(
        self,
        project_id: ProjectId,
        target_ref: TargetRef,
        pipeline_id: str,
        tools: list[str] | None = None,
    ) -> None:
        app.send_task(
            "secplat.codebase.pipeline",
            kwargs={
                "project_id": str(project_id),
                "target_kind": target_ref.kind.value,
                "target_value": target_ref.value,
                "pipeline_id": pipeline_id,
                "tools": tools or ["gitleaks", "semgrep", "trivy", "checkov"],
            },
            queue="scans",
            task_id=pipeline_id,
        )

    def revoke(self, task_id: str) -> None:
        app.control.revoke(task_id, terminate=True, signal="SIGTERM")

