from __future__ import annotations

import logging
import signal
import subprocess
import uuid
from datetime import UTC, datetime, timedelta

from celery.signals import worker_process_init

from secplat.application.scanning.commands import ExecuteScan
from secplat.domain.scanning.value_objects import ScanId, ScanStatus
from secplat.infrastructure.config import get_settings
from secplat.infrastructure.persistence.repositories import SqlAlchemyScanRepository
from secplat.infrastructure.persistence.session import session_factory
from secplat.infrastructure.queue.app import app
from secplat.infrastructure.tools import get_adapter
from secplat.infrastructure.tools.subprocess_runner import SubprocessToolRunner

logger = logging.getLogger(__name__)


@worker_process_init.connect
def _install_sigterm_handler(**_kwargs: object) -> None:
    def _handler(signum: int, frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _handler)


@app.task(name="secplat.scan.run")
def run_scan(scan_id: str) -> None:
    settings = get_settings()
    session = session_factory()()
    try:
        try:
            handler = ExecuteScan(
                scans=SqlAlchemyScanRepository(session),
                adapters=get_adapter,
                runner=SubprocessToolRunner(max_stderr_bytes=settings.stderr_tail_bytes),
                timeout_s=settings.scan_timeout_seconds,
            )
            handler(ScanId(uuid.UUID(scan_id)))
        except Exception as exc:
            logger.exception("scan execution failed: %s", scan_id)
            repo = SqlAlchemyScanRepository(session)
            scan = repo.get(ScanId(uuid.UUID(scan_id)))
            if scan and not scan.status.is_terminal:
                scan.fail(f"worker error: {type(exc).__name__}: {exc}"[:4000])
                repo.save(scan)
            raise
    finally:
        session.close()


@app.task(name="secplat.scan.reconcile")
def reconcile_stale_scans() -> None:
    settings = get_settings()
    running_cutoff = datetime.now(UTC) - timedelta(seconds=settings.scan_timeout_seconds + 300)
    pending_cutoff = datetime.now(UTC) - timedelta(minutes=5)
    session = session_factory()()
    try:
        repo = SqlAlchemyScanRepository(session)
        for scan in repo.list_by_status(ScanStatus.RUNNING, running_cutoff):
            scan.fail("worker lost or stalled (watchdog)")
            repo.save(scan)
            logger.warning("scan %s marked failed by watchdog", scan.id)
        for scan in repo.list_by_status(ScanStatus.PENDING, pending_cutoff):
            if not scan.task_id:
                task_id = str(uuid.uuid4())
                scan.mark_queued(task_id)
                repo.save(scan)
                try:
                    app.send_task(
                        "secplat.scan.run",
                        args=[str(scan.id)],
                        queue="scans",
                        task_id=task_id,
                    )
                except Exception as exc:
                    scan.fail(f"queue publish failed: {type(exc).__name__}: {exc}"[:4000])
                    repo.save(scan)
                    logger.exception("scan %s publish failed", scan.id)
                    continue
                logger.info("scan %s re-queued by watchdog", scan.id)
    finally:
        session.close()


@app.task(name="secplat.recon.pipeline")
def run_recon_pipeline(
    project_id: str,
    target_kind: str,
    target_value: str,
    pipeline_id: str,
    nuclei_severity: list[str] | None = None,
) -> None:
    settings = get_settings()
    session = session_factory()()
    try:
        from secplat.domain.scanning.scan import Scan
        from secplat.domain.scanning.value_objects import ProjectId, TargetKind, TargetRef, ToolName

        p_id = ProjectId(uuid.UUID(project_id))
        target_ref = TargetRef(kind=TargetKind(target_kind), value=target_value)
        repo = SqlAlchemyScanRepository(session)
        runner = SubprocessToolRunner(max_stderr_bytes=settings.stderr_tail_bytes)

        # ── Step 1: Subfinder (Subdomain Recon) ──────────────────────────────
        subfinder_scan = Scan(
            id=ScanId(uuid.uuid4()),
            project_id=p_id,
            target=target_ref,
            tool=ToolName.SUBFINDER,
            config={"rate_limit": 100, "timeout": 30},
        )
        repo.save(subfinder_scan)
        subfinder_scan.mark_queued(f"{pipeline_id}-subfinder")
        repo.save(subfinder_scan)

        exec_subfinder = ExecuteScan(
            scans=repo,
            adapters=get_adapter,
            runner=runner,
            timeout_s=settings.scan_timeout_seconds,
        )
        subfinder_scan = exec_subfinder(subfinder_scan.id)
        if subfinder_scan.status is not ScanStatus.COMPLETED:
            logger.warning("Subfinder step failed in pipeline %s", pipeline_id)
            return

        # Collect discovered subdomains
        findings = repo.list_findings(subfinder_scan.id, severity=None, limit=1000, offset=0)
        discovered_hosts = list({f.host for f in findings if f.host})
        if not discovered_hosts and target_ref.kind is TargetKind.DOMAIN:
            discovered_hosts = [target_ref.value]

        if not discovered_hosts:
            logger.info("No hosts discovered in subfinder step of pipeline %s", pipeline_id)
            return

        # ── Step 2: HTTPx (Active Probe for Discovered Hosts) ─────────────────
        # For each host, probe HTTP/HTTPS
        live_urls: list[str] = []
        for host in discovered_hosts:
            httpx_target = TargetRef(kind=TargetKind.DOMAIN, value=host)
            httpx_scan = Scan(
                id=ScanId(uuid.uuid4()),
                project_id=p_id,
                target=httpx_target,
                tool=ToolName.HTTPX,
                config={"tech_detect": True, "follow_redirects": True},
            )
            repo.save(httpx_scan)
            httpx_scan.mark_queued(f"{pipeline_id}-httpx-{host[:30]}")
            repo.save(httpx_scan)

            exec_httpx = ExecuteScan(
                scans=repo,
                adapters=get_adapter,
                runner=runner,
                timeout_s=300,
            )
            httpx_scan = exec_httpx(httpx_scan.id)
            if httpx_scan.status is ScanStatus.COMPLETED:
                httpx_findings = repo.list_findings(
                    httpx_scan.id, severity=None, limit=100, offset=0
                )
                for hf in httpx_findings:
                    if hf.matched_at and hf.matched_at.startswith(("http://", "https://")):
                        live_urls.append(hf.matched_at)

        unique_live_urls = list(dict.fromkeys(live_urls))
        if not unique_live_urls:
            logger.info("No live HTTP services found in pipeline %s", pipeline_id)
            return

        # ── Step 3: Nuclei (Targeted DAST on Live URLs) ────────────────────────
        for live_url in unique_live_urls:
            nuclei_target = TargetRef(kind=TargetKind.URL, value=live_url)
            nuclei_scan = Scan(
                id=ScanId(uuid.uuid4()),
                project_id=p_id,
                target=nuclei_target,
                tool=ToolName.NUCLEI,
                config={
                    "severity": nuclei_severity or ["critical", "high", "medium"],
                    "rate_limit": 150,
                    "concurrency": 25,
                    "timeout": 10,
                },
            )
            repo.save(nuclei_scan)
            nuclei_scan.mark_queued(f"{pipeline_id}-nuclei-{live_url[:30]}")
            repo.save(nuclei_scan)

            exec_nuclei = ExecuteScan(
                scans=repo,
                adapters=get_adapter,
                runner=runner,
                timeout_s=settings.scan_timeout_seconds,
            )
            exec_nuclei(nuclei_scan.id)

    except Exception as exc:
        logger.exception("recon pipeline %s failed: %s", pipeline_id, exc)
        raise
    finally:
        session.close()


@app.task(name="secplat.codebase.pipeline")
def run_codebase_pipeline(
    project_id: str,
    target_kind: str,
    target_value: str,
    pipeline_id: str,
    tools: list[str] | None = None,
) -> None:
    settings = get_settings()
    session = session_factory()()
    try:
        from secplat.domain.scanning.scan import Scan
        from secplat.domain.scanning.value_objects import ProjectId, TargetKind, TargetRef, ToolName

        p_id = ProjectId(uuid.UUID(project_id))
        target_ref = TargetRef(kind=TargetKind(target_kind), value=target_value)
        repo = SqlAlchemyScanRepository(session)
        runner = SubprocessToolRunner(max_stderr_bytes=settings.stderr_tail_bytes)

        selected_tools = tools or ["gitleaks", "semgrep", "trivy", "checkov"]
        default_configs: dict[str, dict[str, object]] = {
            "gitleaks": {"no_git": True, "redact": True},
            "semgrep": {"config": "auto"},
            "trivy": {"scanners": ["vuln", "secret", "misconfig"]},
            "checkov": {"framework": "all"},
        }

        for tool_str in selected_tools:
            try:
                tool_enum = ToolName(tool_str)
            except ValueError:
                continue

            config = default_configs.get(tool_str, {})
            scan = Scan(
                id=ScanId(uuid.uuid4()),
                project_id=p_id,
                target=target_ref,
                tool=tool_enum,
                config=config,
            )
            repo.save(scan)
            scan.mark_queued(f"{pipeline_id}-{tool_str}")
            repo.save(scan)

            executor = ExecuteScan(
                scans=repo,
                adapters=get_adapter,
                runner=runner,
                timeout_s=settings.scan_timeout_seconds,
            )
            executor(scan.id)

    except Exception as exc:
        logger.exception("codebase pipeline %s failed: %s", pipeline_id, exc)
        raise
    finally:
        session.close()


@app.task(name="secplat.scan.update_templates")
def update_templates() -> None:
    settings = get_settings()
    result = subprocess.run(
        [settings.nuclei_bin, "-ut", "-ud", settings.nuclei_template_dir],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if result.returncode != 0:
        logger.error("nuclei template update failed: %s", result.stderr[-2000:])
    else:
        logger.info("nuclei templates updated")
