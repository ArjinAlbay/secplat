from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from secplat.infrastructure.config import get_settings


def create_celery_app() -> Celery:
    settings = get_settings()
    celery_app = Celery(
        "secplat",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=["secplat.infrastructure.queue.tasks"],
    )
    celery_app.conf.update(
        task_routes={"secplat.scan.run": {"queue": "scans"}},
        beat_schedule={
            "reconcile-stale-scans": {
                "task": "secplat.scan.reconcile",
                "schedule": 60.0,
                "options": {"queue": "scans"},
            },
            "nuclei-template-update": {
                "task": "secplat.scan.update_templates",
                "schedule": crontab(hour=3, minute=0, day_of_week=0),
                "options": {"queue": "scans"},
            },
        },
        timezone="UTC",
        enable_utc=True,
        broker_connection_retry_on_startup=True,
        task_soft_time_limit=settings.scan_timeout_seconds + 60,
        task_time_limit=settings.scan_timeout_seconds + 300,
    )
    return celery_app


app = create_celery_app()
