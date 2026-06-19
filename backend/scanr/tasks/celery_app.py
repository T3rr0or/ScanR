from celery import Celery

from scanr.config import get_settings

settings = get_settings()

celery_app = Celery(
    "scanr",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["scanr.tasks.scan_tasks", "scanr.tasks.report_tasks", "scanr.tasks.scheduler_task", "scanr.tasks.agent_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    # With acks_late, a task killed by a lost worker is redelivered only when
    # this is set; otherwise the message is dropped and the scan never recovers.
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=3600,
    task_time_limit=7200,
    beat_schedule={
        "check-schedules-every-minute": {
            "task": "scanr.tasks.scheduler_task.check_schedules_task",
            "schedule": 60.0,
        },
        "reap-stale-scans-every-2-minutes": {
            "task": "scanr.reap_stale_scans",
            "schedule": 120.0,
        },
    },
)

celery_app.conf.include = [
    "scanr.tasks.scan_tasks",
    "scanr.tasks.report_tasks",
    "scanr.tasks.scheduler_task",
    "scanr.tasks.agent_tasks",
]
