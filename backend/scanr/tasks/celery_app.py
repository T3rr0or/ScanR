from celery import Celery

from scanr.config import get_settings

settings = get_settings()

celery_app = Celery(
    "scanr",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["scanr.tasks.scan_tasks", "scanr.tasks.report_tasks", "scanr.tasks.scheduler_task", "scanr.tasks.agent_tasks", "scanr.tasks.retest_tasks"],
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
    # Security boundary as well as scheduling: scanner, AI, and control tasks run
    # in separately credentialed containers in the bundled deployment.  Without
    # explicit routes, any worker could consume any task and would need the union
    # of every secret/capability.
    task_default_queue="control",
    task_routes={
        "scanr.run_scan": {"queue": "scan"},
        "scanr.retest_finding": {"queue": "scan"},
        "scanr.run_ai_agent": {"queue": "ai"},
        "scanr.generate_report": {"queue": "control"},
        "scanr.reap_stale_scans": {"queue": "control"},
        "scanr.reap_stale_agent_runs": {"queue": "control"},
        "scanr.tasks.scheduler_task.check_schedules_task": {"queue": "control"},
    },
    task_soft_time_limit=3600,
    task_time_limit=7200,
    beat_schedule={
        "check-schedules-every-minute": {
            "task": "scanr.tasks.scheduler_task.check_schedules_task",
            "schedule": 60.0,
            "options": {"queue": "control"},
        },
        "reap-stale-scans-every-2-minutes": {
            "task": "scanr.reap_stale_scans",
            "schedule": 120.0,
            "options": {"queue": "control"},
        },
        "reap-stale-agent-runs-every-2-minutes": {
            "task": "scanr.reap_stale_agent_runs",
            "schedule": 120.0,
            "options": {"queue": "control"},
        },
    },
)

celery_app.conf.include = [
    "scanr.tasks.scan_tasks",
    "scanr.tasks.retest_tasks",
    "scanr.tasks.report_tasks",
    "scanr.tasks.scheduler_task",
    "scanr.tasks.agent_tasks",
]
