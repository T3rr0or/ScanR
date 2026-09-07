from scanr.tasks.celery_app import celery_app


def test_security_sensitive_tasks_are_routed_to_separate_workers():
    routes = celery_app.conf.task_routes
    assert routes["scanr.run_scan"]["queue"] == "scan"
    assert routes["scanr.retest_finding"]["queue"] == "scan"
    assert routes["scanr.run_ai_agent"]["queue"] == "ai"
    assert routes["scanr.generate_report"]["queue"] == "control"
    assert routes["scanr.tasks.scheduler_task.check_schedules_task"]["queue"] == "control"


def test_beat_jobs_are_explicitly_control_queued():
    for entry in celery_app.conf.beat_schedule.values():
        assert entry["options"]["queue"] == "control"


def test_every_routed_task_module_is_loaded_by_workers():
    assert "scanr.tasks.scan_tasks" in celery_app.conf.include
    assert "scanr.tasks.retest_tasks" in celery_app.conf.include
    assert "scanr.tasks.agent_tasks" in celery_app.conf.include
    assert "scanr.tasks.report_tasks" in celery_app.conf.include
    assert "scanr.tasks.scheduler_task" in celery_app.conf.include
