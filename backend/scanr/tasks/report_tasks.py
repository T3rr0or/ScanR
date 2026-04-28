from __future__ import annotations

import asyncio
import logging

from .celery_app import celery_app

logger = logging.getLogger(__name__)


def _make_session():
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool
    from scanr.config import get_settings

    settings = get_settings()
    engine = create_async_engine(
        settings.database_url,
        poolclass=NullPool,
        connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
    )
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)


@celery_app.task(bind=True, name="scanr.generate_report")
def generate_report_task(self, report_id: str) -> dict:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_generate_async(report_id))
    finally:
        loop.close()


async def _generate_async(report_id: str) -> dict:
    from scanr.models import Report
    from scanr.reporting.report_engine import ReportEngine
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool
    from scanr.config import get_settings

    settings = get_settings()
    db_engine = create_async_engine(settings.database_url, poolclass=NullPool,
        connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {})
    SessionLocal = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)
    try:
        async with SessionLocal() as db:
            result = await db.execute(select(Report).where(Report.id == report_id))
            report = result.scalar_one_or_none()
            if not report:
                return {"error": "report not found"}

            try:
                engine = ReportEngine(db=db)
                file_path = await engine.generate(report)
                report.file_path = str(file_path)
                report.status = "completed"
            except Exception as exc:
                logger.exception("Report %s failed: %s", report_id, exc)
                report.status = "failed"
                report.error_message = str(exc)

            await db.commit()
    finally:
        await db_engine.dispose()
    return {"report_id": report_id, "status": report.status}
