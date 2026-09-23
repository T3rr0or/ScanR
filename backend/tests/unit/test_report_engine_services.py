"""Reports must load service rows before synchronous rendering begins."""
import json

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from scanr.models import Host, Port, Report, Scan, Service, User
from scanr.models.base import Base
from scanr.reporting.report_engine import ReportEngine
from scanr.config import get_settings


@pytest.mark.parametrize('format', ['json', 'html'])
@pytest.mark.parametrize('with_service', [True, False])
async def test_report_renders_ports_from_a_fresh_session(tmp_path, monkeypatch, format, with_service):
    monkeypatch.setattr(get_settings(), 'reports_dir', tmp_path / 'reports')
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_factory() as db:
            user = User(id='u1', email='report@example.test', hashed_password='unused')
            scan = Scan(id='s1', user_id=user.id, name='Service report', status='completed')
            host = Host(id='h1', scan=scan, ip='192.0.2.1', status='up')
            port = Port(host=host, number=8080, protocol='tcp', state='open')
            if with_service:
                port.service = Service(name='http', product='FixtureServer', version='1.0')
            db.add_all([user, scan, host, port])
            await db.commit()
        # A new session reproduces the worker: service is not already cached.
        async with session_factory() as db:
            path = await ReportEngine(db).generate(Report(id='r1', scan_id='s1', format=format))
        if format == 'json':
            service = json.loads(path.read_text())['hosts'][0]['ports'][0]['service']
            assert service == ({'name': 'http', 'product': 'FixtureServer', 'version': '1.0'} if with_service else None)
        else:
            assert '192.0.2.1' in path.read_text()
    finally:
        await engine.dispose()
