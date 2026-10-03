"""The engine's setup runs against a real async session without lazy loads.

Lazy-loading a relationship (e.g. scan.targets) inside the async engine raises
MissingGreenlet and fails every scan; unit tests that build contexts by hand
cannot see that. This drives ScanEngine.run up to the first network traffic.
"""
import pytest


class _Stop(Exception):
    pass


@pytest.mark.asyncio
async def test_engine_reaches_discovery_with_window_and_source_address(client, auth_headers, monkeypatch):
    import json

    import scanr.db.session as session_module
    from scanr.core.context import ScanContext
    from scanr.core.engine import ScanEngine

    window = {"timezone": "UTC", "days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "24:00"}
    scan_id = (await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "engine-setup", "targets": ["198.51.100.70"], "profile": "quick",
        "profile_json": json.dumps({"testing_window": window})})).json()["id"]
    seen = {}

    async def stop_before_traffic(self, poll_seconds=30.0):
        seen["window"] = self.testing_window
        seen["source_ip"] = self.source_ip
        raise _Stop

    monkeypatch.setattr(ScanContext, "hold_for_testing_window", stop_before_traffic)
    async with session_module.AsyncSessionLocal() as db:
        with pytest.raises(_Stop):
            await ScanEngine(scan_id=scan_id, db=db).run()
    assert seen["window"] is not None and seen["window"].days == [0, 1, 2, 3, 4, 5, 6]
    assert seen["source_ip"]
