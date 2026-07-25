import pytest
from fastapi import HTTPException

from scanr.sandbox import runner_app


def test_token_fail_closed_when_unset(monkeypatch):
    # No token configured -> reject everything (fail-closed)
    monkeypatch.setattr(runner_app, "_TOKEN", "")
    with pytest.raises(HTTPException):
        runner_app._check_token("anything")


def test_token_must_match(monkeypatch):
    monkeypatch.setattr(runner_app, "_TOKEN", "secret")
    with pytest.raises(HTTPException):
        runner_app._check_token("wrong")
    with pytest.raises(HTTPException):
        runner_app._check_token(None)
    runner_app._check_token("secret")  # correct token -> no raise


def test_create_args_are_hardened(monkeypatch):
    monkeypatch.setattr(runner_app, "_PROXY", "http://sandbox-proxy:8888")
    args = runner_app._create_args("scanr-sbx-test", ["192.0.2.0/24"])

    # detached, non-root, locked-down
    assert "-d" in args
    assert args[args.index("--user") + 1] == "1000:1000"
    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in args
    assert args[args.index("--network") + 1] == runner_app._NETWORK
    assert "--pids-limit" in args
    # writable HOME so non-root pip/install works despite read-only rootfs
    assert any(a.startswith(f"HOME={runner_app._HOME}") for a in args)
    # keep-alive entrypoint so we can exec repeatedly
    assert args[-3:] == [runner_app._IMAGE, "sleep", "infinity"]
    # install proxy is injected
    assert any("HTTP_PROXY=http://sandbox-proxy:8888" in a for a in args)


def test_exec_args_run_command_with_timeout():
    args = runner_app._exec_args("scanr-sbx-test", "id", 30)
    assert args[:3] == ["docker", "exec", "-u"]
    assert "scanr-sbx-test" in args
    # command runs via a shell under a container-side timeout
    assert args[-3:] == ["/bin/sh", "-lc", "id"]
    assert "timeout" in args
    assert "30" in args


def test_token_comparison_is_constant_time(monkeypatch):
    """Guards against recovering the token a byte at a time via response timing."""
    import inspect
    import secrets as _secrets

    src = inspect.getsource(runner_app._check_token)
    assert "compare_digest" in src, "token comparison must use secrets.compare_digest"

    calls: list[tuple[str, str]] = []
    real = _secrets.compare_digest
    monkeypatch.setattr(
        runner_app.secrets, "compare_digest",
        lambda a, b: calls.append((a, b)) or real(a, b),
    )
    monkeypatch.setattr(runner_app, "_TOKEN", "secret")
    runner_app._check_token("secret")
    assert calls, "compare_digest was not exercised"


def test_empty_token_header_rejected(monkeypatch):
    monkeypatch.setattr(runner_app, "_TOKEN", "secret")
    with pytest.raises(HTTPException):
        runner_app._check_token("")


@pytest.mark.parametrize("run_id,ok", [
    ("abc123", True),
    ("run_1.2-3", True),
    ("once-deadbeef", True),
    ("", False),
    ("-flag", False),          # would look like a docker CLI flag
    ("../etc", False),
    ("a b", False),
    ("a" * 65, False),
    ("naïve", False),
])
def test_run_id_pattern(run_id, ok):
    assert bool(runner_app._RUN_ID_RE.match(run_id)) is ok


@pytest.mark.asyncio
async def test_session_cap_enforced(monkeypatch):
    """Sessions are only freed by /session/stop or the reaper, so the count needs
    a ceiling or a caller could exhaust the host."""
    monkeypatch.setattr(runner_app, "_MAX_SESSIONS", 2)
    monkeypatch.setattr(runner_app, "_SESSIONS", {})

    async def fake_run_docker(args, timeout):
        return 0, "", "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)

    await runner_app._ensure_session("run1", [])
    await runner_app._ensure_session("run2", [])
    assert len(runner_app._SESSIONS) == 2

    with pytest.raises(HTTPException) as exc:
        await runner_app._ensure_session("run3", [])
    assert exc.value.status_code == 429

    # An existing session is still served once at the cap.
    assert await runner_app._ensure_session("run1", [])


@pytest.mark.asyncio
async def test_health_leaks_nothing(monkeypatch):
    """Unauthenticated probe must not report image or live session count."""
    monkeypatch.setattr(runner_app, "_SESSIONS", {"r": runner_app.Session(name="n")})
    body = await runner_app.health()
    assert body == {"status": "ok"}


@pytest.mark.asyncio
async def test_status_requires_token(monkeypatch):
    monkeypatch.setattr(runner_app, "_TOKEN", "secret")
    with pytest.raises(HTTPException):
        await runner_app.status(None)
    body = await runner_app.status("secret")
    assert "image" in body and "sessions" in body


def test_non_ascii_token_gives_401_not_500(monkeypatch):
    """secrets.compare_digest raises TypeError on non-ASCII str input; a hostile
    header must still produce a clean 401."""
    monkeypatch.setattr(runner_app, "_TOKEN", "secret")
    with pytest.raises(HTTPException) as exc:
        runner_app._check_token("naïve-tökén")
    assert exc.value.status_code == 401
