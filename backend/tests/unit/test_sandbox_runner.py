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
