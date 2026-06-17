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


def test_docker_args_are_hardened(monkeypatch):
    monkeypatch.setattr(runner_app, "_PROXY", "http://sandbox-proxy:8888")
    body = runner_app.RunRequest(command="id", scope=["192.0.2.0/24"], run_id="abc123", timeout=30)
    args = runner_app._docker_args("scanr-sbx-test", body)

    # ephemeral, non-root, locked-down
    assert "--rm" in args
    assert args[args.index("--user") + 1] == "1000:1000"
    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in args
    assert args[args.index("--network") + 1] == runner_app._NETWORK
    assert "--pids-limit" in args
    # command runs via a shell as the last args
    assert args[-3:] == ["/bin/sh", "-lc", "id"]
    # install proxy is injected
    assert any("HTTP_PROXY=http://sandbox-proxy:8888" in a for a in args)
