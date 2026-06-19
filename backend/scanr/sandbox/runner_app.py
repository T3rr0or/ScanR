"""Sandbox runner — the ONLY component with Docker socket access.

It manages one long-lived, hardened, network-scoped container per agent run and
executes commands inside it via ``docker exec``. A persistent container means
state survives between commands: the agent can install tools, clone repos, drop
files, and build on a foothold across multiple steps — like a real operator —
instead of starting from scratch every command.

This service holds NO ScanR secrets (no SECRET_KEY/VAULT_KEY/DB); the worker
talks to it over the internal network with a shared token.

Run with:  uvicorn scanr.sandbox.runner_app:app --host 0.0.0.0 --port 8090
See docs/ai-sandbox-design.md.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

_TOKEN = os.environ.get("SANDBOX_TOKEN", "")
_IMAGE = os.environ.get("SANDBOX_IMAGE", "scanr-sandbox:latest")
_NETWORK = os.environ.get("SANDBOX_NETWORK", "scanr_sandbox")
_PROXY = os.environ.get("SANDBOX_PROXY_URL", "")  # e.g. http://sandbox-proxy:8888
_MEM = os.environ.get("SANDBOX_MEM", "1g")
_CPUS = os.environ.get("SANDBOX_CPUS", "1.0")
_PIDS = os.environ.get("SANDBOX_PIDS", "256")
# Hard cap on how long any one session container may live, regardless of the
# worker remembering to reap it (defense against leaks if a run crashes).
_MAX_LIFETIME = int(os.environ.get("SANDBOX_MAX_LIFETIME", "3600"))
_REAP_INTERVAL = 60
_MAX_STDOUT = 200_000
_MAX_STDERR = 20_000

# Writable HOME on tmpfs so non-root `pip install --user`, tool configs, and
# language installers work despite the read-only root filesystem.
_HOME = "/home/sbx"
_PATH = f"{_HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class Session:
    name: str
    created: float = field(default_factory=time.monotonic)


# run_id -> Session. The agent loop is sequential per run, so no per-session lock
# is needed for exec; a global lock guards create/reap bookkeeping.
_SESSIONS: dict[str, Session] = {}
_LOCK = asyncio.Lock()


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    task = asyncio.create_task(_reaper())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="ScanR sandbox runner", lifespan=_lifespan)


class ExecRequest(BaseModel):
    command: str = Field(min_length=1, max_length=8000)
    scope: list[str] = Field(default_factory=list)
    run_id: str = ""
    timeout: int = Field(default=120, ge=1, le=1800)


class StopRequest(BaseModel):
    run_id: str = Field(min_length=1)


def _check_token(token: str | None) -> None:
    # Fail-closed: a token MUST be configured, and must match.
    if not _TOKEN or token != _TOKEN:
        raise HTTPException(status_code=401, detail="invalid sandbox token")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "image": _IMAGE, "sessions": len(_SESSIONS)}


def _create_args(name: str, scope: list[str]) -> list[str]:
    """Args for the detached, hardened, keep-alive session container."""
    args = [
        "docker", "run", "-d", "--name", name,
        "--network", _NETWORK,
        "--user", "1000:1000",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=512m,mode=1777",
        "--tmpfs", "/work:rw,size=512m,uid=1000,gid=1000",
        "--tmpfs", f"{_HOME}:rw,size=512m,uid=1000,gid=1000",
        "--workdir", "/work",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", _MEM, "--cpus", _CPUS, "--pids-limit", _PIDS,
        "--env", f"HOME={_HOME}",
        "--env", f"PATH={_PATH}",
    ]
    if _PROXY:
        for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            args += ["--env", f"{var}={_PROXY}"]
    # Scope is informational inside the container; egress is enforced by the
    # network/proxy, not by trusting the command.
    args += ["--env", f"SCANR_SCOPE={','.join(scope)}"]
    # Keep the container alive so we can exec into it repeatedly.
    args += [_IMAGE, "sleep", "infinity"]
    return args


def _exec_args(name: str, command: str, timeout: int) -> list[str]:
    """Args to run one command inside an existing session container.

    Enforces the timeout container-side (`timeout`) so a hung command can't tie
    up the session; an asyncio backstop guards the docker client itself.
    """
    return [
        "docker", "exec", "-u", "1000:1000", "--workdir", "/work", name,
        "timeout", "-k", "5", str(timeout), "/bin/sh", "-lc", command,
    ]


async def _run_docker(args: list[str], timeout: float) -> tuple[int, str, str, bool]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5)
        return -1, "", "command timed out", True
    code = proc.returncode if proc.returncode is not None else -1
    return code, out.decode(errors="replace"), err.decode(errors="replace"), False


async def _remove_container(name: str) -> None:
    with contextlib.suppress(Exception):
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=15)


async def _ensure_session(run_id: str, scope: list[str]) -> str:
    """Return the container name for ``run_id``, creating it if needed."""
    async with _LOCK:
        sess = _SESSIONS.get(run_id)
        if sess is not None:
            return sess.name
        name = f"scanr-sbx-{run_id[:8]}-{uuid.uuid4().hex[:6]}"
        code, _out, err, _to = await _run_docker(_create_args(name, scope), timeout=120)
        if code != 0:
            await _remove_container(name)
            raise HTTPException(status_code=502, detail=f"failed to start sandbox: {err[:300]}")
        _SESSIONS[run_id] = Session(name=name)
        return name


async def _reaper() -> None:
    """Background task: destroy any session that outlives the hard cap."""
    while True:
        await asyncio.sleep(_REAP_INTERVAL)
        now = time.monotonic()
        async with _LOCK:
            stale = [rid for rid, s in _SESSIONS.items() if now - s.created > _MAX_LIFETIME]
            for rid in stale:
                sess = _SESSIONS.pop(rid)
                await _remove_container(sess.name)


@app.post("/exec")
async def exec_command(body: ExecRequest, x_sandbox_token: str | None = Header(default=None)) -> dict:
    _check_token(x_sandbox_token)
    ephemeral = not body.run_id
    run_id = body.run_id or f"once-{uuid.uuid4().hex[:12]}"
    name = await _ensure_session(run_id, body.scope)
    try:
        code, out, err, timed_out = await _run_docker(
            _exec_args(name, body.command, body.timeout),
            timeout=body.timeout + 15,
        )
    finally:
        if ephemeral:
            async with _LOCK:
                _SESSIONS.pop(run_id, None)
            await _remove_container(name)
    return {
        "exit_code": code,
        "stdout": out[:_MAX_STDOUT],
        "stderr": err[:_MAX_STDERR],
        "truncated": len(out) > _MAX_STDOUT,
        "timed_out": timed_out,
    }


@app.post("/session/stop")
async def stop_session(body: StopRequest, x_sandbox_token: str | None = Header(default=None)) -> dict:
    _check_token(x_sandbox_token)
    async with _LOCK:
        sess = _SESSIONS.pop(body.run_id, None)
    if sess is not None:
        await _remove_container(sess.name)
    return {"stopped": sess is not None}
