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
import logging
import os
import re
import secrets
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("scanr.sandbox.runner")

_TOKEN = os.environ.get("SANDBOX_TOKEN", "")
_IMAGE = os.environ.get("SANDBOX_IMAGE", "scanr-sandbox:latest")
_NETWORK = os.environ.get("SANDBOX_NETWORK", "scanr_sandbox")
_PROXY = os.environ.get("SANDBOX_PROXY_URL", "")  # e.g. http://sandbox-proxy:8888
_MEM = os.environ.get("SANDBOX_MEM", "1g")
_CPUS = os.environ.get("SANDBOX_CPUS", "1.0")
_PIDS = os.environ.get("SANDBOX_PIDS", "256")
# Per-run SOCKS5 egress relay (opt-in target egress). _EGRESS_NETWORK is the
# non-internal leg; only the relay is ever attached to it.
_RELAY_IMAGE = os.environ.get("SANDBOX_RELAY_IMAGE", "scanr-sandbox-relay:latest")
_EGRESS_NETWORK = os.environ.get("SANDBOX_EGRESS_NETWORK", "scanr_sandbox_egress")
_RELAY_PORT = int(os.environ.get("SANDBOX_RELAY_PORT", "1080"))
_RELAY_MEM = os.environ.get("SANDBOX_RELAY_MEM", "128m")
# Hard cap on how long any one session container may live, regardless of the
# worker remembering to reap it (defense against leaks if a run crashes).
_MAX_LIFETIME = int(os.environ.get("SANDBOX_MAX_LIFETIME", "3600"))
_REAP_INTERVAL = 60
_MAX_STDOUT = 200_000
_MAX_STDERR = 20_000
# Ceiling on live session containers. Each one holds memory, CPU and PID budget
# on the host, and sessions are only released by an explicit /session/stop or the
# max-lifetime reaper — so without a cap a caller could spawn them until the host
# is exhausted.
_MAX_SESSIONS = int(os.environ.get("SANDBOX_MAX_SESSIONS", "8"))

# run_id becomes part of a Docker container name, which must match
# [a-zA-Z0-9][a-zA-Z0-9_.-]*. Validate rather than rely on docker rejecting it,
# so a malformed id fails fast with a clear error instead of a 502.
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# Writable HOME on tmpfs so non-root `pip install --user`, tool configs, and
# language installers work despite the read-only root filesystem.
_HOME = "/home/sbx"
_PATH = f"{_HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class Session:
    name: str
    created: float = field(default_factory=time.monotonic)
    #: per-run SOCKS5 egress relay container, when target egress was requested.
    #: None means the sandbox has no path to any target (mirrors only).
    relay: str | None = None


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
    scope: list[str] = Field(default_factory=list, max_length=4096)
    run_id: str = Field(default="", max_length=64)
    timeout: int = Field(default=120, ge=1, le=1800)
    #: Opt in to reaching the scan's authorized targets through a per-run SOCKS5
    #: relay. False (default) keeps the sandbox on package mirrors only.
    target_egress: bool = False


class StopRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)


def _check_token(token: str | None) -> None:
    # Fail-closed: a token MUST be configured, and must match. compare_digest
    # keeps the comparison constant-time so the token can't be recovered a byte
    # at a time by timing repeated requests. Compare the UTF-8 encodings: the str
    # form of compare_digest raises TypeError on non-ASCII input, which would turn
    # a hostile header into a 500 instead of a clean 401.
    if not _TOKEN or not token:
        raise HTTPException(status_code=401, detail="invalid sandbox token")
    if not secrets.compare_digest(token.encode("utf-8"), _TOKEN.encode("utf-8")):
        raise HTTPException(status_code=401, detail="invalid sandbox token")


@app.get("/health")
async def health() -> dict:
    """Unauthenticated liveness probe — deliberately says nothing about the
    configured image or live session count, which would be useful reconnaissance
    for anything that reached this service."""
    return {"status": "ok"}


@app.get("/status")
async def status(x_sandbox_token: str | None = Header(default=None)) -> dict:
    """Authenticated detail for operators/diagnostics."""
    _check_token(x_sandbox_token)
    return {
        "status": "ok",
        "image": _IMAGE,
        "sessions": len(_SESSIONS),
        "max_sessions": _MAX_SESSIONS,
    }


def _relay_args(name: str, scope: list[str]) -> list[str]:
    """Args for the per-run SOCKS5 egress relay.

    Dual-homed on purpose: one leg on the internal sandbox network so the sandbox
    can reach it, one leg on the egress network so it can reach targets. It is the
    only thing bridging the two, and it refuses any destination outside ``scope``
    (or inside the infrastructure denylist) — see scanr/sandbox/egress_relay.py.

    It holds no ScanR secrets, drops all capabilities, and runs non-root: it needs
    nothing but two sockets.
    """
    return [
        "docker", "run", "-d", "--name", name,
        "--network", _NETWORK,
        "--user", "1000:1000",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", _RELAY_MEM, "--pids-limit", "64",
        "--env", f"SCANR_ALLOWED_CIDRS={','.join(scope)}",
        "--env", f"SCANR_RELAY_PORT={_RELAY_PORT}",
        _RELAY_IMAGE,
    ]


def _connect_relay_args(name: str) -> list[str]:
    """Attach the relay's second leg: the network where targets are reachable."""
    return ["docker", "network", "connect", _EGRESS_NETWORK, name]


def _create_args(name: str, scope: list[str], relay: str | None = None) -> list[str]:
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
    if relay:
        # Point SOCKS-aware tooling at the per-run relay. Setting these is a
        # convenience, not a control: the container has no route to a target
        # except through the relay, and the relay authorizes every destination
        # itself, so unsetting them gains the command nothing.
        socks = f"socks5://{relay}:{_RELAY_PORT}"
        args += ["--env", f"ALL_PROXY={socks}", "--env", f"all_proxy={socks}"]
        args += ["--env", f"SCANR_SOCKS_PROXY={socks}"]
        args += ["--env", "SCANR_TARGET_EGRESS=1"]
    # Scope is informational inside the container only — it does not gate egress.
    # Egress is enforced by the network: _NETWORK is a Docker `internal` network,
    # so the container's only paths out are the mirror-allowlist proxy and (when
    # requested) the scope-enforcing relay. Never gate on the command text or on
    # this variable.
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
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as exc:
        # docker CLI missing / socket unreachable — surface a clear cause.
        logger.error("failed to spawn docker (%s): %s", args[:2], exc)
        return -1, "", f"failed to run docker: {exc}", False
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


async def _start_relay(suffix: str, scope: list[str]) -> str:
    """Start the per-run egress relay and attach its egress leg.

    Fail-closed: any failure here raises, so _ensure_session tears down and the
    command is denied. A sandbox must never come up believing it has scoped
    egress when the relay that enforces the scope is not running.
    """
    name = f"scanr-rly-{suffix}"
    code, _out, err, _to = await _run_docker(_relay_args(name, scope), timeout=120)
    if code != 0:
        await _remove_container(name)
        raise HTTPException(status_code=502, detail=f"failed to start egress relay: {err[:300]}")
    code, _out, err, _to = await _run_docker(_connect_relay_args(name), timeout=60)
    if code != 0:
        await _remove_container(name)
        raise HTTPException(
            status_code=502, detail=f"failed to attach egress relay to network: {err[:300]}"
        )
    return name


async def _ensure_session(run_id: str, scope: list[str], target_egress: bool = False) -> str:
    """Return the container name for ``run_id``, creating it if needed."""
    async with _LOCK:
        sess = _SESSIONS.get(run_id)
        if sess is not None:
            return sess.name
        if len(_SESSIONS) >= _MAX_SESSIONS:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"sandbox session limit reached ({_MAX_SESSIONS} live sessions); "
                    "stop a run or raise SANDBOX_MAX_SESSIONS"
                ),
            )
        suffix = f"{run_id[:8]}-{uuid.uuid4().hex[:6]}"
        name = f"scanr-sbx-{suffix}"

        relay: str | None = None
        if target_egress:
            # No scope means nothing is authorized; starting a relay that would
            # refuse every destination only invites confusion.
            if not scope:
                raise HTTPException(
                    status_code=400,
                    detail="target egress requested but the scan has no authorized scope",
                )
            relay = await _start_relay(suffix, scope)

        code, _out, err, _to = await _run_docker(_create_args(name, scope, relay), timeout=120)
        if code != 0:
            await _remove_container(name)
            if relay:
                await _remove_container(relay)
            raise HTTPException(status_code=502, detail=f"failed to start sandbox: {err[:300]}")
        _SESSIONS[run_id] = Session(name=name, relay=relay)
        return name


async def _destroy_session(sess: Session) -> None:
    """Remove a session's containers. The relay goes too — leaving it running
    would keep a scope-authorized bridge to the targets alive with nothing on the
    other end."""
    await _remove_container(sess.name)
    if sess.relay:
        await _remove_container(sess.relay)


async def _reaper() -> None:
    """Background task: destroy any session that outlives the hard cap."""
    while True:
        await asyncio.sleep(_REAP_INTERVAL)
        now = time.monotonic()
        async with _LOCK:
            stale = [rid for rid, s in _SESSIONS.items() if now - s.created > _MAX_LIFETIME]
            for rid in stale:
                await _destroy_session(_SESSIONS.pop(rid))


@app.post("/exec")
async def exec_command(body: ExecRequest, x_sandbox_token: str | None = Header(default=None)) -> dict:
    _check_token(x_sandbox_token)
    ephemeral = not body.run_id
    run_id = body.run_id or f"once-{uuid.uuid4().hex[:12]}"
    if not _RUN_ID_RE.match(run_id):
        raise HTTPException(status_code=400, detail="invalid run_id")
    try:
        name = await _ensure_session(run_id, body.scope, body.target_egress)
        try:
            code, out, err, timed_out = await _run_docker(
                _exec_args(name, body.command, body.timeout),
                timeout=body.timeout + 15,
            )
        finally:
            if ephemeral:
                async with _LOCK:
                    sess = _SESSIONS.pop(run_id, None)
                if sess is not None:
                    await _destroy_session(sess)
                else:
                    await _remove_container(name)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - never return an opaque 500 to the worker
        logger.exception("sandbox exec failed for run %s", run_id)
        raise HTTPException(status_code=502, detail=f"sandbox exec error: {exc}") from exc
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
        await _destroy_session(sess)
    return {"stopped": sess is not None}
