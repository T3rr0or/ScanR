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
import ipaddress
import json
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
_NETWORK_PREFIX = os.environ.get("SANDBOX_NETWORK_PREFIX", "scanr-sbx-net")
_PROXY_IMAGE = os.environ.get("SANDBOX_PROXY_IMAGE", "scanr-sandbox-proxy:latest")
_PROXY_PORT = int(os.environ.get("SANDBOX_PROXY_PORT", "8888"))
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
# Every resource created for a sandbox session carries this label.  The runner
# deliberately does not try to recover live sessions after a restart: their
# authorization state lived in this process, so adopting them would be unsafe.
# Instead startup removes every labeled resource before accepting requests.
_SESSION_LABEL = "scanr.sandbox.session=true"
_RESOURCE_LABEL_KEY = "scanr.sandbox.resource"
_EGRESS_LABEL_KEY = "scanr.sandbox.egress"
_EGRESS_LABEL = f"{_EGRESS_LABEL_KEY}=true"
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
    #: Dedicated Docker-internal network. A sandbox never shares an L2 segment
    #: with another run, so it cannot discover or borrow that run's relay.
    network: str
    created: float = field(default_factory=time.monotonic)
    #: Per-run filtered package-mirror proxy. Sharing the old proxy network also
    #: shared every target relay, which defeated per-run scope isolation.
    proxy: str | None = None
    #: per-run SOCKS5 egress relay container, when target egress was requested.
    #: None means the sandbox has no path to any target (mirrors only).
    relay: str | None = None
    #: Authorization is immutable for the lifetime of a run_id.  In particular,
    #: a later request cannot silently reuse a relay created with a broader scope.
    scope: tuple[str, ...] = ()
    target_egress: bool = False


# run_id -> Session. The agent loop is sequential per run, so no per-session lock
# is needed for exec; a global lock guards create/reap bookkeeping.
_SESSIONS: dict[str, Session] = {}
_LOCK = asyncio.Lock()


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # A process restart loses _SESSIONS, but the Docker daemon keeps containers
    # and networks alive.  Never serve while those unaudited bridges still exist.
    await _reconcile_orphaned_resources()
    await _ensure_egress_network()
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


def _network_args(name: str) -> list[str]:
    """Create the isolated, internal-only L2 segment for one agent run."""
    return [
        "docker", "network", "create", "--internal",
        "--label", _SESSION_LABEL,
        "--label", f"{_RESOURCE_LABEL_KEY}=network",
        name,
    ]


def _proxy_args(name: str, network: str) -> list[str]:
    """Args for the run-local, allowlist-only package proxy."""
    return [
        "docker", "run", "-d", "--name", name,
        "--label", _SESSION_LABEL,
        "--label", f"{_RESOURCE_LABEL_KEY}=proxy",
        "--network", network,
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", "128m", "--pids-limit", "64",
        _PROXY_IMAGE,
    ]


def _relay_args(name: str, scope: list[str], network: str) -> list[str]:
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
        "--label", _SESSION_LABEL,
        "--label", f"{_RESOURCE_LABEL_KEY}=relay",
        "--network", network,
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


def _create_args(
    name: str,
    scope: list[str],
    network: str,
    relay: str | None = None,
    proxy: str | None = None,
) -> list[str]:
    """Args for the detached, hardened, keep-alive session container."""
    args = [
        "docker", "run", "-d", "--name", name,
        "--label", _SESSION_LABEL,
        "--label", f"{_RESOURCE_LABEL_KEY}=sandbox",
        "--network", network,
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
    if proxy:
        proxy_url = f"http://{proxy}:{_PROXY_PORT}"
        for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            args += ["--env", f"{var}={proxy_url}"]
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
    # Egress is enforced by a dedicated Docker `internal` network, so the
    # container's only paths out are its own mirror-allowlist proxy and (when
    # requested) its own scope-enforcing relay. Never gate on command text or on
    # this informational variable.
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


async def _read_bounded(
    stream: asyncio.StreamReader | None,
    limit: int,
) -> bytes:
    """Drain a child pipe while retaining at most ``limit + 1`` bytes.

    The extra byte is a truncation sentinel.  Continuing to drain after the cap
    is essential: stopping reads would fill the pipe and deadlock the child.
    """
    if stream is None:
        return b""
    retained = bytearray()
    ceiling = max(0, limit) + 1
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            break
        remaining = ceiling - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return bytes(retained)


async def _collect_process_output(
    proc: asyncio.subprocess.Process,
) -> tuple[bytes, bytes]:
    """Wait for a process while concurrently draining both bounded pipes."""
    stdout_task = asyncio.create_task(_read_bounded(proc.stdout, _MAX_STDOUT))
    stderr_task = asyncio.create_task(_read_bounded(proc.stderr, _MAX_STDERR))
    try:
        await proc.wait()
        streams = await asyncio.gather(stdout_task, stderr_task)
        return streams[0], streams[1]
    finally:
        for task in (stdout_task, stderr_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)


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
        out, err = await asyncio.wait_for(_collect_process_output(proc), timeout=timeout)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5)
        return -1, "", "command timed out", True
    code = proc.returncode if proc.returncode is not None else -1
    return code, out.decode(errors="replace"), err.decode(errors="replace"), False


async def _listed_resource_ids(kind: str) -> list[str]:
    """List Docker object ids carrying ScanR's per-session ownership label."""
    if kind == "container":
        args = [
            "docker", "container", "ls", "-aq", "--filter", f"label={_SESSION_LABEL}"
        ]
    elif kind == "network":
        args = [
            "docker", "network", "ls", "-q", "--filter", f"label={_SESSION_LABEL}"
        ]
    else:  # pragma: no cover - internal programming error
        raise ValueError(f"unsupported Docker resource kind: {kind}")
    code, out, err, timed_out = await _run_docker(args, timeout=30)
    if timed_out or code != 0:
        reason = "timed out" if timed_out else (err.strip() or f"exit {code}")
        raise RuntimeError(f"could not list labeled sandbox {kind}s: {reason[:300]}")
    return [line.strip() for line in out.splitlines() if line.strip()]


async def _network_container_ids(network_id: str) -> list[str]:
    """Return every container attached to a labeled per-session network.

    This also handles upgrades from the previous implementation, which labeled
    its networks but not the containers connected to them.
    """
    args = [
        "docker", "network", "inspect", "--format", "{{json .Containers}}", network_id,
    ]
    code, out, err, timed_out = await _run_docker(args, timeout=30)
    if timed_out or code != 0:
        reason = "timed out" if timed_out else (err.strip() or f"exit {code}")
        raise RuntimeError(
            f"could not inspect orphaned sandbox network {network_id}: {reason[:300]}"
        )
    try:
        containers = json.loads(out.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Docker returned invalid membership data for sandbox network {network_id}"
        ) from exc
    if containers is None:
        return []
    if not isinstance(containers, dict):
        raise RuntimeError(
            f"Docker returned invalid membership data for sandbox network {network_id}"
        )
    return [str(container_id) for container_id in containers]


async def _remove_orphan(kind: str, resource_id: str) -> None:
    noun = "container" if kind == "container" else "network"
    args = ["docker", noun, "rm"]
    if noun == "container":
        args.append("-f")
    args.append(resource_id)
    code, _out, err, timed_out = await _run_docker(args, timeout=30)
    if timed_out or code != 0:
        reason = "timed out" if timed_out else (err.strip() or f"exit {code}")
        raise RuntimeError(
            f"could not remove orphaned sandbox {noun} {resource_id}: {reason[:300]}"
        )


async def _reconcile_orphaned_resources() -> None:
    """Delete resources whose in-process authorization state was lost.

    Failure is fatal to application startup.  Continuing would leave old target
    relays reachable while the session cap and lifetime reaper knew nothing about
    them, which is a security failure rather than a degraded operating mode.
    """
    container_ids = set(await _listed_resource_ids("container"))
    network_ids = await _listed_resource_ids("network")
    for network_id in network_ids:
        container_ids.update(await _network_container_ids(network_id))
    for container_id in sorted(container_ids):
        await _remove_orphan("container", container_id)
    for network_id in network_ids:
        await _remove_orphan("network", network_id)
    _SESSIONS.clear()
    if container_ids or network_ids:
        logger.warning(
            "removed %d orphaned sandbox container(s) and %d network(s) at startup",
            len(container_ids), len(network_ids),
        )


async def _inspect_egress_network() -> dict | None:
    args = [
        "docker", "network", "inspect", "--format", "{{json .}}", _EGRESS_NETWORK,
    ]
    code, out, _err, timed_out = await _run_docker(args, timeout=30)
    if timed_out or code != 0:
        return None
    try:
        details = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Docker returned invalid egress-network metadata") from exc
    if not isinstance(details, dict):
        raise RuntimeError("Docker returned invalid egress-network metadata")
    return details


def _validate_egress_network(details: dict) -> None:
    labels = details.get("Labels") or {}
    valid = (
        details.get("Driver") == "bridge"
        and details.get("Internal") is False
        and isinstance(labels, dict)
        and labels.get(_EGRESS_LABEL_KEY) == "true"
    )
    if not valid:
        raise RuntimeError(
            f"Docker network {_EGRESS_NETWORK!r} exists but is not ScanR's labeled, "
            "non-internal bridge"
        )


async def _ensure_egress_network() -> None:
    """Ensure the shared outer leg exists before any per-run bridge uses it.

    Compose does not materialize a named network when every service referring to
    it is build-only.  Inspecting again after creation makes concurrent runner
    startups safe: losing the create race is fine if the winner made the exact
    labeled bridge we require.
    """
    details = await _inspect_egress_network()
    if details is None:
        await _run_docker(
            [
                "docker", "network", "create",
                "--driver", "bridge",
                "--label", _EGRESS_LABEL,
                _EGRESS_NETWORK,
            ],
            timeout=30,
        )
        details = await _inspect_egress_network()
        if details is None:
            raise RuntimeError(
                f"could not create or inspect sandbox egress network {_EGRESS_NETWORK!r}"
            )
    _validate_egress_network(details)


async def _remove_container(name: str) -> None:
    with contextlib.suppress(Exception):
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=15)


async def _remove_network(name: str) -> None:
    with contextlib.suppress(Exception):
        proc = await asyncio.create_subprocess_exec(
            "docker", "network", "rm", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=15)


async def _start_proxy(suffix: str, network: str) -> str | None:
    """Start a package proxy private to this run and attach its egress leg."""
    if not _PROXY_IMAGE:
        return None
    name = f"scanr-pxy-{suffix}"
    code, _out, err, _to = await _run_docker(_proxy_args(name, network), timeout=120)
    if code != 0:
        await _remove_container(name)
        raise HTTPException(status_code=502, detail=f"failed to start package proxy: {err[:300]}")
    code, _out, err, _to = await _run_docker(_connect_relay_args(name), timeout=60)
    if code != 0:
        await _remove_container(name)
        raise HTTPException(
            status_code=502, detail=f"failed to attach package proxy to network: {err[:300]}"
        )
    return name


async def _start_relay(suffix: str, scope: list[str], network: str) -> str:
    """Start the per-run egress relay and attach its egress leg.

    Fail-closed: any failure here raises, so _ensure_session tears down and the
    command is denied. A sandbox must never come up believing it has scoped
    egress when the relay that enforces the scope is not running.
    """
    name = f"scanr-rly-{suffix}"
    code, _out, err, _to = await _run_docker(_relay_args(name, scope, network), timeout=120)
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


def _normalize_scope(scope: list[str]) -> tuple[str, ...]:
    """Canonicalize the relay's address-only authorization set.

    Rejecting malformed entries here also prevents a comma embedded in one list
    item from becoming two allowlist entries when exported to the relay env var.
    """
    normalized: set[str] = set()
    for entry in scope:
        value = entry.strip()
        if not value:
            continue
        try:
            if "/" in value:
                normalized.add(str(ipaddress.ip_network(value, strict=False)))
            else:
                normalized.add(str(ipaddress.ip_address(value)))
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="sandbox scope contains an invalid address or CIDR",
            ) from exc
    return tuple(sorted(normalized))


async def _ensure_session(run_id: str, scope: list[str], target_egress: bool = False) -> str:
    """Return the container name for ``run_id``, creating it if needed."""
    normalized_scope = _normalize_scope(scope)
    async with _LOCK:
        sess = _SESSIONS.get(run_id)
        if sess is not None:
            if (
                sess.scope != normalized_scope
                or sess.target_egress != bool(target_egress)
            ):
                raise HTTPException(
                    status_code=409,
                    detail="run_id is already bound to a different sandbox scope or egress policy",
                )
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
        network = f"{_NETWORK_PREFIX}-{suffix}"
        proxy: str | None = None
        relay: str | None = None
        if target_egress and not normalized_scope:
            raise HTTPException(
                status_code=400,
                detail="target egress requested but the scan has no authorized scope",
            )
        code, _out, err, _to = await _run_docker(_network_args(network), timeout=60)
        if code != 0:
            await _remove_network(network)
            raise HTTPException(status_code=502, detail=f"failed to create sandbox network: {err[:300]}")
        try:
            proxy = await _start_proxy(suffix, network)
            if target_egress:
                relay = await _start_relay(suffix, list(normalized_scope), network)

            code, _out, err, _to = await _run_docker(
                _create_args(name, list(normalized_scope), network, relay, proxy), timeout=120
            )
            if code != 0:
                raise HTTPException(status_code=502, detail=f"failed to start sandbox: {err[:300]}")
        except Exception:
            await _remove_container(name)
            if relay:
                await _remove_container(relay)
            if proxy:
                await _remove_container(proxy)
            await _remove_network(network)
            raise
        _SESSIONS[run_id] = Session(
            name=name,
            network=network,
            proxy=proxy,
            relay=relay,
            scope=normalized_scope,
            target_egress=bool(target_egress),
        )
        return name


async def _destroy_session(sess: Session) -> None:
    """Remove a session's containers. The relay goes too — leaving it running
    would keep a scope-authorized bridge to the targets alive with nothing on the
    other end."""
    await _remove_container(sess.name)
    if sess.relay:
        await _remove_container(sess.relay)
    if sess.proxy:
        await _remove_container(sess.proxy)
    await _remove_network(sess.network)


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
        "truncated": len(out) > _MAX_STDOUT or len(err) > _MAX_STDERR,
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
