"""Sandbox runner — the ONLY component with Docker socket access.

It spawns an ephemeral, hardened, network-scoped container to run a single
command on behalf of the AI agent, captures the output, and destroys the
container. This service holds NO ScanR secrets (no SECRET_KEY/VAULT_KEY/DB);
the worker talks to it over the internal network with a shared token.

Run with:  uvicorn scanr.sandbox.runner_app:app --host 0.0.0.0 --port 8090
See docs/ai-sandbox-design.md.
"""
from __future__ import annotations

import asyncio
import os
import uuid

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

_TOKEN = os.environ.get("SANDBOX_TOKEN", "")
_IMAGE = os.environ.get("SANDBOX_IMAGE", "scanr-sandbox:latest")
_NETWORK = os.environ.get("SANDBOX_NETWORK", "scanr_sandbox")
_PROXY = os.environ.get("SANDBOX_PROXY_URL", "")  # e.g. http://sandbox-proxy:8888
_MEM = os.environ.get("SANDBOX_MEM", "1g")
_CPUS = os.environ.get("SANDBOX_CPUS", "1.0")
_PIDS = os.environ.get("SANDBOX_PIDS", "256")
_MAX_STDOUT = 200_000
_MAX_STDERR = 20_000

app = FastAPI(title="ScanR sandbox runner")


class RunRequest(BaseModel):
    command: str = Field(min_length=1, max_length=8000)
    scope: list[str] = Field(default_factory=list)
    run_id: str = ""
    timeout: int = Field(default=120, ge=1, le=1800)


def _check_token(token: str | None) -> None:
    # Fail-closed: a token MUST be configured, and must match.
    if not _TOKEN or token != _TOKEN:
        raise HTTPException(status_code=401, detail="invalid sandbox token")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "image": _IMAGE}


def _docker_args(name: str, body: RunRequest) -> list[str]:
    args = [
        "docker", "run", "--rm", "--name", name,
        "--network", _NETWORK,
        "--user", "1000:1000",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=512m,mode=1777",
        "--tmpfs", "/work:rw,size=512m,uid=1000,gid=1000",
        "--workdir", "/work",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", _MEM, "--cpus", _CPUS, "--pids-limit", _PIDS,
    ]
    if _PROXY:
        for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            args += ["--env", f"{var}={_PROXY}"]
    # Scope is informational inside the container; egress is enforced by the
    # network/proxy, not by trusting the command.
    args += ["--env", f"SCANR_SCOPE={','.join(body.scope)}"]
    args += [_IMAGE, "/bin/sh", "-lc", body.command]
    return args


async def _force_remove(name: str) -> None:
    proc = await asyncio.create_subprocess_exec(
        "docker", "rm", "-f", name,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.wait(), timeout=10)
    except (asyncio.TimeoutError, Exception):
        pass


@app.post("/run")
async def run(body: RunRequest, x_sandbox_token: str | None = Header(default=None)) -> dict:
    _check_token(x_sandbox_token)
    name = f"scanr-sbx-{(body.run_id[:8] or uuid.uuid4().hex[:8])}-{uuid.uuid4().hex[:6]}"
    proc = await asyncio.create_subprocess_exec(
        *_docker_args(name, body),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    timed_out = False
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=body.timeout)
    except asyncio.TimeoutError:
        timed_out = True
        await _force_remove(name)
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (asyncio.TimeoutError, Exception):
            pass
        out, err = b"", b"command timed out"

    stdout = out.decode(errors="replace") if out else ""
    stderr = err.decode(errors="replace") if err else ""
    return {
        "exit_code": proc.returncode if proc.returncode is not None else -1,
        "stdout": stdout[:_MAX_STDOUT],
        "stderr": stderr[:_MAX_STDERR],
        "truncated": len(stdout) > _MAX_STDOUT,
        "timed_out": timed_out,
    }
