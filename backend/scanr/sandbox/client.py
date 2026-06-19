"""Worker-side client for the sandbox-runner.

The agent (in the worker) never touches Docker — it asks the isolated runner to
execute a command in a jailed, network-scoped container. Fail-closed: if no
runner is configured or it is unreachable, command execution is denied rather
than silently doing nothing.
"""
from __future__ import annotations

from dataclasses import dataclass

from scanr.config import get_settings


class SandboxUnavailable(Exception):
    """Raised when the sandbox runner is not configured or not reachable."""


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False
    timed_out: bool = False


class SandboxClient:
    def __init__(self, base_url: str, token: str, timeout: int):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    @classmethod
    def from_settings(cls) -> "SandboxClient | None":
        """Build a client from settings, or None if command exec isn't configured."""
        s = get_settings()
        if not s.sandbox_runner_url:
            return None
        return cls(s.sandbox_runner_url, s.sandbox_token, s.sandbox_cmd_timeout)

    async def run(self, *, command: str, scope: list[str], run_id: str) -> SandboxResult:
        """Execute a command in a fresh jailed container scoped to ``scope`` CIDRs.

        Raises SandboxUnavailable on any transport/runner failure (fail-closed).
        """
        import httpx

        payload = {
            "command": command,
            "scope": scope,
            "run_id": run_id,
            "timeout": self._timeout,
        }
        headers = {"X-Sandbox-Token": self._token} if self._token else {}
        try:
            async with httpx.AsyncClient(timeout=self._timeout + 15) as client:
                resp = await client.post(f"{self._base_url}/exec", json=payload, headers=headers)
        except Exception as exc:  # noqa: BLE001 - any failure is fail-closed
            raise SandboxUnavailable(str(exc)) from exc
        if resp.status_code == 401:
            raise SandboxUnavailable("runner rejected the sandbox token")
        if resp.status_code >= 400:
            raise SandboxUnavailable(f"runner error {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        return SandboxResult(
            exit_code=int(data.get("exit_code", -1)),
            stdout=str(data.get("stdout", ""))[:8000],
            stderr=str(data.get("stderr", ""))[:4000],
            truncated=bool(data.get("truncated", False)),
            timed_out=bool(data.get("timed_out", False)),
        )

    async def close(self, *, run_id: str) -> None:
        """Tear down the persistent session container for ``run_id``.

        Best-effort: failures are swallowed (the runner reaps stale sessions on a
        max-lifetime timer anyway, so a missed teardown can't leak indefinitely).
        """
        if not run_id:
            return
        import httpx

        headers = {"X-Sandbox-Token": self._token} if self._token else {}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                await client.post(
                    f"{self._base_url}/session/stop",
                    json={"run_id": run_id},
                    headers=headers,
                )
        except Exception:  # noqa: BLE001 - teardown is best-effort
            pass
