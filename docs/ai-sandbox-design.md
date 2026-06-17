# ScanR AI Sandbox — Design

> Status: **design + first slice**. Gives the AI agent a real shell ("freedom" to
> run arbitrary commands and install tools) inside a **dedicated, disposable,
> network-scoped sandbox** — without exposing ScanR's infrastructure or letting
> it act out of scope.

Decisions taken (with the operator):
- **Freedom level:** sandboxed shell (not just bounded tools).
- **Egress:** deny-all, then allow the scan's authorized target CIDRs **+** a
  configurable package-mirror allowlist (so it can `apt`/`pip` install).
- **Runtime:** a dedicated **sandbox-runner** service that owns the Docker
  socket and spawns ephemeral jailed containers. The API / worker / DB never
  touch the socket.

---

## 1. Why a separate runner

Spawning fresh containers requires Docker-daemon access, which is ≈ root on the
host. The agent loop runs in the **worker**, which holds the DB, the Fernet
vault, and provider API keys — and it ingests **attacker-controlled scan
output** (prime prompt-injection material). Giving *that* process the Docker
socket is the exact trifecta we must avoid.

So a minimal **sandbox-runner** holds the socket and nothing else: no ScanR
secrets, no DB, no app code beyond the runner. The worker asks it to run a
command; the runner returns output. A runner compromise cannot read ScanR
secrets, and the secret-holding worker cannot touch the socket.

```
worker (agent loop, secrets)  --HTTP /run-->  sandbox-runner (Docker socket, no secrets)
                                                   |
                                                   v  spawns, captures, destroys
                                          ephemeral sandbox container
                                          (pentest toolkit, no secrets,
                                           egress: targets + mirrors only)
```

## 2. Components

1. **Sandbox image** (`backend/sandbox/Dockerfile.sandbox`) — a pentest toolkit:
   nmap, nuclei, curl, wget, dnsutils, netcat, python3+pip, etc. Runs as a
   non-root user. No ScanR code or secrets.
2. **Sandbox-runner service** (`backend/scanr/sandbox/runner_app.py`) — a tiny
   FastAPI app, the **only** holder of the Docker socket. `POST /run` →
   spawn → capture → destroy. Authenticated with a shared `SANDBOX_TOKEN`;
   only reachable on the internal compose network. No `SECRET_KEY`/`VAULT_KEY`/
   DB env.
3. **SandboxClient** (`backend/scanr/sandbox/client.py`) — worker-side HTTP
   client to the runner. **Fail-closed**: if no runner is configured or it's
   unreachable, command execution is denied (never silently "succeeds").
4. **Agent integration** — `AgentContext.run_command` + a gated `run_command`
   tool. New capability `allow_command_exec` (admin + aggressive + approval).

## 3. Per-run container hardening

Each `POST /run` launches a container with:
- `--rm`, `--network <per-run-net>`, no bind mounts, no ScanR env.
- `--user` non-root, `--read-only` root fs + a small writable `/tmp` & workdir,
  `--cap-drop ALL` (the sandbox gets **no** `NET_ADMIN`, so it cannot alter its
  own firewall), `--pids-limit`, `--memory`, `--cpus`, `--security-opt
  no-new-privileges`.
- A wall-clock timeout; killed + removed on timeout.

## 4. Egress enforcement (targets + mirrors)

The sandbox container **cannot** change its own networking (no `NET_ADMIN`), so
egress is enforced *around* it:

- **Default deny.** The per-run network has no unrestricted internet route.
- **Targets:** the runner programs firewall rules (nftables/iptables on the
  runner, scoped to the per-run network subnet) allowing egress to the scan's
  authorized target CIDRs only — passed in by the worker from the scan's scope
  (and re-checked against `is_forbidden_target`, so loopback/metadata/infra are
  never in the allowed set).
- **Package mirrors / installs:** the container's `http(s)_proxy` points at a
  small **filtering proxy** (tinyproxy/squid) with a domain allowlist (PyPI,
  Debian/Ubuntu mirrors, GitHub). Direct internet is dropped; only allowlisted
  mirror domains pass, so `pip`/`apt` work but arbitrary exfil does not.
- **DNS** restricted to a chosen resolver.

> Egress correctness is host/Docker-network dependent and must be validated on a
> real deployment. The runner **fails closed**: if it cannot apply the egress
> rules for a run, it refuses to start the container.

## 5. Gating (all enforced in code, layered)

`run_command` is the most powerful tool, so it stacks every guardrail:
1. **Capability:** requires `allow_command_exec` (a new aggressive opt-in) — so
   `aggressive=True` **and** that flag, which is **admin-only** at launch.
2. **Approval:** in guided mode every command waits for operator allow/deny.
3. **Scope:** enforced at the **network layer** (egress allowlist = target
   CIDRs), since arbitrary command text can't be parsed per-argument.
4. **Isolation:** runs in the jailed sandbox, never the worker; no secrets
   reachable.
5. **Budget + audit:** counts against the run budget; every command + output is
   streamed to the console and persisted in the run transcript.
6. **Fail-closed:** no runner configured/reachable, or egress rules can't be
   applied → denied.

## 6. Config

| Setting | Default | Purpose |
|---|---|---|
| `SANDBOX_RUNNER_URL` | empty | Internal URL of the runner. Empty = command exec disabled (fail-closed). |
| `SANDBOX_TOKEN` | empty | Shared auth token between worker and runner. |
| `SANDBOX_IMAGE` | `scanr-sandbox:latest` | Toolkit image the runner spawns. |
| `SANDBOX_MIRROR_ALLOWLIST` | pypi/debian/ubuntu/github | Domains the filtering proxy permits for installs. |
| `SANDBOX_CMD_TIMEOUT` | 120 | Per-command wall-clock seconds. |

## 7. Build slices

1. **(this slice)** Design + agent-side contract: capability, `run_command`
   tool, `AgentContext.run_command`, `SandboxClient` (fail-closed), settings,
   policy, unit tests. Inert until a runner is configured.
2. Runner service + sandbox image + compose wiring (socket isolated to runner).
3. Egress enforcement (firewall rules + filtering proxy) — validated on a real
   Docker host.
4. UI: surface `run_command` actions/output in the transcript (already generic);
   add the `allow_command_exec` toggle to the aggressive opt-ins.

## 8. Residual risk (be honest)
A shell — even jailed — is the highest-risk feature in ScanR. The isolation
(no secrets, scoped egress, no `NET_ADMIN`, non-root, ephemeral) contains the
blast radius, but the runner holding the Docker socket is root-equivalent on its
host; keep it minimal and consider gVisor/Sysbox or a separate host for
high-stakes deployments. Only enable `allow_command_exec` against systems you
are authorized to actively exploit.
