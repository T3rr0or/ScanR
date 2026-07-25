# ScanR AI Sandbox — Design

> Status: **design + first slice**. Gives the AI agent a real shell ("freedom" to
> run arbitrary commands and install tools) inside a **dedicated, disposable,
> network-scoped sandbox** — without exposing ScanR's infrastructure or letting
> it act out of scope.

Decisions taken (with the operator):
- **Freedom level:** sandboxed shell (not just bounded tools).
- **Egress:** deny-all, then allow a package-mirror allowlist (so it can
  `apt`/`pip` install). **Target egress is NOT implemented** — see §4.
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
worker (agent loop, secrets) --HTTP /exec--> sandbox-runner (Docker socket, no secrets)
                             --HTTP /session/stop-->  |
                                                   v  ensures (per run), exec, reaps
                                          persistent session container (per run)
                                          (pentest toolkit, no secrets,
                                           egress: package mirrors only)
```

**Persistent session per run.** Rather than a throwaway container per command,
the runner keeps **one container alive per agent run** and `docker exec`s each
command into it. State (installed tools, downloaded files, the `/work` dir,
footholds) therefore survives between commands — the agent operates statefully
like a real pentester instead of starting cold every step. The container is
reaped when the run ends (worker calls `/session/stop`) and, as a backstop, by a
max-lifetime reaper in the runner so nothing leaks if a run crashes.

**Fat image to keep runs cheap.** The toolkit image is intentionally large: a
broad set of tools + wordlists are baked in at build time so the agent almost
never spends tokens/time installing things at runtime. The agent prompt
advertises the pre-installed toolkit so the model uses it directly.

## 2. Components

1. **Sandbox image** (`backend/sandbox/Dockerfile.sandbox`) — a **fat** Kali-based
   pentest toolkit: nmap, masscan, nikto, sqlmap, gobuster, ffuf, feroxbuster,
   wfuzz, whatweb, wpscan, hydra, john, smbclient, curl, git, python3+pip, plus
   SecLists wordlists. Baked in at build time so the agent rarely installs at
   runtime. Runs as a non-root user. No ScanR code or secrets.
2. **Sandbox-runner service** (`backend/scanr/sandbox/runner_app.py`) — a tiny
   FastAPI app, the **only** holder of the Docker socket. `POST /exec` ensures a
   per-run session container exists, runs the command via `docker exec`, and
   returns output; `POST /session/stop` reaps it. Authenticated with a shared
   `SANDBOX_TOKEN`; only reachable on the internal compose network. No
   `SECRET_KEY`/`VAULT_KEY`/DB env.
3. **SandboxClient** (`backend/scanr/sandbox/client.py`) — worker-side HTTP
   client to the runner (`run` + `close`). **Fail-closed**: if no runner is
   configured or it's unreachable, command execution is denied (never silently
   "succeeds").
4. **Agent integration** — `AgentContext.run_command` + a gated `run_command`
   tool. New capability `allow_command_exec` (admin + aggressive + approval).
   The agent task reaps the session in a `finally` when the run ends.

## 3. Session container hardening

The per-run session container is created (`docker run -d`) with:
- `--network <sandbox-net>`, no bind mounts, no ScanR env; a keep-alive
  entrypoint (`sleep infinity`) so the runner can `docker exec` repeatedly.
- `--user` non-root, `--read-only` root fs + writable **tmpfs** for `/tmp`,
  `/work`, and `HOME` (so non-root `pip install --user` / `git clone` / language
  installers work despite the read-only rootfs),
  `--cap-drop ALL` (the sandbox gets **no** `NET_ADMIN`, so it cannot alter its
  own firewall), `--pids-limit`, `--memory`, `--cpus`, `--security-opt
  no-new-privileges`.
- A per-command wall-clock timeout enforced container-side (`timeout`) plus an
  asyncio backstop; a max-lifetime reaper destroys any session that outlives the
  cap. Because the rootfs is read-only and the user is non-root, system `apt`
  installs are unavailable by design — the fat image pre-bakes the toolkit.

## 4. Egress enforcement (mirrors only — targets NOT reachable)

The sandbox container **cannot** change its own networking (no `NET_ADMIN`), so
egress is enforced *around* it.

**What ships today:**

- **Default deny.** `sandbox_net` is a Docker `internal: true` network, so
  attached containers have no route to the internet or the LAN at all. This holds
  regardless of what the command does — unsetting the proxy env vars gains
  nothing, because there is no route to fall back to.
- **Package mirrors / installs:** the container's `http(s)_proxy` points at
  **sandbox-proxy** (tinyproxy) with a domain allowlist — PyPI, Debian/Ubuntu,
  GitHub, Kali (`backend/sandbox/proxy/filter`). It is dual-homed and is the only
  bridge between `sandbox_net` and the egress network, so allowlisted mirror
  domains are the sandbox's entire reachable surface.
- **No path to the runner.** sandbox-runner holds the Docker socket
  (root-equivalent on the host) and is deliberately **not** attached to
  `sandbox_net`, so a sandbox escape has nothing to pivot to. It creates and execs
  containers via the socket, which needs no network adjacency.

**What is NOT implemented — and the consequence:**

Per-target egress (the original design: the runner programming nftables/iptables
rules for the scan's authorized CIDRs) was never built. Because the network is
`internal: true`, the practical effect is that **the sandbox cannot reach scan
targets at all**. This fails *safe* — the sandbox can never touch an
out-of-scope host — but it also means `run_command` is useful only for local work
(analysis, offline cracking, payload generation, building tooling), not for
scanning or exploiting a target. `run_command`'s tool description states this
explicitly so the agent does not waste iterations discovering it.

To touch a target, the agent uses the scope-checked tools that run from the
worker: `run_port_scan`, `run_plugin`, `fetch_url`, `submit_form`.

> If target egress is added later it must be opt-in, per-scan, derived from the
> scan's authorized scope, re-checked against `is_forbidden_target`, and
> fail-closed — and this section plus the `run_command` tool description must be
> updated in the same change.

## 5. Gating (all enforced in code, layered)

`run_command` is the most powerful tool, so it stacks every guardrail:
1. **Capability:** requires `allow_command_exec` (a new aggressive opt-in) — so
   `aggressive=True` **and** that flag, which is **admin-only** at launch.
2. **Approval:** in guided mode every command waits for operator allow/deny.
3. **Scope:** enforced at the **network layer**. Arbitrary command text can't be
   parsed per-argument, so the container simply has no route to anything but the
   mirror allowlist (§4) — including no route to any scan target.
4. **Isolation:** runs in the jailed sandbox, never the worker; no secrets
   reachable.
5. **Budget + audit:** counts against the run budget; every command + output is
   streamed to the console and persisted in the run transcript.
6. **Fail-closed:** no runner configured/reachable → denied. The network-level
   default deny needs no per-run setup step that could fail open.

## 6. Config

| Setting | Default | Purpose |
|---|---|---|
| `SANDBOX_RUNNER_URL` | empty | Internal URL of the runner. Empty = command exec disabled (fail-closed). |
| `SANDBOX_TOKEN` | empty | Shared auth token between worker and runner. |
| `SANDBOX_IMAGE` | `scanr-sandbox:latest` | Toolkit image the runner spawns. |
| `SANDBOX_MAX_SESSIONS` | 8 | Ceiling on live session containers, so a caller cannot exhaust the host. |
| `SANDBOX_MAX_LIFETIME` | 3600 | Hard cap on one session container's lifetime; the reaper destroys older ones. |

The proxy's mirror allowlist is a file, not an env var: `backend/sandbox/proxy/filter` (mounted read-only, one regex per line).
| `SANDBOX_CMD_TIMEOUT` | 120 | Per-command wall-clock seconds. |

## 7. Build slices

1. **(this slice)** Design + agent-side contract: capability, `run_command`
   tool, `AgentContext.run_command`, `SandboxClient` (fail-closed), settings,
   policy, unit tests. Inert until a runner is configured.
2. Runner service + sandbox image + compose wiring (socket isolated to runner).
3. Egress: filtering proxy + `internal: true` network — **done**. Per-target
   firewall rules — **not implemented** (see §4); the sandbox therefore cannot
   reach scan targets.
4. UI: surface `run_command` actions/output in the transcript (already generic);
   add the `allow_command_exec` toggle to the aggressive opt-ins.

## 8. Residual risk (be honest)
A shell — even jailed — is the highest-risk feature in ScanR. The isolation
(no secrets, no route off the mirror allowlist, no `NET_ADMIN`, non-root,
lifetime-capped) contains the blast radius, but the runner holding the Docker
socket is root-equivalent on its host; keep it minimal, keep it off
`sandbox_net`, and consider gVisor/Sysbox or a separate host for high-stakes
deployments. Only enable `allow_command_exec` against systems you are authorized
to actively exploit.
