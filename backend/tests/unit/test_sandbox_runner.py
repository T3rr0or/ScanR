import asyncio
import json
import sys

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
    args = runner_app._create_args(
        "scanr-sbx-test", ["192.0.2.0/24"], "scanr-sbx-net-test",
        proxy="scanr-pxy-test",
    )

    # detached, non-root, locked-down
    assert "-d" in args
    assert args[args.index("--user") + 1] == "1000:1000"
    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in args
    assert args[args.index("--network") + 1] == "scanr-sbx-net-test"
    assert "--pids-limit" in args
    assert runner_app._SESSION_LABEL in args
    assert f"{runner_app._RESOURCE_LABEL_KEY}=sandbox" in args
    # writable HOME so non-root pip/install works despite read-only rootfs
    assert any(a.startswith(f"HOME={runner_app._HOME}") for a in args)
    # keep-alive entrypoint so we can exec repeatedly
    assert args[-3:] == [runner_app._IMAGE, "sleep", "infinity"]
    # install proxy is injected
    assert any("HTTP_PROXY=http://scanr-pxy-test:8888" in a for a in args)


def test_exec_args_run_command_with_timeout():
    args = runner_app._exec_args("scanr-sbx-test", "id", 30)
    assert args[:3] == ["docker", "exec", "-u"]
    assert "scanr-sbx-test" in args
    # command runs via a shell under a container-side timeout
    assert args[-3:] == ["/bin/sh", "-lc", "id"]
    assert "timeout" in args
    assert "30" in args


@pytest.mark.asyncio
async def test_run_docker_retains_only_bounded_output(monkeypatch):
    """Output is discarded while the child is running, not after an unbounded
    communicate() has already accumulated it in runner memory."""
    monkeypatch.setattr(runner_app, "_MAX_STDOUT", 32)
    monkeypatch.setattr(runner_app, "_MAX_STDERR", 16)
    code, out, err, timed_out = await runner_app._run_docker(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('o' * 100000); sys.stderr.write('e' * 100000)",
        ],
        timeout=10,
    )
    assert code == 0
    assert not timed_out
    # One extra byte is deliberately retained as the truncation sentinel.
    assert out == "o" * 33
    assert err == "e" * 17


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
async def test_existing_session_rejects_changed_scope_or_egress(monkeypatch):
    monkeypatch.setattr(runner_app, "_SESSIONS", {})

    async def fake_run_docker(args, timeout):
        return 0, "", "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)
    name = await runner_app._ensure_session(
        "run1", [" 198.51.100.2 ", "192.0.2.0/24", "198.51.100.2"]
    )
    session = runner_app._SESSIONS["run1"]
    assert session.scope == ("192.0.2.0/24", "198.51.100.2")
    # Ordering, duplicates, and surrounding whitespace are not policy changes.
    assert await runner_app._ensure_session(
        "run1", ["198.51.100.2", "192.0.2.0/24"]
    ) == name

    with pytest.raises(HTTPException) as exc:
        await runner_app._ensure_session("run1", ["192.0.2.0/24"])
    assert exc.value.status_code == 409

    with pytest.raises(HTTPException) as exc:
        await runner_app._ensure_session(
            "run1", ["198.51.100.2", "192.0.2.0/24"], target_egress=True
        )
    assert exc.value.status_code == 409


def test_scope_normalization_rejects_env_list_injection():
    assert runner_app._normalize_scope(
        ["192.0.2.99/24", "2001:0db8::1", "192.0.2.0/24"]
    ) == ("192.0.2.0/24", "2001:db8::1")
    with pytest.raises(HTTPException) as exc:
        runner_app._normalize_scope(["192.0.2.1,0.0.0.0/0"])
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_health_leaks_nothing(monkeypatch):
    """Unauthenticated probe must not report image or live session count."""
    monkeypatch.setattr(
        runner_app, "_SESSIONS",
        {"r": runner_app.Session(name="n", network="scanr-sbx-net-n")},
    )
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


# ── per-run egress relay ──────────────────────────────────────────────────────

def test_each_session_network_is_internal_and_labeled():
    args = runner_app._network_args("scanr-sbx-net-test")
    assert args[:3] == ["docker", "network", "create"]
    assert "--internal" in args
    assert "scanr.sandbox.session=true" in args
    assert f"{runner_app._RESOURCE_LABEL_KEY}=network" in args
    assert args[-1] == "scanr-sbx-net-test"


def test_run_local_proxy_is_hardened_and_uses_only_its_session_network():
    args = runner_app._proxy_args("scanr-pxy-test", "scanr-sbx-net-test")
    assert args[args.index("--network") + 1] == "scanr-sbx-net-test"
    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in args
    assert runner_app._SESSION_LABEL in args
    assert f"{runner_app._RESOURCE_LABEL_KEY}=proxy" in args
    assert args[-1] == runner_app._PROXY_IMAGE


def test_relay_args_are_hardened_and_carry_the_scope(monkeypatch):
    monkeypatch.setattr(runner_app, "_EGRESS_DENY", ("172.18.0.0/16",))
    args = runner_app._relay_args(
        "scanr-rly-test", ["192.0.2.0/24", "198.51.100.7"],
        "scanr-sbx-net-test",
    )
    assert args[args.index("--user") + 1] == "1000:1000"
    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in args
    assert runner_app._SESSION_LABEL in args
    assert f"{runner_app._RESOURCE_LABEL_KEY}=relay" in args
    # Starts on the internal network; the egress leg is attached separately.
    assert args[args.index("--network") + 1] == "scanr-sbx-net-test"
    assert any("SCANR_ALLOWED_CIDRS=192.0.2.0/24,198.51.100.7" in a for a in args)
    # The shared egress bridge is denied, so one run cannot reach a sibling
    # run's relay and borrow its scope.
    assert any("SCANR_DENIED_CIDRS=172.18.0.0/16" in a for a in args)
    # No ScanR secrets, no Docker socket.
    assert not any("VAULT" in a or "SECRET" in a or "docker.sock" in a for a in args)


def test_relay_is_refused_when_the_egress_subnet_is_unknown(monkeypatch):
    """Fail closed: an unguarded relay would allow cross-run pivots."""
    monkeypatch.setattr(runner_app, "_EGRESS_DENY", ())
    with pytest.raises(HTTPException) as exc:
        runner_app._relay_args("scanr-rly-test", ["192.0.2.0/24"], "scanr-sbx-net-test")
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_concurrent_sessions_never_share_a_network(monkeypatch):
    monkeypatch.setattr(runner_app, "_SESSIONS", {})
    monkeypatch.setattr(runner_app, "_PENDING", {})
    monkeypatch.setattr(runner_app, "_EGRESS_DENY", ("172.18.0.0/16",))

    async def fake_run_docker(args, timeout):
        return 0, "", "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)
    await runner_app._ensure_session("run-a", ["192.0.2.1"], target_egress=True)
    await runner_app._ensure_session("run-b", ["198.51.100.2"], target_egress=True)

    first, second = runner_app._SESSIONS.values()
    assert first.network != second.network
    assert first.relay != second.relay
    assert first.proxy != second.proxy


@pytest.mark.asyncio
async def test_slow_session_creation_does_not_block_other_runs(monkeypatch):
    """One run's container bring-up must not serialize every other run.

    _ensure_session runs on every /exec, so holding a global lock across the
    (minutes-long, worst case) docker bring-up froze unrelated runs' tool calls.
    """
    monkeypatch.setattr(runner_app, "_SESSIONS", {})
    monkeypatch.setattr(runner_app, "_PENDING", {})
    block = asyncio.Event()

    async def fake_run_docker(args, timeout):
        # Only the slow run's container create waits; everything else is instant.
        if "run-slow" in " ".join(args):
            await block.wait()
        return 0, "", "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)

    slow = asyncio.create_task(runner_app._ensure_session("run-slow", ["192.0.2.1"]))
    await asyncio.sleep(0)  # let the slow creation start and park

    # The fast run must complete while the slow one is still mid-creation.
    name = await asyncio.wait_for(
        runner_app._ensure_session("run-fast", ["198.51.100.2"]), timeout=1.0
    )
    assert name in {s.name for s in runner_app._SESSIONS.values()}
    assert not slow.done()

    block.set()
    await asyncio.wait_for(slow, timeout=1.0)
    assert set(runner_app._SESSIONS) == {"run-slow", "run-fast"}


@pytest.mark.asyncio
async def test_concurrent_exec_for_one_run_creates_a_single_session(monkeypatch):
    """Callers racing on the same run_id share one creation, not one each."""
    monkeypatch.setattr(runner_app, "_SESSIONS", {})
    monkeypatch.setattr(runner_app, "_PENDING", {})
    creates = 0
    release = asyncio.Event()

    async def fake_run_docker(args, timeout):
        nonlocal creates
        if args[:2] == ["docker", "create"] or "--name" in args:
            creates += 1
        await release.wait()
        return 0, "", "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)

    waiters = [
        asyncio.create_task(runner_app._ensure_session("run-x", ["192.0.2.1"]))
        for _ in range(4)
    ]
    await asyncio.sleep(0)
    release.set()
    names = await asyncio.wait_for(asyncio.gather(*waiters), timeout=2.0)

    assert len(set(names)) == 1, "each caller should get the same container"
    assert list(runner_app._SESSIONS) == ["run-x"]
    assert runner_app._PENDING == {}


def test_relay_egress_leg_is_a_separate_attach():
    args = runner_app._connect_relay_args("scanr-rly-test")
    assert args[:3] == ["docker", "network", "connect"]
    assert args[3] == runner_app._EGRESS_NETWORK
    assert args[4] == "scanr-rly-test"


def test_sandbox_gets_no_socks_env_without_target_egress():
    """Default: no relay, so nothing should advertise a proxy that doesn't exist."""
    args = runner_app._create_args(
        "scanr-sbx-test", ["192.0.2.0/24"], "scanr-sbx-net-test", relay=None
    )
    assert not any("ALL_PROXY" in a for a in args)
    assert not any("SCANR_TARGET_EGRESS" in a for a in args)


def test_sandbox_points_at_the_relay_when_target_egress_is_on():
    args = runner_app._create_args(
        "scanr-sbx-test", ["192.0.2.0/24"], "scanr-sbx-net-test",
        relay="scanr-rly-test",
    )
    socks = f"socks5://scanr-rly-test:{runner_app._RELAY_PORT}"
    assert any(a == f"ALL_PROXY={socks}" for a in args)
    assert any(a == f"all_proxy={socks}" for a in args)
    assert any(a == "SCANR_TARGET_EGRESS=1" for a in args)
    # Still on the internal network only — the relay is the sole path out.
    assert args[args.index("--network") + 1] == "scanr-sbx-net-test"


@pytest.mark.asyncio
async def test_target_egress_without_scope_is_refused(monkeypatch):
    """Fail-closed: an empty scope must not start a relay that allows nothing."""
    monkeypatch.setattr(runner_app, "_SESSIONS", {})
    with pytest.raises(HTTPException) as exc:
        await runner_app._ensure_session("run1", [], target_egress=True)
    assert exc.value.status_code == 400
    assert not runner_app._SESSIONS


@pytest.mark.asyncio
async def test_relay_failure_denies_the_session(monkeypatch):
    """If the component that enforces scope can't start, the sandbox must not."""
    monkeypatch.setattr(runner_app, "_SESSIONS", {})
    monkeypatch.setattr(runner_app, "_PENDING", {})
    monkeypatch.setattr(runner_app, "_EGRESS_DENY", ("172.18.0.0/16",))
    removed: list[str] = []

    async def fake_run_docker(args, timeout):
        if args[:2] == ["docker", "run"] and "scanr-rly-" in " ".join(args):
            return 1, "", "relay boom", False
        return 0, "", "", False

    async def fake_remove(name):
        removed.append(name)

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)
    monkeypatch.setattr(runner_app, "_remove_container", fake_remove)

    with pytest.raises(HTTPException) as exc:
        await runner_app._ensure_session("run1", ["192.0.2.0/24"], target_egress=True)
    assert exc.value.status_code == 502
    assert "egress relay" in exc.value.detail
    assert not runner_app._SESSIONS, "no session may exist without its relay"
    assert any("scanr-rly-" in n for n in removed), "relay must be cleaned up"


@pytest.mark.asyncio
async def test_network_attach_failure_denies_the_session(monkeypatch):
    """A relay with no egress leg would silently allow nothing; treat as failure."""
    monkeypatch.setattr(runner_app, "_SESSIONS", {})
    removed: list[str] = []

    async def fake_run_docker(args, timeout):
        if args[:3] == ["docker", "network", "connect"]:
            return 1, "", "attach boom", False
        return 0, "", "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)
    monkeypatch.setattr(runner_app, "_remove_container",
                        lambda name: removed.append(name) or asyncio.sleep(0))

    with pytest.raises(HTTPException) as exc:
        await runner_app._ensure_session("run1", ["192.0.2.0/24"], target_egress=True)
    assert exc.value.status_code == 502
    assert not runner_app._SESSIONS


@pytest.mark.asyncio
async def test_session_teardown_removes_the_relay_too(monkeypatch):
    """Leaving a relay running would keep a scope-authorized bridge to the
    targets alive with nothing on the other end."""
    removed: list[str] = []

    async def fake_remove(name):
        removed.append(name)

    monkeypatch.setattr(runner_app, "_remove_container", fake_remove)
    removed_networks: list[str] = []
    monkeypatch.setattr(
        runner_app, "_remove_network",
        lambda name: removed_networks.append(name) or asyncio.sleep(0),
    )
    await runner_app._destroy_session(
        runner_app.Session(
            name="scanr-sbx-x", network="scanr-sbx-net-x",
            proxy="scanr-pxy-x", relay="scanr-rly-x",
        )
    )
    assert removed == ["scanr-sbx-x", "scanr-rly-x", "scanr-pxy-x"]
    assert removed_networks == ["scanr-sbx-net-x"]


@pytest.mark.asyncio
async def test_reaper_removes_relays_of_stale_sessions(monkeypatch):
    removed: list[str] = []

    async def fake_remove(name):
        removed.append(name)

    monkeypatch.setattr(runner_app, "_remove_container", fake_remove)
    removed_networks: list[str] = []
    monkeypatch.setattr(
        runner_app, "_remove_network",
        lambda name: removed_networks.append(name) or asyncio.sleep(0),
    )
    monkeypatch.setattr(runner_app, "_MAX_LIFETIME", 0)
    monkeypatch.setattr(runner_app, "_REAP_INTERVAL", 0.01)
    monkeypatch.setattr(
        runner_app, "_SESSIONS",
        {"r": runner_app.Session(
            name="scanr-sbx-y", network="scanr-sbx-net-y", created=0.0,
            proxy="scanr-pxy-y", relay="scanr-rly-y",
        )},
    )
    task = asyncio.create_task(runner_app._reaper())
    await asyncio.sleep(0.1)
    task.cancel()
    assert set(removed) == {"scanr-sbx-y", "scanr-rly-y", "scanr-pxy-y"}
    assert removed_networks == ["scanr-sbx-net-y"]
    assert not runner_app._SESSIONS


# ── restart reconciliation ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_startup_reconciliation_removes_labeled_resources_and_old_members(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(
        runner_app,
        "_SESSIONS",
        {"stale": runner_app.Session(name="stale", network="stale-net")},
    )

    async def fake_run_docker(args, timeout):
        calls.append(args)
        if args[:4] == ["docker", "container", "ls", "-aq"]:
            return 0, "labeled-container\n", "", False
        if args[:4] == ["docker", "network", "ls", "-q"]:
            return 0, "labeled-network\n", "", False
        if args[:3] == ["docker", "network", "inspect"]:
            # Covers an upgrade from the prior runner: its network was labeled,
            # while the containers attached to it were not.
            return 0, json.dumps({"legacy-container": {"Name": "scanr-sbx-old"}}), "", False
        return 0, "", "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)
    await runner_app._reconcile_orphaned_resources()

    assert ["docker", "container", "rm", "-f", "labeled-container"] in calls
    assert ["docker", "container", "rm", "-f", "legacy-container"] in calls
    assert ["docker", "network", "rm", "labeled-network"] in calls
    assert not runner_app._SESSIONS


@pytest.mark.asyncio
async def test_startup_reconciliation_fails_closed_when_docker_cannot_be_audited(monkeypatch):
    async def broken_docker(args, timeout):
        return 1, "", "socket unavailable", False

    monkeypatch.setattr(runner_app, "_run_docker", broken_docker)
    with pytest.raises(RuntimeError, match="could not list labeled sandbox containers"):
        await runner_app._reconcile_orphaned_resources()


@pytest.mark.asyncio
async def test_egress_network_creation_is_labeled_non_internal_and_race_safe(monkeypatch):
    calls: list[list[str]] = []
    inspections = 0

    async def fake_run_docker(args, timeout):
        nonlocal inspections
        calls.append(args)
        if args[:3] == ["docker", "network", "inspect"]:
            inspections += 1
            if inspections == 1:
                return 1, "", "not found", False
            return 0, json.dumps({
                "Driver": "bridge",
                "Internal": False,
                "Labels": {runner_app._EGRESS_LABEL_KEY: "true"},
                "IPAM": {"Config": [{"Subnet": "172.18.0.0/16"}]},
            }), "", False
        if args[:3] == ["docker", "network", "create"]:
            # Another runner may win the create race. Re-inspection, rather than
            # this exit code, determines whether it is safe to continue.
            return 1, "", "already exists", False
        raise AssertionError(args)

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)
    await runner_app._ensure_egress_network()

    create = next(args for args in calls if args[:3] == ["docker", "network", "create"])
    assert create[create.index("--driver") + 1] == "bridge"
    assert runner_app._EGRESS_LABEL in create
    assert "--internal" not in create
    assert inspections == 2


@pytest.mark.asyncio
async def test_egress_network_with_wrong_security_properties_fails_closed(monkeypatch):
    async def fake_run_docker(args, timeout):
        return 0, json.dumps({
            "Driver": "bridge",
            "Internal": True,
            "Labels": {runner_app._EGRESS_LABEL_KEY: "true"},
        }), "", False

    monkeypatch.setattr(runner_app, "_run_docker", fake_run_docker)
    with pytest.raises(RuntimeError, match="not ScanR's labeled, non-internal bridge"):
        await runner_app._ensure_egress_network()
