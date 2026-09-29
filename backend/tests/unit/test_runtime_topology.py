from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[3]
_COMPOSE = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
_SERVICES = _COMPOSE["services"]


def _environment(service: str) -> dict[str, str]:
    return _SERVICES[service].get("environment", {})


def _command(service: str) -> list[str]:
    command = _SERVICES[service]["command"]
    return command if isinstance(command, list) else command.split()


def test_every_active_service_uses_only_declared_explicit_networks() -> None:
    defined = set(_COMPOSE.get("networks", {}))
    referenced: set[str] = set()
    for name, service in _SERVICES.items():
        if service.get("profiles"):
            continue
        assert service.get("networks"), f"active service {name!r} fell onto the shared default network"
        networks = service["networks"]
        referenced.update(networks if isinstance(networks, list) else networks.keys())
    assert not referenced - defined, f"undefined networks referenced: {sorted(referenced - defined)}"


def test_service_networks_enforce_the_runtime_trust_boundaries() -> None:
    expected = {
        "redis": {"data"},
        "postgres": {"data"},
        "frontend": {"frontend", "ingress"},
        "api": {"frontend", "data", "api_egress"},
        "scan-worker": {"data", "browser_control", "scan_egress"},
        "ai-worker": {"data", "browser_control", "sandbox_control", "scan_egress"},
        "control-worker": {"data"},
        "browser": {"browser_control", "scan_egress"},
        "sandbox-runner": {"sandbox_control"},
    }
    for service, networks in expected.items():
        assert set(_SERVICES[service]["networks"]) == networks

    for network in ("frontend", "data", "browser_control", "sandbox_control"):
        assert _COMPOSE["networks"][network].get("internal") is True


def test_celery_consumers_have_one_explicit_queue_and_process_role_each() -> None:
    expected = {
        "scan-worker": ("scan-worker", "scan"),
        "ai-worker": ("ai-worker", "ai"),
        "control-worker": ("control-worker", "control"),
    }
    for service, (role, queue) in expected.items():
        command = _command(service)
        assert command[command.index("-Q") + 1] == queue
        assert _environment(service)["PROCESS_ROLE"] == role
    assert "--beat" not in _command("scan-worker")
    assert "--beat" not in _command("ai-worker")
    assert "--beat" in _command("control-worker")


def test_worker_environments_do_not_receive_unneeded_secrets() -> None:
    scan = _environment("scan-worker")
    ai = _environment("ai-worker")
    control = _environment("control-worker")

    for env in (scan, ai, control):
        assert "SECRET_KEY" not in env
        assert "ADMIN_PASSWORD" not in env
    assert "VAULT_KEY" in scan
    assert "VAULT_KEY" in ai
    assert "VAULT_KEY" not in control
    assert "VAULT_KEY" in _environment("api")
    assert "VAULT_KEY" not in _environment("browser")
    assert "VAULT_KEY" not in _environment("sandbox-runner")

    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "SANDBOX_TOKEN",
        "BROWSER_SERVICE_TOKEN",
    ):
        assert key not in control
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "SANDBOX_TOKEN"):
        assert key not in scan
        assert key in ai


def test_browser_is_secret_free_and_hardened() -> None:
    browser = _SERVICES["browser"]
    env = _environment("browser")
    assert set(env) == {
        "BROWSER_SERVICE_TOKEN",
        "BROWSER_VALIDATION_CONCURRENCY",
        "SCAN_TARGET_DENYLIST",
    }
    assert browser["read_only"] is True
    assert browser["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in browser["security_opt"]
    assert browser["tmpfs"] == ["/tmp:rw,nosuid,nodev,size=256m,mode=1777"]
    command = _command("browser")
    assert "--limit-concurrency" in command


def test_sandbox_runner_uses_per_run_network_and_proxy_images() -> None:
    env = _environment("sandbox-runner")
    assert "SANDBOX_NETWORK_PREFIX" in env
    assert "SANDBOX_PROXY_IMAGE" in env
    assert "SANDBOX_RELAY_IMAGE" in env
    assert "SANDBOX_NETWORK" not in env
    assert "SANDBOX_PROXY_URL" not in env
    assert "sandbox_net" not in _COMPOSE["networks"]
    assert _COMPOSE["networks"]["sandbox_egress"]["labels"] == {
        "scanr.sandbox.egress": "true"
    }
    for service in ("sandbox-proxy", "sandbox-relay"):
        assert _SERVICES[service].get("profiles") == ["build-only"]
