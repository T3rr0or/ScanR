from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from scanr.config import Settings

_BASE = {
    "secret_key": "test-secret-key-minimum-32-characters-long!!",
    "admin_password": "testadminpass123",
}
_ROOT = Path(__file__).resolve().parents[3]


def test_insecure_cookies_are_rejected_outside_explicit_development_mode() -> None:
    with pytest.raises(ValidationError, match="DEVELOPMENT_MODE=true"):
        Settings(
            _env_file=None,
            **_BASE,
            debug=True,
            development_mode=False,
            secure_cookies=False,
        )


def test_insecure_cookies_are_available_for_explicit_local_development() -> None:
    configured = Settings(
        _env_file=None,
        **_BASE,
        development_mode=True,
        secure_cookies=False,
    )
    assert configured.secure_cookies is False


@pytest.mark.parametrize("role", ["scan-worker", "ai-worker", "control-worker"])
def test_non_api_process_roles_do_not_require_jwt_or_admin_secrets(role: str) -> None:
    configured = Settings(
        _env_file=None,
        process_role=role,
        secret_key="",
        admin_password="",
        secure_cookies=True,
    )
    assert configured.process_role == role


def test_api_process_role_still_fails_closed_without_bootstrap_secrets() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(
            _env_file=None,
            process_role="api",
            secret_key="",
            admin_password="",
            secure_cookies=True,
        )


def test_unknown_process_role_is_rejected() -> None:
    with pytest.raises(ValidationError, match="PROCESS_ROLE"):
        Settings(
            _env_file=None,
            process_role="everything-worker",
            secret_key="",
            admin_password="",
            secure_cookies=True,
        )


def test_compose_keeps_plaintext_ports_on_loopback() -> None:
    compose = (_ROOT / "docker-compose.yml").read_text()
    assert "DEVELOPMENT_MODE: ${DEVELOPMENT_MODE:-false}" in compose
    assert '"${SCANR_API_BIND:-127.0.0.1}:8000:8000"' in compose
    assert '"${SCANR_UI_BIND:-127.0.0.1}:80:80"' in compose


def test_frontend_emits_hsts_for_tls_reverse_proxy_deployments() -> None:
    nginx = (_ROOT / "frontend/nginx.conf").read_text()
    assert 'Strict-Transport-Security "max-age=31536000" always' in nginx
