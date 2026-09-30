#!/usr/bin/env python3
"""Create a private ScanR .env and optionally start the Docker deployment."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_SECRETS = {
    "SECRET_KEY": lambda: secrets.token_urlsafe(32),
    "VAULT_KEY": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(24),
    "ADMIN_PASSWORD": lambda: secrets.token_urlsafe(24),
    "SANDBOX_TOKEN": lambda: secrets.token_hex(32),
    "BROWSER_SERVICE_TOKEN": lambda: secrets.token_hex(32),
}
EMAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$")
HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")


class SetupError(Exception):
    """An actionable setup error suitable for displaying to the operator."""


def validate_origin(value: str) -> str:
    value = value.strip()
    if not value or any(ch.isspace() for ch in value):
        raise argparse.ArgumentTypeError("origin must be a single http://localhost or https:// origin")
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("origin must contain a valid hostname and port") from exc
    if not hostname or (port is not None and not 1 <= port <= 65535):
        raise argparse.ArgumentTypeError("origin must contain a valid hostname and port")
    # Restrict values written into dotenv to ordinary DNS/IP origin characters.
    # This excludes Compose interpolation and dotenv quoting/comment syntax.
    try:
        ipaddress.ip_address(hostname)
        valid_host = True
    except ValueError:
        labels = hostname.rstrip(".").split(".")
        valid_host = bool(hostname.rstrip(".")) and (hostname.lower() == "localhost" or all(HOST_LABEL_RE.fullmatch(label) for label in labels))
    local_http = parsed.scheme == "http" and hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    secure = parsed.scheme == "https" and valid_host
    if not (local_http or secure) or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError("origin must be http://localhost (or loopback) or an https:// origin, without a path")
    return value.rstrip("/")


def validate_email(value: str) -> str:
    value = value.strip()
    if not EMAIL_RE.fullmatch(value) or ".." in value or value.endswith("."):
        raise argparse.ArgumentTypeError("admin email must be a valid email address")
    return value


def create_env(env_example: Path, env_path: Path, origin: str, admin_email: str) -> None:
    if env_path.exists():
        raise SetupError(f"Refusing to overwrite existing {env_path}. Keep it safe and edit it manually.")
    if not env_example.is_file():
        raise SetupError(f"Missing template: {env_example}")

    contents = env_example.read_text(encoding="utf-8")
    replacements = dict((key, make()) for key, make in REQUIRED_SECRETS.items())
    replacements.update({"ADMIN_EMAIL": admin_email, "ALLOWED_ORIGINS": origin})
    lines = []
    found: set[str] = set()
    for line in contents.splitlines():
        key, separator, _ = line.partition("=")
        if separator and key in replacements:
            lines.append(f"{key}={replacements[key]}")
            found.add(key)
        else:
            lines.append(line)
    missing = set(replacements) - found
    if missing:
        raise SetupError(f"Template is missing expected settings: {', '.join(sorted(missing))}")
    payload = "\n".join(lines) + "\n"
    # O_EXCL closes the race between the initial existence check and creation.
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write(payload)
    except Exception:
        try:
            env_path.unlink()
        except OSError:
            pass
        raise
    os.chmod(env_path, 0o600)


def run_compose(env_path: Path) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise SetupError("Docker was not found. Install Docker Engine and Docker Compose v2, then run this command again.")
    version = subprocess.run([docker, "compose", "version"], cwd=ROOT, capture_output=True, text=True)
    if version.returncode:
        raise SetupError("Docker Compose v2 is required (the `docker compose` plugin was not available).")

    base = [docker, "compose", "--env-file", str(env_path)]
    config = subprocess.run(base + ["config", "--format", "json"], cwd=ROOT, capture_output=True, text=True)
    if config.returncode:
        raise SetupError("Compose configuration validation failed. Check .env and docker-compose.yml.")
    try:
        resolved = json.loads(config.stdout)
        environment = resolved["services"]["sandbox-runner"]["environment"]
        sandbox_image = environment["SANDBOX_IMAGE"]
        allowed_origins = resolved["services"]["api"]["environment"]["ALLOWED_ORIGINS"]
    except (KeyError, TypeError, ValueError) as exc:
        raise SetupError("Could not resolve SANDBOX_IMAGE from the Compose configuration.") from exc
    success_origin = allowed_origins.split(",", 1)[0].strip() or "http://localhost"
    commands = [
        (base + ["--profile", "build-only", "pull"], "Could not pull required container images."),
        ([docker, "pull", sandbox_image], "Could not pull the configured sandbox image."),
        (base + ["up", "-d", "--wait"], "Compose could not start all services healthy."),
    ]
    phases = ("Pulling Compose images (including build-only images)...", "Pulling the configured sandbox image...", "Starting services and waiting for health checks...")
    for (command, error), phase in zip(commands, phases):
        print(phase, flush=True)
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if result.returncode:
            raise SetupError(error)
    return success_origin


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Configure ScanR safely for a first install.")
    result.add_argument("--origin", type=validate_origin, default="http://localhost", help="browser origin (localhost HTTP or HTTPS); default: http://localhost")
    result.add_argument("--admin-email", type=validate_email, default="admin@example.com", help="email for the initial administrator")
    result.add_argument("--start", action="store_true", help="validate Docker Compose, pull images, and start ScanR")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    env_path = ROOT / ".env"
    try:
        if env_path.exists():
            if not args.start:
                raise SetupError(f"Refusing to overwrite existing {env_path}. Use --start to start from this configuration, or edit it manually.")
            print("Using existing .env; it was not modified.")
        else:
            create_env(ROOT / ".env.example", env_path, args.origin, args.admin_email)
            print("Created .env with unique secrets and owner-only permissions. Secret values were not displayed.")
        if not args.start:
            print("The generated administrator password is stored in the private .env file; keep it safe.")
            print("Next: review .env, then run `python3 scripts/setup.py --start` to pull images and start ScanR.")
            print(f"Open {args.origin} when startup finishes. For remote access, use HTTPS and set ALLOWED_ORIGINS to its exact origin.")
            return 0
        print("The administrator password is stored in the private .env file; keep it safe.")
        success_origin = run_compose(env_path)
        print("ScanR services are running and healthy. Open " + success_origin + " in your browser.")
        return 0
    except (SetupError, OSError) as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
