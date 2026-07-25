"""Every image compose can build must also be published.

sandbox-relay was added to docker-compose.yml but not to the publish matrix, so
the tag its default SANDBOX_RELAY_IMAGE points at never existed. Nothing failed at
build, deploy or startup — it only surfaced at runtime, as a denied session the
first time a scan opted into target egress.

Cross-checking the two files makes the next such omission a test failure instead.
"""
import pathlib
import re

import pytest
import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[3]
_COMPOSE = _ROOT / "docker-compose.yml"
_PUBLISH = _ROOT / ".github" / "workflows" / "docker-publish.yml"


def _compose() -> dict:
    # Substitute ${VAR:-default} / ${VAR} so the file parses without an env.
    raw = _COMPOSE.read_text()
    raw = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}", r"\1", raw)
    raw = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\?[^}]*\}", "placeholder", raw)
    raw = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "placeholder", raw)
    return yaml.safe_load(raw)


def _buildable_images() -> dict[str, str]:
    """service name -> published image name, for every service compose builds."""
    out = {}
    for name, svc in _compose()["services"].items():
        if not isinstance(svc, dict) or "build" not in svc:
            continue
        image = svc.get("image", "")
        # ghcr.io/<owner>/<image-name>:<tag> -> <image-name>
        match = re.search(r"/([a-z0-9-]+):", image)
        if match:
            out[name] = match.group(1)
    return out


def _published_images() -> set[str]:
    matrix = yaml.safe_load(_PUBLISH.read_text())
    entries = matrix["jobs"]["publish"]["strategy"]["matrix"]["image"]
    return {e["name"] for e in entries}


def test_discovery_is_not_vacuous():
    buildable = _buildable_images()
    assert len(buildable) >= 6, f"only found {buildable} — the parser is broken"
    assert "sandbox-relay" in buildable


def test_every_buildable_image_is_published():
    missing = set(_buildable_images().values()) - _published_images()
    assert not missing, (
        f"images built by docker-compose.yml but absent from the publish matrix: "
        f"{sorted(missing)}. They will not exist in the registry, and the failure "
        f"only appears at runtime."
    )


def test_published_dockerfiles_all_exist():
    matrix = yaml.safe_load(_PUBLISH.read_text())
    for entry in matrix["jobs"]["publish"]["strategy"]["matrix"]["image"]:
        path = _ROOT / entry["context"].lstrip("./") / entry["file"]
        assert path.is_file(), f"{entry['name']} references a missing {path}"


@pytest.mark.parametrize("service", ["sandbox-relay"])
def test_build_only_services_are_not_started_by_compose(service):
    """The relay is spawned per run by the runner, so compose must not run one —
    a long-lived shared relay would mean one scope for every scan."""
    svc = _compose()["services"][service]
    assert svc.get("profiles"), f"{service} must be profiled so compose does not start it"
