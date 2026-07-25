"""Structural guard: every mutating endpoint must declare an authorization gate.

The 'viewer' role was unenforced partly because /templates and
/scans/{id}/exclusions used a bare get_current_user for their POST/PUT/DELETE
handlers — authenticating the caller but authorizing nothing, which also meant an
API key with only ':read' scopes could write. Reviewing that by eye does not
scale, so assert it: any new mutating endpoint that forgets a gate fails here
rather than shipping.

require_scope is what carries both checks (API-key scope AND the viewer-role
check), so it is the expected gate for user-facing writes.
"""
import ast
import pathlib
import re

import pytest

_MUTATING = {"post", "put", "patch", "delete"}
_GATES = ("require_scope", "require_admin", "_get_agent")

# Endpoints that legitimately have no authorization gate, with the reason.
_ALLOWED_UNGATED = {
    # Unauthenticated by definition — these are how you obtain a session.
    "auth.py:login",
    "auth.py:refresh",
    "auth.py:logout",
    # Self-service on your own account. Deliberately available to every role,
    # including viewers: authorization is "you are this user", enforced by
    # operating on current_user rather than an id from the request.
    "users.py:update_profile",
    "users.py:change_password",
}

_V1 = pathlib.Path(__file__).resolve().parents[2] / "scanr" / "api" / "v1"


def _router_methods(node: ast.AST) -> list[str]:
    methods = []
    for dec in getattr(node, "decorator_list", []):
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        target = dec.func.value
        is_router = (
            getattr(target, "id", None) == "router"
            or getattr(target, "attr", None) == "router"
        )
        if is_router:
            methods.append(dec.func.attr)
    return methods


def _mutating_endpoints() -> list[tuple[str, str]]:
    """Return (identifier, signature source) for every mutating route handler."""
    found = []
    for path in sorted(_V1.glob("*.py")):
        source = path.read_text()
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _MUTATING.intersection(_router_methods(node)):
                continue
            segment = ast.get_source_segment(source, node) or ""
            signature = segment.split("):")[0]
            found.append((f"{path.name}:{node.name}", signature))
    return found


def test_discovery_actually_finds_endpoints():
    """Guard the guard: a broken AST walk would make this suite vacuously pass."""
    endpoints = _mutating_endpoints()
    assert len(endpoints) > 40, f"only found {len(endpoints)} mutating endpoints"
    names = {name for name, _ in endpoints}
    assert "scans.py:create_scan" in names
    assert "templates.py:create_template" in names
    assert "exclusions.py:delete_exclusion" in names


@pytest.mark.parametrize("name,signature", _mutating_endpoints(), ids=lambda v: v if isinstance(v, str) else "")
def test_mutating_endpoint_is_gated(name, signature):
    if name in _ALLOWED_UNGATED:
        return
    assert any(gate in signature for gate in _GATES), (
        f"{name} mutates state but declares no authorization gate. Use "
        f"require_scope('<resource>:write') — a bare get_current_user "
        f"authenticates without authorizing, so viewers and read-only API keys "
        f"would be allowed through. If it genuinely needs none, add it to "
        f"_ALLOWED_UNGATED with a reason."
    )


def test_allowlist_has_no_stale_entries():
    """A removed/renamed endpoint must not leave a permanent hole behind."""
    names = {name for name, _ in _mutating_endpoints()}
    stale = _ALLOWED_UNGATED - names
    assert not stale, f"_ALLOWED_UNGATED references endpoints that no longer exist: {stale}"


def test_viewer_gate_covers_every_write_scope():
    """Every non-read scope must be denied to viewers.

    _viewer_may_use is derived (deny unless ':read'), so this mainly pins the
    deliberate exceptions: a new one can't be added without updating this test.
    """
    from scanr.deps import ALL_SCOPES, _viewer_may_use

    allowed = {s for s in ALL_SCOPES if _viewer_may_use(s)}
    assert allowed == {
        "scans:read", "findings:read", "reports:read", "credentials:read",
        "plugins:read", "agents:read", "api_keys:read", "webhooks:read",
        "wordlists:read", "host_tags:read",
        # Deliberate exception: also gates report *download*, which is the whole
        # point of a read-only account. See the comment in scanr/deps.py.
        "reports:export",
    }, "viewer-permitted scope set changed — confirm the new scope is read-only"

    # The wildcard must never be viewer-permitted, or a viewer's JWT session
    # (which is granted '*') would bypass the gate entirely.
    assert not _viewer_may_use("*")


def test_no_endpoint_uses_a_scope_outside_all_scopes():
    """A typo'd scope name would silently never match a real API key."""
    from scanr.deps import ALL_SCOPES

    used = set()
    for path in _V1.glob("*.py"):
        used.update(re.findall(r'require_scope\(\s*"([^"]+)"\s*\)', path.read_text()))
    unknown = used - set(ALL_SCOPES)
    assert not unknown, f"endpoints reference scopes missing from ALL_SCOPES: {unknown}"
