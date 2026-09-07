"""Structural guard: every endpoint must declare an authorization gate.

The 'viewer' role was unenforced partly because /templates and
/scans/{id}/exclusions used a bare get_current_user for their POST/PUT/DELETE
handlers — authenticating the caller but authorizing nothing, which also meant an
API key with only ':read' scopes could write. Reviewing that by eye does not
scale, so assert it: any new endpoint that forgets a gate fails here rather than
shipping.

require_scope is what carries both checks (API-key scope AND the viewer-role
check), so it is the expected gate.

Reads are covered too, on the same principle for a different reason. A GET
behind a bare get_current_user authenticates the caller but ignores the API
key's scopes entirely, so a key issued for one narrow integration reads
everything else the owner can see. That is confined to the owner's own data —
these handlers filter by user_id, so it is not a cross-user leak — but it does
defeat the point of granting a scope subset. See _ALLOWED_UNGATED_READS for
which reads are deliberately ungated and which are a recorded gap.
"""
import ast
import pathlib
import re

import pytest

_MUTATING = {"post", "put", "patch", "delete"}
_READ = {"get"}
_GATES = (
    "require_scope",
    "require_scopes",
    "require_admin_scope",
    "require_session_user",
    "require_session_admin",
    "_get_agent",
)

# Endpoints that legitimately have no authorization gate, with the reason.
_ALLOWED_UNGATED = {
    # Unauthenticated by definition — these are how you obtain/end a session.
    "auth.py:login",
    "auth.py:refresh",
    "auth.py:logout",
}

# Reads with no scope gate. Two very different categories, kept apart on
# purpose — the first is a decision, the second is a debt.
#
# (1) Nothing to authorize: a global catalog, the deployment's own posture, a
#     pure function over the request body, or "you are this user". A scope check
#     would gate data that carries no user's results.
_UNGATED_READ_BY_DESIGN = {
    # Unauthenticated by design — the container healthcheck probes it.
    "system.py:health",
    # Plugin catalog: identical for every caller, no scan data.
    "plugins.py:list_plugins",
    "plugins.py:get_plugin",
    # Pure function over the posted body; reads nothing.
    "profile_suggest.py:suggest_scan_profile",
    # Deployment posture, not results: whether AI is configured, what version is
    # running, how fresh the CVE feed is.
    "ai.py:ai_status",
    "system.py:version_check",
    "system.py:cve_status",
    # The agent installer script — the same artifact for every operator.
    "agent_jobs.py:download_agent_script",
    # Self-service: authorization is "you are this user", enforced by reading
    # current_user rather than an id from the request.
    "users.py:get_profile",
}

# (2) Recorded scope-enforcement debt. Keep this separate from deliberate
# exceptions so a future gap cannot be disguised as design. It is empty: result
# views reuse findings:read, scan configuration reuses scans:read, and plugin
# execution history uses plugins:read.
_UNGATED_READ_KNOWN_GAP: set[str] = set()

_ALLOWED_UNGATED_READS = _UNGATED_READ_BY_DESIGN | _UNGATED_READ_KNOWN_GAP

# Reads that may skip authentication entirely. Everything else must at minimum
# identify the caller, even when it declares no scope.
_UNAUTHENTICATED_READS = {"system.py:health"}

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


def _endpoints(methods: set[str]) -> list[tuple[str, str]]:
    """Return (identifier, signature source) for route handlers using `methods`."""
    found = []
    for path in sorted(_V1.glob("*.py")):
        source = path.read_text()
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not methods.intersection(_router_methods(node)):
                continue
            segment = ast.get_source_segment(source, node) or ""
            signature = segment.split("):")[0]
            found.append((f"{path.name}:{node.name}", signature))
    return found


def _has_gate(signature: str) -> bool:
    """Match dependency names exactly (``require_scope`` is a prefix of
    ``require_scopes``, so a plain substring check can hide the wrong guard)."""
    return any(re.search(rf"\b{re.escape(gate)}\b", signature) for gate in _GATES)


def _mutating_endpoints() -> list[tuple[str, str]]:
    return _endpoints(_MUTATING)


def _read_endpoints() -> list[tuple[str, str]]:
    # A handler registered for both GET and a mutating verb is covered by the
    # stricter mutating check, so drop it here rather than assert it twice.
    mutating = {name for name, _ in _mutating_endpoints()}
    return [(n, s) for n, s in _endpoints(_READ) if n not in mutating]


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
    assert _has_gate(signature), (
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


# ── reads ────────────────────────────────────────────────────────────────────

def test_read_discovery_actually_finds_endpoints():
    """Guard the guard, for the read walk."""
    endpoints = _read_endpoints()
    assert len(endpoints) > 40, f"only found {len(endpoints)} read endpoints"
    names = {name for name, _ in endpoints}
    assert "scans.py:list_scans" in names
    assert "findings.py:list_findings" in names


@pytest.mark.parametrize("name,signature", _read_endpoints(), ids=lambda v: v if isinstance(v, str) else "")
def test_read_endpoint_is_gated(name, signature):
    if name in _ALLOWED_UNGATED_READS:
        return
    assert _has_gate(signature), (
        f"{name} reads data but declares no authorization gate. Use "
        f"require_scope('<resource>:read') — a bare get_current_user ignores the "
        f"API key's scopes, so a key granted one narrow scope can read this too. "
        f"If it genuinely needs none (global catalog, system posture, pure "
        f"function, or self-service on current_user), add it to "
        f"_UNGATED_READ_BY_DESIGN with a reason."
    )


@pytest.mark.parametrize("name,signature", _read_endpoints(), ids=lambda v: v if isinstance(v, str) else "")
def test_ungated_read_still_authenticates(name, signature):
    """An ungated read must at least know who is calling.

    Skipping the scope check is a judgement call; skipping authentication makes
    the endpoint public, which is a different decision and needs its own entry.
    """
    if name in _UNAUTHENTICATED_READS:
        return
    gated = _has_gate(signature)
    assert gated or "get_current_user" in signature, (
        f"{name} is reachable without authentication. If that is intended, add "
        f"it to _UNAUTHENTICATED_READS with a reason."
    )


def test_read_allowlists_have_no_stale_entries():
    names = {name for name, _ in _read_endpoints()}
    stale = _ALLOWED_UNGATED_READS - names
    assert not stale, (
        f"read allowlists reference endpoints that no longer exist: {stale}"
    )
    stale_unauth = _UNAUTHENTICATED_READS - names
    assert not stale_unauth, (
        f"_UNAUTHENTICATED_READS references endpoints that no longer exist: {stale_unauth}"
    )


def test_read_allowlist_categories_are_disjoint():
    """A name in both sets would make the 'known gap' list quietly untrue."""
    overlap = _UNGATED_READ_BY_DESIGN & _UNGATED_READ_KNOWN_GAP
    assert not overlap, f"entries claim to be both deliberate and a gap: {overlap}"


def test_known_gap_list_only_shrinks():
    """Pin the size of the recorded gap.

    Gating one of these is a breaking change for existing API keys, so it is a
    deliberate call rather than something to do incidentally — but the count must
    never grow. A new ungated read belongs in _UNGATED_READ_BY_DESIGN with a
    reason, or behind a scope.
    """
    assert len(_UNGATED_READ_KNOWN_GAP) <= 20, (
        "the ungated-read gap grew; new ungated reads must be justified in "
        "_UNGATED_READ_BY_DESIGN or gated with require_scope"
    )


def test_viewer_gate_covers_every_write_scope():
    """Every non-read scope must be denied to viewers.

    _viewer_may_use is derived (deny unless ':read'), so this pins the resulting
    set: a new scope that reads as viewer-safe can't slip in unnoticed.
    """
    from scanr.deps import ALL_SCOPES, _viewer_may_use

    allowed = {s for s in ALL_SCOPES if _viewer_may_use(s)}
    assert allowed == {
        "scans:read", "findings:read", "reports:read", "credentials:read",
        "plugins:read", "agents:read", "api_keys:read", "webhooks:read",
        "wordlists:read", "host_tags:read",
    }, "viewer-permitted scope set changed — confirm the new scope is read-only"

    # No exceptions left: spending LLM budget and spawning report jobs are now
    # their own scopes, so neither is reachable by a read-only account.
    assert not _viewer_may_use("ai:generate")
    assert not _viewer_may_use("reports:create")
    assert not _viewer_may_use("reports:export")  # legacy alias, implies create

    # The wildcard must never be viewer-permitted, or a viewer's JWT session
    # (which is granted '*') would bypass the gate entirely.
    assert not _viewer_may_use("*")


def test_no_endpoint_uses_a_scope_outside_all_scopes():
    """A typo'd scope name would silently never match a real API key."""
    from scanr.deps import ALL_SCOPES

    scope_functions = {
        "ensure_scopes",
        "require_scope",
        "require_scopes",
        "require_admin_scope",
    }
    used = set()
    for path in _V1.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id not in scope_functions:
                continue
            used.update(
                arg.value
                for arg in node.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            )
    unknown = used - set(ALL_SCOPES)
    assert not unknown, f"endpoints reference scopes missing from ALL_SCOPES: {unknown}"


def test_privileged_endpoints_use_scope_aware_or_session_only_admin_guards():
    """A role-only admin dependency turns every narrow admin-owned API key into
    a full-control key. Pin each privileged route to an explicit scope, except
    self-update which deliberately refuses API keys entirely."""
    signatures = dict(_mutating_endpoints() + _read_endpoints())
    expected = {
        "users.py:list_users": "users:manage",
        "users.py:create_user": "users:manage",
        "users.py:update_user": "users:manage",
        "users.py:delete_user": "users:manage",
        "plugins.py:update_plugin": "plugins:write",
        "ai.py:set_api_key": "ai:configure",
        "ai.py:delete_api_key": "ai:configure",
        "ai.py:set_config": "ai:configure",
        "ai.py:set_model": "ai:configure",
        "ai.py:list_provider_models": "ai:configure",
        "integrations.py:get_topdesk_config": "integrations:manage",
        "integrations.py:set_topdesk_config": "integrations:manage",
        "integrations.py:delete_topdesk_config": "integrations:manage",
        "integrations.py:test_topdesk_config": "integrations:manage",
        "system.py:update_status": "system:manage",
        "system.py:reset_update_status": "system:manage",
        "system.py:cve_refresh": "system:manage",
    }
    for endpoint, scope in expected.items():
        signature = signatures[endpoint]
        assert re.search(
            rf'\brequire_admin_scope\s*\(\s*"{re.escape(scope)}"\s*\)',
            signature,
        ), f"{endpoint} must require admin role plus {scope!r}"

    assert re.search(
        r"\brequire_session_admin\b", signatures["system.py:start_update"]
    ), "self-update must reject even wildcard API keys"


def test_ai_actions_declare_both_resource_and_ai_scopes():
    """LLM spend and agent control must not ride on a scan/finding scope alone."""
    signatures = dict(_mutating_endpoints())

    assist = {
        "ai.py:summarize_scan",
        "ai.py:report_narrative",
        "ai.py:false_positives",
    }
    for endpoint in assist:
        signature = signatures[endpoint]
        assert "findings:read" in signature and "ai:generate" in signature

    agent_actions = {
        "ai.py:launch_agent",
        "ai.py:agent_chat",
        "ai.py:agent_stop",
        "ai.py:decide_agent_approval",
        "ai.py:cancel_agent_run",
    }
    for endpoint in agent_actions:
        signature = signatures[endpoint]
        assert "scans:write" in signature and "ai:agent" in signature

    scans_source = (_V1 / "scans.py").read_text()
    resolve_fn = next(
        node
        for node in ast.walk(ast.parse(scans_source))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_resolve_ai_agent_fields"
    )
    conditional_scopes = {
        arg.value
        for node in ast.walk(resolve_fn)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ensure_scopes"
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    }
    assert {"ai:agent", "ai:aggressive"} <= conditional_scopes
