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

# (2) Recorded gap, NOT an endorsement. These return the caller's own scan data
#     but check no scope, so any valid API key reads them regardless of what it
#     was granted. They are listed so the guard below can still fail on *new*
#     ungated reads instead of this class of hole growing silently.
#
#     Closing it is a breaking change and needs a deliberate call: most of these
#     resources have no read scope to require. ALL_SCOPES has no assets:*,
#     analytics:*, templates:*, vulnerabilities:*, screenshots:* or exclusions:*,
#     so gating them means either inventing scopes (existing keys lack them, so
#     they start 403ing) or folding them under findings:read / scans:read (same
#     breakage for keys without those). plugins.py's two are the exception —
#     plugins:read already exists and would fit today.
_UNGATED_READ_KNOWN_GAP = {
    # Aggregates computed over the caller's findings.
    "analytics.py:severity_distribution",
    "analytics.py:findings_timeline",
    "analytics.py:top_vulnerable_hosts",
    "analytics.py:scan_activity",
    "analytics.py:plugin_hit_rate",
    "analytics.py:remediation_rate",
    "analytics.py:open_critical_age",
    "analytics.py:remediation_groups",
    "system.py:stats",
    # Hosts and findings, reshaped.
    "assets.py:list_assets",
    "assets.py:asset_findings",
    "vulnerabilities.py:list_vulnerabilities",
    "vulnerabilities.py:vulnerability_hosts",
    # Scan configuration and artifacts.
    "templates.py:list_templates",
    "templates.py:get_template",
    "exclusions.py:list_exclusions",
    "screenshots.py:list_screenshots",
    "screenshots.py:get_screenshot_image",
    # Per-scan plugin execution history. plugins:read already exists for these.
    "plugins.py:list_plugin_runs",
    "plugins.py:plugin_health",
}

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
    assert any(gate in signature for gate in _GATES), (
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
    gated = any(gate in signature for gate in _GATES)
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

    used = set()
    for path in _V1.glob("*.py"):
        used.update(re.findall(r'require_scope\(\s*"([^"]+)"\s*\)', path.read_text()))
    unknown = used - set(ALL_SCOPES)
    assert not unknown, f"endpoints reference scopes missing from ALL_SCOPES: {unknown}"
