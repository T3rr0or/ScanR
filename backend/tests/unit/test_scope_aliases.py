"""reports:export was split into reports:read + reports:create.

Downloading a report you can already list is a read — it contains nothing the
findings API does not expose — while generating one spawns a background job. The
split is what lets a read-only ('viewer') account fetch results without being
able to spend compute, removing the last exception in _viewer_may_use.

Existing API keys must keep working, so the old scope is honoured as an alias but
refused on new keys.
"""
import pytest

from scanr.deps import (
    ALL_SCOPES,
    DEPRECATED_SCOPES,
    _has_scope,
    _viewer_may_use,
    expand_scopes,
)


def test_legacy_export_scope_still_grants_both_replacements():
    """A key minted before the split must not lose access."""
    held = ["reports:export"]
    assert _has_scope(held, "reports:read")
    assert _has_scope(held, "reports:create")


def test_legacy_scope_grants_nothing_extra():
    held = ["reports:export"]
    for other in ("scans:write", "findings:triage", "ai:generate", "wordlists:write"):
        assert not _has_scope(held, other), other


def test_new_scopes_are_independent():
    assert _has_scope(["reports:read"], "reports:read")
    assert not _has_scope(["reports:read"], "reports:create")
    assert _has_scope(["reports:create"], "reports:create")
    assert not _has_scope(["reports:create"], "reports:read")


def test_wildcard_still_grants_everything():
    for scope in ALL_SCOPES:
        assert _has_scope(["*"], scope), scope


def test_ai_generate_is_not_implied_by_findings_read():
    """The AI endpoints used to ride on findings:read, so a read-only key could
    spend LLM budget. They now need their own scope."""
    assert not _has_scope(["findings:read"], "ai:generate")
    assert _has_scope(["ai:generate"], "ai:generate")


def test_expand_scopes_keeps_originals():
    assert expand_scopes(["reports:export"]) == {
        "reports:export", "reports:read", "reports:create",
    }
    assert expand_scopes(["scans:read"]) == {"scans:read"}
    assert expand_scopes([]) == set()


def test_deprecated_scopes_are_still_valid_scope_names():
    """They must stay in ALL_SCOPES, or an existing key's stored scope list would
    read as unknown."""
    assert DEPRECATED_SCOPES <= ALL_SCOPES


@pytest.mark.parametrize("scope", sorted(DEPRECATED_SCOPES))
def test_deprecated_scopes_are_never_viewer_permitted(scope):
    """A legacy alias must not become a back door into a write capability."""
    assert not _viewer_may_use(scope)
