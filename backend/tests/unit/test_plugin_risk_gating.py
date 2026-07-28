"""Plugin risk declarations, and the gates that depend on them.

Two gates read a plugin's risk level, and both were inert:

  * the engine's safety_level="safe" filter read a bare `intrusive` attribute
    that PluginBase never declared and no plugin ever set, so the clause
    collapsed to a "default_creds" substring match — a "safe" scan still sent
    SQLi, XXE, SSTI, traversal and JNDI payloads at the target;
  * the agent's allow_exploitation capability read `destructive`, which is
    declared on PluginBase but was set by exactly one plugin, to False. Nothing
    was ever denied, and list_plugins told the model every plugin was safe.

The declarations are the load-bearing part: a gate that reads a field nobody
sets is indistinguishable from no gate. These pin both the declarations and the
gates they feed.
"""
import pytest

from scanr.core.engine import _filter_plugins_by_capabilities
from scanr.core.plugin_base import PluginBase
from scanr.core.plugin_manager import get_all_plugin_classes, get_all_plugin_ids, get_enabled_plugins

# Checks that send attack payloads. Reviewed individually; each either injects a
# payload (SQL, template, traversal, XXE, JNDI, XSS) or drives the target into
# making a request it did not intend.
_PAYLOAD_PLUGINS = {
    "web.sqli_detect", "web.sqli_blind", "web.xss_detect", "web.ssti_detect",
    "web.xxe_detect", "web.ssrf_detect", "web.aws_metadata_ssrf",
    "web.path_traversal", "web.open_redirect", "web.log4shell_check",
    "web.broken_access_control", "web.spring4shell_check",
    "web.deserial_probe", "web.http_smuggling",
}

# The subset that can change the target rather than merely probe it.
_STATE_CHANGING = {
    "web.spring4shell_check",  # rebinds Tomcat's AccessLogValve pattern/suffix
    "web.http_smuggling",      # desync affects other users' requests; poisons caches
    "web.deserial_probe",      # serialized payloads execute code on a vulnerable target
}


def _classes():
    return get_all_plugin_classes()


def test_plugin_base_declares_both_risk_levels():
    """The engine reads one, the agent reads the other. Both must be part of the
    contract, or a gate silently reads an attribute nobody defines."""
    assert PluginBase.intrusive is False
    assert PluginBase.destructive is False
    assert PluginBase.risk_intrusive() is False


def test_destructive_implies_intrusive():
    class Writes(PluginBase):
        id = "t.writes"
        destructive = True

        async def check(self, context, host):  # pragma: no cover - not run
            return []

    # Declaring the stronger flag alone must be enough; nothing that can modify a
    # target should have to also remember to tick 'noisy'.
    assert Writes.risk_intrusive() is True


@pytest.mark.parametrize("plugin_id", sorted(_PAYLOAD_PLUGINS))
def test_payload_plugin_declares_its_risk(plugin_id):
    cls = _classes().get(plugin_id)
    assert cls is not None, f"{plugin_id} no longer exists — update _PAYLOAD_PLUGINS"
    assert cls.risk_intrusive(), (
        f"{plugin_id} sends attack payloads but declares neither intrusive nor "
        f"destructive, so safety_level='safe' will run it anyway."
    )


@pytest.mark.parametrize("plugin_id", sorted(_STATE_CHANGING))
def test_state_changing_plugin_is_marked_destructive(plugin_id):
    cls = _classes().get(plugin_id)
    assert cls is not None, f"{plugin_id} no longer exists — update _STATE_CHANGING"
    assert cls.destructive, (
        f"{plugin_id} can modify the target, so it must be destructive — that is "
        f"what gates the agent's allow_exploitation capability."
    )


def test_safe_mode_excludes_every_payload_plugin():
    """The regression itself: 'safe' used to drop only default_creds plugins."""
    plugins = get_enabled_plugins(set(get_all_plugin_ids()))
    # Enable the enumeration capabilities so the only thing filtering here is
    # safety — otherwise the defaults mask the gate under test.
    profile = {
        "safety_level": "safe",
        "enumeration": {"dns_recon": True, "subdomain_enum": True, "directory_enum": True},
    }
    kept = {p.id for p in _filter_plugins_by_capabilities(plugins, profile)}

    still_running = _PAYLOAD_PLUGINS & kept
    assert not still_running, (
        f"safety_level='safe' still runs payload-sending plugins: {sorted(still_running)}"
    )


def test_balanced_still_runs_them():
    """The gate must bite only in safe mode — 'safe' should be a real choice, not
    a global disable."""
    plugins = get_enabled_plugins(set(get_all_plugin_ids()))
    profile = {
        "safety_level": "balanced",
        "enumeration": {"dns_recon": True, "subdomain_enum": True, "directory_enum": True},
    }
    kept = {p.id for p in _filter_plugins_by_capabilities(plugins, profile)}
    assert _PAYLOAD_PLUGINS <= kept, (
        f"balanced should still run payload plugins; missing "
        f"{sorted(_PAYLOAD_PLUGINS - kept)}"
    )


def test_list_plugins_reports_risk_to_the_model():
    """The agent picks plugins from this list; it must not read as all-safe."""
    classes = _classes()
    flagged = [
        pid for pid, cls in classes.items()
        if getattr(cls, "intrusive", False) or getattr(cls, "destructive", False)
    ]
    assert flagged, "no plugin declares any risk — the agent's gates cannot fire"
