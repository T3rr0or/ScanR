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
import ast
from pathlib import Path

import pytest

from scanr.core.engine import _filter_plugins_by_capabilities
from scanr.core.plugin_base import PluginBase, PluginImpact
from scanr.core.plugin_impact import (
    AUTH_ATTEMPT_PLUGIN_IDS,
    EXPLOIT_PLUGIN_IDS,
    KNOWN_PLUGIN_IDS,
    PLUGIN_IMPACTS,
    STATE_CHANGING_PLUGIN_IDS,
    impact_for_plugin,
)
from scanr.core.plugin_manager import (
    get_all_plugin_classes,
    get_all_plugin_ids,
    get_enabled_plugins,
    get_plugin_registration_errors,
)

# Checks that send attack payloads. Reviewed individually; each either injects a
# payload (SQL, template, traversal, XXE, JNDI, XSS) or drives the target into
# making a request it did not intend.
_PAYLOAD_PLUGINS = {
    "web.sqli_detect", "web.sqli_blind", "web.xss_detect", "web.ssti_detect",
    "web.xxe_detect", "web.ssrf_detect", "web.aws_metadata_ssrf",
    "web.path_traversal", "web.open_redirect", "web.log4shell_check",
    "web.broken_access_control", "web.spring4shell_check",
    "web.deserial_probe", "web.http_smuggling", "web.jwt_misconfig",
    "web.waf_detect",
}

# The subset that can change the target rather than merely probe it.
_STATE_CHANGING = {
    "authenticated.docker_privileged_check",  # authenticates over SSH and executes commands
    "authenticated.ssh_audit",  # authenticates over SSH and executes commands
    "services.sip_scan",  # sends a real REGISTER that can change extension routing
    "services.smb_share_enum",  # creates/deletes a fixed test file on each share
    "web.spring4shell_check",  # rebinds Tomcat's AccessLogValve pattern/suffix
    "web.http_smuggling",      # desync affects other users' requests; poisons caches
    "web.deserial_probe",      # serialized payloads execute code on a vulnerable target
    "services.snmp_walk",      # writes sysContact to prove a community is read-write
    "web.http_methods",        # PUT/PATCH/DELETE fallback probes
}

# These implementations send supplied credentials (or, for ldap_signing, an
# anonymous simple bind). They must not silently become balanced-safe again.
_AUTHENTICATING_PLUGINS = {
    "services.ad_password_policy",
    "services.admin_share_access",
    "services.asreproastable",
    "services.k8s_rbac_enum",
    "services.kerberoastable",
    "services.ldap_signing",
    "services.ldap_user_enum",
    "services.smb_authenticated_enum",
    "services.trust_enum",
    "services.unconstrained_delegation",
    "services.winrm_access",
    # These use create_web_client(), which automatically adds stored web auth
    # headers. SQLi is omitted here because its exploit payload is stronger.
    "web.broken_access_control",
    "web.dir_bruteforce",
    "web.js_libraries",
}

# These go beyond diagnostic markers: they retrieve protected data, exercise an
# authentication bypass, induce internal requests/DB work, or send a CVE probe.
_EXPLOIT_PROBES = {
    "services.etcd_unauth",
    "services.gmsa_readable",
    "services.ike_aggressive_mode",
    "services.ntp_monlist",
    "web.aws_metadata_ssrf",
    "web.jwt_misconfig",
    "web.path_traversal",
    "web.sqli_blind",
    "web.sqli_detect",
    "web.ssrf_detect",
    "web.waf_detect",
    "web.xxe_detect",
}


def _classes():
    return get_all_plugin_classes()


def test_plugin_base_declares_both_risk_levels():
    """The engine reads one, the agent reads the other. Both must be part of the
    contract, or a gate silently reads an attribute nobody defines."""
    assert PluginBase.intrusive is False
    assert PluginBase.destructive is False
    assert PluginBase.impact is PluginImpact.unknown
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


def test_balanced_runs_intrusive_but_not_destructive_plugins():
    """Balanced permits diagnostic payloads, not auth/exploit/state changes."""
    plugins = get_enabled_plugins(set(get_all_plugin_ids()))
    profile = {
        "safety_level": "balanced",
        "enumeration": {"dns_recon": True, "subdomain_enum": True, "directory_enum": True},
    }
    kept = {p.id for p in _filter_plugins_by_capabilities(plugins, profile)}
    assert not ((AUTH_ATTEMPT_PLUGIN_IDS | EXPLOIT_PLUGIN_IDS | STATE_CHANGING_PLUGIN_IDS) & kept)
    expected_intrusive = {
        pid for pid in _PAYLOAD_PLUGINS
        if PLUGIN_IMPACTS[pid] is PluginImpact.intrusive
    }
    assert expected_intrusive <= kept


def test_aggressive_runs_destructive_plugins():
    plugins = get_enabled_plugins(set(get_all_plugin_ids()))
    profile = {
        "safety_level": "aggressive",
        "enumeration": {"dns_recon": True, "subdomain_enum": True, "directory_enum": True},
    }
    kept = {p.id for p in _filter_plugins_by_capabilities(plugins, profile)}
    assert _STATE_CHANGING <= kept


def test_list_plugins_reports_risk_to_the_model():
    """The agent picks plugins from this list; it must not read as all-safe."""
    classes = _classes()
    flagged = [
        pid for pid, cls in classes.items()
        if getattr(cls, "intrusive", False) or getattr(cls, "destructive", False)
    ]
    assert flagged, "no plugin declares any risk — the agent's gates cannot fire"


def test_impact_manifest_covers_every_plugin_source_exactly():
    """A newly-added plugin cannot silently inherit a permissive default."""
    plugin_root = Path(__file__).parents[2] / "scanr" / "plugins"
    source_ids: set[str] = set()
    for path in plugin_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(isinstance(base, ast.Name) and base.id == "PluginBase" for base in node.bases):
                continue
            for statement in node.body:
                if not isinstance(statement, ast.Assign):
                    continue
                if not any(isinstance(target, ast.Name) and target.id == "id" for target in statement.targets):
                    continue
                if isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                    source_ids.add(statement.value.value)

    assert source_ids == KNOWN_PLUGIN_IDS
    assert set(PLUGIN_IMPACTS) == source_ids
    assert all(impact is not PluginImpact.unknown for impact in PLUGIN_IMPACTS.values())


def test_registry_has_no_impact_registration_failures():
    get_all_plugin_classes()
    assert get_plugin_registration_errors() == {}


@pytest.mark.parametrize("plugin_id", sorted(AUTH_ATTEMPT_PLUGIN_IDS))
def test_credential_attempts_are_explicitly_classified(plugin_id):
    assert PLUGIN_IMPACTS[plugin_id] is PluginImpact.auth_attempt


@pytest.mark.parametrize("plugin_id", sorted(_AUTHENTICATING_PLUGINS))
def test_reviewed_credential_using_plugins_remain_auth_attempts(plugin_id):
    assert PLUGIN_IMPACTS[plugin_id] is PluginImpact.auth_attempt


@pytest.mark.parametrize("plugin_id", sorted(EXPLOIT_PLUGIN_IDS))
def test_exploit_probes_are_explicitly_classified(plugin_id):
    assert PLUGIN_IMPACTS[plugin_id] is PluginImpact.exploit


@pytest.mark.parametrize("plugin_id", sorted(_EXPLOIT_PROBES))
def test_reviewed_exploit_probes_remain_aggressive_only(plugin_id):
    assert PLUGIN_IMPACTS[plugin_id] is PluginImpact.exploit


def test_service_fallback_is_active_not_passive():
    assert PLUGIN_IMPACTS["services.service_fallback"] is PluginImpact.active


def test_missing_impact_metadata_is_fail_closed():
    assert impact_for_plugin("test.new_unreviewed_plugin") is None
    class Unknown(PluginBase):
        id = "test.new_unreviewed_plugin"

        async def check(self, context, host):
            return []

    assert Unknown.impact is PluginImpact.unknown
