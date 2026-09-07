from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from typing import TYPE_CHECKING

import scanr.plugins as plugins_pkg
from scanr.core.plugin_base import PluginBase, PluginImpact
from scanr.core.plugin_impact import impact_for_plugin

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_registry: dict[str, type[PluginBase]] = {}
_registration_errors: dict[str, str] = {}


def _discover_plugins() -> None:
    """Walk scanr.plugins.* and register all PluginBase subclasses."""
    global _registry
    if _registry:
        return

    for finder, module_name, is_pkg in pkgutil.walk_packages(
        path=plugins_pkg.__path__,
        prefix=plugins_pkg.__name__ + ".",
        onerror=lambda x: None,
    ):
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:
            logger.warning("Failed to import plugin module %s: %s", module_name, exc)
            continue

        for _, cls in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(cls, PluginBase)
                and cls is not PluginBase
                and hasattr(cls, "id")
                and cls.id
            ):
                impact = impact_for_plugin(cls.id)
                if impact is None or impact is PluginImpact.unknown:
                    message = "missing reviewed impact metadata"
                    _registration_errors[cls.id] = message
                    logger.error("Refusing to register plugin %s: %s", cls.id, message)
                    continue
                # Keep the legacy booleans synchronized for AI callers while all
                # gates migrate to the richer mandatory impact enum.
                cls.impact = impact
                cls.intrusive = impact in {
                    PluginImpact.intrusive,
                    PluginImpact.auth_attempt,
                    PluginImpact.exploit,
                    PluginImpact.state_changing,
                }
                cls.destructive = impact is PluginImpact.state_changing
                _registry[cls.id] = cls
                logger.debug("Registered plugin: %s", cls.id)


def get_enabled_plugins(enabled_ids: set[str]) -> list[PluginBase]:
    """Return instantiated plugin objects for the given enabled plugin IDs."""
    _discover_plugins()
    plugins: list[PluginBase] = []
    for pid, cls in _registry.items():
        if pid in enabled_ids:
            try:
                plugins.append(cls())
            except Exception as exc:
                logger.warning("Failed to instantiate plugin %s: %s", pid, exc)
    return plugins


def get_all_plugin_ids() -> list[str]:
    _discover_plugins()
    return list(_registry.keys())


def get_all_plugin_classes() -> dict[str, type[PluginBase]]:
    """Return discovered plugin classes keyed by plugin id."""
    _discover_plugins()
    return dict(_registry)


def get_plugin_registration_errors() -> dict[str, str]:
    """Expose fail-closed registration failures for health checks/tests."""
    _discover_plugins()
    return dict(_registration_errors)
