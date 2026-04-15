from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from typing import TYPE_CHECKING

import scanr.plugins as plugins_pkg
from scanr.core.plugin_base import PluginBase

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_registry: dict[str, type[PluginBase]] = {}


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
