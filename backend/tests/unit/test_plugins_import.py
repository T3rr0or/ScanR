from __future__ import annotations

import importlib
from pathlib import Path


def test_all_plugin_modules_importable() -> None:
    plugin_root = Path(__file__).parents[2] / "scanr" / "plugins"
    modules = []
    for path in plugin_root.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        rel = path.relative_to(plugin_root.parent).with_suffix("")
        modules.append("scanr." + ".".join(rel.parts))

    failures: dict[str, str] = {}
    for module in sorted(modules):
        try:
            importlib.import_module(module)
        except Exception as exc:  # pragma: no cover - failure path reports all broken modules
            failures[module] = f"{type(exc).__name__}: {exc}"

    assert not failures
