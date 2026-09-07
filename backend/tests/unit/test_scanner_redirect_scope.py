"""Scanner network clients must not cross a scope boundary via HTTP redirects."""
from __future__ import annotations

import ast
from pathlib import Path


def test_scanner_code_has_no_automatic_redirect_following():
    root = Path(__file__).parents[2] / "scanr"
    offenders: list[str] = []

    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "follow_redirects":
                    continue
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}")

    assert offenders == [], (
        "automatic redirects can leave the authorized scan target; explicitly "
        f"authorize each Location instead: {offenders}"
    )

