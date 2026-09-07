from __future__ import annotations

from pathlib import Path
import subprocess

_ACTION = Path(__file__).resolve().parents[3] / ".github/actions/scanr-scan/action.yml"


def _run_blocks(source: str) -> list[str]:
    """Extract composite-action shell blocks without adding a YAML dependency."""
    lines = source.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if not line.startswith("      run:"):
            continue
        block: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate and len(candidate) - len(candidate.lstrip()) <= 6:
                break
            block.append(candidate)
        blocks.append("\n".join(block))
    return blocks


def test_untrusted_inputs_are_not_interpolated_into_shell_programs() -> None:
    source = _ACTION.read_text()
    blocks = _run_blocks(source)
    assert blocks
    for block in blocks:
        assert "${{ inputs." not in block


def test_shell_blocks_are_valid_bash() -> None:
    for block in _run_blocks(_ACTION.read_text()):
        subprocess.run(["bash", "-n"], input=block, text=True, check=True)


def test_cli_is_installed_from_the_exact_action_checkout() -> None:
    source = _ACTION.read_text()
    assert "github.action_path" in source
    assert '--require-hashes -r "$backend_path/requirements.txt"' in source
    assert '--no-deps "$backend_path"' in source
    assert "git+https://" not in source


def test_all_shell_inputs_have_validation_guards() -> None:
    source = _ACTION.read_text()
    for variable in (
        "SCANR_URL",
        "SCANR_TOKEN",
        "SCANR_TARGETS",
        "SCANR_PROFILE",
        "SCANR_PROFILE_JSON",
        "SCANR_FAIL_ON",
        "SCANR_SARIF_FILE",
        "SCANR_TIMEOUT",
        "SCANR_INSECURE",
        "SCANR_UPLOAD_SARIF",
    ):
        assert variable in source
    assert "urlsplit" in source
    assert "json.loads" in source
    assert "86400" in source
    assert "parent traversal" in source
