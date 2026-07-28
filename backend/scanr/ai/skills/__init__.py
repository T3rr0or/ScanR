"""Loadable agent skills.

A skill is procedural expertise — how a competent tester approaches a class of
problem — kept out of the system prompt until it is relevant. ScanR has 136
plugins that know *how to check* things; skills carry the judgement about *what
to try next and why*, which is the part a model is otherwise guessing at.

Keeping them loadable matters for a concrete reason: the system prompt is paid for
on every single turn of a run. Inlining the AD methodology so it is available for
the one scan in ten that hits a domain controller taxes the other nine. The index
(name + one line) is cheap; the body is fetched on demand.

Skills are markdown with a small YAML-ish header:

    ---
    name: active-directory
    description: One line, shown in the index.
    ---
    Body...
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

__all__ = ["Skill", "get_skill", "list_skills"]

_DIR = Path(__file__).parent
_HEADER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)
#: Skill names are used to pick a file, so constrain them rather than trusting a
#: model-supplied string to be a safe path component.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    body: str


def _parse(path: Path) -> Skill | None:
    text = path.read_text(encoding="utf-8")
    match = _HEADER.match(text)
    if not match:
        return None
    meta = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    name = meta.get("name") or path.stem
    if not _NAME_RE.match(name):
        return None
    return Skill(
        name=name,
        description=meta.get("description", ""),
        body=text[match.end():].strip(),
    )


@lru_cache(maxsize=1)
def _all() -> dict[str, Skill]:
    out: dict[str, Skill] = {}
    for path in sorted(_DIR.glob("*.md")):
        skill = _parse(path)
        if skill:
            out[skill.name] = skill
    return out


def list_skills() -> list[Skill]:
    return list(_all().values())


def get_skill(name: str) -> Skill | None:
    """Look up a skill by name.

    Name-keyed, never path-joined: a model-supplied '../../etc/passwd' resolves to
    a miss rather than a file read.
    """
    return _all().get(str(name or "").strip().lower())
