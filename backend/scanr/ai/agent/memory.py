"""Agent working memory: a todo list and durable notes.

Why this exists. The agent's only memory today is its conversation, which has two
problems on a long autonomous run: the plan drifts as earlier turns fall out of
the window, and anything learned early ("admin panel is at /manage, creds
user:pass work") is lost the moment it scrolls away. Both show up as the agent
re-deriving things it already knew, which costs budget and looks incompetent in
the transcript.

A todo list keeps intent stable across that window; notes keep facts. Both are
persisted on the run, so they survive the watchdog restarting a stalled run and
they show up in the exported trace — which makes the agent's reasoning auditable
rather than something you reconstruct from tool calls.

Pure functions over plain dicts, so the merge/validation rules are testable
without a database.
"""
from __future__ import annotations

__all__ = [
    "MAX_NOTES",
    "MAX_NOTE_CHARS",
    "MAX_TODOS",
    "TODO_STATUSES",
    "empty_scratchpad",
    "format_notes",
    "format_todos",
    "upsert_note",
    "write_todos",
]

TODO_STATUSES = ("pending", "in_progress", "done")

# Bounds exist because this content is replayed into the model's context on every
# turn: an unbounded note store would quietly eat the budget the agent needs for
# actual work.
MAX_TODOS = 40
MAX_NOTES = 50
MAX_NOTE_CHARS = 4000
MAX_TITLE_CHARS = 200


def empty_scratchpad() -> dict:
    return {"todos": [], "notes": {}}


def _coerce(scratchpad: dict | None) -> dict:
    """Tolerate a missing or malformed scratchpad rather than failing a run over it."""
    if not isinstance(scratchpad, dict):
        return empty_scratchpad()
    todos = scratchpad.get("todos")
    notes = scratchpad.get("notes")
    return {
        "todos": todos if isinstance(todos, list) else [],
        "notes": notes if isinstance(notes, dict) else {},
    }


def write_todos(scratchpad: dict | None, items: list) -> tuple[dict, str]:
    """Replace the whole todo list.

    Whole-list replacement rather than per-item mutation: models are markedly
    better at restating a full plan than at tracking opaque item ids across turns,
    and it makes the list self-correcting — a stale entry disappears the next time
    the plan is written rather than lingering forever.

    Returns (new_scratchpad, human_summary). Raises ValueError on bad input so the
    tool layer can hand the model something actionable.
    """
    state = _coerce(scratchpad)
    if not isinstance(items, list):
        raise ValueError("todos must be a list")
    if len(items) > MAX_TODOS:
        raise ValueError(f"too many todos ({len(items)}); keep the plan under {MAX_TODOS} items")

    cleaned: list[dict] = []
    for raw in items:
        if isinstance(raw, str):
            raw = {"title": raw}
        if not isinstance(raw, dict):
            raise ValueError("each todo must be an object with 'title' and optional 'status'")
        title = str(raw.get("title", "")).strip()
        if not title:
            raise ValueError("every todo needs a non-empty title")
        status = str(raw.get("status", "pending")).strip().lower()
        if status not in TODO_STATUSES:
            raise ValueError(f"invalid status {status!r}; use one of {', '.join(TODO_STATUSES)}")
        cleaned.append({"title": title[:MAX_TITLE_CHARS], "status": status})

    state["todos"] = cleaned
    return state, format_todos(cleaned)


def upsert_note(scratchpad: dict | None, topic: str, content: str) -> tuple[dict, str]:
    """Store (or replace) a note under ``topic``.

    Keyed by topic rather than appended, so revisiting a subject corrects the
    record instead of leaving the model to reconcile two versions of the same
    fact. An empty body deletes — that is how the agent retracts something it
    later found to be wrong.
    """
    state = _coerce(scratchpad)
    topic = str(topic or "").strip()
    if not topic:
        raise ValueError("a note needs a topic")
    topic = topic[:MAX_TITLE_CHARS]

    body = str(content or "").strip()
    if not body:
        state["notes"].pop(topic, None)
        return state, f"deleted note {topic!r}"

    if topic not in state["notes"] and len(state["notes"]) >= MAX_NOTES:
        raise ValueError(
            f"note limit reached ({MAX_NOTES}); replace or delete an existing topic first"
        )

    truncated = len(body) > MAX_NOTE_CHARS
    state["notes"][topic] = body[:MAX_NOTE_CHARS]
    return state, f"saved note {topic!r}" + (" (truncated)" if truncated else "")


def format_todos(todos: list) -> str:
    if not todos:
        return "(no todos)"
    marks = {"pending": "[ ]", "in_progress": "[~]", "done": "[x]"}
    lines = [f"{marks.get(t.get('status'), '[ ]')} {t.get('title', '')}" for t in todos]
    remaining = sum(1 for t in todos if t.get("status") != "done")
    lines.append(f"({remaining} of {len(todos)} remaining)")
    return "\n".join(lines)


def format_notes(notes: dict, topic: str | None = None) -> str:
    if topic:
        body = notes.get(topic)
        return f"# {topic}\n{body}" if body else f"(no note for {topic!r})"
    if not notes:
        return "(no notes)"
    return "\n\n".join(f"# {name}\n{body}" for name, body in sorted(notes.items()))
