"""Agent working memory and loadable skills.

Two things are worth pinning here. First, the todo list is replace-not-merge —
that is the whole reason it stays self-correcting, and a future "helpful" merge
would silently resurrect abandoned plan items. Second, `get_skill` picks a file
from a model-supplied string, so it must be name-keyed rather than path-joined.
"""
import pytest

from scanr.ai.agent.memory import (
    MAX_NOTE_CHARS,
    MAX_NOTES,
    MAX_TODOS,
    empty_scratchpad,
    format_notes,
    format_todos,
    upsert_note,
    write_todos,
)
from scanr.ai.skills import get_skill, list_skills


# ── todos ────────────────────────────────────────────────────────────────────

def test_write_todos_replaces_rather_than_merges():
    """A dropped item must actually disappear — otherwise a revised plan is the
    union of every plan the agent ever had."""
    state, _ = write_todos(empty_scratchpad(), ["enumerate", "exploit", "report"])
    state, _ = write_todos(state, [{"title": "enumerate", "status": "done"}, "report"])
    assert [t["title"] for t in state["todos"]] == ["enumerate", "report"]
    assert state["todos"][0]["status"] == "done"


def test_bare_strings_default_to_pending():
    state, _ = write_todos(None, ["look at 10.0.0.5"])
    assert state["todos"] == [{"title": "look at 10.0.0.5", "status": "pending"}]


def test_notes_survive_a_todo_rewrite():
    state, _ = upsert_note(empty_scratchpad(), "domain", "corp.local")
    state, _ = write_todos(state, ["something else entirely"])
    assert state["notes"] == {"domain": "corp.local"}


@pytest.mark.parametrize(
    "items",
    [
        "not a list",
        [{"title": ""}],
        ["   "],
        [{"title": "x", "status": "blocked"}],
        [123],
    ],
)
def test_bad_todo_input_raises(items):
    with pytest.raises(ValueError):
        write_todos(empty_scratchpad(), items)


def test_status_is_case_insensitive():
    state, _ = write_todos(None, [{"title": "x", "status": "IN_PROGRESS"}])
    assert state["todos"][0]["status"] == "in_progress"


def test_todo_list_is_bounded():
    with pytest.raises(ValueError):
        write_todos(None, [f"item {i}" for i in range(MAX_TODOS + 1)])


def test_format_todos_shows_remaining_work():
    out = format_todos([{"title": "a", "status": "done"}, {"title": "b", "status": "pending"}])
    assert "[x] a" in out and "[ ] b" in out
    assert "(1 of 2 remaining)" in out


def test_format_todos_empty():
    assert format_todos([]) == "(no todos)"


# ── notes ────────────────────────────────────────────────────────────────────

def test_note_upsert_replaces_by_topic():
    state, _ = upsert_note(empty_scratchpad(), "creds", "admin:admin")
    state, msg = upsert_note(state, "creds", "admin:hunter2")
    assert state["notes"] == {"creds": "admin:hunter2"}
    assert "saved" in msg


def test_empty_content_deletes_the_note():
    """How the agent retracts a fact it later found to be wrong."""
    state, _ = upsert_note(empty_scratchpad(), "creds", "admin:admin")
    state, msg = upsert_note(state, "creds", "   ")
    assert state["notes"] == {}
    assert "deleted" in msg


def test_deleting_a_missing_note_is_not_an_error():
    state, msg = upsert_note(empty_scratchpad(), "nothing-here", "")
    assert state["notes"] == {}
    assert "deleted" in msg


def test_note_needs_a_topic():
    with pytest.raises(ValueError):
        upsert_note(empty_scratchpad(), "  ", "body")


def test_oversized_note_is_truncated_not_rejected():
    """Losing the tail of a note beats losing the note."""
    state, msg = upsert_note(empty_scratchpad(), "dump", "x" * (MAX_NOTE_CHARS + 500))
    assert len(state["notes"]["dump"]) == MAX_NOTE_CHARS
    assert "truncated" in msg


def test_note_count_is_bounded_but_updates_still_work():
    state = empty_scratchpad()
    for i in range(MAX_NOTES):
        state, _ = upsert_note(state, f"topic-{i}", "body")
    with pytest.raises(ValueError):
        upsert_note(state, "one-too-many", "body")
    # replacing an existing topic must stay possible at the limit, or the agent
    # can never correct itself once it is full
    state, _ = upsert_note(state, "topic-0", "corrected")
    assert state["notes"]["topic-0"] == "corrected"


def test_format_notes_single_and_all():
    notes = {"b": "second", "a": "first"}
    assert format_notes(notes, "a") == "# a\nfirst"
    assert format_notes(notes).index("# a") < format_notes(notes).index("# b")
    assert "no note for" in format_notes(notes, "missing")
    assert format_notes({}) == "(no notes)"


# ── malformed state ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [None, "", [], {"todos": "nope", "notes": 5}, {"other": 1}])
def test_malformed_scratchpad_is_tolerated(bad):
    """A run must not die because an older row stored something unexpected."""
    state, _ = write_todos(bad, ["recover"])
    assert state["todos"] == [{"title": "recover", "status": "pending"}]
    assert state["notes"] == {}


# ── skills ───────────────────────────────────────────────────────────────────

def test_every_shipped_skill_parses():
    skills = list_skills()
    assert len(skills) >= 5
    for skill in skills:
        assert skill.description, f"{skill.name} has no description for the index"
        assert len(skill.body) > 200, f"{skill.name} body looks like a stub"


def test_get_skill_is_case_insensitive_and_trims():
    assert get_skill("  Active-Directory  ") is not None


@pytest.mark.parametrize(
    "name",
    ["../../../etc/passwd", "../__init__", "active-directory.md", "", "  ", "nope"],
)
def test_get_skill_rejects_anything_that_is_not_a_known_name(name):
    """Name-keyed lookup: a traversal attempt is a miss, not a file read."""
    assert get_skill(name) is None


def test_skill_names_are_unique_and_index_is_cheap():
    skills = list_skills()
    assert len({s.name for s in skills}) == len(skills)
    index = "\n".join(f"- {s.name}: {s.description}" for s in skills)
    assert len(index) < 1200, "the always-on index should stay small"
