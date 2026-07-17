"""Regression: scan-engine wordlist loading must not cross user boundaries (IDOR).

core/engine.py (~lines 334-355) loads brute-force wordlists referenced by a
scan profile with an owner-or-global (NULL user_id) filter. Running the full
engine is too heavy for a unit test, so this exercises the exact query
semantics the engine uses; keep it in sync with that query.
"""
import pytest
from sqlalchemy import or_, select

from scanr.auth.password import hash_password
from scanr.models.base import new_uuid
from scanr.models.user import User, UserRole
from scanr.models.wordlist import Wordlist


def _user(email: str) -> User:
    return User(
        id=new_uuid(),
        email=email,
        hashed_password=hash_password("somepassword1"),
        role=UserRole.analyst,
        is_active=True,
    )


@pytest.mark.asyncio
async def test_wordlist_load_scoped_to_owner_or_global(db):
    owner = _user("wl-owner@example.com")
    other = _user("wl-other@example.com")
    db.add_all([owner, other])
    await db.flush()

    wl_mine = Wordlist(id=new_uuid(), user_id=owner.id, name="mine", type="usernames",
                       file_path="/tmp/wl-a.txt")
    wl_other = Wordlist(id=new_uuid(), user_id=other.id, name="other", type="usernames",
                        file_path="/tmp/wl-b.txt")
    wl_global = Wordlist(id=new_uuid(), user_id=None, name="builtin", type="usernames",
                         file_path="/tmp/wl-c.txt", is_builtin=True)
    db.add_all([wl_mine, wl_other, wl_global])
    await db.commit()

    wl_ids = [wl_mine.id, wl_other.id, wl_global.id]

    # Query mirrors core/engine.py wordlist load (owner-or-global filter).
    result = await db.execute(
        select(Wordlist).where(
            Wordlist.id.in_(wl_ids),
            or_(Wordlist.user_id == owner.id, Wordlist.user_id.is_(None)),
        )
    )
    loaded = {w.id for w in result.scalars().all()}

    assert wl_mine.id in loaded
    assert wl_global.id in loaded
    assert wl_other.id not in loaded, "another user's wordlist must not load into my scan"
