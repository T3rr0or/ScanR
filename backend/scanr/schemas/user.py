from typing import Literal

from pydantic import BaseModel

# Must stay in sync with scanr.models.user.UserRole. Validated as a Literal
# rather than a bare str: authorization compares role against exact strings, so
# an unrecognised value (a typo like "Admin", or an invented role) would be
# silently treated as un-privileged — failing safe, but confusingly.
UserRoleName = Literal["admin", "analyst", "viewer"]


class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str | None = None
    role: UserRoleName = "analyst"


class UserRead(BaseModel):
    id: str
    email: str
    full_name: str | None
    role: str
    is_active: bool

    model_config = {"from_attributes": True}
