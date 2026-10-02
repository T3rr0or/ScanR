from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None  # None when delivered via HttpOnly cookie
    token_type: str = "bearer"


class LoginResponse(BaseModel):
    """Either a session, or a challenge for the account's second factor."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    mfa_required: bool = False
    # Short-lived proof that the password step succeeded; exchanged together
    # with an authenticator or recovery code at /auth/login/mfa.
    mfa_token: str | None = None


class MfaLoginRequest(BaseModel):
    mfa_token: str = Field(..., max_length=2048)
    # A 6-digit authenticator code or a recovery code like "k7m2p-q9xw4".
    code: str = Field(..., min_length=6, max_length=32)
