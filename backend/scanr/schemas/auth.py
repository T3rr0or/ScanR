from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None  # None when delivered via HttpOnly cookie
    token_type: str = "bearer"
