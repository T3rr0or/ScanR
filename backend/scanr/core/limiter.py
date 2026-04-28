from fastapi import Request
from slowapi import Limiter


def _real_ip(request: Request) -> str:
    """Return the real client IP, honouring X-Forwarded-For from trusted proxies."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the leftmost (client) IP; proxies append right-to-left
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_real_ip, default_limits=["300/minute"])
