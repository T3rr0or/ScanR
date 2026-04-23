from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from scanr.api.router import api_router, ws_router_outer
from scanr.api.websocket import router as ws_router
from scanr.config import get_settings
from scanr.db.init_db import create_tables, seed_admin, seed_plugins, seed_templates, _seed_builtin_wordlists
from scanr.db.session import AsyncSessionLocal
from scanr.utils.logging import configure_logging

from scanr.core.limiter import limiter

settings = get_settings()
configure_logging(debug=settings.debug)
logger = logging.getLogger(__name__)

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ScanR starting up...")
    await create_tables()
    async with AsyncSessionLocal() as db:
        await seed_admin(db)
        await seed_plugins(db)
        await seed_templates(db)
        await _seed_builtin_wordlists(db)
    logger.info("ScanR ready")
    yield
    logger.info("ScanR shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ScanR",
        description="Professional vulnerability scanner for authorized penetration testing",
        version=settings.app_version,
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    )

    app.include_router(api_router)
    app.include_router(ws_router)  # WebSocket routes at /ws/...

    @app.get("/")
    async def root():
        return {"name": "ScanR", "version": settings.app_version, "docs": "/docs"}

    return app


app = create_app()
