from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from scanr.api.router import api_router, ws_router_outer
from scanr.api.websocket import router as ws_router
from scanr.config import get_settings
from scanr.db.init_db import create_tables, seed_admin, seed_plugins, seed_templates
from scanr.db.session import AsyncSessionLocal
from scanr.utils.logging import configure_logging

from scanr.core.limiter import limiter

settings = get_settings()
configure_logging(debug=settings.debug)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ScanR starting up...")
    await create_tables()
    async with AsyncSessionLocal() as db:
        await seed_admin(db)
        await seed_plugins(db)
        await seed_templates(db)
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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)
    app.include_router(ws_router)  # WebSocket routes at /ws/...

    @app.get("/")
    async def root():
        return {"name": "ScanR", "version": settings.app_version, "docs": "/docs"}

    return app


app = create_app()
