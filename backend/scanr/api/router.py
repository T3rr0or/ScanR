from fastapi import APIRouter

from .v1 import (
    agent_jobs,
    agents,
    analytics,
    api_keys,
    assets,
    auth,
    credentials,
    exclusions,
    findings,
    host_tags,
    plugins,
    profile_suggest,
    reports,
    schedules,
    scans,
    screenshots,
    system,
    templates,
    users,
    vulnerabilities,
    webhooks,
    wordlists,
)
from .websocket import router as ws_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(profile_suggest.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(plugins.router)
api_router.include_router(credentials.router)
api_router.include_router(reports.router)
api_router.include_router(schedules.router)
api_router.include_router(screenshots.router)
api_router.include_router(system.router)
api_router.include_router(analytics.router)
api_router.include_router(api_keys.router)
api_router.include_router(webhooks.router)
api_router.include_router(templates.router)
api_router.include_router(exclusions.router)
api_router.include_router(agents.router)
api_router.include_router(agent_jobs.router)
api_router.include_router(users.router)
api_router.include_router(assets.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(host_tags.router)
api_router.include_router(wordlists.router)

# WebSocket (no v1 prefix — cleaner WS URLs)
ws_router_outer = APIRouter()
ws_router_outer.include_router(ws_router)
