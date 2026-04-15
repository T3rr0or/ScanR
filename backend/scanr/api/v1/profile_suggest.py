"""
Auto scan profile suggestion based on target analysis.
"""
from __future__ import annotations

import ipaddress
import re

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models.scan_template import ScanTemplate
from scanr.models.user import User

router = APIRouter(prefix="/scans", tags=["scans"])

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def _classify_targets(targets: list[str]) -> dict:
    has_domain = False
    has_private_ip = False
    has_public_ip = False
    has_large_cidr = False
    all_single = True

    for t in targets:
        t = t.strip()
        if "/" in t:
            # CIDR
            all_single = False
            try:
                net = ipaddress.ip_network(t, strict=False)
                if net.num_addresses > 256:
                    has_large_cidr = True
                addr = next(net.hosts(), net.network_address)
                if any(addr in p for p in _PRIVATE_NETS):
                    has_private_ip = True
                else:
                    has_public_ip = True
            except ValueError:
                pass
        elif _DOMAIN_RE.match(t):
            has_domain = True
        else:
            try:
                addr = ipaddress.ip_address(t)
                if any(addr in p for p in _PRIVATE_NETS):
                    has_private_ip = True
                else:
                    has_public_ip = True
            except ValueError:
                has_domain = True  # treat unknown as domain

    return {
        "has_domain": has_domain,
        "has_private_ip": has_private_ip,
        "has_public_ip": has_public_ip,
        "has_large_cidr": has_large_cidr,
        "all_single": all_single,
        "count": len(targets),
    }


def _suggest(info: dict) -> tuple[str, str, str, int]:
    """Return (template_name, profile_json_hint, reason, confidence 0-100)."""
    if info["has_large_cidr"] or info["count"] > 20:
        return (
            "Quick Scan",
            '{"port_range": "top-1000", "plugins": ["network.*", "web.http_headers", "ssl_tls.cert_inspector"]}',
            "Large target set — Quick Scan minimises scan time",
            70,
        )
    if info["has_domain"] and not info["has_private_ip"]:
        return (
            "Web Audit",
            '{"port_range": "80,443,8080,8443,8000,8888,3000,5000,9000", "plugins": ["web.*", "ssl_tls.*", "nuclei.runner"]}',
            "Domain target(s) suggest internet-facing web application",
            85,
        )
    if info["has_private_ip"] and not info["has_domain"] and not info["has_public_ip"]:
        return (
            "Internal Network Audit",
            '{"port_range": "top-10000", "plugins": ["network.*", "services.*", "ssh.*", "ssl_tls.*"]}',
            "Private IP range(s) suggest internal network assessment",
            90,
        )
    if info["has_domain"] and info["has_private_ip"]:
        return (
            "Full Scan",
            '{"port_range": "1-65535", "plugins": ["*"]}',
            "Mixed internal + domain targets — Full Scan for complete coverage",
            65,
        )
    return (
        "Full Scan",
        '{"port_range": "1-65535", "plugins": ["*"]}',
        "General target — Full Scan recommended",
        60,
    )


@router.get("/suggest-profile")
async def suggest_scan_profile(
    targets: str = Query(..., description="Comma-separated list of IPs/CIDRs/domains"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    if not target_list:
        return {"error": "No targets provided"}

    info = _classify_targets(target_list)
    template_name, profile_hint, reason, confidence = _suggest(info)

    # Try to find the matching system template ID
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.name == template_name, ScanTemplate.is_system == True)
    )
    tmpl = result.scalar_one_or_none()

    return {
        "suggested_template": template_name,
        "template_id": tmpl.id if tmpl else None,
        "profile_json": profile_hint,
        "reason": reason,
        "confidence": confidence,
        "target_analysis": info,
    }
