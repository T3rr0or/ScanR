"""Scan summaries for people: email, Microsoft Teams and Slack.

Webhooks (scanr.core.webhook_dispatcher) deliver machine-readable JSON to
integrations. Notification channels deliver a short, formatted message: what
finished, the counts, and the findings to fix first, with a link back.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.models import Finding, Host, Scan
from scanr.models.notification_channel import NotificationChannel

logger = logging.getLogger(__name__)

EVENTS = ("scan.completed", "scan.failed")
KINDS = ("email", "slack", "teams")

# Incoming-webhook hosts. Restricting them keeps a channel from becoming a way
# to make ScanR POST scan results to arbitrary servers.
_SLACK_HOSTS = ("hooks.slack.com",)
_TEAMS_SUFFIXES = (
    ".webhook.office.com",          # classic Office 365 connector
    ".logic.azure.com",             # Teams "Workflows" (Power Automate)
    ".powerautomate.com",
    ".environment.api.powerplatform.com",
)
_TOP_FINDINGS = 5
_SEVERITIES = ("critical", "high", "medium", "low", "info")


class NotificationError(Exception):
    pass


def validate_target(kind: str, target: str) -> str:
    """Normalise and check a destination. Raises ValueError with a readable reason."""
    target = target.strip()
    if kind == "email":
        local, _, domain = target.rpartition("@")
        if not local or "." not in domain or any(c in target for c in " \r\n,;<>"):
            raise ValueError("Enter a single email address")
        return target
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        raise ValueError("Webhook URL must start with https://")
    if kind == "slack" and host not in _SLACK_HOSTS:
        raise ValueError("Slack webhook URLs start with https://hooks.slack.com/")
    if kind == "teams" and not host.endswith(_TEAMS_SUFFIXES):
        raise ValueError(
            "Use the URL from a Teams Workflows 'Post to a channel when a webhook request is "
            "received' flow, or a classic incoming webhook (*.webhook.office.com)"
        )
    if kind not in KINDS:
        raise ValueError(f"Unknown channel type {kind!r}")
    return target


def encrypt_target(kind: str, target: str) -> str:
    if kind == "email":
        return target
    from scanr.credentials import vault

    return vault.encrypt({"url": target})


def decrypt_target(channel: NotificationChannel) -> str:
    if channel.kind == "email":
        return channel.target
    from scanr.credentials import vault

    return str(vault.decrypt(channel.target)["url"])


def display_target(channel: NotificationChannel) -> str:
    """What the UI may show: email in full, webhook URLs only by host."""
    if channel.kind == "email":
        return channel.target
    try:
        return f"{urlparse(decrypt_target(channel)).hostname}/…"
    except Exception:
        return "(unreadable — check VAULT_KEY)"


@dataclass
class TopFinding:
    title: str
    location: str
    severity: str
    priority: float | None
    kev: bool
    reasons: list[str]


@dataclass
class ScanSummary:
    scan_id: str
    name: str
    status: str
    hosts_up: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    top: list[TopFinding] = field(default_factory=list)
    max_priority: float | None = None
    error: str | None = None

    @property
    def link(self) -> str:
        return get_settings().public_url

    @property
    def headline(self) -> str:
        if self.status == "failed":
            return f"Scan failed: {self.name}"
        urgent = sum(1 for f in self.top if (f.priority or 0) >= 80)
        if urgent:
            return f"Scan finished: {self.name} — {urgent} to fix now"
        return f"Scan finished: {self.name}"


async def build_summary(db: AsyncSession, scan: Scan) -> ScanSummary:
    summary = ScanSummary(
        scan_id=scan.id,
        name=scan.name,
        status=str(scan.status),
        hosts_up=scan.hosts_up or 0,
        counts={s: getattr(scan, f"findings_{s}", 0) or 0 for s in _SEVERITIES},
        error=scan.error_message,
    )
    rows = await db.execute(
        select(Finding, Host.ip)
        .outerjoin(Host, Finding.host_id == Host.id)
        .where(
            Finding.scan_id == scan.id,
            Finding.false_positive == False,  # noqa: E712
            Finding.remediation_status == "open",
            Finding.severity != "info",
        )
        .order_by(Finding.priority_score.desc().nulls_last(), Finding.created_at.desc())
        .limit(_TOP_FINDINGS)
    )
    for finding, ip in rows.all():
        try:
            reasons = json.loads(finding.priority_reasons or "[]")
        except ValueError:
            reasons = []
        location = ip or "-"
        if finding.port_number:
            location += f":{finding.port_number}"
        summary.top.append(TopFinding(
            title=finding.title,
            location=location,
            severity=finding.severity,
            priority=finding.priority_score,
            kev=finding.is_kev,
            reasons=[str(r) for r in reasons][1:3],
        ))
    scores = [f.priority for f in summary.top if f.priority is not None]
    summary.max_priority = max(scores) if scores else None
    return summary


def _counts_line(summary: ScanSummary) -> str:
    return ", ".join(f"{summary.counts.get(s, 0)} {s}" for s in _SEVERITIES[:4])


def _finding_line(f: TopFinding) -> str:
    score = f"[{round(f.priority)}{' KEV' if f.kev else ''}] " if f.priority is not None else ""
    why = f" — {'; '.join(f.reasons)}" if f.reasons else ""
    return f"{score}{f.title} ({f.location}){why}"


def render_text(summary: ScanSummary) -> str:
    lines = [summary.headline, ""]
    if summary.status == "failed":
        lines.append(f"Error: {summary.error or 'unknown'}")
    else:
        lines.append(f"{summary.hosts_up} hosts up. Findings: {_counts_line(summary)}.")
        if summary.top:
            lines += ["", "Fix first:"] + [f"  {_finding_line(f)}" for f in summary.top]
    lines += ["", f"Open ScanR: {summary.link}"]
    return "\n".join(lines)


def render_html(summary: ScanSummary) -> str:
    e = html.escape
    parts = [f"<h2 style=\"font-family:sans-serif\">{e(summary.headline)}</h2>"]
    if summary.status == "failed":
        parts.append(f"<p style=\"font-family:sans-serif\">Error: {e(summary.error or 'unknown')}</p>")
    else:
        parts.append(
            f"<p style=\"font-family:sans-serif\">{summary.hosts_up} hosts up. "
            f"Findings: {e(_counts_line(summary))}.</p>"
        )
        if summary.top:
            rows = "".join(
                "<tr>"
                f"<td style=\"padding:4px 8px\"><b>{'' if f.priority is None else round(f.priority)}</b>"
                f"{' KEV' if f.kev else ''}</td>"
                f"<td style=\"padding:4px 8px\">{e(f.title)}<br><small>{e(f.location)}"
                f"{' — ' + e('; '.join(f.reasons)) if f.reasons else ''}</small></td>"
                "</tr>"
                for f in summary.top
            )
            parts.append(
                "<p style=\"font-family:sans-serif\"><b>Fix first</b></p>"
                f"<table style=\"font-family:sans-serif;font-size:13px;border-collapse:collapse\">{rows}</table>"
            )
    parts.append(f"<p style=\"font-family:sans-serif\"><a href=\"{e(summary.link)}\">Open ScanR</a></p>")
    return "".join(parts)


def slack_payload(summary: ScanSummary) -> dict:
    lines = [f"*{summary.headline}*"]
    if summary.status == "failed":
        lines.append(f"Error: {summary.error or 'unknown'}")
    else:
        lines.append(f"{summary.hosts_up} hosts up · {_counts_line(summary)}")
        lines += [f"• {_finding_line(f)}" for f in summary.top]
    # Slack treats <, > and & as markup; finding titles come from scanned hosts.
    text = "\n".join(lines).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text += f"\n<{summary.link}|Open ScanR>"
    return {"text": summary.headline, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}]}


def teams_payload(summary: ScanSummary) -> dict:
    body: list[dict] = [{"type": "TextBlock", "text": summary.headline, "weight": "Bolder", "size": "Medium", "wrap": True}]
    if summary.status == "failed":
        body.append({"type": "TextBlock", "text": f"Error: {summary.error or 'unknown'}", "wrap": True, "color": "Attention"})
    else:
        body.append({"type": "TextBlock", "text": f"{summary.hosts_up} hosts up · {_counts_line(summary)}", "wrap": True})
        if summary.top:
            body.append({
                "type": "FactSet",
                "facts": [
                    {
                        "title": f"{'' if f.priority is None else round(f.priority)}{' KEV' if f.kev else ''}",
                        "value": f"{f.title} ({f.location})",
                    }
                    for f in summary.top
                ],
            })
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "actions": [{"type": "Action.OpenUrl", "title": "Open ScanR", "url": summary.link}],
    }
    return {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
    }


def _send_email_sync(to: str, subject: str, text: str, html_body: str) -> None:
    settings = get_settings()
    if not settings.smtp_enabled:
        raise NotificationError("Email is not configured on this server (set SMTP_HOST and SMTP_FROM)")
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    message.add_alternative(html_body, subtype="html")
    context = ssl.create_default_context()
    try:
        if settings.smtp_security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20, context=context)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
        with server:
            if settings.smtp_security == "starttls":
                server.starttls(context=context)
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotificationError(f"SMTP delivery failed: {exc}") from exc


async def _post_json(url: str, payload: dict) -> None:
    from scanr.utils import safe_http

    client = await safe_http.pinned_async_client(
        url, extra_denylist=get_settings().scan_denylist, timeout=15.0, forbid_private=True
    )
    async with client:
        resp = await client.post(url, json=payload)
    if not resp.is_success:
        raise NotificationError(f"HTTP {resp.status_code}: {resp.text[:200]}")


async def send(channel: NotificationChannel, summary: ScanSummary) -> None:
    """Deliver one summary. Raises NotificationError (or ValueError for a bad target)."""
    try:
        target = decrypt_target(channel)
    except Exception as exc:
        raise NotificationError("Stored destination could not be decrypted; check VAULT_KEY") from exc
    if channel.kind == "email":
        await asyncio.to_thread(_send_email_sync, target, summary.headline, render_text(summary), render_html(summary))
    elif channel.kind == "slack":
        await _post_json(validate_target("slack", target), slack_payload(summary))
    elif channel.kind == "teams":
        await _post_json(validate_target("teams", target), teams_payload(summary))
    else:
        raise NotificationError(f"Unknown channel type {channel.kind!r}")


async def deliver(db: AsyncSession, channel: NotificationChannel, summary: ScanSummary) -> bool:
    """Send and record the outcome on the channel. The caller commits."""
    try:
        await send(channel, summary)
    except Exception as exc:
        logger.warning("Notification %s (%s) failed: %s", channel.id, channel.kind, exc)
        channel.last_status = "failed"
        channel.last_error = str(exc)[:500]
        return False
    finally:
        channel.last_sent_at = datetime.now(timezone.utc)
    channel.last_status = "sent"
    channel.last_error = None
    return True


def wants(channel: NotificationChannel, event: str, summary: ScanSummary) -> bool:
    try:
        events = json.loads(channel.events)
    except ValueError:
        return False
    if event not in events:
        return False
    if event == "scan.completed" and channel.min_priority is not None:
        return summary.max_priority is not None and summary.max_priority >= channel.min_priority
    return True


async def notify_scan_finished(db: AsyncSession, scan_id: str) -> int:
    """Send the scan's summary to every matching channel of its owner."""
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if scan is None or str(scan.status) not in ("completed", "failed"):
        return 0
    event = f"scan.{scan.status}"
    channels = (await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.user_id == scan.user_id,
            NotificationChannel.enabled == True,  # noqa: E712
        )
    )).scalars().all()
    if not channels:
        return 0
    summary = await build_summary(db, scan)
    sent = 0
    for channel in channels:
        if wants(channel, event, summary):
            sent += await deliver(db, channel, summary)
    await db.commit()
    return sent


def sample_summary() -> ScanSummary:
    """What a test message shows."""
    return ScanSummary(
        scan_id="test",
        name="Test notification from ScanR",
        status="completed",
        hosts_up=12,
        counts={"critical": 1, "high": 3, "medium": 7, "low": 4, "info": 9},
        top=[
            TopFinding("Example: known exploited VPN appliance flaw", "203.0.113.10:443", "high", 91.0, True,
                       ["known exploited (CISA KEV)", "internet-facing host"]),
            TopFinding("Example: outdated TLS configuration", "10.0.0.5:443", "medium", 41.0, False, []),
        ],
        max_priority=91.0,
    )

