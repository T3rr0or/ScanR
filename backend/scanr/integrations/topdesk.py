"""TOPdesk incident integration.

Pushes a finding into TOPdesk as an incident so remediation is tracked where the
service desk already works, instead of in a PDF someone has to transcribe.

Two things carry most of the design:

**Idempotency.** Pressing "create ticket" twice, or re-running an automation,
must not open two incidents for one finding. Every incident is stamped with
``externalNumber = scanr:<fingerprint>``, where the fingerprint is the same
plugin+host+port+title identity the SARIF export uses. Before creating, we search
TOPdesk for that number and adopt an existing incident if one is there. A unique
constraint on (finding_id, provider) backs this up locally, so the two failure
modes — lost local link, concurrent local requests — are each covered.

**Credentials.** TOPdesk authenticates with an *application password*, not the
operator's own password. It is stored Fernet-encrypted via the credential vault,
admin-only, and never returned by the API.

Not verifiable here: there is no TOPdesk instance to test against, so the wire
format follows the documented `/tas/api/incidents` contract and the tests drive a
mocked transport. The `/test` endpoint exists so an operator can confirm the real
thing in one click rather than discovering it on first use.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from urllib.parse import quote, urljoin, urlparse

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

PROVIDER = "topdesk"

_KEY_PREFIX = "integration.topdesk."
_URL_KEY = _KEY_PREFIX + "url"
_USER_KEY = _KEY_PREFIX + "username"
_PASSWORD_KEY = _KEY_PREFIX + "password"  # vault-encrypted
_DEFAULTS_KEY = _KEY_PREFIX + "defaults"

#: TOPdesk stamps this on the incident so we can find it again. Namespaced so it
#: cannot collide with numbers the customer's own automation writes.
EXTERNAL_NUMBER_PREFIX = "scanr:"

#: ScanR severity → TOPdesk priority name. These are the out-of-the-box TOPdesk
#: names; an instance with a customised priority scheme overrides them in the
#: integration's defaults rather than us guessing.
_DEFAULT_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P4",
}


class TopdeskError(Exception):
    """A TOPdesk call failed in a way the operator needs to see."""


@dataclass(frozen=True)
class TopdeskConfig:
    url: str
    username: str
    password: str
    #: Optional per-instance field names (category, subcategory, call type, …).
    defaults: dict

    @property
    def base(self) -> str:
        return self.url.rstrip("/") + "/"


def build_external_number(fingerprint: str) -> str:
    return f"{EXTERNAL_NUMBER_PREFIX}{fingerprint}"


def validate_url(url: str) -> str:
    """Reject URLs that point at ScanR's own infrastructure.

    Private ranges are deliberately *allowed*: on-premise TOPdesk is common, and a
    self-hosted scanner reaching a self-hosted service desk over RFC1918 is the
    normal case. What must never be reachable is loopback, link-local (cloud
    metadata) or the scanner's own services — which is exactly what
    is_forbidden_target covers, so this is narrower than the webhook rule on
    purpose. It is also admin-only configuration, not per-user.
    """
    from scanr.config import get_settings
    from scanr.utils.ip_utils import is_forbidden_target

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TopdeskError("TOPdesk URL must start with http:// or https://")
    host = parsed.hostname
    if not host:
        raise TopdeskError("TOPdesk URL is missing a hostname")
    if is_forbidden_target(host, get_settings().scan_denylist):
        raise TopdeskError(
            "TOPdesk URL points at loopback, link-local or ScanR's own infrastructure"
        )
    return url.rstrip("/")


# ── configuration storage ────────────────────────────────────────────────────

async def save_config(
    db: AsyncSession, *, url: str, username: str, password: str | None, defaults: dict | None
) -> None:
    """Persist the integration settings. ``password=None`` keeps the stored one,
    so an operator can edit the URL without re-entering the secret."""
    import json

    from scanr.ai import settings_store as store
    from scanr.credentials import vault

    validated = validate_url(url)
    await store._set_raw(db, _URL_KEY, validated)
    await store._set_raw(db, _USER_KEY, username)
    if password:
        await store._set_raw(db, _PASSWORD_KEY, vault.encrypt({"v": password}))
    await store._set_raw(db, _DEFAULTS_KEY, json.dumps(defaults or {}))


async def clear_config(db: AsyncSession) -> None:
    from scanr.ai import settings_store as store

    for key in (_URL_KEY, _USER_KEY, _PASSWORD_KEY, _DEFAULTS_KEY):
        await store._delete_raw(db, key)


async def load_config(db: AsyncSession) -> TopdeskConfig | None:
    """Return the configured integration, or None if it is not set up."""
    import json

    from scanr.ai import settings_store as store
    from scanr.credentials import vault

    url = await store._get_raw(db, _URL_KEY)
    username = await store._get_raw(db, _USER_KEY)
    raw_password = await store._get_raw(db, _PASSWORD_KEY)
    if not (url and username and raw_password):
        return None
    try:
        password = vault.decrypt(raw_password).get("v") or ""
    except Exception:
        logger.error("Stored TOPdesk password could not be decrypted (VAULT_KEY changed?)")
        return None
    if not password:
        return None
    raw_defaults = await store._get_raw(db, _DEFAULTS_KEY)
    try:
        defaults = json.loads(raw_defaults) if raw_defaults else {}
    except ValueError:
        defaults = {}
    return TopdeskConfig(url=url, username=username, password=password, defaults=defaults)


async def config_status(db: AsyncSession) -> dict:
    """Non-secret view for the UI. Never includes the application password."""
    from scanr.ai import settings_store as store

    url = await store._get_raw(db, _URL_KEY)
    username = await store._get_raw(db, _USER_KEY)
    has_password = bool(await store._get_raw(db, _PASSWORD_KEY))
    return {
        "configured": bool(url and username and has_password),
        "url": url,
        "username": username,
        "has_password": has_password,
    }


# ── incident payload ─────────────────────────────────────────────────────────

def build_incident(finding, host_ip: str, fingerprint: str, defaults: dict) -> dict:
    """Map a finding onto a TOPdesk incident.

    Only fields TOPdesk accepts by *name* are set; anything instance-specific
    (category, operator group, caller) comes from the configured defaults, because
    guessing at a customer's taxonomy produces incidents their service desk has to
    re-file by hand.
    """
    severity = str(getattr(finding, "severity", "") or "info").lower()
    location = f"{host_ip}:{finding.port_number}" if finding.port_number else host_ip

    brief = f"[{severity.upper()}] {finding.title}"[:80]  # TOPdesk caps this field

    body_parts = [
        f"Reported by ScanR (finding {finding.id}).",
        "",
        f"Severity: {severity}",
        f"Affected: {location or 'unknown'}",
        f"Check: {finding.plugin_id}",
    ]
    if getattr(finding, "cvss_score", None) is not None:
        body_parts.append(f"CVSS: {finding.cvss_score}")
    if getattr(finding, "description", None):
        body_parts += ["", "Description:", str(finding.description)]
    if getattr(finding, "evidence", None):
        body_parts += ["", "Evidence:", str(finding.evidence)[:2000]]
    if getattr(finding, "remediation", None):
        body_parts += ["", "Remediation:", str(finding.remediation)]

    incident: dict = {
        "briefDescription": brief,
        "request": "\n".join(body_parts),
        "externalNumber": build_external_number(fingerprint),
    }

    priority = (defaults.get("priority_by_severity") or {}).get(severity) or _DEFAULT_PRIORITY.get(severity)
    if priority:
        incident["priority"] = {"name": priority}

    # Named lookups, only when the operator configured them.
    for field, key in (
        ("category", "category"),
        ("subcategory", "subcategory"),
        ("callType", "call_type"),
        ("entryType", "entry_type"),
        ("operatorGroup", "operator_group"),
    ):
        value = defaults.get(key)
        if value:
            incident[field] = {"name": value}

    caller_email = defaults.get("caller_email")
    if caller_email:
        incident["callerLookup"] = {"email": caller_email}

    branch = defaults.get("branch")
    if branch:
        incident.setdefault("callerLookup", {})["branch"] = {"name": branch}

    status = defaults.get("status")
    if status in ("firstLine", "secondLine", "partial"):
        incident["status"] = status

    return incident


# ── client ───────────────────────────────────────────────────────────────────

class TopdeskClient:
    """Thin TOPdesk REST client.

    ``transport`` exists so tests can drive the whole flow — search, adopt,
    create, error mapping — without a live instance.
    """

    def __init__(self, config: TopdeskConfig, transport=None, timeout: float = 20.0):
        self._config = config
        self._transport = transport
        self._timeout = timeout

    def _headers(self) -> dict:
        token = base64.b64encode(
            f"{self._config.username}:{self._config.password}".encode()
        ).decode()
        return {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _client(self):
        import httpx

        return httpx.AsyncClient(
            timeout=self._timeout,
            transport=self._transport,
            # A redirect would re-send the Authorization header to wherever it
            # points; make the operator fix the URL instead.
            follow_redirects=False,
        )

    def incident_url(self, number: str | None) -> str | None:
        if not number:
            return None
        return urljoin(self._config.base, f"tas/secure/incident?action=show&unid={quote(number)}")

    async def _request(self, method: str, path: str, **kw):
        import httpx

        url = urljoin(self._config.base, path.lstrip("/"))
        try:
            async with self._client() as client:
                resp = await client.request(method, url, headers=self._headers(), **kw)
        except httpx.HTTPError as exc:
            raise TopdeskError(f"Could not reach TOPdesk: {exc}") from exc

        if resp.status_code in (401, 403):
            raise TopdeskError(
                "TOPdesk rejected the credentials. Check the username and that the "
                "application password is valid for this instance."
            )
        if resp.status_code == 404:
            raise TopdeskError(
                f"TOPdesk returned 404 for {path} — check the instance URL "
                f"(it should be the base, e.g. https://example.topdesk.net)."
            )
        if 300 <= resp.status_code < 400:
            # Redirects are deliberately not followed, so treat one as a
            # configuration error rather than letting it through as success:
            # otherwise a URL that redirects (http→https, a load balancer) passes
            # the connection test and fails later, when someone files a ticket.
            raise TopdeskError(
                f"TOPdesk redirected ({resp.status_code}) to "
                f"{resp.headers.get('location', 'an unknown location')}. Redirects are "
                f"not followed, because that would resend the credentials to wherever "
                f"the redirect points — configure the final URL directly."
            )
        if resp.status_code >= 400:
            raise TopdeskError(f"TOPdesk error {resp.status_code}: {resp.text[:300]}")
        return resp

    async def verify(self) -> dict:
        """Cheap authenticated call, so an operator can confirm setup in one click."""
        resp = await self._request("GET", "tas/api/incidents", params={"page_size": 1})
        return {"ok": True, "status_code": resp.status_code}

    async def find_by_external_number(self, external_number: str) -> dict | None:
        """Adopt an existing incident rather than opening a duplicate."""
        resp = await self._request(
            "GET", "tas/api/incidents",
            params={"query": f"externalNumber=={external_number}", "page_size": 1},
        )
        try:
            data = resp.json()
        except ValueError:
            return None
        if isinstance(data, list) and data:
            return data[0]
        return None

    async def create_incident(self, payload: dict) -> dict:
        resp = await self._request("POST", "tas/api/incidents", json=payload)
        try:
            return resp.json()
        except ValueError as exc:
            raise TopdeskError("TOPdesk returned a non-JSON response to the create call") from exc

    async def get_incident(self, incident_id: str) -> dict | None:
        resp = await self._request("GET", f"tas/api/incidents/id/{quote(incident_id)}")
        try:
            return resp.json()
        except ValueError:
            return None


# ── orchestration ────────────────────────────────────────────────────────────

async def create_ticket_for_finding(
    db: AsyncSession,
    finding,
    host_ip: str,
    *,
    user_id: str | None = None,
    client: "TopdeskClient | None" = None,
) -> tuple["object", bool]:
    """Create (or adopt) the TOPdesk incident for a finding.

    Returns (TicketLink, created) — ``created`` is False when an existing incident
    was adopted, so the caller can tell the operator "already tracked" rather than
    implying a new ticket was opened.

    Order matters. The local link is checked first (cheapest, and covers the
    common repeat press), then TOPdesk is searched by external number (covers a
    link lost to a database restore, or a ticket opened by a different ScanR
    instance), and only then is anything created.
    """
    from sqlalchemy import select

    from scanr.models import TicketLink
    from scanr.models.base import new_uuid
    from scanr.reporting.sarif_renderer import _fingerprint

    existing = (
        await db.execute(
            select(TicketLink).where(
                TicketLink.finding_id == finding.id, TicketLink.provider == PROVIDER
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing, False

    config = await load_config(db)
    if config is None:
        raise TopdeskError(
            "TOPdesk is not configured. Set the instance URL, username and "
            "application password in Settings → Integrations."
        )
    client = client or TopdeskClient(config)

    fingerprint = _fingerprint(finding.plugin_id, host_ip, finding.port_number, finding.title)
    external_number = build_external_number(fingerprint)

    incident = await client.find_by_external_number(external_number)
    created = False
    if incident is None:
        incident = await client.create_incident(
            build_incident(finding, host_ip, fingerprint, config.defaults)
        )
        created = True

    incident_id = str(incident.get("id") or "")
    if not incident_id:
        raise TopdeskError("TOPdesk did not return an incident id")
    number = incident.get("number")

    link = TicketLink(
        id=new_uuid(),
        finding_id=finding.id,
        provider=PROVIDER,
        external_id=incident_id,
        external_key=str(number) if number else None,
        url=client.incident_url(incident_id),
        external_status=_status_of(incident),
        created_by=user_id,
    )
    db.add(link)
    try:
        await db.commit()
    except Exception:
        # Unique (finding_id, provider): another request won the race. Its ticket
        # is the same incident — externalNumber dedup guarantees that — so adopt
        # the row it wrote rather than surfacing an integrity error.
        await db.rollback()
        winner = (
            await db.execute(
                select(TicketLink).where(
                    TicketLink.finding_id == finding.id, TicketLink.provider == PROVIDER
                )
            )
        ).scalar_one_or_none()
        if winner is None:
            raise
        return winner, False
    await db.refresh(link)
    return link, created


def _status_of(incident: dict) -> str | None:
    """TOPdesk reports processing status in a few shapes depending on version."""
    for key in ("processingStatus", "status"):
        value = incident.get(key)
        if isinstance(value, dict) and value.get("name"):
            return str(value["name"])[:64]
        if isinstance(value, str) and value:
            return value[:64]
    return None
