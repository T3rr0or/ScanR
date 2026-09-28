"""Certificate Transparency log exposure.

Every publicly-trusted certificate issued since 2018 is published to append-only
Certificate Transparency logs. Those logs are a permanent, searchable inventory
of names an organisation has ever certified — including the ones it never meant
to publish. A certificate for ``jenkins.internal.example.com`` or
``staging-db.example.com`` tells an attacker the host exists, what it probably
runs, and that it was worth protecting, without a single packet sent to the
target.

This is the only check in ScanR that queries a third party rather than the
target, so it is opt-in twice over: it needs both ``tls_checks`` and
``dns_recon`` enabled. The query is the target's own domain name, sent to a
public CT log aggregator — the same lookup an attacker performs first, which is
the point of running it.

Nothing is sent to the target. The names found here are candidates for the rest
of the scan, not findings about a live service.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.utils.safe_http import UnsafeHTTPDestination, pinned_async_client

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_CT_LOG_HOST = "crt.sh"
_CT_LOG_URL = "https://crt.sh/?output=json&q=%25.{domain}"
_TIMEOUT = 20.0
# CT logs return every certificate ever issued; a large estate can return tens of
# thousands of rows. Cap the read so a scan cannot be stalled by the response.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_NAMES_REPORTED = 200

_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

# Name fragments that mark a host as one an organisation did not intend to
# advertise. Matched as a label, not a substring, so "development.example.com"
# matches and "devices.example.com" does not.
SENSITIVE_LABELS = frozenset({
    "adfs", "admin", "backup", "bastion", "ci", "citrix", "confluence", "corp",
    "dc", "dev", "development", "gitlab", "grafana", "internal", "intranet",
    "jenkins", "jira", "jump", "kibana", "lab", "ldap", "mgmt", "monitor",
    "nexus", "ops", "phpmyadmin", "preprod", "private", "qa", "rancher", "rdp",
    "sandbox", "sonar", "stage", "staging", "test", "testing", "uat", "vault",
    "vcenter", "vpn",
})


def extract_names(rows: object, domain: str) -> list[str]:
    """Hostnames under `domain` from a crt.sh JSON response.

    The response is third-party data, so every row is treated as untrusted:
    anything that is not a syntactically valid hostname inside the scanned
    domain is dropped rather than reported.
    """
    if not isinstance(rows, list):
        return []
    suffix = "." + domain
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            raw = row.get(field)
            if not isinstance(raw, str):
                continue
            for candidate in raw.replace("\\n", "\n").splitlines():
                name = candidate.strip().lower().lstrip("*.").rstrip(".")
                if not name or len(name) > 253:
                    continue
                if name != domain and not name.endswith(suffix):
                    continue
                if not _HOSTNAME_RE.match(name):
                    continue
                names.add(name)
    return sorted(names)


def sensitive_names(names: list[str], domain: str) -> list[str]:
    """Names whose labels suggest a non-public environment."""
    flagged = []
    for name in names:
        if name == domain:
            continue
        labels = name.removesuffix("." + domain).split(".")
        if any(label in SENSITIVE_LABELS for label in labels):
            flagged.append(name)
            continue
        # Composite labels such as "staging-api" or "vpn2".
        for label in labels:
            parts = re.split(r"[-_0-9]+", label)
            if any(part in SENSITIVE_LABELS for part in parts if part):
                flagged.append(name)
                break
    return flagged


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class CtLogExposurePlugin(PluginBase):
    id = "ssl_tls.ct_log_exposure"
    name = "Certificate Transparency Log Exposure"
    description = (
        "Enumerate hostnames the target's domain has published to public "
        "Certificate Transparency logs, flagging internal and pre-production names"
    )
    category = PluginCategory.ssl_tls
    severity = Severity.info
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        domain = self._domain(context, host)
        if not domain:
            return []

        names = await self._query_ct_logs(domain)
        if not names:
            return []

        flagged = sensitive_names(names, domain)
        return [self._build_finding(domain, names, flagged)]

    @staticmethod
    def _domain(context: "ScanContext", host: "Host") -> str | None:
        hostname = (getattr(host, "hostname", None) or "").strip().lower()
        if not hostname and context is not None:
            hostname = (context.original_hostname(host.ip) or "").strip().lower()
        hostname = hostname.removeprefix("*.").rstrip(".")
        if not hostname or _is_ip(hostname) or "." not in hostname:
            return None
        # Keep the supplied hostname as the scope. Guessing a registrable parent
        # from the last two labels turns app.example.co.uk into co.uk (and can
        # cross tenant boundaries on shared hosting domains).
        return hostname

    async def _query_ct_logs(self, domain: str) -> list[str]:
        url = _CT_LOG_URL.format(domain=domain)
        try:
            client = await pinned_async_client(
                url, timeout=_TIMEOUT, verify=True, forbid_private=True
            )
        except UnsafeHTTPDestination as exc:
            logger.debug("CT log lookup refused for %s: %s", domain, exc)
            return []
        except Exception as exc:
            logger.debug("CT log client setup failed for %s: %s", domain, exc)
            return []

        try:
            async with client:
                response = await client.get(url, headers={"Accept": "application/json"})
                if response.status_code != 200:
                    return []
                if len(response.content) > _MAX_RESPONSE_BYTES:
                    logger.debug("CT log response for %s exceeded the read cap", domain)
                    return []
                rows = response.json()
        except Exception as exc:
            # No egress to the aggregator, rate limiting, or a malformed body.
            # None of those are findings about the target.
            logger.debug("CT log lookup failed for %s: %s", domain, exc)
            return []

        return extract_names(rows, domain)

    def _build_finding(
        self, domain: str, names: list[str], flagged: list[str]
    ) -> FindingData:
        severity = Severity.medium if flagged else Severity.info
        shown = names[:_MAX_NAMES_REPORTED]

        evidence = [
            f"Queried {_CT_LOG_HOST} for certificates covering *.{domain}",
            f"Distinct hostnames published: {len(names)}",
        ]
        if flagged:
            evidence.append("")
            evidence.append(f"Names suggesting non-public environments ({len(flagged)}):")
            evidence.extend(f"  {name}" for name in flagged[:_MAX_NAMES_REPORTED])
        evidence.append("")
        evidence.append("All published hostnames:")
        evidence.extend(f"  {name}" for name in shown)
        if len(names) > len(shown):
            evidence.append(f"  [... {len(names) - len(shown)} more omitted]")

        if flagged:
            description = (
                f"Public Certificate Transparency logs list {len(names)} hostnames under "
                f"{domain}, of which {len(flagged)} carry labels that mark them as "
                "internal, pre-production, or administrative.\n\n"
                "These names are permanently public. CT logs are append-only by design, "
                "so a certificate issued once for an internal host cannot be withdrawn "
                "from the record — removing DNS or decommissioning the host does not "
                "remove the name. An attacker starts an engagement here: the list gives "
                "them a target inventory including the systems least likely to be "
                "monitored, and names like 'jenkins' or 'vcenter' say what to expect "
                "before a single packet is sent."
            )
        else:
            description = (
                f"Public Certificate Transparency logs list {len(names)} hostnames under "
                f"{domain}. This is the attack surface inventory an attacker builds "
                "before touching the network, recorded here so the report reflects what "
                "is publicly known about this domain. Nothing in the list looks like an "
                "internal or pre-production name."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=(
                f"Internal Hostnames Published in Certificate Transparency Logs ({domain})"
                if flagged
                else f"Certificate Transparency Inventory for {domain}"
            ),
            description=description,
            evidence="\n".join(evidence),
            remediation=(
                "Treat CT logs as public and plan for it rather than trying to undo it. "
                "Issue certificates for internal hosts from an internal CA, which does "
                "not log to CT. Where a public certificate is genuinely needed for an "
                "internal name, use a wildcard so the specific host name is never "
                "published, or a name that carries no information about the system's "
                "role. Monitor CT logs for your own domains (crt.sh and Cert Spotter "
                "both offer alerting) so an unexpected issuance is noticed — that is "
                "also how mis-issuance and certain phishing setups are caught.\n\n"
                "For the names already published: confirm each is intended to be "
                "reachable, and firewall the ones that are not."
            ),
            references=[
                "https://certificate.transparency.dev/",
                "https://crt.sh/",
                "https://datatracker.ietf.org/doc/html/rfc6962",
            ],
            port_number=None,
            protocol=None,
        )
