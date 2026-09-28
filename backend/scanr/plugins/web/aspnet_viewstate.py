"""ASP.NET ViewState protection.

``__VIEWSTATE`` is a serialized .NET object graph that the client is asked to
hold and hand back. Two settings decide whether that is safe:

* **Encryption** (``viewStateEncryptionMode``). Without it the field is a
  readable object graph — base64, not ciphertext. Control state, data-bound row
  contents, and whatever the developer parked in ``ViewState[...]`` are all
  legible to anyone who views source. Connection strings and internal paths turn
  up there regularly.

* **MAC validation** (``enableViewStateMac``). Without it the server
  deserializes whatever the client sends. ``ObjectStateFormatter`` is a
  gadget-rich deserializer, so an attacker who can supply an unverified
  ViewState gets remote code execution on the web server — no credentials, no
  further vulnerability required. This is the class ``ysoserial.net`` targets.

Encryption is read from the field itself: ``ObjectStateFormatter`` output starts
with the marker ``0xFF 0x01``, so a field that decodes to that prefix is
plaintext, whatever the app's configuration claims.

MAC validation is confirmed rather than guessed, because guessing it from
``__VIEWSTATEGENERATOR`` is unreliable. One corrupted ViewState is posted back
and the server's own answer decides: an explicit MAC-validation error means the
protection works; a normally rendered page means it does not.

That probe is why this check is intrusive. It is not state-changing: no
``__EVENTTARGET`` is sent, and ASP.NET rejects the malformed ViewState during
``LoadViewState`` — before any postback event handler can run — so no page action
is dispatched. It will appear in the application's error log, which is the
expected cost of an intrusive check.
"""
from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# ObjectStateFormatter's serialization marker: version 0xFF, format 0x01.
_PLAINTEXT_MARKER = b"\xff\x01"

_HIDDEN_FIELD_RE = re.compile(
    r"""<input[^>]*?\btype\s*=\s*["']?hidden["']?[^>]*?>""", re.I | re.S
)
_ATTR_RE = re.compile(r"""\b(name|value|id)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)

_PATHS = ("/", "/default.aspx", "/login.aspx", "/Default.aspx")

# The server telling us the MAC was checked. Any of these means the protection
# is working, so nothing is reported.
_MAC_FAILURE_MARKERS = (
    "validation of viewstate mac failed",
    "viewstate mac validation",
    "the state information is invalid for this page",
    "viewstatemacvalidationerror",
    "invalid viewstate",
    "httpexception: unable to validate data",
    "unable to validate data",
    "machinekey",
)

# Strings worth naming when a plaintext ViewState carries them.
_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("SQL connection string", re.compile(rb"(?i)(?:Data Source|Initial Catalog|Integrated Security)\s*=")),
    ("embedded password", re.compile(rb"(?i)\b(?:password|pwd)\s*=\s*\S")),
    ("UNC path", re.compile(rb"\\\\[A-Za-z0-9_.$-]+\\[A-Za-z0-9_.$-]+")),
    ("local filesystem path", re.compile(rb"[A-Za-z]:\\(?:inetpub|Windows|Program Files|Users)\\")),
    ("email address", re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
)

_MIN_PRINTABLE_RUN = 6
_MAX_STRINGS_SHOWN = 15


@dataclass
class ViewStateForm:
    """A page carrying a ViewState, and the fields needed to post it back."""

    url: str
    viewstate: str
    fields: dict[str, str]

    @property
    def has_generator(self) -> bool:
        return "__VIEWSTATEGENERATOR" in self.fields


def parse_hidden_fields(html: str) -> dict[str, str]:
    """Hidden input name→value pairs, keyed by name (falling back to id)."""
    fields: dict[str, str] = {}
    for tag in _HIDDEN_FIELD_RE.findall(html):
        attributes: dict[str, str] = {}
        for match in _ATTR_RE.finditer(tag):
            key = match.group(1).lower()
            attributes[key] = match.group(2) or match.group(3) or match.group(4) or ""
        name = attributes.get("name") or attributes.get("id")
        if name:
            fields[name] = attributes.get("value", "")
    return fields


def decode_viewstate(value: str) -> bytes | None:
    """Base64-decode a ViewState field; None when it is not valid base64."""
    stripped = value.strip()
    if not stripped:
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None


def is_plaintext(raw: bytes | None) -> bool:
    """True when the field is an unencrypted ObjectStateFormatter graph."""
    return bool(raw) and raw[:2] == _PLAINTEXT_MARKER


def readable_strings(raw: bytes, minimum: int = _MIN_PRINTABLE_RUN) -> list[str]:
    """Printable runs inside a decoded ViewState — what an attacker reads off it."""
    found: list[str] = []
    current = bytearray()
    for byte in raw:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
            continue
        if len(current) >= minimum:
            found.append(current.decode("ascii"))
        current.clear()
    if len(current) >= minimum:
        found.append(current.decode("ascii"))
    return found


def sensitive_content(raw: bytes) -> list[str]:
    """Named categories of sensitive data present in a plaintext ViewState."""
    return [label for label, pattern in _SENSITIVE_PATTERNS if pattern.search(raw)]


def corrupt_viewstate(value: str) -> str:
    """A ViewState whose bytes no longer match any MAC over them.

    The change is in the payload rather than a trailing signature, so a server
    that validates the MAC must reject it and a server that does not must try to
    deserialize it. Padding is preserved so the field stays valid base64 and the
    difference is never about the encoding.
    """
    raw = decode_viewstate(value)
    if raw is None or len(raw) < 8:
        return value
    mutated = bytearray(raw)
    middle = len(mutated) // 2
    mutated[middle] ^= 0xFF
    return base64.b64encode(bytes(mutated)).decode("ascii")


def mac_is_validated(status_code: int, body: str) -> bool:
    """Did the server reject our corrupted ViewState?

    Fail closed: any server error, and any body naming a validation failure,
    counts as the protection working. Only a cleanly rendered page is treated as
    proof that the ViewState was accepted unverified.
    """
    if status_code >= 500:
        return True
    if status_code in (400, 403, 406, 419):
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in _MAC_FAILURE_MARKERS)


class AspNetViewStatePlugin(PluginBase):
    id = "web.aspnet_viewstate"
    name = "ASP.NET ViewState Protection"
    description = (
        "Detect unencrypted ASP.NET ViewState and confirm whether MAC validation "
        "is enforced, which decides whether the field is a deserialization sink"
    )
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        authority = getattr(host, "hostname", None) or host.ip
        for port in host.ports:
            if not is_web_port(port):
                continue
            base_url = f"{web_scheme(port)}://{authority}:{port.number}"
            try:
                findings.extend(
                    await self._check_port(context, base_url, host.ip, port.number, authority)
                )
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("aspnet_viewstate: %s failed: %s", base_url, exc)
        return findings

    async def _check_port(
        self, context, base_url: str, pin_ip: str, pin_port: int, authority: str
    ) -> list[FindingData]:
        async with create_web_client(
            context, pin_ip=pin_ip, pin_port=pin_port, pin_hostname=authority
        ) as client:
            form = await self._find_viewstate(client, base_url)
            if form is None:
                return []

            findings: list[FindingData] = []
            raw = decode_viewstate(form.viewstate)
            if is_plaintext(raw) and raw is not None:
                findings.append(self._plaintext_finding(form, raw, pin_port))

            accepted = await self._probe_mac(client, form)
            if accepted:
                findings.append(self._mac_finding(form, pin_port))
            return findings

    async def _find_viewstate(self, client, base_url: str) -> ViewStateForm | None:
        for path in _PATHS:
            url = f"{base_url}{path}"
            try:
                response = await client.get(url, timeout=8.0)
            except Exception:
                continue
            if response.status_code != 200:
                continue
            if "html" not in response.headers.get("content-type", "").lower():
                continue
            fields = parse_hidden_fields(response.text)
            viewstate = fields.get("__VIEWSTATE", "")
            if viewstate and decode_viewstate(viewstate):
                return ViewStateForm(url=url, viewstate=viewstate, fields=fields)
        return None

    async def _probe_mac(self, client, form: ViewStateForm) -> bool:
        """True when the server accepted a ViewState it could not have verified."""
        corrupted = corrupt_viewstate(form.viewstate)
        if corrupted == form.viewstate:
            return False
        # Post back every hidden field the page gave us, with only __VIEWSTATE
        # altered, and deliberately no __EVENTTARGET — so nothing can dispatch a
        # page event even on a server that accepts the field.
        payload = dict(form.fields)
        payload["__VIEWSTATE"] = corrupted
        payload.pop("__EVENTTARGET", None)
        payload.pop("__EVENTARGUMENT", None)
        try:
            response = await client.post(form.url, data=payload, timeout=10.0)
        except Exception:
            # No answer is not evidence the field was accepted.
            return False
        if response.status_code != 200:
            return False
        return not mac_is_validated(response.status_code, response.text)

    def _plaintext_finding(
        self, form: ViewStateForm, raw: bytes, port: int
    ) -> FindingData:
        sensitive = sensitive_content(raw)
        strings = readable_strings(raw)
        severity = Severity.medium if sensitive else Severity.low

        evidence = [
            f"GET {form.url} → 200, __VIEWSTATE present ({len(form.viewstate)} base64 chars)",
            f"Decoded {len(raw)} bytes beginning {raw[:2].hex()} — the "
            "ObjectStateFormatter plaintext marker, so the field is not encrypted.",
        ]
        if sensitive:
            evidence.append(f"Sensitive content categories found: {', '.join(sensitive)}")
        if strings:
            evidence.append("Readable strings recovered from the ViewState:")
            evidence.extend(f"  {text}" for text in strings[:_MAX_STRINGS_SHOWN])
            if len(strings) > _MAX_STRINGS_SHOWN:
                evidence.append(f"  [... {len(strings) - _MAX_STRINGS_SHOWN} more]")

        description = (
            f"The ASP.NET page at {form.url} returns an unencrypted __VIEWSTATE. The "
            "field is base64-encoded, not encrypted: anyone who views the page source "
            "can decode the serialized object graph and read the server-side state the "
            "page stored in it.\n\n"
            "What that discloses depends on what the application put there, and "
            "developers routinely put more in ViewState than they realise — control "
            "properties, data-bound row contents, and any value assigned to "
            "ViewState[...] are all included."
        )
        if sensitive:
            description += (
                "\n\nThis ViewState contains data matching the categories listed in the "
                "evidence. Treat anything recovered as disclosed to every visitor of "
                "this page."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="ASP.NET ViewState Is Not Encrypted",
            description=description,
            evidence="\n".join(evidence),
            remediation=(
                "Encrypt the field: set "
                "'<pages viewStateEncryptionMode=\"Always\" />' in web.config, and keep "
                "the machineKey out of source control. Better, stop storing anything "
                "sensitive in ViewState at all — server-side session state is not sent "
                "to the client and cannot be read from it. Where a page does not need "
                "ViewState, disable it with 'EnableViewState=\"false\"'."
            ),
            references=[
                "https://learn.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/master-pages/control-id-naming-in-content-pages-cs",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                "curl -s <url> | grep -o '__VIEWSTATE\" value=\"[^\"]*' | "
                "cut -d'\"' -f3 | base64 -d | strings | head"
            ),
        )

    def _mac_finding(self, form: ViewStateForm, port: int) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="ASP.NET ViewState MAC Validation Not Enforced",
            description=(
                f"The page at {form.url} accepted a __VIEWSTATE whose bytes were "
                "modified after the server issued it, and rendered normally instead of "
                "reporting a validation failure. The server is therefore deserializing "
                "client-supplied data without verifying it.\n\n"
                "ViewState is deserialized by ObjectStateFormatter, which resolves "
                "arbitrary .NET types. That is a remote code execution primitive, not an "
                "integrity problem: publicly available tooling (ysoserial.net's "
                "ViewState plugin) generates a payload that runs commands in the "
                "worker process. No credentials and no second vulnerability are needed — "
                "the request is an ordinary form post to a page that is usually "
                "unauthenticated.\n\n"
                "Code execution in the IIS worker process means the application's "
                "connection strings, the machineKey itself, and any credential the app "
                "pool identity holds are all reachable, and the host becomes a "
                "foothold on the internal network."
            ),
            evidence=(
                f"GET {form.url} → 200, __VIEWSTATE captured\n"
                f"__VIEWSTATEGENERATOR present: {'yes' if form.has_generator else 'no'}\n"
                "POST to the same URL with one payload byte of __VIEWSTATE inverted "
                "(valid base64, no __EVENTTARGET sent) → 200 with a normally rendered "
                "page.\n"
                "A server validating the MAC must reject a modified ViewState; this one "
                "accepted it, so no MAC over the field is being checked."
            ),
            remediation=(
                "Enforce MAC validation. Remove any 'enableViewStateMac=\"false\"' from "
                "web.config and from per-page directives — that setting is the usual "
                "cause. Then upgrade the framework: .NET 4.5.2 and later ignore the "
                "setting entirely and always validate, so a current runtime closes this "
                "permanently.\n\n"
                "Also rotate the machineKey after remediation, and set "
                "'viewStateEncryptionMode=\"Always\"'. An attacker who reached this page "
                "may already have executed code and read the existing key, in which case "
                "a validated ViewState is still forgeable until the key changes.\n\n"
                "Treat this host as potentially already compromised: review the IIS logs "
                "for POSTs carrying oversized __VIEWSTATE values, and the worker process "
                "for unexpected child processes."
            ),
            references=[
                "https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/mitigation-viewstatemac-always-enforced",
                "https://github.com/pwntester/ysoserial.net",
                "https://nvd.nist.gov/vuln/detail/CVE-2020-0688",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                "ysoserial.net -p ViewState -g TextFormattingRunProperties "
                "--islegacy --isdebug -c 'echo test'   # requires written authorization"
            ),
        )
