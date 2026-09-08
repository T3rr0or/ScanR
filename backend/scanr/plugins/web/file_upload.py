"""Unrestricted file upload testing.

Finds multipart upload endpoints by crawling and asks two separate questions,
because they carry very different risk and are very often answered differently:

1. **Is a dangerous extension accepted?** A handler that stores `x.php` has lost
   the extension allowlist, but the file may land outside the web root, behind a
   random name, or in object storage where it can never be executed.
2. **Is the stored file retrievable?** If the response discloses a path and that
   path serves the bytes back — especially under a content type the browser will
   render — the upload is reachable, and an `.svg` or `.html` alone is stored
   XSS on the application's own origin.

They are reported as two findings with different scores rather than one blended
"unrestricted upload", so an operator can triage the reachable ones first.

**Nothing uploaded here is a webshell.** Every payload body is a plain-text
marker string — no `<?php`, no scriptlet, no `<script>`. The check proves the
*policy* is missing without leaving a working backdoor on a third-party system,
and the marker names ScanR so an administrator finding it knows what it is.

Two false-positive guards, because "HTTP 200" means very little on an upload
endpoint:

* A **benign control** (`.txt`) must be accepted first. If the endpoint rejects
  a plain text file too, it is not an upload endpoint that works for us, and
  nothing it says about `.php` is interpretable.
* The control response must differ from a plain **GET** of the same path. A SPA
  catch-all that serves `index.html` with HTTP 200 for every method and every
  body would otherwise "accept" all five dangerous extensions.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import crawl, create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

_FORM_BLOCK_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.I | re.S)
_FILE_INPUT_RE = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?file[\"']?[^>]*>", re.I)
_NAME_ATTR_RE = re.compile(r"\bname\s*=\s*[\"']([^\"']+)[\"']", re.I)
_ACTION_ATTR_RE = re.compile(r"\baction\s*=\s*[\"']([^\"']*)[\"']", re.I)

# Endpoints worth a probe even when no form was found — SPAs post to these from
# JavaScript, so the HTML crawler never sees them. Each is still subject to the
# benign-control guard, so a 404 or a catch-all costs one request and nothing more.
_COMMON_UPLOAD_PATHS = ["/upload", "/api/upload", "/upload.php", "/api/v1/upload", "/files"]
_COMMON_FIELD_NAMES = ["file", "upload", "attachment", "image"]

_MAX_PAGES = 6        # pages parsed for upload forms
_MAX_ENDPOINTS = 3    # endpoints actually probed
_MAX_LISTED = 8       # resources named in a finding

# Extensions whose acceptance is a policy failure, with the content type a
# browser-driven attacker would send. Content is inert text in every case.
_DANGEROUS: list[tuple[str, str, str]] = [
    (".php", "application/x-php", "server-side PHP"),
    (".jsp", "application/x-jsp", "server-side JSP"),
    (".aspx", "application/x-aspx", "server-side ASP.NET"),
    (".svg", "image/svg+xml", "SVG (renders inline, can carry script)"),
    (".html", "text/html", "HTML (stored XSS on this origin)"),
]

# Content types that make a retrievable upload directly exploitable in a browser.
_RENDERED_TYPES = ("text/html", "application/xhtml", "image/svg+xml", "application/xml", "text/xml")

_REJECTION_HINTS = (
    "not allowed", "not permitted", "invalid file", "invalid extension",
    "unsupported", "disallowed", "forbidden", "file type", "only images",
    "bad request", "rejected",
)

# Where a disclosed bare filename most plausibly lives, when the response gives
# a name but no path.
_GUESS_DIRS = ["/uploads/", "/files/", "/upload/", "/media/", "/static/uploads/"]

_PATH_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:%~")


def _marker_body(token: str) -> str:
    """Inert payload content. Deliberately contains no executable syntax."""
    return (
        f"SCANR-UPLOAD-TEST-{token}\n"
        "Harmless marker written by an authorised ScanR security scan. "
        "It contains no code and is safe to delete.\n"
    )


def _payload_for(ext: str, token: str) -> str:
    marker = _marker_body(token)
    if ext == ".svg":
        # A valid SVG so a strict image parser accepts it, with no <script>.
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
            f"<title>{marker.splitlines()[0]}</title></svg>\n"
        )
    if ext == ".html":
        return f"<p>{marker.splitlines()[0]}</p>\n"
    return marker


class _Upload:
    """One upload attempt reduced to what the comparisons need."""

    __slots__ = ("status", "body", "filename", "ext")

    def __init__(self, resp, filename: str, ext: str) -> None:
        self.status = resp.status_code
        self.body = resp.text
        self.filename = filename
        self.ext = ext


def _succeeded(probe: _Upload | None) -> bool:
    return probe is not None and 200 <= probe.status < 400


def _looks_rejected(control_body: str, body: str) -> bool:
    """True when the response says no in a way the successful control did not."""
    low = body.lower()
    control_low = control_body.lower()
    return any(hint in low and hint not in control_low for hint in _REJECTION_HINTS)


def _extract_stored_ref(body: str, filename: str) -> str | None:
    """Pull the disclosed path/URL for `filename` out of a response body."""
    idx = body.find(filename)
    if idx < 0:
        return None
    start = idx
    while start > 0 and body[start - 1] in _PATH_CHARS:
        start -= 1
    ref = body[start:idx + len(filename)]
    # Trim a leading fragment of a longer word, e.g. `filename":"` leftovers.
    return ref or None


class FileUploadPlugin(PluginBase):
    id = "web.file_upload"
    name = "Unrestricted File Upload"
    description = (
        "Test multipart upload endpoints for acceptance of dangerous extensions "
        "and for retrievability of the stored file, using inert marker content"
    )
    category = PluginCategory.web
    intrusive = True
    severity = Severity.high
    ports = HTTP_PORTS
    timeout = 300

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            try:
                findings.extend(await self._test_host(context, base_url, port.number))
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("file_upload: %s failed: %s", base_url, exc)
        return findings

    async def _test_host(self, context, base_url: str, port: int) -> list[FindingData]:
        findings: list[FindingData] = []
        async with create_web_client(context) as client:
            crawled = await crawl(base_url, client)
            endpoints = await self._discover_endpoints(client, base_url, crawled)
            for path, field in endpoints[:_MAX_ENDPOINTS]:
                findings.extend(await self._test_endpoint(client, base_url, path, field, port))
                if findings:
                    # One demonstrated upload endpoint is enough to act on; the
                    # rest are the same defect and only add scan traffic.
                    break
        return findings

    # ── discovery ────────────────────────────────────────────────────────────

    async def _discover_endpoints(self, client, base_url: str, crawled) -> list[tuple[str, str]]:
        """(path, file field name) pairs that look like upload handlers."""
        found: list[tuple[str, str]] = []
        for path in (crawled.paths or ["/"])[:_MAX_PAGES]:
            try:
                resp = await client.get(f"{base_url}{path}", timeout=8.0)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            for match in _FORM_BLOCK_RE.finditer(resp.text):
                file_input = _FILE_INPUT_RE.search(match.group("body"))
                if not file_input:
                    continue
                name_match = _NAME_ATTR_RE.search(file_input.group(0))
                field = name_match.group(1) if name_match else "file"
                action_match = _ACTION_ATTR_RE.search(match.group("attrs"))
                action = action_match.group(1) if action_match else ""
                target = urlparse(urljoin(f"{base_url}{path}", action or path)).path or path
                if (target, field) not in found:
                    found.append((target, field))

        for path in _COMMON_UPLOAD_PATHS:
            if not any(p == path for p, _ in found):
                found.append((path, _COMMON_FIELD_NAMES[0]))
        return found

    # ── probing ──────────────────────────────────────────────────────────────

    async def _test_endpoint(
        self, client, base_url: str, path: str, field: str, port: int
    ) -> list[FindingData]:
        url = f"{base_url}{path}"
        token = secrets.token_hex(6)

        # Guard 1: a benign .txt must be accepted, or nothing else is readable.
        control = await self._upload(
            client, url, field, f"scanr_{token}.txt", ".txt", "text/plain", token
        )
        if not _succeeded(control):
            return []

        # Guard 2: distinguish a real handler from a catch-all that answers 200
        # to everything with the same SPA shell.
        try:
            plain = await client.get(url, timeout=8.0)
            if plain.status_code == control.status and plain.text == control.body:
                return []
        except Exception:
            return []

        accepted: list[_Upload] = []
        for ext, content_type, _label in _DANGEROUS:
            probe = await self._upload(
                client, url, field, f"scanr_{token}{ext}", ext, content_type, token
            )
            if _succeeded(probe) and not _looks_rejected(control.body, probe.body):
                accepted.append(probe)

        if not accepted:
            return []

        findings = [self._accepted_finding(url, field, accepted, port)]
        retrievable = await self._check_retrievable(client, url, accepted, token)
        if retrievable:
            findings.append(self._retrievable_finding(url, retrievable, port))
        return findings

    async def _upload(
        self, client, url: str, field: str, filename: str, ext: str,
        content_type: str, token: str,
    ) -> _Upload | None:
        files = {field: (filename, _payload_for(ext, token).encode(), content_type)}
        try:
            resp = await client.post(url, files=files, timeout=15.0)
        except Exception:
            return None
        return _Upload(resp, filename, ext)

    async def _check_retrievable(
        self, client, url: str, accepted: list[_Upload], token: str
    ) -> list[tuple[str, str, str]]:
        """(url, extension, content type) for uploads we could fetch back."""
        results: list[tuple[str, str, str]] = []
        for probe in accepted:
            ref = _extract_stored_ref(probe.body, probe.filename)
            candidates: list[str] = []
            if ref and "/" in ref:
                candidates.append(urljoin(url, ref))
            else:
                # Only a bare name was disclosed — try the conventional dirs.
                candidates.extend(urljoin(url, d + probe.filename) for d in _GUESS_DIRS)
            for candidate in candidates[:len(_GUESS_DIRS)]:
                try:
                    resp = await client.get(candidate, timeout=8.0)
                except Exception:
                    continue
                # The marker must come back, or we fetched some unrelated page.
                if resp.status_code == 200 and f"SCANR-UPLOAD-TEST-{token}" in resp.text:
                    served = resp.headers.get("content-type", "unknown").split(";")[0].strip()
                    results.append((candidate, probe.ext, served))
                    break
        return results

    # ── reporting ────────────────────────────────────────────────────────────

    def _accepted_finding(
        self, url: str, field: str, accepted: list[_Upload], port: int
    ) -> FindingData:
        labels = {ext: label for ext, _ct, label in _DANGEROUS}
        listed = accepted[:_MAX_LISTED]
        lines = "\n".join(
            f"  {p.filename}  ({labels.get(p.ext, p.ext)})  -> HTTP {p.status}" for p in listed
        )
        exts = ", ".join(p.ext for p in listed)
        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title="File upload accepts dangerous extensions",
            description=(
                f"The upload endpoint {url} (field {field!r}) accepted files with the "
                f"extensions {exts}. The extension allowlist is missing or is applied only "
                "in the browser. Whether this is exploitable depends on where the file "
                "lands — this check did not confirm that the stored file can be fetched "
                "back — but an upload handler that stores server-side script extensions is "
                "one misconfigured document root away from remote code execution."
            ),
            evidence=(
                f"Endpoint: {url}\nMultipart field: {field}\n"
                "A benign .txt control was accepted first, and the endpoint's response to "
                "an upload differs from a plain GET, so these are real handler responses.\n"
                f"Accepted:\n{lines}\n\n"
                "Uploaded content was an inert ScanR marker string — no executable code."
            ),
            remediation=(
                "Validate uploads on the server against an allowlist of extensions AND of "
                "sniffed content types, and rename stored files to a generated name with "
                "the allowed extension appended — never trust the client-supplied filename. "
                "Store uploads outside the document root or in object storage, and serve "
                "them through a handler that sets Content-Disposition: attachment and "
                "X-Content-Type-Options: nosniff."
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/434.html",
            ],
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            port_number=port,
            protocol="tcp",
        )

    def _retrievable_finding(
        self, url: str, retrievable: list[tuple[str, str, str]], port: int
    ) -> FindingData:
        listed = retrievable[:_MAX_LISTED]
        rendered = [
            (u, ext, ct) for u, ext, ct in listed
            if any(ct.lower().startswith(t) for t in _RENDERED_TYPES)
        ]
        lines = "\n".join(f"  {u}  (uploaded as {ext}, served as {ct})" for u, ext, ct in listed)
        if rendered:
            severity, score = Severity.high, 8.1
            extra = (
                f"{len(rendered)} of these are served with a content type the browser "
                "renders, so a crafted upload executes as script on this origin: "
                + ", ".join(f"{ct} ({ext})" for _u, ext, ct in rendered) + ". "
            )
        else:
            severity, score = Severity.high, 7.5
            extra = ""
        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="Uploaded file with a dangerous extension is publicly retrievable",
            description=(
                f"Files uploaded to {url} are stored under a predictable, publicly reachable "
                "URL and were fetched back over an unauthenticated request, with the "
                f"attacker-chosen extension preserved. {extra}An attacker can host arbitrary "
                "content on this origin — phishing pages, stored XSS, or, if the server "
                "maps the extension to an interpreter, code that runs with the web server's "
                "privileges. This check uploaded inert text, so code execution was not "
                "attempted and is not proven."
            ),
            evidence=(
                "Retrieved after upload (the ScanR marker was present in each response):\n"
                f"{lines}"
            ),
            remediation=(
                "Serve user uploads from a separate origin or a dedicated download handler, "
                "never from a path the application server maps to an interpreter. Rename "
                "stored files to unpredictable server-generated names, force "
                "Content-Disposition: attachment with X-Content-Type-Options: nosniff, and "
                "apply the same authorisation to retrieval that applied to the upload."
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/434.html",
            ],
            cvss_score=score,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
            port_number=port,
            protocol="tcp",
        )
