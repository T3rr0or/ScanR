"""ScanR CLI — interact with a running ScanR API or run scans directly."""
from __future__ import annotations

import sys
from typing import NoReturn

import click
import httpx
from rich.console import Console
from rich.table import Table

console = Console()


def _verify(ctx) -> bool:
    """TLS verification setting for outbound API calls.

    Verification is on unless the operator explicitly opts out. The CLI carries
    an API key in the Authorization header of every request, so an unverified
    connection hands that credential to anyone able to intercept the route — and
    for `scanr ci` it also lets them forge the pass/fail verdict a pipeline gates
    on. Self-signed internal deployments opt out with --insecure.
    """
    return bool(ctx.obj.get("verify", True))


def _api(ctx, path: str, method: str = "GET", body: dict | None = None):
    base = ctx.obj["base_url"]
    token = ctx.obj.get("token", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = httpx.request(method, f"{base}{path}", json=body, headers=headers, timeout=30,
                             verify=_verify(ctx))
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        console.print(f"[red]API error {e.response.status_code}: {e.response.text}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Connection error: {e}[/red]")
        sys.exit(1)


@click.group()
@click.option("--url", default="http://localhost:8000", envvar="SCANR_URL", help="ScanR API base URL")
@click.option("--token", envvar="SCANR_TOKEN", default="", help="JWT access token")
@click.option("--insecure", is_flag=True, envvar="SCANR_INSECURE", default=False,
              help="Skip TLS certificate verification (self-signed internal deployments only).")
@click.pass_context
def cli(ctx, url, token, insecure):
    """ScanR — Professional Vulnerability Scanner CLI"""
    ctx.ensure_object(dict)
    ctx.obj["base_url"] = url.rstrip("/")
    ctx.obj["token"] = token
    ctx.obj["verify"] = not insecure
    if insecure and url.lower().startswith("https://"):
        # Say it out loud: the token in every request is exposed to anyone on the
        # path, and a `ci` verdict can be forged.
        console.print(
            "[yellow]Warning: TLS certificate verification disabled (--insecure). "
            "The API token is exposed to anyone able to intercept this connection.[/yellow]"
        )


# ── Auth ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--email", prompt=True)
@click.option("--password", prompt=True, hide_input=True)
@click.pass_context
def login(ctx, email, password):
    """Login and print access token."""
    data = _api(ctx, "/api/v1/auth/login", "POST", {"email": email, "password": password})
    console.print(f"[green]Token:[/green] {data['access_token']}")
    console.print("[dim]Set env: export SCANR_TOKEN=<token>[/dim]")


# ── Scans ─────────────────────────────────────────────────────────────────────

@cli.group()
def scan():
    """Manage scans."""


@scan.command("list")
@click.pass_context
def scan_list(ctx):
    """List all scans."""
    scans = _api(ctx, "/api/v1/scans")
    t = Table(title="Scans")
    for col in ("ID", "Name", "Status", "Profile", "Hosts Up", "Critical", "High"):
        t.add_column(col)
    for s in scans:
        t.add_row(s["id"][:8], s["name"], s["status"], s["profile"],
                  str(s["hosts_up"]), str(s["findings_critical"]), str(s["findings_high"]))
    console.print(t)


@scan.command("create")
@click.option("--name", required=True)
@click.option("--target", "targets", multiple=True, required=True)
@click.option("--profile", default="standard", type=click.Choice(["quick", "standard", "full"]))
@click.pass_context
def scan_create(ctx, name, targets, profile):
    """Create and launch a new scan."""
    s = _api(ctx, "/api/v1/scans", "POST", {"name": name, "targets": list(targets), "profile": profile})
    scan_id = s["id"]
    console.print(f"[green]Scan created:[/green] {scan_id}")
    _api(ctx, f"/api/v1/scans/{scan_id}/launch", "POST")
    console.print(f"[green]Scan launched.[/green] Monitor: scanr scan status --id {scan_id}")


@scan.command("status")
@click.option("--id", "scan_id", required=True)
@click.pass_context
def scan_status(ctx, scan_id):
    """Show scan status and finding counts."""
    s = _api(ctx, f"/api/v1/scans/{scan_id}")
    console.print(f"ID: {s['id']}")
    console.print(f"Name: {s['name']}")
    console.print(f"Status: [bold]{s['status']}[/bold]")
    console.print(f"Hosts: {s['hosts_up']}/{s['hosts_total']} up")
    console.print(f"Findings: Critical={s['findings_critical']} High={s['findings_high']} Medium={s['findings_medium']}")


@scan.command("cancel")
@click.option("--id", "scan_id", required=True)
@click.pass_context
def scan_cancel(ctx, scan_id):
    """Cancel a running scan."""
    _api(ctx, f"/api/v1/scans/{scan_id}/cancel", "POST")
    console.print(f"[yellow]Scan {scan_id} cancelled.[/yellow]")


# ── Findings ──────────────────────────────────────────────────────────────────

@cli.group()
def findings():
    """Query findings."""


@findings.command("list")
@click.option("--scan-id", default=None)
@click.option("--severity", default=None, type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--limit", default=50)
@click.pass_context
def findings_list(ctx, scan_id, severity, limit):
    """List findings."""
    params = f"?limit={limit}"
    if scan_id:
        params += f"&scan_id={scan_id}"
    if severity:
        params += f"&severity={severity}"
    data = _api(ctx, f"/api/v1/findings{params}")
    t = Table(title="Findings")
    for col in ("Severity", "Title", "Plugin", "Port", "CVSS"):
        t.add_column(col)
    sev_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green", "info": "blue"}
    for f in data:
        color = sev_colors.get(f["severity"], "white")
        t.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f["title"][:60],
            f["plugin_id"],
            str(f.get("port_number", "")),
            str(f.get("cvss_score", "")),
        )
    console.print(t)


# ── Reports ───────────────────────────────────────────────────────────────────

@cli.group()
def report():
    """Generate and download reports."""


@report.command("generate")
@click.option("--scan-id", required=True)
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "pdf", "json", "csv"]))
@click.pass_context
def report_generate(ctx, scan_id, fmt):
    """Generate a report for a scan."""
    r = _api(ctx, "/api/v1/reports", "POST", {"scan_id": scan_id, "format": fmt})
    console.print(f"[green]Report queued:[/green] {r['id']} (status: {r['status']})")
    console.print(f"Download: scanr report download --id {r['id']}")


@report.command("download")
@click.option("--id", "report_id", required=True)
@click.option("--output", "-o", default=None)
@click.pass_context
def report_download(ctx, report_id, output):
    """Download a completed report."""
    base = ctx.obj["base_url"]
    token = ctx.obj.get("token", "")
    headers = {"Authorization": f"Bearer {token}"}
    resp = httpx.get(f"{base}/api/v1/reports/{report_id}/download", headers=headers,
                     verify=_verify(ctx))
    if resp.status_code != 200:
        console.print(f"[red]Error: {resp.status_code} {resp.text}[/red]")
        return
    fname = output or f"report_{report_id[:8]}"
    with open(fname, "wb") as f:
        f.write(resp.content)
    console.print(f"[green]Downloaded:[/green] {fname}")


# ── Plugins ───────────────────────────────────────────────────────────────────

@cli.group()
def plugin():
    """Manage plugins."""


@plugin.command("list")
@click.pass_context
def plugin_list(ctx):
    """List all plugins."""
    plugins = _api(ctx, "/api/v1/plugins")
    t = Table(title="Plugins")
    for col in ("ID", "Name", "Category", "Severity", "Enabled"):
        t.add_column(col)
    for p in plugins:
        enabled = "[green]yes[/green]" if p["enabled"] else "[red]no[/red]"
        t.add_row(p["id"], p["name"], p["category"], p["default_severity"], enabled)
    console.print(t)


# ── NVD ───────────────────────────────────────────────────────────────────────

@cli.command("update-nvd")
def update_nvd():
    """Download/update NVD CVE feeds for CVE matching."""
    console.print("Downloading NVD feeds (this may take a few minutes)...")
    from scanr.plugins.cve.nvd_loader import download_feeds
    download_feeds()
    console.print("[green]NVD feeds updated.[/green]")


# ── CI ────────────────────────────────────────────────────────────────────────

#: Exit codes. CI needs to tell "found vulnerabilities" (a real result the build
#: should reflect) apart from "the tool broke" (retry, or fix the pipeline) —
#: collapsing both into 1 makes a broken scanner look like a clean report or vice
#: versa.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _fail(message: str) -> NoReturn:
    console.print(f"[red]{message}[/red]")
    sys.exit(EXIT_ERROR)


def _ci_request(ctx, path: str, method: str = "GET", body: dict | None = None,
                raw: bool = False):
    """Raise on failure. Callers decide whether that should end the run."""
    base = ctx.obj["base_url"]
    token = ctx.obj.get("token", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = httpx.request(method, f"{base}{path}", json=body, headers=headers,
                         timeout=60, verify=_verify(ctx))
    resp.raise_for_status()
    return resp.content if raw else resp.json()


def _ci_api(ctx, path: str, method: str = "GET", body: dict | None = None, raw: bool = False):
    """Exit EXIT_ERROR on failure — for calls the verdict depends on.

    Not used for optional extras like SARIF: a reporting hiccup must not turn a
    real result into "the tool broke".
    """
    try:
        return _ci_request(ctx, path, method, body, raw)
    except httpx.HTTPStatusError as e:
        _fail(f"API error {e.response.status_code}: {e.response.text[:300]}")
    except Exception as e:
        _fail(f"Connection error: {e}")


def _counts_at_or_above(counts: dict, threshold: str) -> int:
    """How many findings are at least as severe as `threshold`."""
    cutoff = _SEVERITIES.index(threshold)
    return sum(int(counts.get(sev, 0) or 0) for sev in _SEVERITIES[: cutoff + 1])


@cli.command("ci")
@click.option("--target", "-t", multiple=True, required=True,
              help="Target to scan. Repeatable.")
@click.option("--name", default=None, help="Scan name (default: derived from targets).")
@click.option("--profile", default="standard",
              help="Scan profile: quick | standard | full | custom.")
@click.option("--profile-json", default=None,
              help="Raw profile_json for full control over capabilities.")
@click.option("--fail-on", type=click.Choice(_SEVERITIES + ["never"]), default="high",
              help="Exit non-zero when a finding at or above this severity is found.")
@click.option("--sarif", "sarif_path", default=None,
              help="Write a SARIF 2.1.0 report here (for GitHub code scanning).")
@click.option("--timeout", default=3600, show_default=True,
              help="Seconds to wait for the scan before giving up.")
@click.option("--poll-interval", default=10, show_default=True, help="Seconds between status checks.")
@click.option("--quiet", is_flag=True, help="Only print the summary.")
@click.pass_context
def ci(ctx, target, name, profile, profile_json, fail_on, sarif_path, timeout,
       poll_interval, quiet):
    """Run a scan to completion and exit non-zero if it finds anything.

    Built for pipelines: blocks until the scan finishes, prints a severity
    summary, optionally writes SARIF, and sets the exit code from the result.

    \b
    Exit codes:
      0  scan completed, nothing at or above --fail-on
      1  scan completed, findings at or above --fail-on
      2  something went wrong (API, timeout, scan failed) — not a verdict

    \b
    Authenticate with an API key (SCANR_TOKEN=sk_...); it needs the
    scans:write, findings:read and reports:read/create scopes.
    """
    import time

    if not ctx.obj.get("token"):
        _fail("No token. Set SCANR_TOKEN (an API key, sk_...) or pass --token.")

    scan_name = name or f"CI: {', '.join(target)[:80]}"
    payload = {"name": scan_name, "targets": list(target), "profile": profile}
    if profile_json:
        payload["profile_json"] = profile_json

    created = _ci_api(ctx, "/api/v1/scans", "POST", payload)
    scan_id = created["id"]
    if not quiet:
        console.print(f"[cyan]Scan {scan_id}[/cyan] created for {len(target)} target(s)")

    _ci_api(ctx, f"/api/v1/scans/{scan_id}/launch", "POST")

    deadline = time.time() + timeout
    status = "pending"
    last_shown = None
    while time.time() < deadline:
        info = _ci_api(ctx, f"/api/v1/scans/{scan_id}")
        status = info.get("status", "unknown")
        if status in ("completed", "failed", "cancelled"):
            break
        shown = f"{status} — {info.get('hosts_up', 0)}/{info.get('hosts_total', 0)} hosts"
        if not quiet and shown != last_shown:
            console.print(f"[dim]{shown}[/dim]")
            last_shown = shown
        time.sleep(poll_interval)
    else:
        _fail(f"Timed out after {timeout}s waiting for scan {scan_id} (last status: {status}).")

    if status != "completed":
        detail = info.get("error_message") or ""
        _fail(f"Scan {status}. {detail}".strip())

    counts = {
        "critical": info.get("findings_critical", 0),
        "high": info.get("findings_high", 0),
        "medium": info.get("findings_medium", 0),
        "low": info.get("findings_low", 0),
        "info": info.get("findings_info", 0),
    }

    if sarif_path:
        _write_sarif(ctx, scan_id, sarif_path, quiet)

    table = Table(title=f"Scan {scan_id[:8]} — {info.get('hosts_up', 0)} host(s) up")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in _SEVERITIES:
        table.add_row(sev, str(counts[sev]))
    console.print(table)

    if fail_on == "never":
        console.print("[green]--fail-on never: not failing the build.[/green]")
        sys.exit(EXIT_OK)

    breaching = _counts_at_or_above(counts, fail_on)
    if breaching:
        console.print(
            f"[red]{breaching} finding(s) at or above '{fail_on}'.[/red] "
            f"[dim]Full detail: {ctx.obj['base_url']}/scans/{scan_id}[/dim]"
        )
        sys.exit(EXIT_FINDINGS)

    console.print(f"[green]No findings at or above '{fail_on}'.[/green]")
    sys.exit(EXIT_OK)


def _write_sarif(ctx, scan_id: str, path: str, quiet: bool) -> None:
    """Generate and download a SARIF report.

    A SARIF failure must not change the build verdict — the scan already ran and
    its result stands — so this warns and moves on rather than exiting.
    """
    import time
    from pathlib import Path

    try:
        report = _ci_request(ctx, "/api/v1/reports", "POST",
                             {"scan_id": scan_id, "format": "sarif"})
        report_id = report["id"]
        for _ in range(60):
            state = _ci_request(ctx, f"/api/v1/reports/{report_id}")
            if state.get("status") == "completed":
                break
            if state.get("status") == "failed":
                console.print(f"[yellow]SARIF report failed: {state.get('error_message')}[/yellow]")
                return
            time.sleep(2)
        else:
            console.print("[yellow]SARIF report did not finish in time; skipping.[/yellow]")
            return
        content = _ci_request(ctx, f"/api/v1/reports/{report_id}/download", raw=True)
        Path(path).write_bytes(content)
        if not quiet:
            console.print(f"[green]SARIF written to {path}[/green]")
    except Exception as exc:  # noqa: BLE001 - reporting never decides the build
        console.print(f"[yellow]Could not write SARIF ({exc}); continuing.[/yellow]")


if __name__ == "__main__":
    cli()
