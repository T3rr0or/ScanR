"""ScanR CLI — interact with a running ScanR API or run scans directly."""
from __future__ import annotations

import sys

import click
import httpx
from rich.console import Console
from rich.table import Table

console = Console()


def _api(ctx, path: str, method: str = "GET", body: dict | None = None):
    base = ctx.obj["base_url"]
    token = ctx.obj.get("token", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = httpx.request(method, f"{base}{path}", json=body, headers=headers, timeout=30, verify=False)
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
@click.pass_context
def cli(ctx, url, token):
    """ScanR — Professional Vulnerability Scanner CLI"""
    ctx.ensure_object(dict)
    ctx.obj["base_url"] = url.rstrip("/")
    ctx.obj["token"] = token


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
    resp = httpx.get(f"{base}/api/v1/reports/{report_id}/download", headers=headers, verify=False)
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


if __name__ == "__main__":
    cli()
