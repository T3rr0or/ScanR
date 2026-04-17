#!/usr/bin/env python3
"""
Quick plugin test harness — no DB, no Docker needed.

Usage:
  python test_plugin.py <plugin_id> <ip> [port,port,...] [hostname]

Examples:
  python test_plugin.py web.sqli_detect 192.168.1.10 80,443
  python test_plugin.py web.waf_detect testphp.vulnweb.com 80 testphp.vulnweb.com
  python test_plugin.py network.subdomain_enum 1.2.3.4 80 example.com
  python test_plugin.py ssl_tls.cert_inspector 192.168.1.1 443
  python test_plugin.py services.redis_unauth 192.168.1.5 6379
"""
import asyncio
import importlib
import logging
import sys
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class FakeLogger:
    async def info(self, msg, **kw):
        print(f"[LOG] {msg}")
    async def warning(self, msg, **kw):
        print(f"[WARN] {msg}")
    async def error(self, msg, **kw):
        print(f"[ERR] {msg}")


@dataclass
class FakeScan:
    id: str = "test-scan"
    profile_json: Any = None


@dataclass
class FakeContext:
    scan_id: str = "test-scan"
    scan: Any = field(default_factory=FakeScan)
    db: Any = None
    profile: str = "standard"
    credential_data: Any = None
    cancelled: bool = False
    log: Any = field(default_factory=FakeLogger)


def make_host(ip: str, ports: list[int], hostname: str | None = None):
    def make_port(n):
        return SimpleNamespace(
            number=n,
            state="open",
            protocol="tcp",
            service=SimpleNamespace(product="", version="", banner=""),
        )
    return SimpleNamespace(
        ip=ip,
        hostname=hostname or ip,
        os=None,
        ports=[make_port(p) for p in ports],
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

async def run(plugin_id: str, ip: str, ports: list[int], hostname: str | None):
    # plugin_id like "web.sqli_detect" → module "scanr.plugins.web.sqli_detect"
    parts = plugin_id.split(".")
    if len(parts) != 2:
        print(f"ERROR: plugin_id must be <category>.<name>, got '{plugin_id}'")
        sys.exit(1)
    module_path = f"scanr.plugins.{parts[0]}.{parts[1]}"
    try:
        mod = importlib.import_module(module_path)
    except ImportError as e:
        print(f"ERROR: cannot import {module_path}: {e}")
        sys.exit(1)

    # Find the PluginBase subclass
    from scanr.core.plugin_base import PluginBase
    plugin_cls = None
    for name in dir(mod):
        obj = getattr(mod, name)
        try:
            if isinstance(obj, type) and issubclass(obj, PluginBase) and obj is not PluginBase:
                plugin_cls = obj
                break
        except TypeError:
            pass

    if not plugin_cls:
        print(f"ERROR: no PluginBase subclass found in {module_path}")
        sys.exit(1)

    plugin = plugin_cls()
    print(f"\n{'='*60}")
    print(f"Plugin : {plugin.id} — {plugin.name}")
    print(f"Target : {ip}  ports={ports}  hostname={hostname}")
    print(f"{'='*60}\n")

    ctx = FakeContext()
    host = make_host(ip, ports, hostname)

    findings = await plugin.check(ctx, host)

    if not findings:
        print("\n[RESULT] No findings.\n")
        return

    print(f"\n[RESULT] {len(findings)} finding(s):\n")
    for i, f in enumerate(findings, 1):
        print(f"  [{i}] {f.severity.upper()}  {f.title}")
        if f.evidence:
            snippet = f.evidence[:300].replace("\n", "\n       ")
            print(f"       Evidence: {snippet}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    plugin_id = sys.argv[1]
    ip = sys.argv[2]
    raw_ports = sys.argv[3].split(",") if len(sys.argv) > 3 else ["80"]
    ports = [int(p) for p in raw_ports]
    hostname = sys.argv[4] if len(sys.argv) > 4 else None

    asyncio.run(run(plugin_id, ip, ports, hostname))
