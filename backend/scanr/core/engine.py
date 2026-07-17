from __future__ import annotations

import asyncio
import json
import socket
import logging
import time

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.core.context import ScanContext
from scanr.core.plugin_base import PluginCategory
from scanr.core.plugin_manager import get_enabled_plugins
from scanr.core.rate_limiter import RateLimiter
from scanr.core.result_collector import ResultCollector
from scanr.core.scan_logger import ScanLogger
from scanr.models import Credential, Host, Plugin, Scan, ScanCredential, ScanStatus, Target
from scanr.models.base import new_uuid
from scanr.plugins.ssl_tls._ports import is_tls_port_data
from scanr.plugins.web._ports import is_web_port_data
from scanr.utils.ip_utils import classify_target, is_forbidden_target, is_valid_ip

logger = logging.getLogger(__name__)

BUG_BOUNTY_PORT_RANGE = "80,443,8080,8443,8000,8001,8888,3000,5000,9000,9443,10443,32400"

BUG_BOUNTY_SUBDOMAIN_PREFIXES = [
    "www", "api", "app", "apps", "auth", "login", "sso", "admin", "portal",
    "dashboard", "staging", "stage", "dev", "test", "beta", "preview", "uat",
    "cdn", "static", "assets", "media", "docs", "status", "support", "help",
    "blog", "shop", "store", "pay", "billing", "checkout", "secure", "vpn",
    "mail", "webmail", "mx", "git", "gitlab", "jira", "confluence", "jenkins",
    "grafana", "kibana", "monitor", "metrics",
]


def _plugin_allowed(plugin_id: str, filters: list[str]) -> bool:
    """Return True if plugin_id matches any entry in the profile filter list."""
    for f in filters:
        if f == "*":
            return True
        if f.endswith(".*") and plugin_id.startswith(f[:-1]):
            return True
        if f == plugin_id:
            return True
    return False


def _plugin_applies_to_host_data(plugin, ports: list[dict]) -> bool:
    if plugin.ports is None:
        return True
    category = getattr(plugin, "category", None)
    if category == PluginCategory.web and any(is_web_port_data(p) for p in ports):
        return True
    # TLS checks run on any port nmap flagged as TLS-wrapped, not just 443/8443/…
    if category == PluginCategory.ssl_tls and any(is_tls_port_data(p) for p in ports):
        return True
    return any(p["number"] in plugin.ports and p["state"] == "open" for p in ports)


def _is_domain_mode(profile: dict, targets: list[str]) -> bool:
    if profile.get("target_type") == "domain":
        return True
    if profile.get("scan_context") == "external" and targets and all(not is_valid_ip(t) for t in targets):
        return True
    if profile.get("target_mode") in {"domain", "bug_bounty", "external"}:
        return True
    return bool(targets) and all(not is_valid_ip(t) for t in targets)


def _target_type(profile: dict, raw_targets: list[str], expanded_targets: list[str]) -> str:
    configured = profile.get("target_type")
    if configured in {"ip", "cidr", "range", "hostname", "domain"}:
        return configured
    raw = [t.strip() for t in raw_targets if t.strip()]
    raw_types = [classify_target(t) for t in raw]
    if raw_types and all(t == "ip" for t in raw_types):
        return "ip"
    if raw_types and all(t == "cidr" for t in raw_types):
        return "cidr"
    if raw_types and all(t == "range" for t in raw_types):
        return "range"
    if raw_types and all(t in {"ip", "cidr", "range"} for t in raw_types):
        return "range"
    if expanded_targets and all(is_valid_ip(t) for t in expanded_targets):
        return "ip" if len(expanded_targets) == 1 else "cidr"
    if raw and all("." in t and not is_valid_ip(t) for t in raw):
        return "domain"
    return "hostname"


def _enum_config(profile: dict) -> dict:
    enum = profile.get("enumeration") or {}
    return {
        "service_detection": bool(enum.get("service_detection", True)),
        "http_probing": bool(enum.get("http_probing", True)),
        "tls_checks": bool(enum.get("tls_checks", True)),
        "security_headers": bool(enum.get("security_headers", True)),
        "screenshots": bool(enum.get("screenshots", True)),
        "nuclei": bool(enum.get("nuclei", True)),
        "directory_enum": bool(enum.get("directory_enum", False)),
        "subdomain_enum": bool(enum.get("subdomain_enum", profile.get("subdomain_enum", False))),
        "dns_recon": bool(enum.get("dns_recon", False)),
    }


def _filter_plugins_by_capabilities(plugins: list, profile: dict) -> list:
    enum = _enum_config(profile)
    safety = profile.get("safety_level", "balanced")
    allowed = []
    for plugin in plugins:
        pid = plugin.id
        if not enum["screenshots"] and pid == "web.screenshot":
            continue
        if not enum["nuclei"] and pid.startswith("nuclei."):
            continue
        if not enum["tls_checks"] and pid.startswith("ssl_tls."):
            continue
        if not enum["security_headers"] and pid == "web.http_headers":
            continue
        if not enum["directory_enum"] and pid in {"web.dir_bruteforce", "web.sensitive_files"}:
            continue
        if not enum["dns_recon"] and pid in {"network.dns_recon", "network.dns_zone_transfer", "network.subdomain_takeover"}:
            continue
        if not enum["subdomain_enum"] and pid == "network.subdomain_enum":
            continue
        if safety == "safe" and (getattr(plugin, "intrusive", False) or "default_creds" in pid):
            continue
        allowed.append(plugin)
    return allowed


async def _expand_domain_targets(targets: list[str], scan_log: ScanLogger, profile: dict) -> list[str]:
    roots = [t.strip().lower().removeprefix("*.") for t in targets if t.strip()]
    include_subdomains = _enum_config(profile)["subdomain_enum"]
    max_subdomains = int(profile.get("max_subdomains", 50))
    discovered: list[str] = []

    if include_subdomains:
        await scan_log.phase_start(
            "recon",
            f"Domain recon: resolving common subdomains for {len(roots)} domain target(s)",
        )
        discovered = await _resolve_common_subdomains(roots, max_subdomains)
        await scan_log.phase_done(
            "recon",
            f"Domain recon complete: {len(discovered)} resolvable subdomain target(s) added",
        )

    seen: set[str] = set()
    ordered: list[str] = []
    for target in [*roots, *discovered]:
        if target and target not in seen:
            seen.add(target)
            ordered.append(target)
    return ordered


async def _resolve_common_subdomains(domains: list[str], limit: int) -> list[str]:
    sem = asyncio.Semaphore(30)
    loop = asyncio.get_running_loop()
    found: list[str] = []

    async def resolve(fqdn: str) -> str | None:
        async with sem:
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, socket.getaddrinfo, fqdn, None),
                    timeout=3.0,
                )
                return fqdn
            except Exception:
                return None

    candidates = [
        f"{prefix}.{domain}"
        for domain in domains
        for prefix in BUG_BOUNTY_SUBDOMAIN_PREFIXES
    ]
    for result in await asyncio.gather(*(resolve(c) for c in candidates)):
        if result:
            found.append(result)
            if len(found) >= limit:
                break
    return found


async def _find_forbidden_resolved_targets(targets: list[str]) -> list[str]:
    """Return targets whose direct or DNS-resolved IP hits the denylist.

    IP targets are checked as-is; hostname targets are resolved and every
    returned address is checked. Unresolvable hostnames are skipped — host
    discovery reports those later.
    """
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(50)
    forbidden: list[str] = []

    async def check(target: str) -> None:
        if is_valid_ip(target):
            if is_forbidden_target(target):
                forbidden.append(target)
            return
        async with sem:
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(target, None), timeout=5.0)
            except Exception:
                return
        for info in infos:
            resolved_ip = info[4][0]
            if is_forbidden_target(resolved_ip):
                forbidden.append(f"{target} -> {resolved_ip}")
                return

    await asyncio.gather(*(check(t) for t in targets))
    return forbidden


def _hostname_for_host(input_target: str, host_data: dict) -> str | None:
    if not is_valid_ip(input_target):
        return input_target
    return host_data.get("hostname")


class ScanEngine:
    """Orchestrates a complete scan: discovery → ports → fingerprint → plugins."""

    def __init__(self, scan_id: str, db: AsyncSession):
        self.scan_id = scan_id
        self.db = db

    async def run(self) -> None:
        scan_log = ScanLogger(self.scan_id)  # debug flag set after scan loaded in _run
        try:
            await self._run(scan_log)
        finally:
            await scan_log.close()

    async def _run(self, scan_log: ScanLogger) -> None:
        await scan_log.info("Scan engine started", phase="engine")

        # Check tool availability and warn about missing binaries
        import shutil as _shutil
        if not _shutil.which("nuclei"):
            await scan_log.warn(
                "Nuclei binary not found — Nuclei template scanning will be skipped. "
                "Install with: nuclei -update-templates",
                phase="engine",
            )
        if not _shutil.which("masscan"):
            await scan_log.warn(
                "masscan binary not found — bulk port discovery will use nmap instead",
                phase="engine",
            )

        # Load scan + targets
        result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = result.scalar_one()

        # Parse profile flags once — done here so we only query scan once
        _pj: dict = {}
        try:
            if scan.profile_json:
                _pj = json.loads(scan.profile_json) if isinstance(scan.profile_json, str) else scan.profile_json
                scan_log._debug = _pj.get("debug", False)
        except Exception:
            pass

        targets_result = await self.db.execute(
            select(Target).where(Target.scan_id == self.scan_id)
        )
        targets = targets_result.scalars().all()

        perf = (_pj.get("performance") or {}) if isinstance(_pj, dict) else {}
        max_hosts = int(perf.get("max_concurrent_hosts") or _pj.get("max_concurrent") or 20)
        max_plugins = int(perf.get("max_concurrent_plugins") or 20)

        # Build context
        rate_limiter = RateLimiter(max_concurrent_hosts=max_hosts, max_concurrent_plugins=max_plugins)
        context = ScanContext(
            scan_id=self.scan_id,
            scan=scan,
            db=self.db,
            profile=scan.profile,
            log=scan_log,
            stealth_mode=_pj.get("stealth", False),
            rate_limiter=rate_limiter,
        )

        # Decrypt credentials if provided. Scans can have either one legacy
        # vault credential or multiple scan-scoped credentials from the UI.
        from scanr.credentials.vault import decrypt

        def _register_credential(data: dict, *, role: str = "generic") -> None:
            if not data:
                return
            context.credentials.append(data)
            context.credentials_by_role.setdefault(role, data)
            context.credential_data = context.credential_data or data

        if scan.credential_id:
            cred_result = await self.db.execute(
                select(Credential)
                .where(Credential.id == scan.credential_id)
            )
            cred = cred_result.scalar_one_or_none()
            if cred:
                data = decrypt(cred.encrypted_data)
                data.setdefault("username", cred.username)
                data.setdefault("type", cred.type)
                data.setdefault("role", "generic")
                _register_credential(data, role="generic")
                await scan_log.info(f"Credentials loaded: {cred.name}", phase="engine")

        scan_creds_result = await self.db.execute(
            select(ScanCredential)
            .where(ScanCredential.scan_id == self.scan_id)
        )
        scan_creds = scan_creds_result.scalars().all()
        for scan_cred in scan_creds:
            data = decrypt(scan_cred.encrypted_data)
            data.setdefault("username", scan_cred.username)
            data.setdefault("domain", scan_cred.domain)
            data.setdefault("type", scan_cred.type)
            data.setdefault("role", scan_cred.role)
            _register_credential(data, role=scan_cred.role)
        if scan_creds:
            await scan_log.info(f"Scan-scoped credentials loaded: {len(scan_creds)}", phase="engine")

        # Load wordlist paths for brute_force config (profile already parsed above)
        brute_cfg = _pj.get("brute_force", {}) if isinstance(_pj, dict) else {}

        wl_ids = [v for k, v in brute_cfg.items() if k.endswith("_wordlist_id") and v]
        if wl_ids:
            from scanr.models.wordlist import Wordlist as _Wordlist
            # IDOR guard: only the scan owner's wordlists or global/built-in
            # ones (NULL user_id) may be referenced by a scan profile.
            wl_result = await self.db.execute(
                select(_Wordlist).where(
                    _Wordlist.id.in_(wl_ids),
                    or_(
                        _Wordlist.user_id == scan.user_id,
                        _Wordlist.user_id.is_(None),
                    ),
                )
            )
            for wl in wl_result.scalars().all():
                context._wordlist_paths[wl.id] = wl.file_path

        collector = ResultCollector(self.scan_id, self.db, scan_log, user_id=scan.user_id, db_lock=context.db_lock)

        # Load enabled plugins from DB
        plugin_result = await self.db.execute(select(Plugin).where(Plugin.enabled == True))
        enabled_ids = {p.id for p in plugin_result.scalars().all()}
        plugins = get_enabled_plugins(enabled_ids)

        # Expand all targets to individual IPs/hostnames
        from scanr.utils.ip_utils import expand_targets

        all_targets: list[str] = []
        raw_targets = [target.value for target in targets]
        for target in targets:
            all_targets.extend(expand_targets(target.value))

        _pj["target_type"] = _target_type(_pj, raw_targets, all_targets)
        if _pj.get("target_type") == "domain":
            enum = _pj.setdefault("enumeration", {})
            enum["subdomain_enum"] = bool(enum.get("subdomain_enum", _pj.get("subdomain_enum", True)))
            enum["dns_recon"] = bool(enum.get("dns_recon", True))

        # Filter plugins by profile_json.plugins list (e.g. ["web.*", "ssl_tls.*"]).
        # This must happen after target normalization so domain defaults can
        # enable DNS/subdomain workflows before capability filtering.
        profile_filter: list[str] | None = None
        raw_filter = _pj.get("plugins", ["*"])
        if raw_filter != ["*"]:
            profile_filter = raw_filter

        if profile_filter:
            plugins = [p for p in plugins if _plugin_allowed(p.id, profile_filter)]

        plugins = _filter_plugins_by_capabilities(plugins, _pj)

        # Drop plugins that require credentials when none are loaded
        if not context.credentials:
            plugins = [p for p in plugins if not p.requires_auth]

        await scan_log.info(f"Loaded {len(plugins)} plugins (profile filter: {profile_filter or '*'})", phase="engine")

        perf_max_hosts = perf.get("max_hosts")
        if perf_max_hosts and len(all_targets) > int(perf_max_hosts):
            all_targets = all_targets[: int(perf_max_hosts)]
            await scan_log.warn(
                f"Target list capped at {perf_max_hosts} host(s) by performance settings",
                phase="engine",
            )

        domain_mode = _is_domain_mode(_pj, all_targets)
        if domain_mode:
            if _pj.get("port_range") in {"1-65535", "-p-", "-p -"} and not _pj.get("allow_full_port_scan", False):
                _pj["port_range"] = BUG_BOUNTY_PORT_RANGE
                scan.profile_json = json.dumps(_pj)
                await scan_log.info(
                    f"Domain target detected — using external web port range {_pj['port_range']} instead of full internal port sweep",
                    phase="recon",
                )
            all_targets = await _expand_domain_targets(all_targets, scan_log, _pj)

        # Defense-in-depth: re-validate targets at execution time. The API checks
        # the denylist when a scan is created, but DNS answers can change (or be
        # attacker-controlled) after validation, and non-creation paths (target
        # edits, schedules) may not re-validate. Resolve every hostname target and
        # refuse to run if any resolved IP is forbidden.
        forbidden = await _find_forbidden_resolved_targets(all_targets)
        if forbidden:
            sample = ", ".join(forbidden[:10])
            await scan_log.error(
                f"Target(s) resolve to forbidden address(es): {sample} — aborting scan",
                phase="engine",
            )
            scan.status = ScanStatus.failed
            scan.error_message = f"Forbidden target resolved: {sample}"
            await self.db.commit()
            return

        scan.hosts_total = len(all_targets)
        await self.db.commit()

        await scan_log.phase_start(
            "discovery",
            f"Host discovery: probing {len(all_targets)} target(s) — profile={scan.profile}",
        )

        # Phase 1: Host discovery
        #
        # For large IP ranges (>1024 hosts) when masscan is available, use masscan for
        # discovery instead of TCP connect. Masscan scans the full CIDR for a small
        # set of common probe ports simultaneously — it finds hosts that have any of
        # those ports open (e.g. Windows boxes on 445/3389, printers on 9100).
        #
        # Discovery port data is NOT reused for the port-scan phase: discovery only
        # probed common ports, so the port-scan phase runs a full-range masscan
        # below — but only on the (much smaller) set of live hosts.
        from scanr.scanner.port_scanner.masscan_wrapper import MasscanWrapper
        port_scan_cfg = context.port_scanning_config()
        scanners = port_scan_cfg.get("scanners", ["tcp_connect"])
        masscan_results: dict[str, list[int]] = {}
        masscan_ran = False
        # Computed once; live_targets is always a subset of all_targets so reused below.
        # all_are_ips encodes domain_mode=False already so no need to repeat below.
        all_are_ips = not domain_mode and all(is_valid_ip(t) for t in all_targets)

        use_masscan_discovery = (
            len(all_targets) > 1024
            and all_are_ips
            and MasscanWrapper.is_available()
            and not _pj.get("disable_masscan", False)
            and ("tcp_connect" in scanners or "syn" in scanners)
        )

        if use_masscan_discovery:
            from scanr.scanner.discovery.ping_sweep import PingSweep
            await scan_log.info(
                f"Large range ({len(all_targets)} hosts) — using masscan for host discovery",
                phase="discovery",
            )
            ms = MasscanWrapper()
            # Discovery: scan only common probe ports to find live hosts quickly
            discovery_ports = ",".join(str(p) for p in PingSweep.PROBE_PORTS_FAST) if hasattr(PingSweep, 'PROBE_PORTS_FAST') else "80,443,22,445,3389,8080,8443,25,53,21,23,3306,5432,6379,8888"
            discovery_results = await ms.scan(all_targets, discovery_ports, context)
            masscan_ran = True
            live_targets = list(discovery_results.keys())
            # Keep masscan_results empty so port scan phase runs full range
            masscan_results = {}
            await scan_log.info(
                f"masscan discovery complete: {len(live_targets)} hosts with open ports found",
                phase="discovery",
            )
        else:
            from scanr.scanner.discovery.ping_sweep import PingSweep
            sweeper = PingSweep()
            live_targets = await sweeper.discover(all_targets, context)

        scan.hosts_up = len(live_targets)
        await self.db.commit()
        await scan_log.phase_done(
            "discovery",
            f"Discovery complete: {len(live_targets)}/{len(all_targets)} hosts up",
        )

        if not live_targets:
            discovery_mode = context.discovery_config().get("mode", "fast")
            if discovery_mode == "aggressive":
                await scan_log.warn(
                    f"No hosts detected via discovery, but "
                    f"'{discovery_mode}' mode forces scan with -Pn",
                    phase="engine",
                )
                # Mutate profile_json so subsequent config reads pick up the override
                _pj.setdefault("discovery", {})["assume_up"] = True
                _pj.setdefault("port_scanning", {})["firewall_strategy"] = "skip_ping"
                context.scan.profile_json = json.dumps(_pj)
                live_targets = all_targets[:]
            else:
                await scan_log.warn("No live hosts found — scan complete", phase="engine")
                return

        # Phase boundary: pick up API-side pause/cancel before launching host tasks.
        # A cancel here propagates CancelledError to the task wrapper, which
        # finalizes the scan as cancelled.
        await context.refresh_control_state()
        await context.wait_if_paused()
        context.check_cancelled()

        await scan_log.phase_start(
            "portscan",
            f"Port scanning {len(live_targets)} host(s) ...",
        )

        # Masscan port scan (runs the full port range on the live hosts only).
        # When discovery already used masscan, use_masscan is necessarily True, so
        # this is the single masscan port pass — discovery only probed common ports.
        use_masscan = (
            MasscanWrapper.is_available()
            and not _pj.get("disable_masscan", False)
            and all_are_ips
            and ("tcp_connect" in scanners or "syn" in scanners)
        )
        if use_masscan:
            await scan_log.info(
                f"masscan available — running bulk port discovery on {len(live_targets)} hosts",
                phase="portscan",
            )
            ms = MasscanWrapper()
            masscan_results = await ms.scan(live_targets, context.get_port_range(), context)
            masscan_ran = True
            await scan_log.info(
                f"masscan complete: {sum(len(v) for v in masscan_results.values())} open ports across "
                f"{len(masscan_results)} hosts",
                phase="portscan",
            )
        else:
            if domain_mode:
                reason = "disabled for domain scan"
            elif ((_pj.get("port_scanning") or {}).get("scanner") == "tcp_connect"):
                reason = "disabled by TCP connect scanner selection"
            else:
                reason = "not found"
            await scan_log.info(
                f"masscan {reason} — using nmap for port/service discovery",
                phase="portscan",
            )

        # Phase 2+3+4: Per-host port scan + service fingerprint + plugin dispatch
        sem = rate_limiter.host_slot()
        tasks = [
            self._scan_host(ip, context, plugins, collector, sem, masscan_results.get(ip))
            for ip in live_targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for exc in results:
            if isinstance(exc, Exception) and not isinstance(exc, asyncio.CancelledError):
                logger.error("Unhandled host scan error: %s", exc, exc_info=exc)

        await self.db.commit()

        # Update hosts_up to reflect actually scanned hosts (not just discovery projection)
        scan.hosts_up = context.hosts_scanned
        await self.db.commit()

        # Cancel control plane: host tasks aborted via context flags at their
        # boundaries. Finalize as cancelled, keep partial results, and skip the
        # credential-chain / AI / completion-webhook phases. The task wrapper
        # preserves this status instead of overwriting it with completed/failed.
        if context.cancelled:
            await scan_log.warn(
                f"Scan cancelled by user — keeping partial results "
                f"({context.hosts_scanned} hosts scanned, {context.findings_count} findings)",
                phase="engine",
            )
            scan.status = ScanStatus.cancelled
            await self.db.commit()
            return

        # Warn if nothing was scanned AND masscan also found nothing — strong signal
        # of a privilege/network problem. Don't raise: zero open ports is a valid
        # result on a firewalled network and should complete, not fail, the scan.
        if live_targets and context.hosts_scanned == 0 and not masscan_ran:
            await scan_log.warn(
                f"Port scanning returned 0 results for {len(live_targets)} live host(s). "
                "Possible cause: nmap lacks raw-socket privileges or all hosts block probes. "
                "Check worker logs.",
                phase="engine",
            )

        # Credential chaining phase (opt-in via profile_json.credential_chain:true)
        if _pj.get("credential_chain", False) and getattr(context, "discovered_credentials", []):
            await scan_log.phase_start("chain", f"Credential chain: {len(context.discovered_credentials)} credential(s) to test")
            try:
                from scanr.core.credential_chain import run_credential_chain
                all_hosts_result = await self.db.execute(
                    select(Host)
                    .where(Host.scan_id == self.scan_id)
                )
                all_hosts = all_hosts_result.scalars().all()
                await run_credential_chain(context, all_hosts, collector)
                await self.db.commit()
            except Exception as exc:
                logger.error("Credential chain failed: %s", exc, exc_info=True)
            await scan_log.phase_done("chain", "Credential chain complete")

        # AI steering phase: if the scan opted into AI, let the agent act on the
        # discovered hosts/services/findings before the scan finishes.
        await self._run_ai_phase(scan, scan_log)

        await scan_log.phase_done(
            "engine",
            f"Scan complete — {context.hosts_scanned} hosts scanned, "
            f"{context.findings_count} findings",
        )

        # Fire scan.completed webhook. scan.status is a plain str (String
        # column) — never call .value on it. The ORM select refreshes the
        # in-memory row, so a scan cancelled/failed externally while the AI
        # phase ran is detected here and gets no false completion webhook.
        scan_result = await self.db.execute(select(Scan).where(Scan.id == self.scan_id))
        scan = scan_result.scalar_one()
        if scan.status == ScanStatus.running:
            try:
                from scanr.core.webhook_dispatcher import dispatch
                await dispatch("scan.completed", {
                    "scan_id": self.scan_id,
                    "scan_name": scan.name,
                    "status": scan.status,
                    "hosts_scanned": context.hosts_scanned,
                    "hosts_up": scan.hosts_up,
                    "findings_total": context.findings_count,
                    "findings_critical": scan.findings_critical,
                    "findings_high": scan.findings_high,
                    "findings_medium": scan.findings_medium,
                    "findings_low": scan.findings_low,
                }, scan.user_id, self.db)
            except Exception as exc:
                logger.error("scan.completed webhook dispatch failed: %s", exc)
        else:
            await scan_log.info(
                f"Scan ended with status '{scan.status}' — skipping completion webhook",
                phase="engine",
            )

    async def _run_ai_phase(self, scan, scan_log: ScanLogger) -> None:
        """Let the opted-in AI agent steer the scan once enumeration is done.

        Runs the agent inline (its own DB session) with the discovered hosts,
        services, and findings already in place, so it can perform high-value
        follow-up checks (targeted plugins / port scans) that become part of the
        scan. Best-effort: a failure here never fails the scan.
        """
        if not getattr(scan, "ai_agent_enabled", False):
            return
        try:
            from scanr.ai.agent.autostart import build_scan_agent_run

            default_obj = (
                "Scanning and enumeration just finished for this scan. Review the "
                "discovered hosts, services, and findings, then perform the highest-"
                "value follow-up checks now — run targeted plugins or port scans "
                "against promising hosts, corroborate the most serious issues, and "
                "record what you find. Finish with a prioritized assessment and "
                "concrete next steps."
            )
            objective = (scan.ai_agent_objective or "").strip() or default_obj
            run = await build_scan_agent_run(self.db, scan, objective=objective)
            if run is None:
                return

            await scan_log.phase_start("ai_agent", f"AI agent steering the scan ({run.mode})")
            from scanr.tasks.agent_tasks import _run_agent_async

            await _run_agent_async(run.id)
            await scan_log.phase_done("ai_agent", "AI agent phase complete")
        except Exception as exc:  # noqa: BLE001 - never let AI break the scan
            logger.error("AI steering phase failed: %s", exc, exc_info=True)
            await scan_log.warn(f"AI agent phase failed: {exc}", phase="ai_agent")

    async def _scan_host(
        self,
        ip: str,
        context: ScanContext,
        plugins: list,
        collector: ResultCollector,
        sem: asyncio.Semaphore,
        known_ports: list[int] | None = None,
    ) -> None:
        async with sem:
            context.check_cancelled()
            await context.wait_if_paused()  # blocks until resumed or cancelled
            context.check_cancelled()

            await context.log.info(f"Scanning {ip} ...", phase="portscan", host=ip)

            from scanr.scanner.port_scanner.nmap_wrapper import NmapWrapper

            nmap = NmapWrapper()
            host_data = await nmap.scan_host(ip, context, known_ports=known_ports)
            if not host_data:
                if known_ports:
                    # nmap got no response but masscan confirmed these ports — use masscan data
                    await context.log.warn(
                        f"{ip} — nmap unresponsive; using {len(known_ports)} masscan-confirmed port(s)",
                        phase="portscan", host=ip,
                    )
                    host_data = {
                        "address": ip,
                        "ports": [
                            {"number": p, "protocol": "tcp", "state": "open", "reason": "syn-ack"}
                            for p in sorted(known_ports)
                        ],
                    }
                else:
                    await context.log.warn(f"{ip} — no response from nmap", phase="portscan", host=ip)
                    return

            open_ports = [p for p in host_data.get("ports", []) if p["state"] == "open"]
            # nmap returned 0 open ports but masscan confirmed some — merge masscan ports
            if not open_ports and known_ports:
                existing = {p["number"] for p in host_data.get("ports", [])}
                for port_num in sorted(known_ports):
                    if port_num not in existing:
                        host_data.setdefault("ports", []).append(
                            {"number": port_num, "protocol": "tcp", "state": "open", "reason": "syn-ack"}
                        )
                open_ports = [p for p in host_data["ports"] if p["state"] == "open"]
                if open_ports:
                    await context.log.warn(
                        f"{ip} — nmap found 0 open ports; using {len(open_ports)} masscan-confirmed port(s)",
                        phase="portscan", host=ip,
                    )
            await context.log.info(
                f"{ip} — {len(open_ports)} open port(s): "
                + ", ".join(str(p["number"]) for p in open_ports[:20])
                + ("..." if len(open_ports) > 20 else ""),
                phase="portscan",
                host=ip,
            )

            # Persist host + ports + services in a savepoint so a flush failure
            # doesn't corrupt the outer transaction.
            from scanr.models import Port, Service
            try:
                async with context.db_lock:
                    async with self.db.begin_nested():
                        host = Host(
                            id=new_uuid(),
                            scan_id=self.scan_id,
                            ip=host_data.get("address") or ip,
                            hostname=_hostname_for_host(ip, host_data),
                            mac_address=host_data.get("mac"),
                            os_name=host_data.get("os_name"),
                            os_accuracy=host_data.get("os_accuracy"),
                            status="up",
                        )
                        self.db.add(host)

                        # IDs are generated in Python (new_uuid), so port/service
                        # rows can be built with their foreign keys up front and
                        # persisted in a single flush instead of one round trip
                        # per port — far fewer DB calls for hosts with many ports.
                        new_rows: list[object] = []
                        for p in host_data.get("ports", []):
                            port = Port(
                                id=new_uuid(),
                                host_id=host.id,
                                number=p["number"],
                                protocol=p["protocol"],
                                state=p["state"],
                                reason=p.get("reason"),
                                banner=p.get("banner"),
                            )
                            new_rows.append(port)

                            if p.get("service"):
                                svc = p["service"]
                                new_rows.append(Service(
                                    id=new_uuid(),
                                    port_id=port.id,
                                    name=svc.get("name"),
                                    product=svc.get("product"),
                                    version=svc.get("version"),
                                    extra_info=svc.get("extra_info"),
                                    cpe=svc.get("cpe"),
                                    tunnel=svc.get("tunnel"),
                                ))
                                if svc.get("product"):
                                    await context.log.debug(
                                        f"{ip}:{p['number']} — {svc.get('product','')} {svc.get('version','')}".strip(),
                                        phase="fingerprint",
                                        host=ip,
                                    )
                        if new_rows:
                            self.db.add_all(new_rows)
                        await self.db.flush()
                    # Release transaction locks before slow plugin checks run.
                    await self.db.commit()
            except Exception as exc:
                logger.error("Failed to persist host %s: %s", ip, exc, exc_info=True)
                await context.log.error(f"Failed to persist host {ip}: {exc}", phase="engine", host=ip)
                return

            # Reload host with eagerly-loaded ports+services so plugins can
            # safely access host.ports without triggering lazy-load (which
            # raises MissingGreenlet in async SQLAlchemy).
            from scanr.models import Port as _Port
            async with context.db_lock:
                host_result = await self.db.execute(
                    select(Host)
                    .where(Host.id == host.id)
                    .options(selectinload(Host.ports).selectinload(_Port.service))
                )
                host = host_result.scalar_one()
                await self.db.commit()

            # Phase 4: Run applicable plugins concurrently
            host_ports = host_data.get("ports", [])
            applicable = [
                pl for pl in plugins
                if _plugin_applies_to_host_data(pl, host_ports)
            ]

            if applicable:
                await context.log.info(
                    f"{ip} — running {len(applicable)} plugin(s)",
                    phase="plugin",
                    host=ip,
                )
            plugin_sem = context.rate_limiter.plugin_slot(ip) if context.rate_limiter else asyncio.Semaphore(20)
            plugin_tasks = [
                self._run_plugin(plugin, context, host, host_data, collector, plugin_sem)
                for plugin in applicable
            ]
            await asyncio.gather(*plugin_tasks, return_exceptions=True)

            async with context.db_lock:
                await self.db.flush()
                await self.db.commit()
            context.hosts_scanned += 1

    async def _run_plugin(self, plugin, context, host, host_data, collector, sem):
        async with sem:
            context.check_cancelled()
            started = time.perf_counter()
            await context.log.debug(
                f"{host.ip} — plugin: {plugin.name}",
                phase="plugin",
                host=host.ip,
                plugin=plugin.id,
            )
            try:
                findings = await asyncio.wait_for(
                    plugin.check(context, host),
                    timeout=getattr(plugin, "timeout", None) or context.performance_config()["timeout"],
                )
                for f in findings:
                    await collector.add_finding(host.id, f)
                    context.findings_count += 1
                    await context.log.finding(
                        f.title,
                        f.severity.value,
                        host=host.ip,
                        plugin=plugin.id,
                    )
                await self._record_plugin_run(
                    context,
                    host,
                    plugin.id,
                    status="success",
                    duration_ms=_elapsed_ms(started),
                    findings_count=len(findings),
                )
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                logger.error("Plugin %s timed out on %s", plugin.id, host.ip)
                duration_ms = _elapsed_ms(started)
                await context.log.error(
                    f"Plugin {plugin.id} timed out on {host.ip} after {duration_ms}ms",
                    phase="plugin",
                    host=host.ip,
                    plugin=plugin.id,
                )
                await self._record_plugin_run(
                    context,
                    host,
                    plugin.id,
                    status="timeout",
                    duration_ms=duration_ms,
                    error="Plugin timed out",
                )
            except Exception as exc:
                logger.error(
                    "Plugin %s failed on %s: %s", plugin.id, host.ip, exc, exc_info=True
                )
                duration_ms = _elapsed_ms(started)
                await context.log.error(
                    f"Plugin {plugin.id} failed on {host.ip}: {exc}",
                    phase="plugin",
                    host=host.ip,
                    plugin=plugin.id,
                )
                await self._record_plugin_run(
                    context,
                    host,
                    plugin.id,
                    status="error",
                    duration_ms=duration_ms,
                    error=str(exc)[:2000],
                )

    async def _record_plugin_run(
        self,
        context: ScanContext,
        host: Host,
        plugin_id: str,
        *,
        status: str,
        duration_ms: int,
        findings_count: int = 0,
        error: str | None = None,
    ) -> None:
        from scanr.models import PluginRun
        from scanr.models.base import new_uuid

        async with context.db_lock:
            run = PluginRun(
                id=new_uuid(),
                scan_id=self.scan_id,
                host_id=host.id,
                plugin_id=plugin_id,
                host_ip=host.ip,
                status=status,
                duration_ms=duration_ms,
                findings_count=findings_count,
                error=error,
            )
            self.db.add(run)
            await self.db.flush()
            await self.db.commit()


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))
