"""Credential chaining engine.

After the main scan phase, if context.discovered_credentials is populated,
this module tests those credentials against other hosts in the scan.

Only runs when profile_json.credential_chain is true.
Credentials are in-memory only — never persisted to DB.
"""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def run_credential_chain(context, hosts: list, collector) -> None:
    """Test discovered credentials against other hosts in the scan."""

    creds = getattr(context, "discovered_credentials", [])
    if not creds:
        return

    await context.log.info(
        f"Credential chain: testing {len(creds)} discovered credential(s) against {len(hosts)} host(s)",
        phase="chain",
    )

    # Cap credential attempts to avoid account lockouts and scan timeouts
    _MAX_CREDS = 10
    _MAX_HOSTS = 20
    creds_to_test = creds[:_MAX_CREDS]
    hosts_to_test = [h for h in hosts][:_MAX_HOSTS]

    sem = asyncio.Semaphore(3)  # max 3 concurrent auth attempts

    async def _throttled(cred, host):
        # Honour per-host rate limiter before each attempt
        if context.rate_limiter and not await context.rate_limiter.wait_if_throttled(host.ip):
            return
        async with sem:
            await asyncio.sleep(0.5)  # basic anti-lockout spacing
            await _test_credential(context, cred, host, collector)

    tasks = []
    for cred in creds_to_test:
        for host in hosts_to_test:
            if host.ip == cred.get("source_host"):
                continue
            tasks.append(_throttled(cred, host))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _test_credential(context, cred: dict, host, collector) -> None:
    cred_type = cred.get("type", "")
    username = cred.get("username", "")
    password = cred.get("password", "")
    source = cred.get("source_host", "?")

    if cred_type in ("ssh", "ssh_key") and any(p.number == 22 and p.state == "open" for p in host.ports):
        await _test_ssh(context, host, username, password, cred.get("key_material"), source, collector)

    if cred_type in ("web_cred", "http_basic") and any(
        p.number in (80, 443, 8080, 8443) and p.state == "open" for p in host.ports
    ):
        await _test_web(context, host, username, password, source, collector)


async def _test_ssh(context, host, username: str, password: str | None, key_material: str | None, source: str, collector) -> None:
    try:
        import asyncssh
        auth_kwargs: dict = {}
        if key_material:
            key = asyncssh.import_private_key(key_material)
            auth_kwargs["client_keys"] = [key]
            auth_kwargs["known_hosts"] = None
        elif password:
            auth_kwargs["password"] = password
            auth_kwargs["known_hosts"] = None
        else:
            return

        conn = await asyncio.wait_for(
            asyncssh.connect(host.ip, port=22, username=username, **auth_kwargs),
            timeout=8.0,
        )
        await conn.close()

        # Success — credential works on this host
        from scanr.core.plugin_base import FindingData, Severity
        await collector.add_finding(host.id, FindingData(
            plugin_id="services.credential_chain_ssh",
            severity=Severity.critical,
            title=f"Credential Chain: SSH Access on {host.ip} via Credentials from {source}",
            description=(
                f"Credentials discovered on {source} (user: {username!r}) were successfully "
                f"reused to authenticate via SSH on {host.ip}. "
                "This indicates credential reuse across the network."
            ),
            evidence=f"Username: {username}\nSource host: {source}\nTarget: {host.ip}:22",
            remediation=(
                "Use unique credentials per host. "
                "Rotate all credentials exposed during the scan. "
                "Implement SSH key management to prevent key reuse."
            ),
            port_number=22,
            protocol="tcp",
        ))
        await context.log.finding(
            f"Credential chain hit: {username}@{host.ip} via SSH (creds from {source})",
            "critical", host=host.ip, plugin="services.credential_chain_ssh",
        )
    except (ImportError, asyncio.TimeoutError):
        pass
    except Exception as exc:
        logger.debug("SSH credential chain attempt failed %s@%s: %s", username, host.ip, exc)


async def _test_web(context, host, username: str, password: str, source: str, collector) -> None:
    try:
        import httpx
        port = next(p.number for p in host.ports if p.number in (443, 8443, 80, 8080) and p.state == "open")
        scheme = "https" if port in (443, 8443) else "http"
        base = f"{scheme}://{host.ip}:{port}"

        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            for path in ["/admin", "/login", "/wp-login.php", "/"]:
                try:
                    resp = await client.get(f"{base}{path}", auth=(username, password))
                    if resp.status_code == 200 and "logout" in resp.text.lower():
                        from scanr.core.plugin_base import FindingData, Severity
                        await collector.add_finding(host.id, FindingData(
                            plugin_id="services.credential_chain_web",
                            severity=Severity.high,
                            title=f"Credential Chain: Web Auth on {host.ip} via Credentials from {source}",
                            description=(
                                f"HTTP Basic auth credentials from {source} (user: {username!r}) "
                                f"were accepted at {base}{path}."
                            ),
                            evidence=f"Username: {username}\nSource: {source}\nTarget: {base}{path}\nHTTP {resp.status_code}",
                            remediation="Use unique credentials per service. Rotate all exposed credentials.",
                            port_number=port,
                            protocol="tcp",
                        ))
                        return
                except Exception:
                    pass
    except (StopIteration, Exception) as exc:
        logger.debug("Web credential chain attempt failed %s@%s: %s", username, host.ip, exc)
