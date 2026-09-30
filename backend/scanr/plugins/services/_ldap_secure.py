"""Helpers for authenticated LDAP without sending credentials in cleartext."""
from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanr.core.context import ScanContext


class LdapTlsError(RuntimeError):
    """TLS could not be established or the server certificate was rejected.

    Distinct from a failed bind so the scan can tell the operator how to fix
    it instead of silently finding nothing.
    """


def _looks_like_tls_failure(exc: BaseException) -> bool:
    if isinstance(exc, ssl.SSLError):
        return True
    text = str(exc).lower()
    return any(marker in text for marker in ("ssl", "tls", "certificate"))


def secure_ldap_connection(ldap3, ip: str, port: int, username: str, password: str,
                          *, timeout: int = 10, hostnames: Iterable[str | None] = ()):
    """Bind to LDAPS or require StartTLS before binding on LDAP/389.

    Deliberately fails closed if TLS cannot be negotiated or the certificate
    does not validate. The certificate may name the target IP or any of
    ``hostnames`` (typically the DC's DNS name, which is what AD CS issues).
    Set ``LDAP_CA_FILE`` to trust an internal CA. Callers own the returned
    connection and must unbind it.
    """
    if port not in (389, 636, 3268, 3269):
        raise ValueError(f"unsupported LDAP port: {port}")
    from scanr.config import get_settings

    valid_names = [ip, *dict.fromkeys(name.rstrip(".") for name in hostnames if name)]
    tls_options: dict[str, Any] = {"validate": ssl.CERT_REQUIRED, "valid_names": valid_names}
    ca_file = get_settings().ldap_ca_file
    if ca_file:
        if not ca_file.is_file():
            raise LdapTlsError(f"LDAP_CA_FILE {ca_file} does not exist or is not a file")
        tls_options["ca_certs_file"] = str(ca_file)
    # ldap3 otherwise defaults to CERT_NONE and does not verify the endpoint name.
    tls = ldap3.Tls(**tls_options)
    server = ldap3.Server(
        ip, port=port, use_ssl=(port in (636, 3269)), tls=tls, get_info=ldap3.ALL,
        connect_timeout=timeout,
    )
    conn = ldap3.Connection(
        server, user=username, password=password, auto_bind=False,
        receive_timeout=15,
    )
    try:
        if port in (389, 3268):
            try:
                negotiated = conn.open() and conn.start_tls()
            except Exception as exc:
                raise LdapTlsError(f"LDAP StartTLS negotiation failed: {exc}") from exc
            if not negotiated:
                raise LdapTlsError("LDAP StartTLS negotiation failed")
        try:
            bound = conn.bind()
        except Exception as exc:
            # On LDAPS the TLS handshake happens inside bind().
            if _looks_like_tls_failure(exc):
                raise LdapTlsError(f"LDAPS TLS handshake failed: {exc}") from exc
            raise
        if not bound:
            raise RuntimeError("LDAP bind failed")
        return conn
    except Exception:
        try:
            conn.unbind()
        except Exception:
            pass
        raise


async def run_ldap_check(context: "ScanContext", plugin_id: str, ip: str,
                         func: Callable[..., Any], *args: Any, default: Any = None) -> Any:
    """Run a blocking LDAP check in a thread; report TLS rejections to the scan.

    Without this, a DC whose certificate the scanner cannot validate yields no
    findings and no explanation.
    """
    try:
        return await asyncio.get_running_loop().run_in_executor(None, func, *args)
    except LdapTlsError as exc:
        await warn_ldap_tls(context, plugin_id, ip, exc)
        return [] if default is None else default


async def warn_ldap_tls(context: "ScanContext", plugin_id: str, ip: str, exc: LdapTlsError) -> None:
    await context.log.warn(
        f"{plugin_id}: skipped {ip}: {exc}. Authenticated LDAP requires a certificate "
        "that names the DC's IP or hostname and chains to a trusted CA; set "
        "LDAP_CA_FILE to your internal CA bundle.",
        phase="plugin",
    )
