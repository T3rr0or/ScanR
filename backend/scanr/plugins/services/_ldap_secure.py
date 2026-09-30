"""Helpers for authenticated LDAP without sending credentials in cleartext."""
from __future__ import annotations

import ssl


def secure_ldap_connection(ldap3, ip: str, port: int, username: str, password: str,
                          *, timeout: int = 10):
    """Bind to LDAPS or require StartTLS before binding on LDAP/389.

    Deliberately fails closed if StartTLS cannot be negotiated. Callers own the
    returned connection and must unbind it.
    """
    if port not in (389, 636, 3268, 3269):
        raise ValueError(f"unsupported LDAP port: {port}")
    # ldap3 otherwise defaults to CERT_NONE and does not verify the endpoint
    # name. IP targets therefore need a matching IP SAN in their certificate.
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, valid_names=[ip])
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
            if not conn.open() or not conn.start_tls():
                raise RuntimeError("LDAP StartTLS negotiation failed")
        if not conn.bind():
            raise RuntimeError("LDAP bind failed")
        return conn
    except Exception:
        try:
            conn.unbind()
        except Exception:
            pass
        raise
