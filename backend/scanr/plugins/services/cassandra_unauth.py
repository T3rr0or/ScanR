from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class CassandraUnauthPlugin(PluginBase):
    id = "services.cassandra_unauth"
    name = "Cassandra Unauthenticated Access"
    description = "Detect Cassandra native protocol allowing startup without authentication"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [9042]

    async def check(self, context, host):
        if 9042 not in _open(host, {9042}):
            return []
        body = struct.pack(">H", 1) + struct.pack(">H", len("CQL_VERSION")) + b"CQL_VERSION" + struct.pack(">H", len("3.0.0")) + b"3.0.0"
        frame = b"\x04\x00\x00\x01\x01" + struct.pack(">I", len(body)) + body
        try:
            data = await _tcp_probe(host.ip, 9042, frame, 32)
            if len(data) >= 9 and data[4] == 0x02:
                return [_finding(self.id, Severity.critical, "Cassandra Allows Unauthenticated Startup", "Cassandra native protocol returned READY instead of AUTHENTICATE, indicating authentication may be disabled.", "STARTUP -> READY", "Enable PasswordAuthenticator/authorizer, require TLS, and restrict Cassandra to cluster networks.", 9042)]
        except Exception:
            pass
        return []

