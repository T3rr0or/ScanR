from __future__ import annotations

import base64
import json
import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

WEAK_SECRETS = [
    "secret", "password", "changeme", "123456", "qwerty",
    "jwt_secret", "mysecret", "token", "key", "admin",
    "your-256-bit-secret", "your-secret-key",
]


def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _make_none_alg_token(header_b64: str, payload_b64: str) -> str:
    """Craft a JWT with alg=none."""
    try:
        header = json.loads(_b64_decode(header_b64))
    except Exception:
        return ""
    header["alg"] = "none"
    new_header = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{new_header}.{payload_b64}."


class JwtMisconfigPlugin(PluginBase):
    id = "web.jwt_misconfig"
    name = "JWT Misconfiguration"
    description = "Detect JWT alg:none attack and weak HMAC signing secrets"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{ip}:{port.number}/" if (ip := host.ip) else None
            if not base_url:
                continue

            # Try to collect a JWT from common endpoints
            jwt = await self._find_jwt(base_url)
            if not jwt:
                continue

            parts = jwt.split(".")
            if len(parts) != 3:
                continue

            header_b64, payload_b64, sig = parts

            # Test alg:none
            none_token = _make_none_alg_token(header_b64, payload_b64)
            if none_token and await self._test_token_accepted(context, base_url, none_token):
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="JWT alg:none Attack Accepted",
                    description=(
                        "The server accepts JWT tokens with algorithm set to 'none', "
                        "meaning signature verification is bypassed. An attacker can forge "
                        "arbitrary tokens without knowing the secret key."
                    ),
                    evidence=f"Server accepted unsigned JWT at {base_url}",
                    remediation=(
                        "Explicitly whitelist allowed algorithms in your JWT library. "
                        "Never accept 'none' as a valid algorithm."
                    ),
                    references=[
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "https://cwe.mitre.org/data/definitions/347.html",
                    ],
                    port_number=port.number,
                    protocol="tcp",
                ))

            # Test weak secrets (HMAC only)
            try:
                header_data = json.loads(_b64_decode(header_b64))
                alg = header_data.get("alg", "")
                if alg.startswith("HS"):
                    weak = await self._test_weak_secret(header_b64, payload_b64, sig, alg)
                    if weak:
                        findings.append(FindingData(
                            plugin_id=self.id,
                            severity=Severity.medium,
                            title="JWT Signed with Weak Secret",
                            description=(
                                f"The JWT is signed using the weak secret '{weak}'. "
                                "An attacker can brute-force the secret and forge tokens."
                            ),
                            evidence=f"JWT at {base_url} verified with secret='{weak}'",
                            remediation=(
                                "Use a cryptographically random secret of at least 256 bits. "
                                "Consider switching to RSA/EC asymmetric signing."
                            ),
                            references=["https://owasp.org/www-project-api-security/"],
                            port_number=port.number,
                            protocol="tcp",
                        ))
            except Exception:
                pass

        return findings

    async def _find_jwt(self, base_url: str) -> str | None:
        """Try to get a JWT from common endpoints."""
        endpoints = ["", "api/", "api/v1/", "auth/", "login"]
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                for ep in endpoints:
                    try:
                        resp = await client.get(base_url + ep)
                        # Check headers
                        auth = resp.headers.get("authorization", "")
                        if auth.startswith("Bearer "):
                            match = JWT_REGEX.search(auth)
                            if match:
                                return match.group(0)
                        # Check body
                        match = JWT_REGEX.search(resp.text)
                        if match:
                            return match.group(0)
                        # Check cookies
                        for cookie_val in resp.cookies.values():
                            match = JWT_REGEX.search(cookie_val)
                            if match:
                                return match.group(0)
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    async def _test_token_accepted(self, context, base_url: str, token: str) -> bool:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, **context.proxy_config()) as client:
                resp = await client.get(base_url, headers={"Authorization": f"Bearer {token}"})
                return resp.status_code == 200
        except Exception:
            return False

    async def _test_weak_secret(self, header_b64: str, payload_b64: str, sig: str, alg: str) -> str | None:
        import hashlib
        import hmac
        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_fn = alg_map.get(alg, hashlib.sha256)
        message = f"{header_b64}.{payload_b64}".encode()
        try:
            expected_sig = base64.urlsafe_b64decode(sig + "==")
        except Exception:
            return None
        for secret in WEAK_SECRETS:
            computed = hmac.new(secret.encode(), message, hash_fn).digest()  # type: ignore[attr-defined]
            if hmac.compare_digest(computed, expected_sig):
                return secret
        return None
