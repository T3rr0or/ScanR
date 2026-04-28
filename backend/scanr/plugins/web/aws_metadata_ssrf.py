from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]
_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
_IMDS_V2_TOKEN_URL = "http://169.254.169.254/latest/api/token"

# URL parameters commonly used for SSRF
_URL_PARAMS = [
    "url", "uri", "target", "dest", "redirect", "proxy", "fetch", "src", "endpoint", "load",
]

# Signatures indicating metadata access
_META_SIGNATURES = [
    re.compile(r"ami-id|instance-id|local-ipv4|public-hostname|iam/security-credentials", re.I),
    re.compile(r"instanceId|accountId|architecture|imageId", re.I),
]

_USERDATA_SIGNATURES = [
    re.compile(r"#!/bin|cloud-init|#cloud-config|#!/usr/bin/env"),
]


class AwsMetadataSsrfPlugin(PluginBase):
    id = "web.aws_metadata_ssrf"
    name = "AWS Metadata SSRF / IMDSv1 Exposure"
    description = "Check for IMDSv1 SSRF and direct metadata endpoint access"
    category = PluginCategory.web
    severity = Severity.critical
    ports = [80, 443, 8080, 8443, 8000, 3000]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []

        # Check 1: Direct metadata access — result is scanner-wide, run once per scan
        _cache_attr = "_aws_direct_meta_checked"
        if not getattr(context, _cache_attr, False):
            setattr(context, _cache_attr, True)
            direct = await self._check_direct_metadata()
            if direct:
                findings.append(direct)

        # Check 2: SSRF via web app
        for port in host.ports:
            if port.number not in _HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._check_ssrf(base_url, port.number)
            if result:
                findings.append(result)

        return findings

    async def _check_direct_metadata(self) -> FindingData | None:
        """Try to access AWS metadata directly (works when scanner is in same VPC)."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(_METADATA_URL)
                if resp.status_code == 200:
                    content = resp.text
                    if (
                        any(sig.search(content) for sig in _META_SIGNATURES)
                        or (
                            len(content) > 10
                            and any(
                                kw in content
                                for kw in ["ami-id", "instance-type", "local-ipv4", "public-keys"]
                            )
                        )
                    ):
                        cred_info = ""
                        try:
                            r2 = await client.get(
                                "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                            )
                            if r2.status_code == 200 and r2.text.strip():
                                role = r2.text.strip()
                                cred_info = f"\nIAM role: {role}"
                                r3 = await client.get(
                                    f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}"
                                )
                                if r3.status_code == 200:
                                    cred_info += f"\nIAM credentials accessible: {r3.text[:200]}"
                        except Exception:
                            pass

                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title="AWS Instance Metadata Service (IMDSv1) Directly Accessible",
                            description=(
                                "The AWS EC2 Instance Metadata Service (IMDS) at 169.254.169.254 is directly "
                                "accessible from the scanning host, indicating the scanner is running in the "
                                "same VPC or subnet as the target. IMDSv1 is accessible without authentication, "
                                "exposing instance credentials, user-data, and account information."
                            ),
                            evidence=f"GET {_METADATA_URL} → 200\nMetadata: {content[:300]}{cred_info}",
                            remediation=(
                                "Enforce IMDSv2 on all EC2 instances: aws ec2 modify-instance-metadata-options "
                                "--instance-id i-xxx --http-tokens required --http-put-response-hop-limit 1. "
                                "Block 169.254.169.254 access via iptables for container workloads. "
                                "Rotate IAM credentials if they were exposed."
                            ),
                            references=[
                                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
                            ],
                            protocol="tcp",
                        )
        except Exception:
            pass
        return None

    async def _check_ssrf(self, base_url: str, port: int) -> FindingData | None:
        """Test web app for SSRF to cloud metadata endpoint."""
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=6.0,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR)"},
            ) as client:
                for param in _URL_PARAMS:
                    urls_to_try = [
                        f"{base_url}/?{param}={_METADATA_URL}",
                        f"{base_url}/api?{param}={_METADATA_URL}",
                    ]
                    for url in urls_to_try:
                        try:
                            resp = await client.get(url)
                            if resp.status_code == 200:
                                for sig in _META_SIGNATURES:
                                    if sig.search(resp.text):
                                        return FindingData(
                                            plugin_id=self.id,
                                            severity=Severity.critical,
                                            title="SSRF to AWS Metadata Service — Cloud Credentials Exposed",
                                            description=(
                                                f"The web application at {base_url} is vulnerable to Server-Side "
                                                f"Request Forgery and fetches the AWS instance metadata endpoint "
                                                f"when the {param!r} parameter is set to "
                                                "http://169.254.169.254/. An attacker can steal IAM role "
                                                "credentials, user-data, and account information."
                                            ),
                                            evidence=(
                                                f"Request: GET {url}\n"
                                                f"Response {resp.status_code}: {resp.text[:400]}"
                                            ),
                                            remediation=(
                                                "Validate and whitelist allowed URL schemes and destinations. "
                                                "Block requests to 169.254.169.254 and RFC1918 ranges from "
                                                "application servers. "
                                                "Enforce IMDSv2 (hop limit 1) to prevent SSRF from reaching IMDS."
                                            ),
                                            references=[
                                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                                            ],
                                            port_number=port,
                                            protocol="tcp",
                                        )
                        except Exception:
                            pass
        except Exception as exc:
            logger.debug("AWS metadata SSRF check failed for %s: %s", base_url, exc)
        return None
