from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class MinioS3ExposurePlugin(PluginBase):
    id = "services.minio_s3_exposure"
    name = "MinIO / S3-Compatible Storage Exposure"
    description = "Detect exposed MinIO consoles or unauthenticated S3 listing"
    category = PluginCategory.services
    severity = Severity.high
    ports = [9000, 9001, 80, 443]

    async def check(self, context, host):
        for port in _open(host, set(self.ports)):
            got = await _http_get(context, host.ip, port, "/")
            if got:
                text = got[1].text[:5000].lower()
                hdr = str(got[1].headers).lower()
                if "minio" in text or "x-amz-request-id" in hdr or "listbucketresult" in text:
                    sev = Severity.critical if "listbucketresult" in text else Severity.high
                    return [_finding(self.id, sev, "S3-Compatible Storage Exposed", "Object storage endpoint or MinIO console is reachable and may expose bucket metadata.", f"{got[0]} returned MinIO/S3 indicators", "Require authentication, disable public bucket listing, and restrict storage APIs to trusted clients.", port)]
        return []

