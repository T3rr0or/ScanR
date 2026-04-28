"""Utility to format raw HTTP request/response pairs as structured evidence strings."""
from __future__ import annotations


def format_http_evidence(
    method: str,
    url: str,
    request_headers: dict,
    request_body: str | None,
    status_code: int,
    response_headers: dict,
    response_body: str,
    max_body: int = 1000,
) -> str:
    req_lines = [f"{method} {url}"]
    req_lines.extend(f"{k}: {v}" for k, v in request_headers.items())
    if request_body:
        req_lines.extend(["", request_body[:500]])

    resp_lines = [f"HTTP/1.1 {status_code}"]
    resp_lines.extend(f"{k}: {v}" for k, v in response_headers.items())
    resp_lines.extend(["", response_body[:max_body]])
    if len(response_body) > max_body:
        resp_lines.append(f"[... {len(response_body) - max_body} bytes truncated]")

    return (
        "=== REQUEST ===\n" + "\n".join(req_lines) +
        "\n\n=== RESPONSE ===\n" + "\n".join(resp_lines)
    )


def format_from_httpx(resp, *, max_body: int = 1000) -> str:
    """Convenience wrapper for httpx Response objects."""
    req = resp.request
    return format_http_evidence(
        method=req.method,
        url=str(req.url),
        request_headers=dict(req.headers),
        request_body=req.content.decode(errors="replace") if req.content else None,
        status_code=resp.status_code,
        response_headers=dict(resp.headers),
        response_body=resp.text,
        max_body=max_body,
    )
