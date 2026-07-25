---
name: tls-triage
description: Separating TLS findings that matter from the ones that pad a report.
---
# TLS

TLS checks generate volume. Most of it is noise, and reporting all of it buries
the part that is not.

## Actually matters
- **Expired or wrong-host certificate** — breaks trust today and users are
  already clicking through it.
- **`ssl_tls.heartbleed`** — memory disclosure, remotely, unauthenticated.
- **Private key exposure**, or a certificate whose key appears elsewhere.
- **Protocol downgrade that is reachable** — SSLv3/TLS 1.0 still negotiable by a
  real client, not merely listed as supported.

## Usually does not
- TLS 1.0/1.1 supported alongside 1.2/1.3 on an internal service with modern
  clients — worth a line, not a medium.
- CBC cipher suites in 2026 — real, ancient, and not what gets an assessment
  taken seriously.
- Missing HSTS on an API with no browser clients.

## How to decide
Ask who the clients are. A payment endpoint and an internal metrics scraper
warrant different verdicts on identical cipher output. `list_hosts` tells you what
the service is; `web.http_headers` and the screenshots tell you whether a browser
ever talks to it.

Group the low-value ones into a single hardening finding rather than filing eight.
