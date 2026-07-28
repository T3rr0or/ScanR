---
name: web-authentication
description: Testing login, session and access-control behaviour on a discovered web app.
---
# Web authentication and access control

## Order
1. Map before touching: `fetch_url` the root, then the paths
   `web.dir_bruteforce` and `web.swagger_openapi_exposure` already found. The
   scan usually knows more about the app than a fresh crawl would.
2. Read the auth surface: login form, cookie flags
   (`web.cookie_security`), JWT structure (`web.jwt_misconfig`), OAuth/OIDC
   endpoints (`web.oauth_oidc_misconfig`), SAML metadata.
3. Only then try anything active.

## What is worth proving
- **Broken access control** is the highest-yield class and the one scanners miss.
  Two accounts, or one account and an object id from another: request the second
  user's resource with the first user's session. A 200 with the other user's data
  is the finding; a 302 to login is not.
- **Session fixation / weak logout** — does the session id change on
  authentication? Does logout invalidate server-side or just drop the cookie?
- **JWT** — `alg: none`, HMAC-vs-RSA confusion, missing `exp`, or a secret weak
  enough to brute force. `web.jwt_misconfig` flags the shape; confirm by forging
  one and using it.

## Credentials
`submit_form` is intrusive and approval-gated for a reason. Never spray. If the
scan supplied credentials, use those. If it did not, do not guess at production
accounts — say so and move on.

## Evidence
An access-control finding needs the request, the session it was made with, and
the response showing data that session should not see. Without all three it is an
assertion, and a client will reject it.
