# Trusted certificates

Place extra CA certificates here (PEM). This folder is mounted read-only into
the scan worker at `/app/certs`.

**Authenticated LDAP.** ScanR only binds to domain controllers over LDAPS or
StartTLS and always validates the certificate. If your DCs use certificates
from an internal CA (for example AD CS), save that root (and any
intermediates) as `certs/ldap-ca.pem` and set in `.env`:

```dotenv
LDAP_CA_FILE=/app/certs/ldap-ca.pem
```

Then restart: `docker compose up -d scan-worker`.
