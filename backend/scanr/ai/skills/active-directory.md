---
name: active-directory
description: Working a Windows domain — what the AD findings actually chain into, and the order to try them.
---
# Active Directory

ScanR's AD plugins report conditions. This is what they chain into.

## Read the ground first
`list_findings` then `list_hosts`. A domain controller usually shows 88 (Kerberos),
389/636 (LDAP), 445 (SMB) together — that combination is the DC, and it is the
objective. Everything else is a route to it.

## The chains that matter
- **`services.zerologon`** — DC takeover outright. Nothing else is worth doing
  first. It is also destructive to the machine account, so it needs the
  exploitation capability and an explicit decision, not a reflex.
- **`services.dcsync_check`** — the account can replicate directory secrets. Game
  over for the domain; confirm which principal holds it.
- **`services.kerberoastable` / `services.asreproastable`** — offline crackable
  credentials. Value depends entirely on password policy: check
  `services.ad_password_policy` before claiming these are high impact. An
  8-character minimum with no lockout is a different finding from a 20-character
  one.
- **`services.smb_signing` / `services.ldap_signing` /
  `services.ldap_channel_binding` off** — relay. Alone it is a hardening gap; with
  `services.llmnr_nbns_check` it is a practical path to authenticated access,
  because you can coerce the authentication you relay.
- **`services.unconstrained_delegation`** — a host that can impersonate anyone who
  authenticates to it. Pair it with a coercion primitive and it is a DC compromise.
- **`services.adcs_enum`** — certificate templates are the quiet route to domain
  admin. Check which templates allow enrollee-supplied subjects.

## What to write down
Use `note_write` for: the domain name and DC IPs, which principals hold which
rights, and the password policy. Every later step depends on those, and
re-deriving them wastes turns.

## Be honest about proof
Roastable accounts are *not* compromised credentials until something cracks. Say
"crackable offline" and record the policy that decides how likely that is. Do not
report a hash as access.
