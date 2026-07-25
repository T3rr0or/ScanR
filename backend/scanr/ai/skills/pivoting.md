---
name: pivoting
description: Turning one compromised host into reach across the network, within scope.
---
# Lateral movement

## Scope is enforced, not advisory
Every target-taking tool checks the scan's scope in code. A refusal is not an
obstacle to route around; it means the host is not authorised and the engagement
does not cover it. Note it and move on.

## Sequence
1. **Inventory what access you have.** Which credentials did the scan supply, and
   which did it discover (`services.kerberoastable`, `web.api_key_exposure`,
   `services.snmp_community`, `services.ftp_cleartext`)?
2. **Find where it is worth using.** `list_hosts` for hosts exposing 22, 445,
   3389, 5985 — those accept a credential. A host with only 9100 open does not.
3. **Confirm before claiming.** `run_plugin services.admin_share_access` or
   `services.winrm_access` proves the credential works there. Until one of those
   returns, reuse is a hypothesis.

## The sandbox
`run_command` gives a real shell, but its network reach depends on the run's
capabilities. Without target egress it reaches package mirrors only — use it for
local work (analysing collected data, offline cracking, building tooling), not for
scanning. `$SCANR_SCOPE` shows what is in scope; `$ALL_PROXY`, when set, is the
only route to it.

## Record the path
`note_write` the chain as you establish it: which credential, from which host, to
which host, proved by which check. That chain is the finding — individual
accesses are much less interesting than the route they form.
