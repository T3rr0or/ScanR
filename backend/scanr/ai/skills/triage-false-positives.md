---
name: triage-false-positives
description: Deciding whether a finding is real before it reaches a client report.
---
# Triage

The expensive mistake is not a missed finding, it is a confident wrong one. A
client who disproves your first finding stops reading the rest of the report.

## The questions, in order
1. **Did the check observe or infer?** Pattern-matched banners
   (`services.*_version`, `cve.cve_matcher`) infer from a version string, which
   is wrong whenever the vendor backports patches. Behavioural checks
   (`services.smb_null_session`, `services.ftp_anon`) observed something.
2. **Is the evidence in the finding sufficient to reproduce it?** If you cannot
   tell from `get_finding` what to re-run, neither can the client.
3. **Does the context change the severity?** A default credential on a
   management interface reachable only from an already-privileged VLAN is not
   the same finding as one on the perimeter. Say which you have.
4. **Can you demonstrate it?** `run_plugin` re-runs the exact check. For web
   issues `fetch_url` often settles it in one request.

## Proving a client-side issue
`browser_validate` loads a payload URL in a real browser and reports whether it
executed. Put `{CANARY}` where a marker belongs — ScanR substitutes a token it
generated, so the result is proof rather than your own claim:

    http://10.0.0.5/search?q=<script>alert('{CANARY}')</script>

Read the verdict carefully. `reflected` means the parameter came back in the
page and did nothing — that is the single most common false positive in web
scanning, not a finding. Only `proved` means script ran in the page's origin.
`inconclusive` means the browser could not load it; retry or say so, but never
report it as clean.

Pass `finding_id` when it proves out and the finding is marked verified, which
is what stops a reviewer having to re-test it.

## Reporting the verdict
`create_finding` is for things you established, not things you suspect. If a
check is probably right but unproven, say that in the evidence rather than
downgrading silently — "version string indicates vulnerable, not
behaviourally confirmed" is useful; a quiet medium is not.

## Do not
Do not mark something resolved because a host stopped answering. Unreachable is
not fixed.
