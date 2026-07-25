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

## Reporting the verdict
`create_finding` is for things you established, not things you suspect. If a
check is probably right but unproven, say that in the evidence rather than
downgrading silently — "version string indicates vulnerable, not
behaviourally confirmed" is useful; a quiet medium is not.

## Do not
Do not mark something resolved because a host stopped answering. Unreachable is
not fixed.
