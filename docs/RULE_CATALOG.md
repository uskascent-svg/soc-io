# Rule catalog

The current rules are simple deterministic triage heuristics. They have not been validated against a representative labeled dataset; no accuracy or coverage claim is made.

| Rule ID | Trigger | Default label | Suggested analyst checks |
|---|---|---|---|
| SOCIO-AUTH-001 | At least five failed authentication/login events sharing source, user, and source IP within a 10-minute window | High | Verify source, time window, account context, MFA and subsequent successful logins |
| SOCIO-PROC-001 | Process event contains `-enc `, `-EncodedCommand`, or `FromBase64String` marker | Medium | Inspect parent/child process tree and authorized administration context |
| SOCIO-AV-001 | Event type is `malware`, `av_detection`, or `antivirus_detection` | High | Review original vendor alert, host timeline and vendor-specific evidence |

## Limitations
- Authentication correlation uses 10-minute clusters anchored at the first event in each cluster; events outside that window are separated.
- Rule inputs must be normalized into the documented event schema.
- Process marker matching is case-insensitive substring matching and can produce false positives.
- Source-specific event schemas and unknown event types are not comprehensively mapped.
- Severity is a rule label, not a probability or confidence score.
- A missing alert does not imply the absence of malicious activity.

## Change process
For each new or modified rule, include a stable rule ID, rationale, expected telemetry, false-positive considerations, analyst guidance, and positive/negative regression tests. Document rule behavior changes in the release notes.
