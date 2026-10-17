# SOC-IO security model

## Intended use
Offline triage of synthetic or explicitly authorized lab events. Event payloads are parsed as data; the engine does not execute commands, contact endpoints, or perform response actions.

## Trust boundaries and current controls
- JSONL records are bounded by a maximum line size and total event count.
- Required fields and timezone-aware timestamps are validated.
- Invalid records are rejected with warnings instead of terminating the whole input stream.
- Duplicate IDs are scoped to the event source.
- Authentication-failure correlation is keyed by source, user, and source IP to avoid combining unrelated feeds.
- Detection is deterministic and explainable; severity is a label, not a probability.

## Not implemented
Authentication, authorization, tenant isolation, case API, database or migrations, durable audit storage, retention, backup/restore, rate limiting, deployment hardening, external OIDC, complete Sysmon schema coverage, ML training/evaluation, or validated detection performance.

## Deployment gates before shared use
1. Threat model and independent security review.
2. Real OIDC integration tests for signature, issuer, audience, expiry, key rotation, and claims.
3. Tenant-isolation tests for every database relation and API operation.
4. Reviewed database migrations and successful backup/restore drills.
5. Secrets management, TLS, network restrictions, rate limits, audit integrity, monitoring, and rollback.
6. Real Windows/Sysmon lab validation with versioned evidence.
7. Documented false-positive and false-negative evaluation against a labeled test set.
8. Incident-response procedures and human approval for any response action.

Do not expose a public API or claim production readiness until the relevant evidence has been reviewed.
