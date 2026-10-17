# SOC-IO security model

## Intended use

Offline triage of synthetic or explicitly authorized lab events. Event payloads are parsed as data; the engine does not execute commands, contact endpoints, or perform response actions. The optional Windows collector only reads the local Sysmon Operational log when explicitly invoked.

## Trust boundaries and current controls

- JSONL records are bounded and validated; malformed records are skipped with warnings.
- Duplicate IDs are scoped to source.
- Detection is deterministic and explainable; severity is a label, not a probability.
- Sysmon collection is local, opt-in, read-only, bounded to 1–5000 records, with a 60-second timeout and 20 MB output cap.
- Optional SQLite storage uses schema versioning, transactions, foreign keys, and append-only-by-trigger audit rows for ordinary database operations.
- SQLite is local single-user persistence only; a local administrator can modify or replace the database. It is not cryptographically tamper-evident.

## Not implemented

External OIDC, authentication/authorization, tenant isolation, multi-user case API, encryption at rest within the app, remote collection, continuous streaming, guaranteed event completeness, immutable external audit sink, backup automation, complete Sysmon coverage, representative detection evaluation, or validated detection performance.

## Deployment gates before shared use

1. Threat model and independent security review.
2. Real OIDC integration tests for signature, issuer, audience, expiry, key rotation, and claims.
3. Tenant-isolation tests for every database relation and API operation.
4. Reviewed migrations and successful backup/restore drills.
5. Secrets management, TLS, network restrictions, rate limits, audit integrity, monitoring, and rollback.
6. Windows/Sysmon validation against Event Viewer with versioned evidence and documented collection gaps.
7. Reproducible detection evaluation against a sufficiently representative, independently labeled dataset.
8. Incident-response procedures and human approval for response actions.

Do not expose a public API or claim production readiness until relevant evidence has been reviewed.
