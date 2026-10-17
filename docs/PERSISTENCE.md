# Persistence and local audit log

SOC-IO supports optional local SQLite persistence for completed analysis runs. This is intended for a single analyst on a trusted local machine, not as a shared service or security boundary.

## Use

\`\`\`powershell
$env:PYTHONPATH = "src"
python -m socio.cli examples/events.jsonl --db .\\data\\soc-io.db --json report.json
\`\`\`

The database stores analysis-run metadata and report JSON, normalized event JSON, alert JSON, and an append-only-by-trigger local audit table. Schema versioning is tracked in \`schema_migrations\`; migrations currently initialize version 1. SQLite foreign keys and WAL mode are enabled. Run persistence uses a transaction.

## Operational controls and limitations

- Keep the database on an access-controlled local volume; it may contain sensitive command lines, usernames, hostnames, IPs, and alert evidence.
- Exclude database, WAL, and SHM files from Git. Never use real telemetry in public issues.
- Back up the database using SQLite's supported backup mechanism or a consistent offline copy. Periodically test restoration and document retention/deletion requirements.
- The audit table has local triggers preventing UPDATE and DELETE through ordinary SQL. This is not tamper-proof against a local administrator or someone who can replace the database file.
- No encryption-at-rest layer is provided by SOC-IO; use approved OS/storage controls.
- There is no authenticated API, multi-user access, tenant isolation, remote database, or role-based authorization. Do not put this database on a shared network path or expose it as a service.
- Future schema changes must add explicit migrations and migration tests; do not silently edit existing schema assumptions.

This persistence step is not a production-readiness claim.
