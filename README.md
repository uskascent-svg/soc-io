# SOC-IO
**Security Operations Center — Investigation & Orchestration**

SOC-IO is an experimental, offline-first security-event triage toolkit for learning and authorized lab validation. It reads normalized JSONL events, applies transparent deterministic rules, optionally collects recent local Sysmon events on Windows, persists local analysis runs to SQLite, and includes a small synthetic rule-regression evaluation harness.

> **Safety status:** experimental prototype, not a production SIEM/SOC. Rule matches are investigation leads—not proof of compromise. The synthetic evaluation fixture is only a regression baseline and does not establish real-world detection accuracy.

## Quick start

Requirements: Python 3.10 or newer; runtime uses the standard library.

\`\`\`bash
PYTHONPATH=src python -m socio.cli examples/events.jsonl
PYTHONPATH=src python -m socio.cli examples/events.jsonl --json report.json
PYTHONPATH=src python -m socio.cli examples/events.jsonl --db ./data/soc-io.db --json report.json
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m socio.evaluation examples/evaluation_baseline.json --out evaluation-results.json
python -m compileall -q src tests
\`\`\`

Windows PowerShell:

\`\`\`powershell
$env:PYTHONPATH = "src"
python -m socio.cli examples/events.jsonl --db .\\data\\soc-io.db --json report.json
python -m unittest discover -s tests -v
python -m socio.evaluation examples/evaluation_baseline.json --out evaluation-results.json
\`\`\`

## Windows / Sysmon collection

Collection is opt-in and read-only; it requires Windows, PowerShell, and an already configured Sysmon installation.

\`\`\`powershell
$env:PYTHONPATH = "src"
python -m socio.cli --collect-sysmon --out .\\sysmon-events.jsonl --limit 500
python -m socio.cli .\\sysmon-events.jsonl --db .\\data\\soc-io.db --json .\\sysmon-report.json
\`\`\`

See [Windows/Sysmon guide](docs/WINDOWS_SYSMON_COLLECTION.md). Collection remains best-effort and must be compared with Event Viewer on an authorized lab host.

## Local persistence

\`--db PATH\` stores analysis-run metadata, event and alert JSON, and a local audit record in SQLite using a versioned schema and transaction. It is a single-user local feature, not a multi-user server or a security boundary. Protect the database as sensitive telemetry; see [persistence guide](docs/PERSISTENCE.md). Audit rows are protected against ordinary updates/deletes by SQLite triggers, not against a local administrator replacing the file.

## Detection baseline

Run \`PYTHONPATH=src python -m socio.evaluation examples/evaluation_baseline.json\` for a reproducible rule-case regression report. The fixture is tiny and synthetic; its metrics are not representative performance estimates and must not be marketed as accuracy.

## Dashboard

Open [dashboard/index.html](dashboard/index.html) locally and load a CLI-generated JSON report. It makes no network requests.

## Repository map

- \`src/socio/engine.py\` — parsing and deterministic triage.
- \`src/socio/cli.py\` — CLI, optional Sysmon collection, optional SQLite persistence.
- \`src/socio/windows.py\` — local Sysmon collection and normalization.
- \`src/socio/storage.py\` — versioned SQLite storage and local audit table.
- \`src/socio/evaluation.py\` — labeled synthetic rule-case evaluation harness.
- \`examples/evaluation_baseline.json\` — small labeled synthetic fixture.
- \`tests/\` — unit and regression tests.
- \`docs/\` — schema, runbooks, security model, collector and persistence guides.

## Roadmap

1. Validate real Windows/Sysmon collection against Event Viewer and document collection gaps.
2. Complete storage hardening, migration review, and backup/restore drills.
3. Integrate external OIDC and test issuer, audience, signature, expiry, key rotation, and roles.
4. Add multi-user cases only after authorization and tenant-isolation tests.
5. Expand the labeled evaluation set and publish reproducible metrics with explicit limitations.
6. Complete independent security review and operational hardening before any shared deployment.

## Security and responsible use

Use only synthetic data or telemetry you are authorized to analyze. Do not commit secrets or real logs. Authentication, OIDC, multi-user case management, production-grade audit integrity, and validated detection performance are not implemented. No production-readiness claim is made.
