# SOC-IO
**Security Operations Center — Investigation & Orchestration**

SOC-IO is an experimental, offline-first security-event triage toolkit for learning and authorized lab validation. It reads normalized JSONL events, applies transparent deterministic rules, and produces analyst-friendly terminal summaries and JSON reports. An explicitly invoked Windows collector can export recent local Sysmon records to the same normalized format.

> **Safety status:** experimental prototype, not a production SIEM/SOC. Rule matches are investigation leads—not proof of compromise. No validated ML model or detection-accuracy claim is made. Do not use this tool as the sole basis for incident decisions.

## Quick start

Requirements: Python 3.10 or newer. Runtime uses the Python standard library.

\`\`\`bash
# From the repository root
PYTHONPATH=src python -m socio.cli examples/events.jsonl
PYTHONPATH=src python -m socio.cli examples/events.jsonl --json report.json
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
\`\`\`

Windows PowerShell:

\`\`\`powershell
$env:PYTHONPATH = "src"
python -m socio.cli examples/events.jsonl
python -m socio.cli examples/events.jsonl --json report.json
python -m unittest discover -s tests -v
\`\`\`

## Optional Windows / Sysmon collection

Collection is opt-in and read-only. It requires Windows, PowerShell, and an already configured Sysmon installation with the Operational log enabled. It does not install Sysmon, change policy, collect remotely, or execute event content.

\`\`\`powershell
$env:PYTHONPATH = "src"
python -m socio.cli --collect-sysmon --out .\\sysmon-events.jsonl --limit 500
python -m socio.cli .\\sysmon-events.jsonl --json .\\sysmon-report.json
\`\`\`

The limit is 1–5000 records (default 500). See [Windows/Sysmon collection guide](docs/WINDOWS_SYSMON_COLLECTION.md) for permissions, field coverage, safe handling of sensitive telemetry, and the validation checklist. A successful export alone does not establish completeness or detection accuracy.

## Current capabilities

- Bounded JSONL ingestion with malformed-record warnings.
- ISO-8601 timestamp and required-field validation.
- Source-scoped event-ID deduplication.
- Deterministic triage rules for repeated authentication failures, encoded command-line indicators, and endpoint security detections.
- Explicitly invoked local Windows/Sysmon export with a bounded record count, timeout, output-size guard, and normalized JSONL output.
- Severity-labelled terminal output and JSON report export.
- Local analyst dashboard for searching/filtering a JSON report and exporting filtered alerts.
- Analyst triage runbook, normalized event schema, and rule catalog.
- Synthetic sample events and regression tests.
- GitHub Actions CI for compile checks, tests, and a sample CLI run.

## Analyst dashboard

Open [dashboard/index.html](dashboard/index.html) directly in a browser. Use **Load JSON report** to select a report exported by the CLI. The dashboard supports search, severity/rule filters, evidence/recommendation details, and filtered JSON export. It runs locally in the browser and makes no network requests. Treat loaded reports as sensitive if they contain real telemetry.

## Input schema

Each non-empty JSONL line must be a JSON object with required \`event_id\`, \`timestamp\` (timezone-aware ISO-8601), \`source\`, and \`event_type\`. Optional fields include \`host\`, \`user\`, \`outcome\`, \`src_ip\`, \`process\`, \`command_line\`, \`file_hash\`, \`destination\`, and \`message\`. See [synthetic events](examples/events.jsonl) and [event schema](docs/EVENT_SCHEMA.md).

## Repository map

- \`src/socio/engine.py\` — parsing, rule evaluation, report generation.
- \`src/socio/cli.py\` — command-line entry point.
- \`src/socio/windows.py\` — opt-in Windows/Sysmon collector and normalization.
- \`dashboard/index.html\` — local report viewer.
- \`tests/\` — unit and regression tests.
- \`examples/\` — synthetic JSONL events.
- \`docs/WINDOWS_SYSMON_COLLECTION.md\` — collector setup and validation.
- \`docs/ANALYST_RUNBOOK.md\` — investigation and case-note workflow.
- \`docs/RULE_CATALOG.md\` — current rule behavior and limitations.
- \`docs/EVENT_SCHEMA.md\` — input schema and parser behavior.
- \`docs/SECURITY_MODEL.md\` — trust boundaries and deployment gates.
- \`.github/workflows/ci.yml\` — automated CI.
- \`SECURITY.md\` — responsible reporting guidance.

## Roadmap

1. Validate Windows/Sysmon ingestion in an authorized lab against Event Viewer, documenting OS/Sysmon versions, field coverage, skipped records, and collection gaps.
2. Add durable persistence and migrations with threat modelling, access controls, retention, and tested backup/restore.
3. Integrate external OIDC with signature, issuer, audience, expiry, key-rotation, and role checks before enabling shared access.
4. Add multi-user cases only after identity, authorization, tenant isolation, and audit integrity are tested.
5. Build a labeled, versioned detection evaluation dataset; publish reproducible precision, recall, false-positive/negative rates, and latency with limitations before making performance claims.
6. Complete security review, monitoring, rate limits, deployment hardening, and incident-response procedures before any shared deployment.

## Security and responsible use

Use only synthetic data or telemetry you are authorized to analyze. Do not commit secrets, access tokens, private keys, or sensitive logs. See [SECURITY.md](SECURITY.md) and the security model.

**Production readiness is not claimed.** The collector is best-effort and manual, not a continuous forwarder. Authentication, authorization, multi-user case management, durable audit storage, external OIDC validation, complete Sysmon coverage, and validated detection performance are not implemented in this starter.
