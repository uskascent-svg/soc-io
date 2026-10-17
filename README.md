# SOC-IO
**Security Operations Center — Investigation & Orchestration**

SOC-IO is an experimental, offline-first security-event triage toolkit for learning and authorized lab validation. It reads normalized JSONL events, applies transparent deterministic rules, and produces analyst-friendly terminal summaries and JSON reports.

> **Safety status:** experimental prototype, not a production SIEM/SOC. Rule matches are investigation leads—not proof of compromise. No validated ML model or detection-accuracy claim is made. Do not use this tool as the sole basis for incident decisions.

## Quick start

Requirements: Python 3.10 or newer. Runtime uses the Python standard library.

```bash
# From the repository root
PYTHONPATH=src python -m socio.cli examples/events.jsonl

# Export a structured report
PYTHONPATH=src python -m socio.cli examples/events.jsonl --json report.json

# Run the test suite
PYTHONPATH=src python -m unittest discover -s tests -v

# Compile-check the project
python -m compileall -q src tests
```

Windows PowerShell:
```powershell
$env:PYTHONPATH = "src"
python -m socio.cli examples/events.jsonl
python -m socio.cli examples/events.jsonl --json report.json
python -m unittest discover -s tests -v
```

## Current capabilities

- Bounded JSONL ingestion with malformed-record warnings.
- ISO-8601 timestamp and required-field validation.
- Source-scoped event-ID deduplication.
- Deterministic triage rules for repeated authentication failures, encoded command-line indicators, and endpoint security detections.
- Severity-labelled terminal output and JSON report export.
- Local analyst dashboard for searching/filtering a JSON report and exporting filtered alerts.
- Analyst triage runbook, normalized event schema, and rule catalog.
- Synthetic sample events and regression tests.
- GitHub Actions CI for compile checks, tests, and a sample CLI run.

## Analyst dashboard

Open [dashboard/index.html](dashboard/index.html) directly in a browser. Use **Load JSON report** to select a report exported by the CLI. The dashboard supports search, severity/rule filters, evidence/recommendation details, and filtered JSON export. It runs locally in the browser and makes no network requests. Treat loaded reports as sensitive if they contain real telemetry.

## Input schema

Each non-empty JSONL line must be a JSON object with:

- Required: `event_id`, `timestamp` (timezone-aware ISO-8601), `source`, `event_type`.
- Optional: `host`, `user`, `outcome`, `src_ip`, `process`, `command_line`, `file_hash`, `destination`, `message`.

See [examples/events.jsonl](examples/events.jsonl). All example data is synthetic and uses documentation-only IP addresses. Full details: [event schema](docs/EVENT_SCHEMA.md).

## Repository map

- `src/socio/engine.py` — parsing, rule evaluation, report generation.
- `src/socio/cli.py` — command-line entry point.
- `dashboard/index.html` — local report viewer.
- `tests/` — unit and regression tests.
- `examples/` — synthetic JSONL events.
- `docs/ANALYST_RUNBOOK.md` — investigation and case-note workflow.
- `docs/RULE_CATALOG.md` — current rule behavior and limitations.
- `docs/EVENT_SCHEMA.md` — input schema and parser behavior.
- `docs/SECURITY_MODEL.md` — trust boundaries and deployment gates.
- `CONTRIBUTING.md` — contribution and testing guidance.
- `.github/workflows/ci.yml` — automated CI.
- `SECURITY.md` — responsible reporting guidance.

## Roadmap

1. Add versioned rules with test cases, severity rationale, false-positive notes, and documented evaluation.
2. Add a reviewed, explicitly opt-in Windows/Sysmon lab collector and host-side validation procedure.
3. Add case management only with a clear trust boundary, strong authorization, tenant isolation, and durable audit controls.
4. Add OIDC, PostgreSQL migrations, retention and backup/restore only after threat modelling and integration tests.
5. Add rate limits, monitoring, deployment hardening, and a labeled detection-evaluation dataset before any shared deployment.

## Security and responsible use

Use only synthetic data or telemetry you are authorized to analyze. Do not commit secrets, access tokens, private keys, or sensitive logs. See [SECURITY.md](SECURITY.md) and the security model.

**Production readiness is not claimed.** Authentication, authorization, multi-tenant case management, durable audit storage, migrations, external OIDC validation, full Sysmon coverage, and validated detection performance are not implemented in this starter.
