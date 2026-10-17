# Windows / Sysmon collection (experimental)

SOC-IO includes an explicitly invoked, read-only local collector for authorized Windows lab machines. It queries the existing \`Microsoft-Windows-Sysmon/Operational\` log through \`Get-WinEvent\`; it does not install/configure Sysmon, change system policy, collect remotely, or take response actions.

## Requirements

- Windows 10/11 or Windows Server with PowerShell and Sysmon already installed and logging enabled.
- Python 3.10+.
- Permission to read the Sysmon Operational event log. If access is denied, use an approved elevated terminal; do not weaken host policy to make the collector work.
- Test only on systems and telemetry you are authorized to access.

## Run

From the repository root in PowerShell:

\`\`\`powershell
$env:PYTHONPATH = "src"
python -m socio.cli --collect-sysmon --out .\\sysmon-events.jsonl --limit 500
python -m socio.cli .\\sysmon-events.jsonl --json .\\sysmon-report.json
python -m unittest discover -s tests -v
\`\`\`

Collection is opt-in; the ordinary JSONL analysis command never starts a collector. \`--limit\` must be 1–5000 (default 500). The collector has a 60-second process timeout and 20 MB response limit. The output file may include sensitive usernames, command lines, file paths, hostnames, and IP addresses. Store it securely and do not commit real telemetry.

## Normalization coverage

The collector maps Sysmon Event IDs 1 (process creation), 3 (network connection), 7 (image load), 10 (process access), 11 (file creation), and 22 (DNS query) to normalized event types. Other IDs are preserved as \`sysmon_event_<id>\` so source coverage is not silently misrepresented. Event IDs are source record identifiers, not detection verdicts. Fields absent from an event remain empty/default values.

The current deterministic rules only inspect fields they explicitly support. For example, Event ID 1 can feed the encoded-command heuristic; adding a collector does not imply detection coverage for all Sysmon event types.

## Validation checklist

1. Confirm Sysmon is installed and the Operational log exists.
2. Run with a small limit (e.g. 20) in an authorized lab.
3. Verify output is valid UTF-8 JSONL and each timestamp is timezone-aware.
4. Compare several records with Event Viewer XML, checking host, record ID, event ID, timestamp, image, command line, user, and network fields where present.
5. Run the existing unit tests and inspect reports.
6. Record OS build, Sysmon version/configuration, collection time range, skipped records, and field gaps before treating a lab run as validated.

## Limitations

This is a best-effort prototype, not a Windows service or real-time forwarder. It polls recent records when manually invoked; it does not provide continuous streaming, remote collection, checkpointing, guaranteed completeness, event-log retention guarantees, or tamper-resistant collection. PowerShell / Sysmon availability and permissions vary. No production-readiness or detection-accuracy claim is made.
