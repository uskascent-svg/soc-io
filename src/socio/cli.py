"""SOC-IO command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from socio.engine import analyze, load_events, make_report
from socio.storage import connect_database, persist_run
from socio.windows import collect_sysmon_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SOC-IO offline security-event triage prototype"
    )
    parser.add_argument("events", type=Path, nargs="?",
                        help="JSONL file of normalized events (omit only with --collect-sysmon)")
    parser.add_argument("--json", dest="output", type=Path,
                        help="write a full JSON analysis report to this path")
    parser.add_argument("--db", type=Path,
                        help="persist this analysis to a local SQLite database (single-user prototype)")
    parser.add_argument("--collect-sysmon", action="store_true",
                        help="explicitly query the local Windows Sysmon Operational log (read-only)")
    parser.add_argument("--out", type=Path,
                        help="destination JSONL path for --collect-sysmon output")
    parser.add_argument("--limit", type=int, default=500,
                        help="maximum Sysmon records to collect (1–5000; default: 500)")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.collect_sysmon:
        if args.events is not None:
            print("socio: do not supply an input events file with --collect-sysmon", file=sys.stderr)
            return 2
        if args.out is None:
            print("socio: --collect-sysmon requires --out PATH", file=sys.stderr)
            return 2
        try:
            rows = collect_sysmon_events(args.limit)
            payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
            args.out.write_text(payload, encoding="utf-8", newline="\n")
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"socio: collection failed: {exc}", file=sys.stderr)
            return 2
        print(f"SOC-IO | source=windows-sysmon | events_written={len(rows)} | output={args.out}")
        print("Reminder: collection is best-effort; validate coverage against Event Viewer.")
        return 0

    if args.events is None:
        print("socio: provide an events JSONL path or use --collect-sysmon --out PATH", file=sys.stderr)
        return 2
    if args.out is not None:
        print("socio: --out is only valid with --collect-sysmon", file=sys.stderr)
        return 2

    try:
        events, warnings = load_events(args.events)
        alerts = analyze(events)
        result = make_report(events, alerts, warnings)
        run_id = None
        if args.db:
            with connect_database(args.db) as connection:
                run_id = persist_run(connection, input_source=str(args.events), events=events,
                                     alerts=alerts, warnings=warnings, report=result)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"socio: error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        try:
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"socio: cannot write report: {exc}", file=sys.stderr)
            return 2

    print(f"SOC-IO | events={len(events)} | alerts={len(alerts)} | warnings={len(warnings)}")
    for alert in alerts:
        print(f"[{alert.severity.upper():8}] {alert.rule_id} {alert.title} — {alert.summary}")
    if args.output:
        print(f"JSON report written to: {args.output}")
    if run_id is not None:
        print(f"SQLite run persisted: run_id={run_id} | database={args.db}")
    print("Reminder: triage results are heuristic leads, not proof of compromise.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
