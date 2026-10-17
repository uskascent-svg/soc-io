"""SOC-IO command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from socio.engine import analyze, load_events, make_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SOC-IO offline security-event triage prototype"
    )
    parser.add_argument("events", type=Path, help="JSONL file of normalized events")
    parser.add_argument(
        "--json", dest="output", type=Path,
        help="write a full JSON report to this path",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        events, warnings = load_events(args.events)
        alerts = analyze(events)
        result = make_report(events, alerts, warnings)
    except (RuntimeError, ValueError) as exc:
        print(f"socio: error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        try:
            args.output.write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            print(f"socio: cannot write report: {exc}", file=sys.stderr)
            return 2

    print(
        f"SOC-IO | events={len(events)} | alerts={len(alerts)} "
        f"| warnings={len(warnings)}"
    )
    for alert in alerts:
        print(
            f"[{alert.severity.upper():8}] {alert.rule_id} "
            f"{alert.title} — {alert.summary}"
        )
    if args.output:
        print(f"JSON report written to: {args.output}")
    print("Reminder: triage results are heuristic leads, not proof of compromise.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
