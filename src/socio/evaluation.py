"""Run a reproducible rule-level regression baseline against labeled synthetic cases.

Metrics describe this tiny fixture only; they are not estimates of real-world
detection performance.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from socio.engine import analyze, parse_event


def evaluate(dataset: dict[str, Any]) -> dict[str, Any]:
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("dataset must contain a non-empty cases list")
    tp = fp = fn = tn = 0
    details = []
    rules: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("events"), list):
            raise ValueError("each case must contain an events list")
        expected = set(case.get("expected_rules", []))
        parsed = [parse_event(row, index + 1) for index, row in enumerate(case["events"])]
        predicted = {alert.rule_id for alert in analyze(parsed)}
        rules.update(expected | predicted)
        case_tp = expected & predicted
        case_fp = predicted - expected
        case_fn = expected - predicted
        tp += len(case_tp)
        fp += len(case_fp)
        fn += len(case_fn)
        tn += len(rules - (expected | predicted))
        details.append({
            "case_id": case.get("id", "unnamed"),
            "expected_rules": sorted(expected),
            "predicted_rules": sorted(predicted),
            "true_positive_rules": sorted(case_tp),
            "false_positive_rules": sorted(case_fp),
            "false_negative_rules": sorted(case_fn),
        })
    # TN is computed across the final rule universe so all cases share a denominator.
    rule_universe = set(rules)
    tn = sum(len(rule_universe - (set(c.get("expected_rules", [])) |
                                 set(d["predicted_rules"])))
             for c, d in zip(cases, details))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "schema_version": "1.0",
        "dataset_description": dataset.get("description", "unspecified"),
        "case_count": len(cases),
        "rule_universe": sorted(rule_universe),
        "confusion_counts_rule_case": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": {"precision": round(precision, 4), "recall": round(recall, 4),
                    "f1": round(f1, 4)},
        "cases": details,
        "limitations": dataset.get("limitations", []) + [
            "Metrics are rule-case counts on this specific dataset, not event-level or production estimates.",
            "Dataset size and synthetic construction do not support claims about generalization.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, nargs="?",
                        default=Path("examples/evaluation_baseline.json"))
    parser.add_argument("--out", type=Path, help="optional JSON results output")
    args = parser.parse_args()
    try:
        dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
        result = evaluate(dataset)
        rendered = json.dumps(result, indent=2) + "\n"
        if args.out:
            args.out.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
