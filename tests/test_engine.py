import json
import tempfile
import unittest
from pathlib import Path

from socio.engine import analyze, load_events, parse_event


def event(event_id, source="auth-a", user="demo", ip="192.0.2.5",
          outcome="failure", event_type="authentication"):
    return {
        "event_id": event_id,
        "timestamp": "2026-10-17T08:00:00Z",
        "source": source,
        "event_type": event_type,
        "user": user,
        "src_ip": ip,
        "outcome": outcome,
    }


class ParsingTests(unittest.TestCase):
    def test_timezone_required(self):
        row = event("1")
        row["timestamp"] = "2026-10-17T08:00:00"
        with self.assertRaisesRegex(ValueError, "timezone"):
            parse_event(row, 1)

    def test_required_fields(self):
        with self.assertRaisesRegex(ValueError, "missing required field"):
            parse_event({"event_id": "x"}, 1)

    def test_wrong_field_type(self):
        row = event("1")
        row["user"] = 7
        with self.assertRaisesRegex(ValueError, "user must be a string"):
            parse_event(row, 1)

    def test_duplicate_ids_are_source_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            rows = [event("1", "a"), event("1", "a"), event("1", "b")]
            path.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )
            loaded, warnings = load_events(path)
            self.assertEqual(len(loaded), 2)
            self.assertEqual(len(warnings), 1)


class DetectionTests(unittest.TestCase):
    def test_five_failures_trigger_rule(self):
        events = [parse_event(event(str(i)), i + 1) for i in range(5)]
        self.assertEqual([alert.rule_id for alert in analyze(events)], ["SOCIO-AUTH-001"])

    def test_sources_do_not_cross_correlate(self):
        rows = [event(str(i), source=f"source-{i}") for i in range(5)]
        parsed = [parse_event(row, i + 1) for i, row in enumerate(rows)]
        self.assertEqual(analyze(parsed), [])

    def test_encoded_process_marker(self):
        row = event("p1", event_type="process_create", outcome="unknown")
        row["command_line"] = "powershell.exe -EncodedCommand EXAMPLE"
        alerts = analyze([parse_event(row, 1)])
        self.assertIn("SOCIO-PROC-001", [alert.rule_id for alert in alerts])


if __name__ == "__main__":
    unittest.main()
