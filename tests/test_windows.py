import unittest
from unittest.mock import patch

from socio.windows import MAX_COLLECT_LIMIT, collect_sysmon_events, normalize_sysmon_record


class SysmonNormalizationTests(unittest.TestCase):
    def test_process_create_normalizes_for_existing_engine(self):
        row = normalize_sysmon_record({
            "RecordId": "42", "TimeCreatedUtc": "2026-10-18T01:02:03.0000000Z",
            "Computer": "LAB-WIN01", "EventId": 1,
            "Data": {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand EXAMPLE",
                "User": r"LAB\analyst", "Hashes": "SHA256=abc123",
            },
        })
        self.assertEqual(row["event_id"], "LAB-WIN01:42")
        self.assertEqual(row["source"], "windows-sysmon")
        self.assertEqual(row["event_type"], "process_create")
        self.assertIn("-EncodedCommand", row["command_line"])
        self.assertEqual(row["host"], "LAB-WIN01")

    def test_network_event_maps_destination(self):
        row = normalize_sysmon_record({
            "RecordId": "43", "TimeCreatedUtc": "2026-10-18T01:02:03Z",
            "Computer": "LAB-WIN01", "EventId": 3,
            "Data": {"DestinationIp": "203.0.113.8", "DestinationHostname": "example.invalid"},
        })
        self.assertEqual(row["event_type"], "network_connection")
        self.assertIn("203.0.113.8", row["destination"])

    def test_invalid_record_rejected(self):
        with self.assertRaises(ValueError):
            normalize_sysmon_record({"EventId": 1})

    def test_limit_is_bounded_before_platform_check(self):
        with self.assertRaisesRegex(ValueError, "between 1"):
            collect_sysmon_events(MAX_COLLECT_LIMIT + 1)

    @patch("socio.windows.sys.platform", "linux")
    def test_collection_is_platform_gated(self):
        with self.assertRaisesRegex(RuntimeError, "only on Windows"):
            collect_sysmon_events(1)


if __name__ == "__main__":
    unittest.main()
