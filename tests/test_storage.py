import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from socio.engine import analyze, make_report, parse_event
from socio.storage import connect_database, persist_run


class SQLitePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "soc-io.db"

    def sample(self):
        rows = []
        for i in range(5):
            rows.append(parse_event({
                "event_id": str(i), "timestamp": f"2026-10-17T08:0{i}:00Z",
                "source": "test-auth", "event_type": "authentication",
                "user": "analyst-test", "src_ip": "192.0.2.8", "outcome": "failure",
            }, i + 1))
        alerts = analyze(rows)
        return rows, alerts, make_report(rows, alerts, [])

    def test_migration_and_persist_run(self):
        events, alerts, report = self.sample()
        with connect_database(self.path) as db:
            run_id = persist_run(db, input_source="synthetic-test", events=events,
                                 alerts=alerts, warnings=[], report=report)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 5)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT run_id FROM analysis_runs").fetchone()[0], run_id)
            self.assertEqual(db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0], 1)

    def test_migration_is_idempotent(self):
        with connect_database(self.path):
            pass
        with connect_database(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 1)

    def test_audit_log_rows_are_append_only(self):
        with connect_database(self.path) as db:
            db.execute("""INSERT INTO audit_log
                (occurred_at, actor, action, object_type, object_id, details_json)
                VALUES ('now','test','test','test','1','{}')""")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                db.execute("UPDATE audit_log SET actor='changed' WHERE object_id='1'")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                db.execute("DELETE FROM audit_log WHERE object_id='1'")

    def test_database_rejects_future_schema(self):
        with connect_database(self.path) as db:
            db.execute("UPDATE schema_migrations SET version=999")
        with self.assertRaisesRegex(RuntimeError, "newer than supported"):
            connect_database(self.path)


if __name__ == "__main__":
    unittest.main()
