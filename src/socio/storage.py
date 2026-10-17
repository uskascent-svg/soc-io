"""Local SQLite persistence for offline SOC-IO runs.

This is single-user local storage, not a multi-user service. It intentionally
has no authentication or network listener. Database files may contain sensitive
security telemetry and must be protected by the operating system.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

SCHEMA_VERSION = 1


def connect_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = WAL")
    migrate(connection)
    return connection


def migrate(connection: sqlite3.Connection) -> None:
    """Apply idempotent, versioned schema migrations transactionally."""
    connection.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    row = connection.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
    current = row["version"] or 0
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current} is newer than supported {SCHEMA_VERSION}"
        )
    if current < 1:
        with connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    input_source TEXT NOT NULL,
                    event_count INTEGER NOT NULL CHECK (event_count >= 0),
                    alert_count INTEGER NOT NULL CHECK (alert_count >= 0),
                    warning_count INTEGER NOT NULL CHECK (warning_count >= 0),
                    report_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL REFERENCES analysis_runs(run_id),
                    source TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    UNIQUE(run_id, source, event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_events_source_time
                    ON events(source, timestamp);
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL REFERENCES analysis_runs(run_id),
                    alert_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    alert_json TEXT NOT NULL,
                    UNIQUE(run_id, alert_id)
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_rule_severity
                    ON alerts(rule_id, severity);
                CREATE TABLE IF NOT EXISTS audit_log (
                    audit_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS audit_log_no_update
                BEFORE UPDATE ON audit_log BEGIN
                    SELECT RAISE(ABORT, 'audit log rows are append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
                BEFORE DELETE ON audit_log BEGIN
                    SELECT RAISE(ABORT, 'audit log rows are append-only');
                END;
            """)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (1, datetime.now(timezone.utc).isoformat()),
            )


def persist_run(
    connection: sqlite3.Connection,
    *,
    input_source: str,
    events: list[Any],
    alerts: list[Any],
    warnings: list[str],
    report: dict[str, Any],
) -> int:
    """Persist one completed analysis atomically and append a run audit record."""
    now = datetime.now(timezone.utc).isoformat()
    with connection:
        cursor = connection.execute(
            """INSERT INTO analysis_runs
               (created_at, input_source, event_count, alert_count, warning_count, report_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now, input_source, len(events), len(alerts), len(warnings),
             json.dumps(report, ensure_ascii=False, sort_keys=True)),
        )
        run_id = int(cursor.lastrowid)
        for event in events:
            row = asdict(event)
            row["timestamp"] = event.timestamp.isoformat()
            connection.execute(
                """INSERT INTO events(run_id, source, event_id, timestamp, event_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (run_id, event.source, event.event_id, event.timestamp.isoformat(),
                 json.dumps(row, ensure_ascii=False, sort_keys=True)),
            )
        for alert in alerts:
            row = asdict(alert)
            connection.execute(
                """INSERT INTO alerts(run_id, alert_id, rule_id, severity, alert_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (run_id, alert.alert_id, alert.rule_id, alert.severity,
                 json.dumps(row, ensure_ascii=False, sort_keys=True)),
            )
        connection.execute(
            """INSERT INTO audit_log
               (occurred_at, actor, action, object_type, object_id, details_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now, "local-cli", "analysis.persisted", "analysis_run", str(run_id),
             json.dumps({"events": len(events), "alerts": len(alerts),
                         "warnings": len(warnings)}, sort_keys=True)),
        )
    return run_id
