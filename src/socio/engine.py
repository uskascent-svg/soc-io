"""Bounded, offline-first security event parsing and deterministic triage rules."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

MAX_LINE_BYTES = 1_000_000
MAX_EVENTS = 100_000
MAX_FIELD_LENGTH = 16_384
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    host: str = "unknown"
    user: str = "unknown"
    outcome: str = "unknown"
    src_ip: str = ""
    process: str = ""
    command_line: str = ""
    file_hash: str = ""
    destination: str = ""
    message: str = ""


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: str
    summary: str
    event_ids: tuple[str, ...]
    entities: dict[str, str]
    recommendations: tuple[str, ...]
    limitations: tuple[str, ...]


def _string(row: dict[str, Any], key: str, default: str = "") -> str:
    value = row.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError(f"{key} exceeds maximum field length")
    return value.strip()


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def parse_event(row: Any, line_number: int) -> Event:
    if not isinstance(row, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")
    for key in ("event_id", "timestamp", "source", "event_type"):
        if key not in row:
            raise ValueError(f"line {line_number}: missing required field {key}")
    event_id = _string(row, "event_id")
    source = _string(row, "source")
    event_type = _string(row, "event_type").lower()
    if not event_id or not source or not event_type:
        raise ValueError(f"line {line_number}: required strings cannot be empty")
    return Event(
        event_id[:256],
        parse_timestamp(row["timestamp"]),
        source[:256],
        event_type[:128],
        _string(row, "host", "unknown")[:256] or "unknown",
        _string(row, "user", "unknown")[:256] or "unknown",
        _string(row, "outcome", "unknown").lower()[:64],
        _string(row, "src_ip")[:256],
        _string(row, "process")[:1024],
        _string(row, "command_line"),
        _string(row, "file_hash").lower()[:256],
        _string(row, "destination")[:1024],
        _string(row, "message")[:4096],
    )


def load_events(path: Path) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    try:
        with path.open("rb") as stream:
            for line_number, raw in enumerate(stream, 1):
                if len(raw) > MAX_LINE_BYTES:
                    warnings.append(f"line {line_number}: oversized record rejected")
                    continue
                if not raw.strip():
                    continue
                if len(events) >= MAX_EVENTS:
                    warnings.append(f"event limit ({MAX_EVENTS}) reached")
                    break
                try:
                    event = parse_event(json.loads(raw.decode("utf-8")), line_number)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    warnings.append(f"line {line_number}: rejected record ({exc})")
                    continue
                key = (event.source, event.event_id)
                if key in seen:
                    warnings.append(f"line {line_number}: duplicate source/event_id ignored")
                    continue
                seen.add(key)
                events.append(event)
    except OSError as exc:
        raise RuntimeError(f"cannot read event file: {exc}") from exc
    events.sort(key=lambda item: (item.timestamp, item.source, item.event_id))
    return events, warnings


def _make_alert(rule_id: str, title: str, severity: str, summary: str,
                events: list[Event], recommendations: tuple[str, ...]) -> Alert:
    evidence = "|".join(f"{event.source}:{event.event_id}" for event in events)
    alert_id = hashlib.sha256(f"{rule_id}|{evidence}".encode()).hexdigest()[:16]
    first = events[0]
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        title=title,
        severity=severity,
        summary=summary,
        event_ids=tuple(event.event_id for event in events),
        entities={
            "host": first.host,
            "user": first.user,
            "source": first.source,
            "src_ip": first.src_ip or "unknown",
        },
        recommendations=recommendations,
        limitations=(
            "Heuristic match; verify source telemetry and surrounding activity.",
            "A match is not proof of compromise; a non-match does not prove safety.",
        ),
    )


def analyze(events: list[Event]) -> list[Alert]:
    """Apply explainable rules to normalized events; never execute event content."""
    alerts: list[Alert] = []
    groups: dict[tuple[str, str, str], list[Event]] = {}
    for event in events:
        if event.event_type in {"authentication", "login", "auth"} and event.outcome in {
            "failure", "failed", "denied"
        }:
            groups.setdefault((event.source, event.user, event.src_ip), []).append(event)

    for (source, user, ip), failures in groups.items():
        failures.sort(key=lambda event: event.timestamp)
        cluster: list[Event] = []
        cluster_start: datetime | None = None
        clusters: list[list[Event]] = []
        for failure in failures:
            if cluster_start is None or failure.timestamp - cluster_start <= timedelta(minutes=10):
                if cluster_start is None:
                    cluster_start = failure.timestamp
                cluster.append(failure)
            else:
                clusters.append(cluster)
                cluster = [failure]
                cluster_start = failure.timestamp
        if cluster:
            clusters.append(cluster)
        for window in clusters:
            if len(window) >= 5:
                alerts.append(_make_alert(
                    "SOCIO-AUTH-001",
                    "Repeated authentication failures",
                    "high",
                    f"{len(window)} failed authentication events for {user} from {ip or 'unknown IP'} in source {source} within a 10-minute window.",
                    window[:20],
                    (
                        "Validate whether activity is expected.",
                        "Review successful logins and MFA outcomes.",
                        "Follow approved incident-response procedures.",
                    ),
                ))

    for event in events:
        text = f"{event.process} {event.command_line} {event.message}".lower()
        if event.event_type in {"process_create", "process", "sysmon_process_create"} and any(
            marker in text for marker in ("-enc ", "-encodedcommand", "frombase64string")
        ):
            alerts.append(_make_alert(
                "SOCIO-PROC-001",
                "Encoded command-line indicator",
                "medium",
                "A process event contains a command-line marker associated with encoded execution.",
                [event],
                (
                    "Inspect process tree and parent process.",
                    "Analyze content only in an isolated environment.",
                    "Confirm whether this is approved administration.",
                ),
            ))
        if event.event_type in {"malware", "av_detection", "antivirus_detection"}:
            alerts.append(_make_alert(
                "SOCIO-AV-001",
                "Endpoint security detection event",
                "high",
                "The source event reports an endpoint security detection.",
                [event],
                (
                    "Review vendor detection evidence.",
                    "Check host timeline and containment status.",
                    "Follow the approved response playbook.",
                ),
            ))

    return sorted(alerts, key=lambda alert: (
        -SEVERITY_RANK[alert.severity], alert.rule_id, alert.alert_id
    ))


def make_report(events: list[Event], alerts: list[Alert], warnings: list[str]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "offline-deterministic-triage",
        "summary": {
            "events_loaded": len(events),
            "alerts_generated": len(alerts),
            "warnings": len(warnings),
        },
        "alerts": [asdict(alert) for alert in alerts],
        "warnings": warnings,
        "limitations": [
            "Not a production SIEM or validated ML model.",
            "Severity labels are not probabilities.",
            "Missing telemetry can cause missed detections.",
        ],
    }
