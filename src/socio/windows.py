"""Explicitly opt-in, read-only Windows Sysmon event collection.

This module only queries the local Sysmon Operational log. It does not install
Sysmon, change audit policy, contact remote hosts, or execute event content.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

MAX_COLLECT_LIMIT = 5000
MAX_OUTPUT_BYTES = 20_000_000
SOURCE = "windows-sysmon"

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational' } -MaxEvents __LIMIT__ -ErrorAction Stop | ForEach-Object {
    [xml]$xml = $_.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        if ($null -ne $item.Name) { $data[[string]$item.Name] = [string]$item.'#text' }
    }
    [pscustomobject]@{
        RecordId = [string]$_.RecordId
        TimeCreatedUtc = $_.TimeCreated.ToUniversalTime().ToString('o')
        Computer = [string]$_.MachineName
        EventId = [int]$_.Id
        Data = $data
    }
})
ConvertTo-Json -InputObject $events -Depth 6 -Compress
"""


def normalize_sysmon_record(record: Any) -> dict[str, str]:
    """Convert one PowerShell-exported Sysmon record into SOC-IO's schema."""
    if not isinstance(record, dict):
        raise ValueError("Sysmon record must be an object")
    try:
        event_number = int(record["EventId"])
        record_id = str(record["RecordId"]).strip()
        timestamp = str(record["TimeCreatedUtc"]).strip()
        host = str(record["Computer"]).strip() or "unknown"
        data = record.get("Data", {})
        if not isinstance(data, dict):
            raise ValueError("Sysmon Data must be an object")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid Sysmon record: {exc}") from exc
    if not record_id or not timestamp:
        raise ValueError("Sysmon record requires RecordId and TimeCreatedUtc")

    event_types = {
        1: "process_create", 3: "network_connection", 7: "image_load",
        10: "process_access", 11: "file_create", 22: "dns_query",
    }
    event_type = event_types.get(event_number, f"sysmon_event_{event_number}")
    image = str(data.get("Image", "") or "")
    command_line = str(data.get("CommandLine", "") or "")
    user = str(data.get("User", data.get("TargetUser", "")) or "unknown")
    src_ip = str(data.get("SourceIp", "") or "")
    destination = " ".join(
        value for value in (
            str(data.get("DestinationIp", "") or ""),
            str(data.get("DestinationHostname", "") or ""),
            str(data.get("QueryName", data.get("Query", "")) or ""),
            str(data.get("TargetFilename", "") or ""),
        ) if value
    )[:1024]
    hashes = str(data.get("Hashes", "") or "")
    message = f"Sysmon Event ID {event_number}; {str(data.get('Details', '') or '')}"[:4096]
    return {
        "event_id": f"{host}:{record_id}"[:256], "timestamp": timestamp,
        "source": SOURCE, "event_type": event_type, "host": host[:256],
        "user": user[:256], "outcome": "unknown", "src_ip": src_ip[:256],
        "process": image[:1024], "command_line": command_line[:16384],
        "file_hash": hashes[:256], "destination": destination, "message": message,
    }


def collect_sysmon_events(limit: int = 500) -> list[dict[str, str]]:
    """Read a bounded number of recent local Sysmon records on Windows."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_COLLECT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_COLLECT_LIMIT}")
    if sys.platform != "win32":
        raise RuntimeError("Sysmon collection is supported only on Windows")
    command = _SCRIPT.replace("__LIMIT__", str(limit))
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not query local Sysmon log: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown PowerShell error").strip()
        raise RuntimeError(f"Sysmon query failed: {detail[:1000]}")
    if len(completed.stdout.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise RuntimeError("Sysmon response exceeded the 20 MB safety limit")
    try:
        raw_records = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("PowerShell returned invalid JSON for Sysmon records") from exc
    if not isinstance(raw_records, list):
        raw_records = [raw_records]
    if len(raw_records) > limit:
        raise RuntimeError("Sysmon response exceeded the requested record limit")
    normalized: list[dict[str, str]] = []
    for record in raw_records:
        try:
            normalized.append(normalize_sysmon_record(record))
        except (ValueError, TypeError):
            continue
    return normalized
