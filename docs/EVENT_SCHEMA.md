# Normalized event schema

Input is UTF-8 JSON Lines (JSONL): one JSON object per line.

## Required fields

| Field | Type | Meaning |
|---|---|---|
| \`event_id\` | string | Identifier local to the source |
| \`timestamp\` | string | ISO-8601 timestamp including timezone, e.g. \`2026-10-17T08:00:00Z\` |
| \`source\` | string | Stable source/feed identifier |
| \`event_type\` | string | Normalized category such as \`authentication\` or \`process_create\` |

## Optional fields

| Field | Type | Meaning |
|---|---|---|
| \`host\` | string | Host or endpoint label |
| \`user\` | string | Account label |
| \`outcome\` | string | Result, e.g. \`failure\` or \`success\` |
| \`src_ip\` | string | Source IP as supplied by the collector |
| \`process\` | string | Process image/name |
| \`command_line\` | string | Command-line text |
| \`file_hash\` | string | File hash string |
| \`destination\` | string | Network destination or resource |
| \`message\` | string | Short source message or description |

All fields are strings when present. Events should be normalized and sanitized before ingestion. Do not include passwords, access tokens, private keys, or unnecessary personal data.

## Windows / Sysmon source

The optional local collector emits \`source=windows-sysmon\`. It maps Event IDs 1, 3, 7, 10, 11, and 22 to process creation, network connection, image load, process access, file creation, and DNS query respectively. Other event IDs are retained as \`sysmon_event_<id>\`. See [Windows/Sysmon collection](WINDOWS_SYSMON_COLLECTION.md). This is a best-effort export, not a claim of complete coverage.

## Parser behavior

- Timezone-less timestamps are rejected.
- Malformed records are skipped and reported as warnings.
- Oversized records are rejected.
- Duplicate \`(source, event_id)\` pairs are ignored.
- IDs are source-local; two sources may legitimately reuse an ID.
- Input is data only and is never executed.
