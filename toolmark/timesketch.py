"""Timesketch-compatible CSV export.

Timesketch is where a lot of DFIR work actually happens, and a timeline nobody
can load into their tooling is a timeline nobody reads. The importer needs
three columns - `message`, `datetime` in ISO 8601 with an offset, and
`timestamp_desc` - and accepts any number of extra columns beside them, so the
agent-specific fields ride along without being flattened away.

Rows with no usable timestamp are dropped, because Timesketch cannot place
them. The count is returned rather than swallowed: a silent drop turns a
partial timeline into one that looks complete.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

COLUMNS = [
    "message",
    "datetime",
    "timestamp",
    "timestamp_desc",
    "data_type",
    "kind",
    "detector",
    "severity",
    "tool",
    "outcome",
    "session_id",
    "agent_id",
    "agent_type",
    "mcp_server",
    "plugin",
    "skill",
    "permission_mode",
    "is_sidechain",
    "depth",
    "cwd",
    "git_branch",
    "project",
    "source",
]


def normalise_datetime(value: str) -> tuple[str, int]:
    """ISO 8601 with an offset, plus epoch microseconds. Returns empty on
    anything unparseable rather than guessing a time."""
    if not value:
        return "", 0
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return "", 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat(), int(parsed.timestamp() * 1_000_000)


def _truncate(text: str, limit: int = 400) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


def timeline_row(row: dict) -> dict | None:
    stamp, micros = normalise_datetime(row.get("timestamp", ""))
    if not stamp:
        return None
    if row.get("kind") == "prompt":
        message = f"prompt: {_truncate(row.get('prompt', ''))}"
        desc = "prompt submitted"
        data_type = "toolmark:prompt"
    else:
        target = row.get("input") or {}
        detail = ""
        if isinstance(target, dict):
            detail = target.get("command") or target.get("file_path") or target.get("url") or ""
        message = f"{row.get('tool', 'tool')} {_truncate(detail, 300)}".strip()
        desc = "agent tool call"
        data_type = "toolmark:tool_call"
    return {
        "message": message,
        "datetime": stamp,
        "timestamp": micros,
        "timestamp_desc": desc,
        "data_type": data_type,
        "kind": row.get("kind", ""),
        "tool": row.get("tool", ""),
        "outcome": row.get("outcome", ""),
        "session_id": row.get("session_id", ""),
        "agent_id": row.get("agent_id") or "",
        "agent_type": row.get("agent_type") or "",
        "mcp_server": row.get("mcp_server") or "",
        "plugin": row.get("plugin") or "",
        "skill": row.get("skill") or "",
        "permission_mode": row.get("permission_mode") or "",
        "is_sidechain": row.get("is_sidechain", ""),
        "depth": row.get("depth", ""),
        "cwd": row.get("cwd", ""),
        "git_branch": row.get("git_branch") or "",
        "project": row.get("project", ""),
        "source": row.get("source", ""),
    }


def finding_row(finding: dict) -> dict | None:
    stamp, micros = normalise_datetime(finding.get("timestamp", ""))
    if not stamp:
        return None
    return {
        "message": f"[{finding.get('severity')}] {finding.get('title')}: {_truncate(finding.get('detail', ''))}",
        "datetime": stamp,
        "timestamp": micros,
        "timestamp_desc": "toolmark finding",
        "data_type": "toolmark:finding",
        "kind": "finding",
        "detector": finding.get("detector", ""),
        "severity": finding.get("severity", ""),
        "session_id": finding.get("session_id", ""),
        "source": finding.get("source", ""),
    }


def write_csv(path: Path, timeline: list[dict], findings: list[dict]) -> tuple[int, int]:
    """Returns (rows written, rows dropped for want of a timestamp)."""
    written = dropped = 0
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for source, builder in ((timeline, timeline_row), (findings, finding_row)):
            for item in source:
                row = builder(item)
                if row is None:
                    dropped += 1
                    continue
                writer.writerow(row)
                written += 1
    return written, dropped
