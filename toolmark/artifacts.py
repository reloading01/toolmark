"""Two artifact planes that live outside the session transcript.

`file-history/` holds the agent's own copies of every file it edited, versioned.
Entries are named `<sha256(absolute_path)[:16]>@v<N>` with no manifest, so the
directory is anonymous on its own - the path has to come from somewhere else.
Two ways to get it: read the edited paths out of the transcripts, or hash a path
you already suspect and look for it. The second still works after the 30-day
transcript cleanup, which is when it matters most.

`jobs/` holds background job orchestration: the launch flags a job was respawned
with, the shell tasks it fanned out, and its own state timeline. None of it is
in the transcript.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

DIGEST_LENGTH = 16

# Config that governs what the agent may do. An agent editing these is editing
# its own permissions - the CVE-2026-25725 shape.
SELF_CONFIG_SUFFIXES = (
    "/.claude/settings.json",
    "/.claude/settings.local.json",
    "/.claude.json",
    "/.mcp.json",
    "/.claude/policy-limits.json",
)
SELF_CONFIG_FRAGMENTS = (
    "/.claude/hooks/",
    "/.claude/agents/",
    "/.claude/skills/",
    "/hooks/hooks.json",
)


def path_digest(path: str) -> str:
    """The identifier Claude Code derives from an absolute path."""
    return hashlib.sha256(path.encode()).hexdigest()[:DIGEST_LENGTH]


@dataclass
class FileVersion:
    session_id: str
    digest: str
    version: int
    stored_path: str
    size: int
    mtime: float
    resolved_path: str | None = None

    @property
    def is_self_config(self) -> bool:
        if not self.resolved_path:
            return False
        return self.resolved_path.endswith(SELF_CONFIG_SUFFIXES) or any(
            fragment in self.resolved_path for fragment in SELF_CONFIG_FRAGMENTS
        )


@dataclass
class Job:
    job_id: str
    state: str = ""
    detail: str = ""
    session_id: str = ""
    cwd: str = ""
    cli_version: str = ""
    backend: str = ""
    created_at: str = ""
    updated_at: str = ""
    flags: dict[str, list[str]] = field(default_factory=dict)
    shell_tasks: list[str] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)


def iter_file_history(claude_dir: Path) -> list[FileVersion]:
    root = claude_dir / "file-history"
    if not root.exists():
        return []
    versions: list[FileVersion] = []
    for session_dir in sorted(root.iterdir()):
        if not session_dir.is_dir():
            continue
        for entry in sorted(session_dir.iterdir()):
            if not entry.is_file() or "@v" not in entry.name:
                continue
            digest, _, raw_version = entry.name.rpartition("@v")
            try:
                version = int(raw_version)
            except ValueError:
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue
            versions.append(
                FileVersion(
                    session_id=session_dir.name,
                    digest=digest,
                    version=version,
                    stored_path=str(entry),
                    size=stat.st_size,
                    mtime=stat.st_mtime,
                )
            )
    return versions


def build_digest_index(paths: Iterable[str]) -> dict[str, str]:
    return {path_digest(path): path for path in paths if path}


def probe_candidates(home: Path, cwds: Iterable[str]) -> list[str]:
    """Config paths worth checking for regardless of what the transcripts say.
    Digesting a suspected path recovers it from an otherwise anonymous history
    directory, including one whose transcript has already been cleaned up."""
    candidates = [
        str(home / ".claude" / "settings.json"),
        str(home / ".claude" / "settings.local.json"),
        str(home / ".claude.json"),
        str(home / ".claude" / "policy-limits.json"),
    ]
    for cwd in cwds:
        if not cwd:
            continue
        base = Path(cwd)
        candidates.append(str(base / ".claude" / "settings.json"))
        candidates.append(str(base / ".claude" / "settings.local.json"))
        candidates.append(str(base / ".mcp.json"))
    return candidates


def resolve_versions(versions: list[FileVersion], index: dict[str, str]) -> None:
    for version in versions:
        resolved = index.get(version.digest)
        if resolved:
            version.resolved_path = resolved


def parse_flags(respawn_flags: list) -> dict[str, list[str]]:
    """Turn `['--permission-mode', 'bypassPermissions', '--reply-on-resume']`
    into `{'--permission-mode': ['bypassPermissions'], '--reply-on-resume': []}`."""
    flags: dict[str, list[str]] = {}
    current: str | None = None
    for item in respawn_flags or []:
        if not isinstance(item, str):
            continue
        if item.startswith("--"):
            current = item
            flags.setdefault(current, [])
        elif current:
            flags[current].append(item)
    return flags


def _read_timeline(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def iter_jobs(claude_dir: Path) -> list[Job]:
    root = claude_dir / "jobs"
    if not root.exists():
        return []
    jobs: list[Job] = []
    for job_dir in sorted(root.iterdir()):
        state_file = job_dir / "state.json"
        if not job_dir.is_dir() or not state_file.exists():
            continue
        try:
            state = json.loads(state_file.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(state, dict):
            continue

        shell_tasks = [
            str(item.get("label", ""))
            for item in state.get("fan") or []
            if isinstance(item, dict) and item.get("kind") == "shell" and item.get("label")
        ]
        jobs.append(
            Job(
                job_id=job_dir.name,
                state=str(state.get("state", "")),
                detail=str(state.get("detail", "")),
                session_id=str(state.get("sessionId", "")),
                cwd=str(state.get("cwd", "")),
                cli_version=str(state.get("cliVersion", "")),
                backend=str(state.get("backend", "")),
                created_at=str(state.get("createdAt", "")),
                updated_at=str(state.get("updatedAt", "")),
                flags=parse_flags(state.get("respawnFlags")),
                shell_tasks=shell_tasks,
                timeline=_read_timeline(job_dir / "timeline.jsonl"),
            )
        )
    return jobs
