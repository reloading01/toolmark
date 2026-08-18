"""Parser for `history.jsonl`, and the evidence-coverage question it answers.

Session transcripts are swept by `cleanupPeriodDays`, default 30. The prompt
index is not, so it routinely reaches back further than the transcripts by an
order of magnitude. That asymmetry decides what an investigation can still see:
what the agent was *told* outlives what it *did*.

Two consequences the rest of the tool depends on. A prompt whose session
transcript is gone marks a hole in the evidence, and counting those holes is
the honest way to state how much of a timeline is missing. And `pastedContents`
stores pasted text inline, so content pasted into a prompt survives the sweep
that removes the transcript showing what the agent did with it.

Nothing here assumes a retention policy. The documented behaviour has been
inconsistent across releases, so spans are measured from the artifacts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class PastedItem:
    item_id: str
    type: str
    content: str


@dataclass
class PromptRecord:
    timestamp_ms: int
    project: str
    prompt: str
    session_id: str = ""
    pasted: list[PastedItem] = field(default_factory=list)

    @property
    def iso(self) -> str:
        if not self.timestamp_ms:
            return ""
        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc).isoformat()


@dataclass
class Coverage:
    """How much of the prompt history still has a transcript behind it."""

    total: int = 0
    with_session_id: int = 0
    covered: int = 0
    orphaned: int = 0
    unlinkable: int = 0
    oldest_prompt_ms: int = 0
    newest_prompt_ms: int = 0
    projects: int = 0
    projects_with_transcripts: int = 0
    # sessions on disk that appear in the prompt history at all, split by how
    # the session was started. The split matters: measurement shows the index
    # records terminal prompts and not desktop ones.
    by_entrypoint: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def orphan_ratio(self) -> float:
        linkable = self.covered + self.orphaned
        return (self.orphaned / linkable) if linkable else 0.0


def parse_history(path: str | Path) -> list[PromptRecord]:
    path = Path(path)
    if not path.exists():
        return []
    records: list[PromptRecord] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue
            pasted: list[PastedItem] = []
            for key, item in (raw.get("pastedContents") or {}).items():
                if isinstance(item, dict):
                    pasted.append(
                        PastedItem(
                            item_id=str(item.get("id", key)),
                            type=str(item.get("type", "")),
                            content=str(item.get("content", "")),
                        )
                    )
            records.append(
                PromptRecord(
                    timestamp_ms=int(raw.get("timestamp") or 0),
                    project=str(raw.get("project") or ""),
                    prompt=str(raw.get("display") or ""),
                    # Absent on older records, which makes them impossible to
                    # tie to a transcript even when one survives.
                    session_id=str(raw.get("sessionId") or ""),
                    pasted=pasted,
                )
            )
    return records


def measure_coverage(
    records: list[PromptRecord],
    surviving_session_ids: set[str],
    transcript_projects: set[str],
    session_entrypoints: dict[str, str] | None = None,
) -> Coverage:
    coverage = Coverage(total=len(records))
    projects: set[str] = set()
    for record in records:
        if record.project:
            projects.add(record.project)
        if record.timestamp_ms:
            coverage.oldest_prompt_ms = (
                min(coverage.oldest_prompt_ms, record.timestamp_ms)
                if coverage.oldest_prompt_ms
                else record.timestamp_ms
            )
            coverage.newest_prompt_ms = max(coverage.newest_prompt_ms, record.timestamp_ms)
        if not record.session_id:
            coverage.unlinkable += 1
            continue
        coverage.with_session_id += 1
        if record.session_id in surviving_session_ids:
            coverage.covered += 1
        else:
            coverage.orphaned += 1
    coverage.projects = len(projects)
    coverage.projects_with_transcripts = len(transcript_projects)

    indexed = {r.session_id for r in records if r.session_id}
    tally: dict[str, list[int]] = {}
    for session_id, entrypoint in (session_entrypoints or {}).items():
        slot = tally.setdefault(entrypoint or "<unrecorded>", [0, 0])
        slot[0] += 1
        if session_id in indexed:
            slot[1] += 1
    coverage.by_entrypoint = {k: (v[0], v[1]) for k, v in tally.items()}
    return coverage


# Planes worth reporting a span for. Retention has moved between releases and
# the documentation has contradicted the changelog, so the span is measured
# rather than asserted.
RETENTION_PLANES = (
    "projects",
    "file-history",
    "shell-snapshots",
    "jobs",
    "paste-cache",
    "tasks",
    "backups",
    "session-env",
)


def observed_retention(claude_dir: Path) -> dict[str, tuple[float, float, int]]:
    """`plane -> (oldest mtime, newest mtime, file count)` for what is on disk."""
    spans: dict[str, tuple[float, float, int]] = {}
    for plane in RETENTION_PLANES:
        root = claude_dir / plane
        if not root.exists():
            continue
        oldest = newest = 0.0
        count = 0
        for entry in root.rglob("*"):
            if not entry.is_file():
                continue
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue
            count += 1
            oldest = min(oldest, mtime) if oldest else mtime
            newest = max(newest, mtime)
        if count:
            spans[plane] = (oldest, newest, count)

    history = claude_dir / "history.jsonl"
    if history.exists():
        records = parse_history(history)
        stamps = [r.timestamp_ms / 1000 for r in records if r.timestamp_ms]
        if stamps:
            spans["history.jsonl"] = (min(stamps), max(stamps), len(records))
    return spans
