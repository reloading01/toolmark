"""Freeze artifacts before the retention sweep removes them.

Detection quality is worth nothing against evidence that no longer exists, and
the measured windows are short: shell snapshots lasted under a day on the host
this was built against, transcripts about a month. By the time anyone notices
an agent did something odd, the record of how it did it may already be gone.

The archive is built to be scanned, not just stored. Blobs are content
addressed under `objects/`, and `latest/` mirrors the source layout with hard
links into them, so `toolmark scan --claude-dir <archive>/latest` works
directly. Nothing is ever deleted from the mirror, which makes it the union of
everything seen across runs rather than a copy of the current state - a file
the sweep removes from the source stays here.

Runs are incremental and cheap enough for a daily cron: unchanged files are
recognised by digest and skipped.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .custody import hash_file, now_iso

# Whole planes worth keeping. Excluded on purpose: plugins/cache and
# plugins/repos hold third-party source trees whose manifests and hooks are
# collected separately below, and cache/ and downloads/ hold no record of what
# the agent did.
PRESERVED_TREES = (
    "projects",
    "file-history",
    "jobs",
    "shell-snapshots",
    "paste-cache",
    "tasks",
    "backups",
    "session-env",
    "telemetry",
    "sessions",
)

PRESERVED_FILES = (
    "history.jsonl",
    "settings.json",
    "settings.local.json",
    "policy-limits.json",
    ".last-cleanup",
)

# From the plugin tree, the parts that decide what the agent can do.
PLUGIN_PATTERNS = ("plugins/*.json", "plugins/**/hooks/*", "plugins/**/plugin.json", "plugins/**/.mcp.json")


@dataclass
class PreserveResult:
    run_id: str
    archive: str
    added: int = 0
    changed: int = 0
    unchanged: int = 0
    vanished: list[str] = field(default_factory=list)
    bytes_added: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def preserved(self) -> int:
        return self.added + self.changed + self.unchanged


def plan_paths(claude_dir: Path, codex_dir: Path | None = None) -> list[tuple[Path, str]]:
    """Returns (source path, archive-relative path) pairs, namespaced by agent
    so one archive can hold more than one."""
    pairs: list[tuple[Path, str]] = []

    for tree in PRESERVED_TREES:
        root = claude_dir / tree
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file():
                pairs.append((path, f"claude/{path.relative_to(claude_dir).as_posix()}"))

    for name in PRESERVED_FILES:
        path = claude_dir / name
        if path.is_file():
            pairs.append((path, f"claude/{name}"))

    for pattern in PLUGIN_PATTERNS:
        for path in claude_dir.glob(pattern):
            if path.is_file():
                pairs.append((path, f"claude/{path.relative_to(claude_dir).as_posix()}"))

    global_config = claude_dir.parent / ".claude.json"
    if global_config.is_file():
        pairs.append((global_config, "claude.json"))

    if codex_dir and codex_dir.exists():
        for folder in ("sessions", "archived_sessions"):
            root = codex_dir / folder
            if not root.exists():
                continue
            for path in root.rglob("rollout-*.jsonl"):
                if path.is_file():
                    pairs.append((path, f"codex/{path.relative_to(codex_dir).as_posix()}"))
        for name in ("config.toml", "history.jsonl"):
            path = codex_dir / name
            if path.is_file():
                pairs.append((path, f"codex/{name}"))

    seen: set[str] = set()
    unique: list[tuple[Path, str]] = []
    for source, relative in pairs:
        if relative in seen:
            continue
        seen.add(relative)
        unique.append((source, relative))
    return unique


def _object_path(archive: Path, digest: str) -> Path:
    return archive / "objects" / digest[:2] / digest


def _link_or_copy(blob: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        target.unlink()
    try:
        os.link(blob, target)
    except OSError:
        # Different filesystem, or a link limit. A copy costs space but keeps
        # the mirror usable, which is the point of it.
        shutil.copy2(blob, target)


def preserve(
    pairs: list[tuple[Path, str]], archive: Path, run_id: str | None = None
) -> tuple[PreserveResult, list[dict]]:
    """Copy each artifact into the archive once per distinct content. Returns
    the result and the per-file records for the index."""
    run_id = run_id or now_iso()
    result = PreserveResult(run_id=run_id, archive=str(archive))
    records: list[dict] = []
    mirror = archive / "latest"
    mirror.mkdir(parents=True, exist_ok=True)

    present: set[str] = set()
    for source, relative in pairs:
        present.add(relative)
        try:
            digest, size = hash_file(source)
            mtime = source.stat().st_mtime
        except OSError as error:
            result.errors.append(f"{source}: {error}")
            continue

        blob = _object_path(archive, digest)
        target = mirror / relative

        if target.exists():
            try:
                existing, _ = hash_file(target)
            except OSError:
                existing = ""
            status = "unchanged" if existing == digest else "changed"
        else:
            status = "added"

        if not blob.exists():
            blob.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, blob)
            result.bytes_added += size

        if status != "unchanged":
            _link_or_copy(blob, target)
            records.append(
                {
                    "run_id": run_id,
                    "path": relative,
                    "source": str(source),
                    "sha256": digest,
                    "size": size,
                    "source_modified": mtime,
                    "status": status,
                }
            )

        if status == "added":
            result.added += 1
        elif status == "changed":
            result.changed += 1
        else:
            result.unchanged += 1

    # Anything in the mirror the source no longer has: the sweep took it, and
    # the copy here is now the only one. This is the payoff of running early.
    for path in mirror.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(mirror).as_posix()
        if relative not in present:
            result.vanished.append(relative)

    return result, records
