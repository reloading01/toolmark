"""Parser for `paste-cache/`.

Text pasted into a session is written here as `<sha256(content)[:16]>.txt`,
which was verified against every entry on the corpus checked. Two things follow
from the name being a digest of the content: the entry can be integrity-checked
without any external record, and a mismatch means the file changed after it was
cached.

This plane matters because it covers a surface the prompt index does not.
`history.jsonl` records terminal prompts only, and none of the cached pastes
measured had a counterpart there - they came from sessions the index never saw.
Injection arrives by paste as readily as by file read, so a report that only
looks at what the agent read misses it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DIGEST_LENGTH = 16


@dataclass
class PasteEntry:
    path: str
    name_digest: str
    content_digest: str
    size: int
    modified: str
    content: str

    @property
    def integrity_ok(self) -> bool:
        return self.name_digest == self.content_digest


def content_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:DIGEST_LENGTH]


def iter_paste_cache(claude_dir: Path) -> list[PasteEntry]:
    root = claude_dir / "paste-cache"
    if not root.exists():
        return []
    entries: list[PasteEntry] = []
    for path in sorted(root.iterdir()):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
            stat = path.stat()
        except OSError:
            continue
        entries.append(
            PasteEntry(
                path=str(path),
                name_digest=path.stem,
                content_digest=content_digest(data),
                size=stat.st_size,
                modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                content=data.decode("utf-8", errors="replace"),
            )
        )
    return entries
