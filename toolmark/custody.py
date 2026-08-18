"""Chain of custody for the artifacts a run reads.

Output that might be used in an investigation has to be able to say where it
came from. Following the shape NIST SP 800-86 asks for: what was acquired, from
which system, when, by whom, and with which procedure, plus a hash of every
item so a later reader can prove the file has not changed since.

The produced reports are hashed too. A manifest that covers only the inputs
lets the findings be edited afterwards without leaving a trace.

Collection is read-only: the tool opens artifacts for reading and writes
nothing back to the source tree.
"""

from __future__ import annotations

import getpass
import hashlib
import platform
import socket
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

_CHUNK = 1024 * 1024


@dataclass
class EvidenceItem:
    path: str
    sha256: str
    size: int
    modified: str
    plane: str


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _plane_of(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        return "external"
    return relative.parts[0] if len(relative.parts) > 1 else relative.name


def collect_evidence(paths, root: Path) -> list[EvidenceItem]:
    """Hash each artifact once. Duplicates are dropped rather than double
    counted, since the same file is often reached through more than one
    collector."""
    items: list[EvidenceItem] = []
    seen: set[str] = set()
    for path in paths:
        path = Path(path)
        key = str(path)
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        try:
            digest, size = hash_file(path)
            modified = _iso(path.stat().st_mtime)
        except OSError:
            continue
        items.append(
            EvidenceItem(path=key, sha256=digest, size=size, modified=modified, plane=_plane_of(path, root))
        )
    return items


def build_manifest(
    *,
    tool_version: str,
    source_root: Path,
    started_at: str,
    evidence: list[EvidenceItem],
    outputs: list[EvidenceItem],
    redacted: bool,
) -> dict:
    planes: dict[str, dict[str, int]] = {}
    for item in evidence:
        bucket = planes.setdefault(item.plane, {"files": 0, "bytes": 0})
        bucket["files"] += 1
        bucket["bytes"] += item.size

    return {
        "manifest_version": 1,
        "procedure": {
            "tool": "toolmark",
            "version": tool_version,
            "invocation": sys.argv,
            "python": platform.python_version(),
            "read_only": True,
            "output_redacted": redacted,
            # A manifest cannot cover itself. Hash this file externally if the
            # set needs to be sealed against later edits.
            "self_coverage": "manifest.json is not listed in outputs",
        },
        "acquisition": {
            "started_at": started_at,
            "completed_at": now_iso(),
            "source_root": str(source_root),
            "operator": _operator(),
            "host": {
                "hostname": _hostname(),
                "platform": platform.platform(),
                "machine": platform.machine(),
            },
        },
        "summary": {
            "evidence_files": len(evidence),
            "evidence_bytes": sum(i.size for i in evidence),
            "planes": planes,
            "output_files": len(outputs),
        },
        "evidence": [asdict(i) for i in evidence],
        "outputs": [asdict(i) for i in outputs],
    }


def _operator() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - depends on the host account setup
        return "<unknown>"


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:  # pragma: no cover - depends on host networking
        return "<unknown>"
