"""Parser for `shell-snapshots/`.

Before running commands, Claude Code snapshots the user's shell: every
function, alias, shell option and the exported PATH. Forensically this is the
host environment as the agent saw it, at a known time - the snapshot filename
carries epoch milliseconds. If a command the agent ran did something other than
what its name implies, the reason is usually in here.

Note that the tool injects shadowing functions of its own (`find`, `grep`,
`pkill`), so "a function named grep exists" is normal. Telling tool-injected
shadowing apart from hostile shadowing is the whole job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# zsh emits three function forms. Missing `function NAME {` would skip exactly
# the shadowing definitions that matter most.
_FUNCTION_START = re.compile(
    r"^(?:function\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s*(?:\(\s*\))?|([A-Za-z_][A-Za-z0-9_.:-]*)\s*\(\s*\))\s*\{"
)
_ALIAS = re.compile(r"^alias\s+(?:--\s+)?([A-Za-z_][A-Za-z0-9_.:-]*)=(.*)$")
_PATH_EXPORT = re.compile(r"^export\s+PATH=(.*)$")
_FILENAME = re.compile(r"^snapshot-([A-Za-z0-9_]+)-(\d+)-\w+\.sh$")

# Markers Claude Code leaves in the shadowing functions it writes itself.
TOOL_SHADOW_MARKERS = ("CLAUDE_CODE_EXECPATH", "_cc_bin", "CLAUDE_PID")


@dataclass
class Snapshot:
    path: str
    shell: str = ""
    epoch_ms: int = 0
    aliases: dict[str, str] = field(default_factory=dict)
    functions: dict[str, str] = field(default_factory=dict)
    path_entries: list[str] = field(default_factory=list)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def parse_snapshot(path: str | Path) -> Snapshot:
    path = Path(path)
    snapshot = Snapshot(path=str(path))

    name_match = _FILENAME.match(path.name)
    if name_match:
        snapshot.shell = name_match.group(1)
        snapshot.epoch_ms = int(name_match.group(2))

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]

        function_match = _FUNCTION_START.match(line)
        if function_match:
            name = function_match.group(1) or function_match.group(2)
            body: list[str] = []
            index += 1
            # The snapshot is generated, not hand-written: bodies are indented
            # and the closing brace sits in column zero. Brace counting would
            # trip over braces inside strings and case patterns.
            while index < len(lines) and lines[index].rstrip() != "}":
                body.append(lines[index])
                index += 1
            snapshot.functions[name] = "\n".join(body)
            index += 1
            continue

        alias_match = _ALIAS.match(line)
        if alias_match:
            snapshot.aliases[alias_match.group(1)] = _strip_quotes(alias_match.group(2))
            index += 1
            continue

        path_match = _PATH_EXPORT.match(line)
        if path_match:
            # Empty elements are kept: an empty PATH element means "current
            # directory", which is the whole point of looking at PATH here.
            snapshot.path_entries = _strip_quotes(path_match.group(1)).split(":")
            index += 1
            continue

        index += 1

    return snapshot


def iter_snapshots(claude_dir: Path) -> list[Snapshot]:
    root = claude_dir / "shell-snapshots"
    if not root.exists():
        return []
    snapshots = []
    for entry in sorted(root.iterdir()):
        if entry.is_file() and entry.name.endswith(".sh"):
            try:
                snapshots.append(parse_snapshot(entry))
            except OSError:
                continue
    return snapshots


def is_tool_shadow(body: str) -> bool:
    return any(marker in body for marker in TOOL_SHADOW_MARKERS)
