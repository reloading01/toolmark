"""Streaming parser for Claude Code session transcripts (`~/.claude/projects/*/*.jsonl`).

The schema drifts between releases, so nothing here is pinned to a version.
Every lookup is defensive, and instead of comparing version strings the parser
records which top-level fields it actually saw. What breaks an analysis is a
field going missing, not a number changing - and a field can disappear inside
one release just as easily as across two.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator

from .model import Event, HookRun, Session, ToolCall, ToolResult

# Without these the transcript cannot be placed in a graph at all.
CORE_FIELDS = frozenset({"uuid", "type", "timestamp", "message"})

# Present-but-optional fields that individual detectors depend on. Their
# absence degrades specific findings rather than breaking the parse.
SIGNAL_FIELDS = frozenset(
    {"parentUuid", "isSidechain", "permissionMode", "toolUseResult", "cwd", "sessionId"}
)

# Everything this build knows how to see. Anything outside it is schema drift
# worth surfacing: a field the agent now writes that nothing here reads yet.
KNOWN_FIELDS = (
    CORE_FIELDS
    | SIGNAL_FIELDS
    | frozenset(
        {
            "agentId", "attributionAgent", "aiTitle", "attachment", "content",
            "customTitle", "effort", "entrypoint", "gitBranch", "lastPrompt",
            "leafUuid", "operation", "promptId", "requestId",
            "sourceToolAssistantUUID", "userType", "version",
        }
    )
)


def _blocks(message: dict) -> list[dict]:
    content = message.get("content")
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return []


def _result_envelope(raw: dict) -> tuple[str, str, bool]:
    """`toolUseResult` carries the real command outcome; the `tool_result` block
    only carries the model-visible rendering."""
    env = raw.get("toolUseResult")
    if not isinstance(env, dict):
        return "", "", False
    stdout = env.get("stdout") or ""
    stderr = env.get("stderr") or ""
    return (
        stdout if isinstance(stdout, str) else json.dumps(stdout),
        stderr if isinstance(stderr, str) else json.dumps(stderr),
        bool(env.get("interrupted")),
    )


def _content_text(block: dict) -> str:
    content = block.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
    return ""


def parse_session(path: str | os.PathLike[str]) -> Session:
    path = Path(path)
    session = Session(session_id=path.stem, path=str(path))

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                session.malformed_lines += 1
                continue
            if not isinstance(raw, dict):
                session.malformed_lines += 1
                continue

            uuid = raw.get("uuid")
            if not uuid:
                # Sidecar records (custom-title, last-prompt, queue-operation)
                # carry no identity and cannot be placed in the graph.
                continue

            if raw.get("sessionId"):
                session.session_id = raw["sessionId"]
            session.seen_fields.update(raw.keys())
            if raw.get("version"):
                session.versions.add(raw["version"])
            # Subagent transcripts live at <session>/subagents/agent-<id>.jsonl
            # and carry the PARENT session id, with their own identity in
            # `agentId`. Keeping both is what makes per-agent attribution work.
            if raw.get("agentId"):
                session.agent_id = raw["agentId"]
            if raw.get("attributionAgent"):
                session.agent_type = raw["attributionAgent"]

            if raw.get("subtype") == "stop_hook_summary":
                session.hook_runs.append(
                    HookRun(
                        event_uuid=uuid,
                        timestamp=raw.get("timestamp", ""),
                        count=raw.get("hookCount") or 0,
                        commands=[
                            str(h.get("command", ""))
                            for h in raw.get("hookInfos") or []
                            if isinstance(h, dict)
                        ],
                        errors=raw.get("hookErrors") or [],
                        additional_context=raw.get("hookAdditionalContext") or [],
                        prevented_continuation=bool(raw.get("preventedContinuation")),
                        stop_reason=str(raw.get("stopReason") or ""),
                        level=str(raw.get("level") or ""),
                        tool_use_id=str(raw.get("toolUseID") or ""),
                        cwd=raw.get("cwd", ""),
                    )
                )

            message = raw.get("message") if isinstance(raw.get("message"), dict) else {}
            event = Event(
                uuid=uuid,
                parent_uuid=raw.get("parentUuid"),
                type=raw.get("type", ""),
                timestamp=raw.get("timestamp", ""),
                line_no=line_no,
                session_id=raw.get("sessionId", session.session_id),
                cwd=raw.get("cwd", ""),
                git_branch=raw.get("gitBranch"),
                version=raw.get("version"),
                entrypoint=raw.get("entrypoint"),
                is_sidechain=bool(raw.get("isSidechain")),
                agent_id=raw.get("agentId"),
                agent_type=raw.get("attributionAgent"),
                permission_mode=raw.get("permissionMode"),
            )

            texts: list[str] = []
            stdout, stderr, interrupted = _result_envelope(raw)
            for block in _blocks(message):
                btype = block.get("type")
                if btype == "text":
                    texts.append(block.get("text", ""))
                elif btype == "tool_use":
                    call = ToolCall(
                        call_id=block.get("id", ""),
                        name=block.get("name", ""),
                        input=block.get("input") if isinstance(block.get("input"), dict) else {},
                        event_uuid=uuid,
                        timestamp=event.timestamp,
                        caller=block.get("caller"),
                    )
                    event.tool_calls.append(call)
                    if call.call_id:
                        session.calls[call.call_id] = call
                elif btype == "tool_result":
                    result = ToolResult(
                        call_id=block.get("tool_use_id", ""),
                        event_uuid=uuid,
                        timestamp=event.timestamp,
                        is_error=bool(block.get("is_error")),
                        interrupted=interrupted,
                        content=_content_text(block),
                        stdout=stdout,
                        stderr=stderr,
                    )
                    event.tool_results.append(result)
                    if result.call_id:
                        session.results[result.call_id] = result

            event.text = "\n".join(t for t in texts if t)
            session.events[uuid] = event
            session.order.append(uuid)

    for uuid in session.order:
        parent = session.events[uuid].parent_uuid
        if parent and parent in session.events:
            session.children.setdefault(parent, []).append(uuid)
        else:
            session.roots.append(uuid)

    return session


def iter_session_files(projects_dir: str | os.PathLike[str], since_days: int | None = None) -> Iterator[Path]:
    """Yield transcript files newest-first, so a time-boxed triage sees the
    freshest evidence before the 30-day cleanup window matters."""
    root = Path(projects_dir)
    if not root.exists():
        return
    files = [p for p in root.rglob("*.jsonl") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    cutoff = None
    if since_days is not None:
        newest = files[0].stat().st_mtime if files else 0
        cutoff = newest - since_days * 86400
    for path in files:
        if cutoff is not None and path.stat().st_mtime < cutoff:
            continue
        yield path
