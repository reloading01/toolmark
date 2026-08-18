"""Parser for Codex CLI transcripts.

Codex writes one JSONL per session under `~/.codex/sessions/<yyyy>/<mm>/<dd>/`
and `archived_sessions/`, named `rollout-<timestamp>-<session-id>.jsonl`, with a
flat `{timestamp, type, payload}` envelope.

What ports and what does not, measured rather than assumed:

* Tool calls pair with their output exactly, through `call_id`, so outcomes are
  as reliable as they are on Claude Code.
* `turn_context` carries `approval_policy` and `sandbox_policy`, which is the
  unattended-execution question in different words.
* MCP invocations name their server and tool, so component attribution works.
* Records carry no parent link. `turn_id` exists but not on tool calls, so
  there is no tree to rebuild - events are ordered, not caused. The session is
  marked `causality="ordered"` and detectors that reason about descent decline
  to run on it rather than treating adjacency as causation.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator

from .model import Event, Session, ToolCall, ToolResult

_FILENAME = re.compile(r"^rollout-(?P<stamp>[\dT:-]+)-(?P<session>[0-9a-f-]{36})\.jsonl$")

# Tool calls carry their command under different keys depending on the tool.
_COMMAND_KEYS = ("cmd", "command")


def _payload(raw: dict) -> dict:
    payload = raw.get("payload")
    return payload if isinstance(payload, dict) else {}


def _record_type(raw: dict, payload: dict) -> str:
    return str(payload.get("type") or raw.get("type") or "")


def _arguments(payload: dict) -> dict:
    """`function_call` arguments arrive as a JSON string; `custom_tool_call`
    carries raw text under `input`."""
    raw = payload.get("arguments")
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"arguments": raw}
    if payload.get("input") is not None:
        return {"input": payload["input"]}
    return {}


def _normalise_command(tool_input: dict) -> dict:
    """Expose whichever key holds the command under a single name so the
    detectors do not need to know each tool's argument spelling."""
    for key in _COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            tool_input.setdefault("command", value)
            break
    return tool_input


def _permission_mode(approval: str, sandbox) -> str:
    sandbox_type = ""
    if isinstance(sandbox, dict):
        sandbox_type = str(sandbox.get("type", ""))
    elif isinstance(sandbox, str):
        sandbox_type = sandbox
    if not approval and not sandbox_type:
        return ""
    return f"{approval or 'unknown'}/{sandbox_type or 'unknown'}"


def parse_codex_session(path: str | os.PathLike[str]) -> Session:
    path = Path(path)
    session = Session(session_id=path.stem, path=str(path))
    session.causality = "ordered"

    match = _FILENAME.match(path.name)
    if match:
        session.session_id = match.group("session")

    cwd = ""
    permission_mode = ""
    version = ""
    previous_uuid: str | None = None
    # exec_command_end and patch_apply_end arrive after the generic output and
    # carry the real outcome, so results are enriched once both are seen.
    enrichment: dict[str, dict] = {}

    with path.open(encoding="utf-8", errors="replace") as fh:
        for index, line in enumerate(fh, start=1):
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

            payload = _payload(raw)
            kind = _record_type(raw, payload)
            timestamp = str(raw.get("timestamp") or payload.get("timestamp") or "")

            if kind == "session_meta":
                session.session_id = str(payload.get("session_id") or payload.get("id") or session.session_id)
                cwd = str(payload.get("cwd") or cwd)
                version = str(payload.get("cli_version") or "")
                if version:
                    session.versions.add(version)
                continue

            if kind == "turn_context":
                cwd = str(payload.get("cwd") or cwd)
                permission_mode = _permission_mode(
                    str(payload.get("approval_policy") or ""), payload.get("sandbox_policy")
                )
                continue

            if kind in ("exec_command_end", "patch_apply_end"):
                call_id = str(payload.get("call_id") or "")
                if call_id:
                    enrichment[call_id] = payload
                continue

            uuid = f"codex-{index}"
            event = Event(
                uuid=uuid,
                parent_uuid=previous_uuid,
                type=kind,
                timestamp=timestamp,
                line_no=index,
                session_id=session.session_id,
                cwd=cwd,
                version=version or None,
                entrypoint="codex-cli",
                permission_mode=permission_mode or None,
            )

            if kind in ("function_call", "custom_tool_call"):
                call = ToolCall(
                    call_id=str(payload.get("call_id") or ""),
                    name=str(payload.get("name") or kind),
                    input=_normalise_command(_arguments(payload)),
                    event_uuid=uuid,
                    timestamp=timestamp,
                )
                event.tool_calls.append(call)
                if call.call_id:
                    session.calls[call.call_id] = call

            elif kind in ("function_call_output", "custom_tool_call_output"):
                call_id = str(payload.get("call_id") or "")
                output = payload.get("output")
                extra = enrichment.get(call_id) or {}
                exit_code = extra.get("exit_code")
                result = ToolResult(
                    call_id=call_id,
                    event_uuid=uuid,
                    timestamp=timestamp,
                    is_error=bool(exit_code) or extra.get("success") is False,
                    content=output if isinstance(output, str) else json.dumps(output, ensure_ascii=False),
                    stdout=str(extra.get("stdout") or ""),
                    stderr=str(extra.get("stderr") or ""),
                )
                event.tool_results.append(result)
                if call_id:
                    session.results[call_id] = result

            elif kind == "mcp_tool_call_end":
                invocation = payload.get("invocation") or {}
                event.mcp_server = str(invocation.get("server") or "") or None
                event.mcp_tool = str(invocation.get("tool") or "") or None

            elif kind in ("user_message", "agent_message"):
                event.text = str(payload.get("message") or "")

            elif kind == "message":
                content = payload.get("content")
                if isinstance(content, list):
                    event.text = "\n".join(
                        str(part.get("text", "")) for part in content if isinstance(part, dict)
                    )

            session.seen_fields.update(payload.keys())
            session.events[uuid] = event
            session.order.append(uuid)
            previous_uuid = uuid

    for uuid in session.order:
        parent = session.events[uuid].parent_uuid
        if parent and parent in session.events:
            session.children.setdefault(parent, []).append(uuid)
        else:
            session.roots.append(uuid)
    return session


def iter_codex_sessions(codex_dir: str | os.PathLike[str]) -> Iterator[Path]:
    root = Path(codex_dir)
    if not root.exists():
        return
    files = [
        p
        for folder in ("sessions", "archived_sessions")
        for p in (root / folder).rglob("rollout-*.jsonl")
        if p.is_file()
    ]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    yield from files
