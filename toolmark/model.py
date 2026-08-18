"""Data model for parsed Claude Code session transcripts."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolCall:
    """A `tool_use` block: the agent asking for an action."""

    call_id: str
    name: str
    input: dict
    event_uuid: str
    timestamp: str
    caller: str | None = None


@dataclass
class ToolResult:
    """A `tool_result` block plus the `toolUseResult` envelope that carries stdout/stderr."""

    call_id: str
    event_uuid: str
    timestamp: str
    is_error: bool = False
    interrupted: bool = False
    content: str = ""
    stdout: str = ""
    stderr: str = ""

    @property
    def outcome(self) -> str:
        if self.interrupted:
            return "interrupted"
        return "error" if self.is_error else "ok"


@dataclass
class HookRun:
    """A `stop_hook_summary` record: hooks that actually executed, as opposed
    to hooks merely declared in a settings file."""

    event_uuid: str
    timestamp: str
    count: int = 0
    commands: list[str] = field(default_factory=list)
    errors: list = field(default_factory=list)
    additional_context: list = field(default_factory=list)
    prevented_continuation: bool = False
    stop_reason: str = ""
    level: str = ""
    tool_use_id: str = ""
    cwd: str = ""


@dataclass
class Compaction:
    """A `compact_boundary` record. Compaction starts a fresh chain whose
    `parentUuid` is null, so `logicalParentUuid` is the only thing tying the
    transcript back together across the seam."""

    event_uuid: str
    timestamp: str
    logical_parent_uuid: str = ""
    trigger: str = ""
    pre_tokens: int = 0
    duration_ms: int = 0


@dataclass
class ToolDenial:
    """A tool call that was requested and stopped, by the user or by the
    auto-mode classifier. The attempt is evidence whether or not it ran."""

    event_uuid: str
    timestamp: str
    kind: str
    source_event_uuid: str = ""
    result: str = ""
    cwd: str = ""


@dataclass
class ModelRefusal:
    """Safeguards declined a request. When a fallback model is named, the work
    was retried somewhere else rather than abandoned."""

    event_uuid: str
    timestamp: str
    category: str
    subtype: str = ""
    explanation: str = ""
    original_model: str = ""
    fallback_model: str = ""
    refused_message_uuid: str = ""
    retracted_uuids: list[str] = field(default_factory=list)
    content: str = ""


@dataclass
class Event:
    """One JSONL line, normalised. `parent_uuid` is what makes the transcript a graph."""

    uuid: str
    parent_uuid: str | None
    type: str
    timestamp: str
    line_no: int
    session_id: str = ""
    cwd: str = ""
    git_branch: str | None = None
    version: str | None = None
    entrypoint: str | None = None
    is_sidechain: bool = False
    logical_parent_uuid: str | None = None
    is_compact_summary: bool = False
    agent_id: str | None = None
    agent_type: str | None = None
    mcp_server: str | None = None
    mcp_tool: str | None = None
    plugin: str | None = None
    skill: str | None = None
    permission_mode: str | None = None
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)


@dataclass
class Session:
    """A single transcript file, indexed for causal traversal."""

    session_id: str
    path: str
    agent_id: str | None = None
    agent_type: str | None = None
    events: dict[str, Event] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    children: dict[str, list[str]] = field(default_factory=dict)
    roots: list[str] = field(default_factory=list)
    calls: dict[str, ToolCall] = field(default_factory=dict)
    results: dict[str, ToolResult] = field(default_factory=dict)
    versions: set[str] = field(default_factory=set)
    seen_fields: set[str] = field(default_factory=set)
    hook_runs: list[HookRun] = field(default_factory=list)
    denials: list[ToolDenial] = field(default_factory=list)
    compactions: list[Compaction] = field(default_factory=list)
    retracted_uuids: list[str] = field(default_factory=list)
    superseded_uuids: list[str] = field(default_factory=list)
    neutralized_by_fork: int = 0
    refusals: list[ModelRefusal] = field(default_factory=list)
    malformed_lines: int = 0
    # "recorded" when the transcript links each record to its parent,
    # "ordered" when only sequence is available. Detectors that reason
    # about descent must not run on the second.
    causality: str = "recorded"

    def result_for(self, call_id: str) -> ToolResult | None:
        return self.results.get(call_id)

    def ancestors(self, uuid: str) -> list[Event]:
        """Walk parent_uuid to the root. Cycle-guarded: transcripts are appended
        concurrently by subagents and a truncated write can produce a loop."""
        chain: list[Event] = []
        seen: set[str] = set()
        cur = self.events.get(uuid)
        while cur and (cur.parent_uuid or cur.logical_parent_uuid):
            parent_uuid = cur.parent_uuid or cur.logical_parent_uuid
            if parent_uuid in seen:
                break
            seen.add(parent_uuid)
            parent = self.events.get(parent_uuid)
            if parent is None:
                break
            chain.append(parent)
            cur = parent
        return chain

    def depth(self, uuid: str) -> int:
        return len(self.ancestors(uuid))

    def descendants(self, uuid: str, max_depth: int = 6) -> list[tuple["Event", int]]:
        """Events caused by `uuid`, breadth-first, bounded. The bound matters:
        everything after a root event is technically its descendant, so an
        unbounded walk would call the whole session a consequence of its first
        line."""
        found: list[tuple[Event, int]] = []
        frontier: list[tuple[str, int]] = [(uuid, 0)]
        seen: set[str] = {uuid}
        while frontier:
            node, depth = frontier.pop(0)
            if depth >= max_depth:
                continue
            for child in self.children.get(node, []):
                if child in seen:
                    continue
                seen.add(child)
                found.append((self.events[child], depth + 1))
                frontier.append((child, depth + 1))
        return found

    def iter_tool_calls(self):
        """Tool calls in file order, paired with their result when one exists."""
        for uuid in self.order:
            for call in self.events[uuid].tool_calls:
                yield call, self.results.get(call.call_id)
