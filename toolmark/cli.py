"""toolmark CLI: parse Claude Code transcripts into a causal timeline and
run agent-layer detectors over them.

Collection is deliberately out of scope. Point `--claude-dir` at a live host or
at the output of a collector (TRACE, Velociraptor, a mounted image).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .artifacts import build_digest_index, iter_file_history, iter_jobs, probe_candidates, resolve_versions
from .detect import (
    Finding,
    collect_declared_hook_commands,
    detect_config_tampering,
    detect_hooks,
    detect_job_risks,
    detect_path_hijack,
    detect_shell_shadowing,
    run_session_detectors,
)
from .parse import CORE_FIELDS, KNOWN_FIELDS, SIGNAL_FIELDS, iter_session_files, parse_session
from .redact import redact_value, truncate
from .shellsnap import iter_snapshots

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _timeline_rows(session, redact_output: bool):
    for call, result in session.iter_tool_calls():
        event = session.events[call.event_uuid]
        yield {
            "timestamp": call.timestamp,
            "session_id": session.session_id,
            "event_uuid": call.event_uuid,
            "parent_uuid": event.parent_uuid,
            "depth": session.depth(call.event_uuid),
            "is_sidechain": event.is_sidechain,
            "agent_id": event.agent_id or session.agent_id,
            "agent_type": event.agent_type or session.agent_type,
            "tool": call.name,
            "subagent_type": call.input.get("subagent_type") if isinstance(call.input, dict) else None,
            "input": redact_value(call.input, redact_output),
            "outcome": result.outcome if result else "no result recorded",
            "stderr": truncate(redact_value(result.stderr, redact_output), 300) if result else "",
            "permission_mode": event.permission_mode,
            "cwd": event.cwd,
            "git_branch": event.git_branch,
            "version": event.version,
            "source": session.path,
        }


def _write_jsonl(path: Path, rows) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            count += 1
    return count


def cmd_scan(args: argparse.Namespace) -> int:
    claude_dir = Path(args.claude_dir).expanduser()
    if not claude_dir.exists():
        print(f"error: {claude_dir} does not exist", file=sys.stderr)
        return 2

    redact_output = not args.no_redact
    projects = [Path(p).expanduser() for p in args.project or []]
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    findings: list[Finding] = detect_hooks(claude_dir, projects, redact_output)
    declared_hooks = collect_declared_hook_commands(claude_dir, projects)

    timeline: list[dict] = []
    versions: set[str] = set()
    seen_fields: set[str] = set()
    edited_paths: set[str] = set()
    cwds: set[str] = set()
    sessions_read = 0
    subagent_transcripts = 0
    malformed = 0
    injection_stats: dict[str, int] = {}
    hook_runs = 0

    for path in iter_session_files(claude_dir / "projects", args.since_days):
        if args.limit and sessions_read >= args.limit:
            break
        session = parse_session(path)
        sessions_read += 1
        if session.agent_id:
            subagent_transcripts += 1
        malformed += session.malformed_lines
        versions |= session.versions
        seen_fields |= session.seen_fields
        hook_runs += len(session.hook_runs)
        findings.extend(
            run_session_detectors(session, redact_output, injection_stats, declared_hooks)
        )
        for call in session.calls.values():
            target = call.input.get("file_path") or call.input.get("notebook_path")
            if isinstance(target, str):
                edited_paths.add(target)
        cwds.update(event.cwd for event in session.events.values() if event.cwd)
        if not args.no_timeline:
            timeline.extend(_timeline_rows(session, redact_output))

    # file-history entries are named by path digest with no manifest, so they
    # resolve only against paths seen in transcripts or paths we think to probe.
    home = claude_dir.parent
    file_versions = iter_file_history(claude_dir)
    resolve_versions(file_versions, build_digest_index(edited_paths | set(probe_candidates(home, cwds))))
    findings.extend(detect_config_tampering(file_versions))

    jobs = iter_jobs(claude_dir)
    findings.extend(detect_job_risks(jobs, redact_output))

    snapshots = iter_snapshots(claude_dir)
    findings.extend(detect_shell_shadowing(snapshots, redact_output))
    findings.extend(detect_path_hijack(snapshots))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.timestamp))

    findings_path = out_dir / "findings.jsonl"
    written = _write_jsonl(findings_path, (f.to_dict() for f in findings))
    outputs = [f"{findings_path} ({written} findings)"]

    if not args.no_timeline:
        timeline.sort(key=lambda r: r["timestamp"] or "")
        timeline_path = out_dir / "timeline.jsonl"
        written = _write_jsonl(timeline_path, timeline)
        outputs.append(f"{timeline_path} ({written} tool calls)")

    artifacts_path = out_dir / "artifacts.jsonl"
    resolved = sum(1 for v in file_versions if v.resolved_path)
    written = _write_jsonl(
        artifacts_path,
        [
            {
                "kind": "file_version",
                "session_id": v.session_id,
                "digest": v.digest,
                "version": v.version,
                "resolved_path": v.resolved_path,
                "stored_path": v.stored_path,
                "size": v.size,
                "mtime": v.mtime,
            }
            for v in file_versions
        ]
        + [
            {
                "kind": "shell_snapshot",
                "path": s.path,
                "shell": s.shell,
                "epoch_ms": s.epoch_ms,
                "functions": len(s.functions),
                "aliases": len(s.aliases),
                "path_entries": s.path_entries,
            }
            for s in snapshots
        ]
        + [
            {
                "kind": "job",
                "job_id": j.job_id,
                "state": j.state,
                "session_id": j.session_id,
                "cwd": j.cwd,
                "cli_version": j.cli_version,
                "created_at": j.created_at,
                "updated_at": j.updated_at,
                "detail": truncate(redact_value(j.detail, redact_output), 300),
                "flags": redact_value(j.flags, redact_output),
                "shell_tasks": [truncate(redact_value(t, redact_output), 300) for t in j.shell_tasks],
                "timeline_events": len(j.timeline),
            }
            for j in jobs
        ],
    )
    outputs.append(f"{artifacts_path} ({written} artifact records)")

    by_detector = Counter(f.detector for f in findings)
    by_severity = Counter(f.severity for f in findings)

    print(f"sessions parsed : {sessions_read}", file=sys.stderr)
    print(
        f"  subagent files : {subagent_transcripts} of them are subagent transcripts",
        file=sys.stderr,
    )
    print(f"tool calls      : {len(timeline)}", file=sys.stderr)
    if malformed:
        print(f"malformed lines : {malformed}", file=sys.stderr)
    print(
        f"file versions   : {len(file_versions)} ({resolved} resolved to a path, "
        f"{len(file_versions) - resolved} anonymous)",
        file=sys.stderr,
    )
    print(
        f"ingress scanned : {injection_stats.get('ingress_scanned', 0)} results "
        f"({injection_stats.get('ingress_with_markers', 0)} carried instruction-like markers)",
        file=sys.stderr,
    )
    print(
        f"hook executions : {hook_runs} recorded ({len(declared_hooks)} hook commands declared in config)",
        file=sys.stderr,
    )
    print(f"background jobs : {len(jobs)}", file=sys.stderr)
    print(
        f"shell snapshots : {len(snapshots)} "
        f"({sum(len(s.functions) for s in snapshots)} functions, {sum(len(s.aliases) for s in snapshots)} aliases)",
        file=sys.stderr,
    )
    print(f"findings        : {dict(by_severity)} {dict(by_detector)}", file=sys.stderr)
    for line in outputs:
        print(f"wrote           : {line}", file=sys.stderr)

    if versions:
        ordered = sorted(versions)
        span = ordered[0] if len(ordered) == 1 else f"{ordered[0]}..{ordered[-1]} ({len(ordered)} versions)"
        print(f"agent versions  : {span}", file=sys.stderr)

    # Schema health is measured, not assumed from a version string: a field
    # this build reads can vanish inside a single release.
    missing_core = sorted(CORE_FIELDS - seen_fields)
    missing_signal = sorted(SIGNAL_FIELDS - seen_fields)
    drift = sorted(seen_fields - KNOWN_FIELDS)
    if missing_core:
        print(
            f"warning         : core fields absent from every transcript {missing_core}; "
            f"the parser's assumptions do not hold for this data",
            file=sys.stderr,
        )
    if missing_signal:
        print(
            f"note            : signal fields never seen {missing_signal}; "
            f"detectors relying on them cannot fire",
            file=sys.stderr,
        )
    if drift:
        print(
            f"note            : {len(drift)} unread top-level field(s) present {drift[:8]}"
            f"{' ...' if len(drift) > 8 else ''}; schema has moved past this build",
            file=sys.stderr,
        )
    if redact_output:
        print("note            : secrets masked in output; pass --no-redact for raw values", file=sys.stderr)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="toolmark", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="parse transcripts and run detectors")
    scan.add_argument("--claude-dir", default="~/.claude", help="agent home directory (default: ~/.claude)")
    scan.add_argument("--project", action="append", help="project root to scan for .claude/settings.json (repeatable)")
    scan.add_argument("--out-dir", default="toolmark-out", help="output directory")
    scan.add_argument("--since-days", type=int, help="only transcripts within N days of the newest one")
    scan.add_argument("--limit", type=int, help="stop after N transcripts")
    scan.add_argument("--no-timeline", action="store_true", help="skip timeline.jsonl")
    scan.add_argument("--no-redact", action="store_true", help="do not mask secrets in output")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
