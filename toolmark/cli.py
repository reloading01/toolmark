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
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .pastecache import iter_paste_cache
from .codex import iter_codex_sessions, parse_codex_session
from .artifacts import build_digest_index, iter_file_history, iter_jobs, probe_candidates, resolve_versions
from .custody import build_manifest, collect_evidence, now_iso
from .detect import (
    Finding,
    collect_declared_hook_commands,
    detect_cached_pastes,
    detect_config_tampering,
    detect_hooks,
    detect_job_risks,
    detect_pasted_injection,
    detect_path_hijack,
    detect_shell_shadowing,
    detect_supply_chain,
    run_session_detectors,
)
from .inventory import collect_mcp_servers, collect_plugins, collect_project_trust
from .history import measure_coverage, observed_retention, parse_history
from .parse import CORE_FIELDS, KNOWN_FIELDS, SIGNAL_FIELDS, iter_session_files, parse_session
from .redact import redact_value, truncate
from .timesketch import write_csv
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
            "kind": "tool_call",
            "is_sidechain": event.is_sidechain,
            "agent_id": event.agent_id or session.agent_id,
            "agent_type": event.agent_type or session.agent_type,
            "mcp_server": event.mcp_server,
            "plugin": event.plugin,
            "skill": event.skill,
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
    used_components: dict[str, set[str]] = {"mcp_server": set(), "plugin": set(), "skill": set()}
    newest_activity = 0.0
    session_ids: set[str] = set()
    transcript_projects: set[str] = set()
    session_entrypoints: dict[str, str] = {}
    versions: set[str] = set()
    seen_fields: set[str] = set()
    edited_paths: set[str] = set()
    cwds: set[str] = set()
    sessions_read = 0
    subagent_transcripts = 0
    malformed = 0
    injection_stats: dict[str, int] = {}
    started_at = now_iso()
    evidence_paths: list[Path] = []
    hook_runs = 0
    withdrawn = 0
    compactions = 0

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
        withdrawn += len(session.retracted_uuids) + len(session.superseded_uuids)
        compactions += len(session.compactions)
        findings.extend(
            run_session_detectors(session, redact_output, injection_stats, declared_hooks)
        )
        for call in session.calls.values():
            target = call.input.get("file_path") or call.input.get("notebook_path")
            if isinstance(target, str):
                edited_paths.add(target)
        cwds.update(event.cwd for event in session.events.values() if event.cwd)
        newest_activity = max(newest_activity, path.stat().st_mtime)
        evidence_paths.append(path)
        for event in session.events.values():
            if event.mcp_server:
                used_components["mcp_server"].add(event.mcp_server)
            if event.plugin:
                used_components["plugin"].add(event.plugin)
            if event.skill:
                used_components["skill"].add(event.skill)
        session_ids.add(session.session_id)
        transcript_projects.add(path.parent.name)
        if not session.agent_id:
            entrypoint = next((e.entrypoint for e in session.events.values() if e.entrypoint), "")
            session_entrypoints[session.session_id] = entrypoint
        if not args.no_timeline:
            timeline.extend(_timeline_rows(session, redact_output))

    # file-history entries are named by path digest with no manifest, so they
    # resolve only against paths seen in transcripts or paths we think to probe.
    home = claude_dir.parent
    evidence_paths.extend(
        p
        for p in [
            claude_dir / "history.jsonl",
            claude_dir / "settings.json",
            claude_dir / "settings.local.json",
            claude_dir / "policy-limits.json",
            claude_dir / "plugins" / "installed_plugins.json",
            claude_dir / "plugins" / "known_marketplaces.json",
            home / ".claude.json",
        ]
        if p.exists()
    )
    evidence_paths.extend((claude_dir / "plugins").rglob("hooks/hooks.json"))
    evidence_paths.extend(p / ".mcp.json" for p in projects if (p / ".mcp.json").exists())

    file_versions = iter_file_history(claude_dir)
    resolve_versions(file_versions, build_digest_index(edited_paths | set(probe_candidates(home, cwds))))
    findings.extend(detect_config_tampering(file_versions))
    evidence_paths.extend(Path(v.stored_path) for v in file_versions)

    jobs = iter_jobs(claude_dir)
    evidence_paths.extend((claude_dir / "jobs").rglob("state.json"))
    evidence_paths.extend((claude_dir / "jobs").rglob("timeline.jsonl"))
    findings.extend(detect_job_risks(jobs, redact_output))

    codex_sessions = 0
    codex_calls = 0
    if args.codex_dir:
        codex_dir = Path(args.codex_dir).expanduser()
        for path in iter_codex_sessions(codex_dir):
            if args.limit and codex_sessions >= args.limit:
                break
            session = parse_codex_session(path)
            codex_sessions += 1
            codex_calls += len(session.calls)
            malformed += session.malformed_lines
            evidence_paths.append(path)
            findings.extend(run_session_detectors(session, redact_output, injection_stats, declared_hooks))
            if not args.no_timeline:
                timeline.extend(_timeline_rows(session, redact_output))

    mcp_servers = collect_mcp_servers(claude_dir, projects)
    installed_plugins = collect_plugins(claude_dir)
    project_trust = collect_project_trust(claude_dir)
    findings.extend(
        detect_supply_chain(
            mcp_servers, installed_plugins, project_trust, newest_activity, redact_output=redact_output
        )
    )

    pastes = iter_paste_cache(claude_dir)
    findings.extend(detect_cached_pastes(pastes, redact_output))
    evidence_paths.extend(Path(p.path) for p in pastes)

    snapshots = iter_snapshots(claude_dir)
    evidence_paths.extend(Path(s.path) for s in snapshots)
    findings.extend(detect_shell_shadowing(snapshots, redact_output))
    findings.extend(detect_path_hijack(snapshots))

    history_records = [] if args.no_history else parse_history(claude_dir / "history.jsonl")
    coverage = None
    if history_records:
        findings.extend(detect_pasted_injection(history_records, redact_output))
        surviving = {s for s in session_ids if s}
        coverage = measure_coverage(history_records, surviving, transcript_projects, session_entrypoints)
        if not args.no_timeline:
            timeline.extend(
                {
                    "kind": "prompt",
                    "timestamp": record.iso,
                    "session_id": record.session_id,
                    "project": record.project,
                    "prompt": truncate(redact_value(record.prompt, redact_output), 500),
                    "pasted_items": len(record.pasted),
                    "transcript_present": bool(record.session_id and record.session_id in surviving),
                    "source": "history.jsonl",
                }
                for record in history_records
            )

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
                "kind": "mcp_server",
                "name": s.name,
                "scope": s.scope,
                "source": s.source,
                "transport": s.transport,
                "command": truncate(redact_value(s.command, redact_output), 300),
                "url": s.url,
                "project": s.project,
                "used_in_transcripts": s.name in used_components["mcp_server"],
            }
            for s in mcp_servers
        ]
        + [
            {
                "kind": "plugin",
                "name": p.name,
                "marketplace": p.marketplace,
                "marketplace_known": p.marketplace_known,
                "installed_at": p.installed_at,
                "last_updated": p.last_updated,
                "scope": p.scope,
                "used_in_transcripts": p.name.split("@")[0] in used_components["plugin"],
            }
            for p in installed_plugins
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

    if not args.no_timeline:
        csv_path = out_dir / "timeline.csv"
        written, dropped = write_csv(csv_path, timeline, [f.to_dict() for f in findings])
        outputs.append(
            f"{csv_path} ({written} Timesketch rows"
            + (f", {dropped} dropped for want of a timestamp" if dropped else "")
            + ")"
        )

    if not args.no_manifest:
        evidence = collect_evidence(evidence_paths, claude_dir)
        produced = [Path(line.split(" (")[0]) for line in outputs]
        manifest_path = out_dir / "manifest.json"
        manifest = build_manifest(
            tool_version=__version__,
            source_root=claude_dir,
            started_at=started_at,
            evidence=evidence,
            outputs=collect_evidence(produced, out_dir),
            redacted=redact_output,
        )
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
        outputs.append(
            f"{manifest_path} ({len(evidence)} evidence files, "
            f"{manifest['summary']['evidence_bytes'] / 1e6:.0f} MB hashed)"
        )

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
    if coverage:
        print(
            f"prompt history  : {coverage.total} prompts across {coverage.projects} projects, "
            f"{coverage.covered} with a surviving transcript",
            file=sys.stderr,
        )
        print(
            f"  evidence gap  : {coverage.orphaned} prompts whose transcript is gone "
            f"({coverage.orphan_ratio:.0%} of linkable), {coverage.unlinkable} with no session id to link",
            file=sys.stderr,
        )
        for entrypoint, (total_sessions, indexed_sessions) in sorted(coverage.by_entrypoint.items()):
            share = indexed_sessions / total_sessions if total_sessions else 0
            note = "" if share > 0.5 else "  <- prompts for these sessions are not in the index"
            print(
                f"  {entrypoint:<15} {indexed_sessions}/{total_sessions} sessions appear in the prompt history{note}",
                file=sys.stderr,
            )
    declared_names = {s.name for s in mcp_servers}
    used_names = used_components["mcp_server"]
    print(
        f"components      : {len(mcp_servers)} MCP servers declared, {len(installed_plugins)} plugins installed, "
        f"{sum(1 for t in project_trust if t.trusted)}/{len(project_trust)} projects trusted",
        file=sys.stderr,
    )
    if used_names:
        print(
            f"  reconciliation: {len(used_names & declared_names)}/{len(used_names)} servers seen in transcripts "
            f"are declared in config; the rest are injected by the host at runtime",
            file=sys.stderr,
        )
    if withdrawn or compactions:
        print(
            f"withdrawn       : {withdrawn} message(s) removed from transcripts, "
            f"{compactions} compaction boundary/ies",
            file=sys.stderr,
        )
    if codex_sessions:
        print(
            f"codex sessions  : {codex_sessions} ({codex_calls} tool calls); ordered only, so "
            f"injection chains are not evaluated for them",
            file=sys.stderr,
        )
    if pastes:
        intact = sum(1 for p in pastes if p.integrity_ok)
        print(
            f"cached pastes   : {len(pastes)} ({intact} matching their own digest)",
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

    spans = observed_retention(claude_dir)
    if spans:
        print("retention observed on disk (measured, not assumed):", file=sys.stderr)
        for plane, (oldest, newest, count) in sorted(spans.items(), key=lambda kv: -(kv[1][1] - kv[1][0])):
            days = (newest - oldest) / 86400
            print(
                f"  {plane:<16}{datetime.fromtimestamp(oldest, tz=timezone.utc):%Y-%m-%d} .. "
                f"{datetime.fromtimestamp(newest, tz=timezone.utc):%Y-%m-%d}  ({days:6.1f} days, {count} files)",
                file=sys.stderr,
            )

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
    scan.add_argument("--codex-dir", help="also scan a Codex CLI directory, for example ~/.codex")
    scan.add_argument("--no-manifest", action="store_true", help="skip the chain-of-custody manifest")
    scan.add_argument("--no-history", action="store_true", help="skip history.jsonl")
    scan.add_argument("--no-redact", action="store_true", help="do not mask secrets in output")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
