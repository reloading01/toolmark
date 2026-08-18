"""The single file an analyst reads first.

The JSONL outputs answer questions you already know how to ask. This one is for
the moment before that, when the question is "where do I even look", and it is
built around sessions rather than findings because an incident happens inside a
session, not inside a detector.

It also states what it cannot tell you. A report that lists what was found and
stays quiet about what was swept, withdrawn or never recorded reads as complete
when it is not, and at three in the morning nobody goes looking for the caveat.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

SEVERITY_WEIGHT = {"high": 10, "medium": 3, "low": 1}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# The one field per detector that says what actually happened.
_EVIDENCE_FIELD = {
    "credential_access": lambda e: _command(e.get("input")),
    "blocked_action": lambda e: _command(e.get("input")) or e.get("fallback_routes"),
    "injection_chain": lambda e: f"{e.get('markers')} -> {[c.get('kind') for c in e.get('consequences', [])]}",
    "hook_persistence": lambda e: _command(e.get("handler")) or e.get("event"),
    "hook_execution": lambda e: e.get("undeclared") or e.get("commands"),
    "permission_bypass": lambda e: f"{e.get('from')} -> {e.get('to')}, {e.get('tool_calls_in_window')} calls",
    "config_tampering": lambda e: e.get("resolved_path"),
    "job_risk": lambda e: e.get("command") or list(e.get("flags") or {}),
    "shell_shadowing": lambda e: f"{e.get('kind')} {e.get('name')}",
    "path_hijack": lambda e: e.get("entry"),
    "supply_chain": lambda e: e.get("plugin") or e.get("server"),
    "withdrawn_content": lambda e: e.get("retracted") or e.get("trigger"),
    "cached_paste": lambda e: e.get("markers") or e.get("content_digest"),
    "pasted_injection": lambda e: e.get("markers"),
}


def _command(value) -> str:
    if isinstance(value, dict):
        for key in ("command", "file_path", "url", "input"):
            if value.get(key):
                return str(value[key])
        return ""
    return str(value or "")


def _clip(text, limit: int = 130) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _evidence_line(finding: dict) -> str:
    getter = _EVIDENCE_FIELD.get(finding.get("detector", ""))
    if not getter:
        return ""
    try:
        return _clip(getter(finding.get("evidence") or {}))
    except Exception:
        return ""


def _score(findings: list[dict]) -> int:
    return sum(SEVERITY_WEIGHT.get(f.get("severity", "low"), 1) for f in findings)


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings, key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 3), f.get("timestamp") or "")
    )


def build_report(findings: list[dict], context: dict) -> str:
    by_session: dict[str, list[dict]] = defaultdict(list)
    hostwide: list[dict] = []
    for finding in findings:
        session = finding.get("session_id") or ""
        (by_session[session] if session else hostwide).append(finding)

    ranked = sorted(
        by_session.items(),
        key=lambda item: (
            -sum(1 for f in item[1] if f.get("severity") == "high"),
            -_score(item[1]),
        ),
    )
    with_high = [s for s, f in ranked if any(x.get("severity") == "high" for x in f)]

    lines: list[str] = []
    add = lines.append

    add("# toolmark report")
    add("")
    add(
        f"{context.get('source_root', '')} · {context.get('host', '')} · "
        f"generated {datetime.now(tz=timezone.utc).isoformat(timespec='seconds')} · "
        f"toolmark {context.get('tool_version', '')}"
    )
    add("")

    add("## Start here")
    add("")
    severities = Counter(f.get("severity") for f in findings)
    add(
        f"{len(findings)} findings across {len(by_session)} sessions "
        f"({severities.get('high', 0)} high, {severities.get('medium', 0)} medium, "
        f"{severities.get('low', 0)} low). {len(with_high)} sessions carry a high-severity finding."
    )
    add("")

    if ranked:
        total = sum(_score(f) for _, f in ranked) or 1
        top_share = sum(_score(f) for _, f in ranked[:5]) / total
        if top_share >= 0.5:
            add(
                f"The findings concentrate: the top five sessions hold {top_share:.0%} of the weight. "
                f"Start with them."
            )
        else:
            add(
                f"The findings are spread thin - the top five sessions hold only {top_share:.0%} of the "
                f"weight, which is what routine activity looks like rather than one event. Read the "
                f"detectors below for what is baseline here before chasing any single session."
            )
        add("")
        add("| session | project | high | med | low | first finding |")
        add("|---|---|---|---|---|---|")
        for session, group in ranked[:10]:
            counts = Counter(f.get("severity") for f in group)
            first = _sorted_findings(group)[0]
            project = context.get("session_projects", {}).get(session, "")
            add(
                f"| `{session[:8]}` | {project} | {counts.get('high', 0)} | {counts.get('medium', 0)} "
                f"| {counts.get('low', 0)} | {first.get('title', '')} |"
            )
        add("")

    add("## Sessions worth opening")
    add("")
    opened = 0
    for session, group in ranked:
        if not any(f.get("severity") == "high" for f in group) or opened >= 10:
            continue
        opened += 1
        counts = Counter(f.get("severity") for f in group)
        project = context.get("session_projects", {}).get(session, "")
        add(f"### `{session}`")
        add("")
        add(f"{project} · {counts.get('high', 0)} high, {counts.get('medium', 0)} medium, {counts.get('low', 0)} low")
        add("")
        for finding in _sorted_findings(group)[:12]:
            stamp = (finding.get("timestamp") or "")[:19]
            evidence = _evidence_line(finding)
            head = f"- **{finding.get('severity')}** `{finding.get('detector')}`"
            if stamp:
                head += f" {stamp}"
            add(head + f" — {finding.get('title')}" + (f"\n  `{evidence}`" if evidence else ""))
        if len(group) > 12:
            add(f"- ... and {len(group) - 12} more in findings.jsonl")
        add("")
    if not opened:
        add("No session carries a high-severity finding.")
        add("")

    if hostwide:
        add("## Configuration and host")
        add("")
        add("Findings that belong to the machine rather than to any one session.")
        add("")
        grouped: dict[str, list[dict]] = defaultdict(list)
        for finding in hostwide:
            grouped[finding.get("detector", "")].append(finding)
        for detector, group in sorted(grouped.items()):
            add(f"**{detector}** ({len(group)})")
            for finding in _sorted_findings(group)[:6]:
                evidence = _evidence_line(finding)
                add(
                    f"- {finding.get('severity')} — {finding.get('title')}"
                    + (f" · `{evidence}`" if evidence else "")
                )
            if len(group) > 6:
                add(f"- ... and {len(group) - 6} more")
            add("")

    add("## What this report cannot tell you")
    add("")
    for note in context.get("gaps", []):
        add(f"- {note}")
    add("")
    return "\n".join(lines)
