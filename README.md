# toolmark

Digital forensics for AI coding agents.

When a developer machine is compromised, or an agent does something nobody asked it to, the questions are the usual ones. What ran? In what order? What caused it? Claude Code already writes the answer to disk. Every tool call, its input, its result, the permission mode it ran under, and which subagent made it are sitting in `~/.claude`. Nothing reads that as evidence, so this does.

Toolmark analysis is the forensic discipline of reading the marks a tool leaves on a surface. This reads the marks an agent's tools leave on a machine.

## Install

```bash
git clone https://github.com/reloading01/toolmark
cd toolmark
python3 -m toolmark.cli scan --claude-dir ~/.claude --out-dir ./out
```

Python 3.10 or newer. No dependencies, no network calls, no telemetry. Everything is read-only.

## Preserve first

Detection quality counts for nothing against evidence that is already gone, and the windows are short. On the host this was built against, shell snapshots lasted under a day and transcripts about a month. By the time anyone notices an agent did something odd, the record of how it did it may have been swept.

```bash
toolmark preserve --claude-dir ~/.claude --codex-dir ~/.codex --archive ~/toolmark-archive
```

Blobs are content addressed under `objects/`, and `latest/` mirrors the source layout with hard links into them, so the archive costs one copy of each distinct file and can be read straight back:

```bash
toolmark scan --claude-dir ~/toolmark-archive/latest/claude
```

Nothing is removed from the mirror, which makes it the union of everything seen across runs rather than a snapshot of the current state.

Running it by hand only helps if you remember to, and the shortest windows measured were under a day, so a scheduled run is what makes the archive worth having. On macOS, write this to `~/Library/LaunchAgents/dev.toolmark.preserve.plist` and load it with `launchctl load -w <path>`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.toolmark.preserve</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>-m</string><string>toolmark.cli</string>
    <string>preserve</string>
    <string>--claude-dir</string><string>/Users/you/.claude</string>
    <string>--codex-dir</string><string>/Users/you/.codex</string>
    <string>--archive</string><string>/Users/you/toolmark-archive</string>
  </array>
  <key>WorkingDirectory</key><string>/path/to/toolmark</string>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardErrorPath</key><string>/Users/you/toolmark-archive/preserve.log</string>
</dict>
</plist>
```

Elsewhere, a cron line does the same job:

```
0 9 * * * cd /path/to/toolmark && /usr/bin/python3 -m toolmark.cli preserve --claude-dir ~/.claude --archive ~/toolmark-archive >> ~/toolmark-archive/preserve.log 2>&1
```

Daily is a compromise, not a guarantee: a snapshot plane that lives under a day can still be swept between runs. Preserving more often costs almost nothing, since an unchanged pass stores nothing at all. When a file disappears from the source the run says so, and the preserved copy is then the only one left. Runs are incremental: a second pass over 2,762 files took 1.3 seconds and stored nothing new. Cheap enough for a daily cron, which is the point.

## Run

```
sessions parsed : <n>
  subagent files : <n> of them are subagent transcripts
tool calls      : <n>
file versions   : <n> (<n> resolved to a path, <n> anonymous)
ingress scanned : <n> results (<n> carried instruction-like markers)
hook executions : <n> recorded (<n> hook commands declared in config)
prompt history  : <n> prompts across <n> projects, <n> with a surviving transcript
  evidence gap  : <n> prompts whose transcript is gone (<n>% of linkable)
background jobs : <n>
shell snapshots : <n>
findings        : {'high': <n>, 'medium': <n>, 'low': <n>}
agent versions  : <oldest>..<newest> (<n> versions)
```

Three files land in `--out-dir`:

| File | Contents |
|---|---|
| `findings.jsonl` | One record per detection, severity-ordered, with the evidence attached |
| `timeline.jsonl` | One record per tool call: parent, depth, subagent, outcome, permission mode, cwd, git branch |
| `report.md` | The triage report: where to start, what each session did, and what the run could not see |
| `timeline.csv` | The same timeline in Timesketch's import format, with findings interleaved as events |
| `manifest.json` | Chain of custody: a SHA-256 of every artifact read and every report written, with the acquisition context |
| `artifacts.jsonl` | File versions, background jobs and shell snapshots recovered from the other artifact planes |

Useful flags: `--since-days N` to time-box a triage, `--project PATH` to pull in a repository's `.claude/settings.json`, `--limit N`, `--no-timeline`, `--no-redact`.

`report.md` is the one to open first. The JSONL files answer questions you already know how to ask; the report is for the moment before that, when the question is where to look at all. It ranks sessions rather than findings, because an incident happens inside a session and a list sorted by severity just interleaves twenty of them.

It also states its own limits. A run that reports what it found and stays quiet about what was swept, withdrawn or never recorded reads as complete when it is not, so the last section says how many prompts have no surviving transcript, which retention windows are shortest, how many messages were withdrawn, and how many sessions record order without causation. If the findings do not concentrate in a few sessions the report says that too, rather than pointing at a top session the data does not support.

`timeline.csv` is the same data in the shape Timesketch imports: `message`, `datetime` with an offset, `timestamp_desc`, and the agent-specific fields riding along as extra columns. Findings are written as events too, so a single sketch holds what happened and what was flagged on one axis. Rows with no usable timestamp cannot be placed and are dropped, and the count comes back with the run rather than disappearing quietly.

Every run writes a chain-of-custody manifest alongside the reports, following what NIST SP 800-86 asks a collection to record: what was acquired, from which host, when, by whom, and with which procedure, plus a SHA-256 of each item so a later reader can prove nothing changed. The reports are hashed too, since a manifest covering only the inputs would let findings be edited afterwards without leaving a trace. Hashing the whole corpus costs a few seconds, so it is on by default; `--no-manifest` turns it off. The manifest cannot cover itself, and says so.

Note that the manifest records the operator account and hostname on purpose. That is the point of a custody record, and it is also why the output directory is not something to commit.

Secrets are masked by default. The report is itself a leak surface, because transcripts hold raw prompts, file contents and credentials, so turning masking off is explicit.

## What it detects

| Detector | Fires on |
|---|---|
| `hook_persistence` | Hooks that run code on their own schedule, across all five handler types and every file a hook can be declared in |
| `withdrawn_content` | Messages the transcript says were retracted or superseded, and context lost to compaction |
| `blocked_action` | Tool calls the user or the auto-mode classifier stopped, and requests the model's own safeguards declined |
| `supply_chain` | Plugins from unregistered marketplaces, components introduced just before the activity collected, and MCP servers the repository defines for itself |
| `cached_paste` | Instruction-like content in a cached paste, and entries that no longer match their own digest |
| `pasted_injection` | Instruction-like content entering through a prompt or a paste, which outlives the transcript that would show what came of it |
| `hook_execution` | Hooks that actually ran: ones that errored, blocked the agent, injected context, or fired from a declaration that no longer exists |
| `injection_chain` | Instruction-like content the agent read, followed by a sensitive action descending from it |
| `credential_access` | Tool calls targeting credential material, reported with the outcome so an attempt is not filed as a success |
| `permission_bypass` | A session that escalated into unattended execution mid-run, separated from one launched that way |
| `config_tampering` | The agent writing its own configuration, with the prior content still recoverable |
| `job_risk` | Background jobs launched with relaxed permissions, and the shell tasks they fanned out |
| `shell_shadowing` | Functions and aliases named after real binaries, minus the ones the tool installs itself |
| `path_hijack` | PATH elements resolving to the working directory, a temp directory, or a relative path |

Two of those are worth expanding on.

**Hooks are the persistence primitive on this platform.** [CVE-2026-25725](https://github.com/anthropics/claude-code/security/advisories/GHSA-ff64-7w26-62rf) let code inside the sandbox create `.claude/settings.json` with a `SessionStart` hook, which then ran with host privileges on the next start. A hook can be declared in user settings, project settings, local settings, managed policy, a plugin's `hooks/hooks.json`, skill frontmatter or subagent frontmatter, and can be a `command`, `http`, `mcp_tool`, `prompt` or `agent` handler. An `http` handler carrying `allowedEnvVars` is an environment-variable exfiltration primitive with a hook's name on it. Hooks belonging to plugins installed from a marketplace listed in `known_marketplaces.json` are downgraded, since they are declared infrastructure rather than implants.

Declared and executed are different questions, and the transcript answers the second one. `stop_hook_summary` records carry the hooks that actually ran, their errors, whether one blocked the agent from continuing, and whether one fed additional context back into the model. Comparing those commands against every declaration still on disk catches the shape that config scanning cannot: a hook that ran, and whose declaration was then deleted.

**A transcript can say it is incomplete.** When safeguards decline a request the offending messages are retracted, and an assistant message can supersede earlier ones. Neither survives: none of the referenced identifiers were found anywhere on disk, in the same transcript or any other. So this is not recoverable content, it is a documented hole, and a report that stays silent about it implies a completeness the file does not have. Compaction is the same shape at a larger scale, and it also breaks the graph: a compaction boundary carries a null parent and links back only through `logicalParentUuid`, so the parser follows that link when stitching the tree and when walking ancestors.

**Blocked attempts are evidence too.** A tool call that was stopped still states what the agent was trying to do, and anything reading only what succeeded misses it entirely. Denials come from two places: the user declining a prompt, and the auto-mode classifier refusing an action. The classifier pauses auto mode after three consecutive blocks, so that documented threshold is what raises severity rather than an invented one. Separately, the model's own safeguards can decline a request; when the transcript names a fallback model, the work was retried elsewhere rather than abandoned, and that is the part worth reading. Refusals are grouped per session and category, because a session that trips safeguards repeatedly should be one finding rather than a hundred.

**Injection chains need both halves.** Content that reads like an instruction, and a sensitive action descending from it in the causal graph. Proximity alone means nothing, because reading a file and then running a command is what the tool does all day. Markers alone are worse, because they fire on any repository that discusses prompt injection, including this one. So marker-only reporting was rejected rather than shipped and tuned later. Markers cover instruction override, concealment from the user, system-tag spoofing, and zero-width or unicode-tag characters. Consequences cover credential access, egress, a write to the agent's own config, and escalation into an unattended permission mode.

## Artifacts it reads

| Path | What is in it |
|---|---|
| `projects/<project>/<session>.jsonl` | The session transcript: prompts, tool calls, results, permission mode, cwd, git branch |
| `projects/<project>/<session>/subagents/agent-<id>.jsonl` | Subagent transcripts, carrying the parent session id plus their own `agentId` and `attributionAgent` |
| `file-history/<session>/<digest>@v<N>` | The agent's own copy of every file it edited, versioned |
| `jobs/<id>/state.json`, `timeline.jsonl` | Background job launch flags, fanned-out shell tasks, and the job's state transitions |
| `shell-snapshots/snapshot-<shell>-<epoch_ms>-<id>.sh` | The shell as the agent saw it: functions, aliases, options, exported PATH |
| `~/.claude.json` | User and local scoped MCP servers, per-project trust decisions, server enable/disable state, and a tool usage ledger |
| `<project>/.mcp.json` | Project-scoped MCP servers, committed to the repository |
| `paste-cache/` | Text pasted into a session, stored as `<sha256(content)[:16]>.txt`, so each entry checks its own integrity |
| `history.jsonl` | Every prompt typed at the terminal, with timestamp, project and pasted content inline |
| `settings.json`, `plugins/`, `known_marketplaces.json` | Configuration, installed plugins, registered marketplaces |

`parentUuid` is the point of the whole thing. A transcript is not a flat log. Every record names its parent, which is what makes "which file read led to which command" an answerable question instead of a guess. `isSidechain` and `subagent_type` separate subagent branches from the main thread.

`file-history` entries are named `<sha256(absolute path)[:16]>@v<N>` with no manifest, so the directory is anonymous by itself. The path comes either from edit targets in the transcripts, or from hashing a path you already suspect and looking for it. The second route still works after the 30-day transcript cleanup, which is exactly when it matters. Content is hard-linked across session directories, so an entry filed under a session whose transcript is gone still resolves if the same file was edited in a surviving session.

## Supply chain

An agent's reach is whatever its components can do, and those components are third-party code. The first confirmed malicious MCP server in the wild shipped fifteen clean releases before adding a line that copied every email to its author, so what is installed and what ran are separate questions.

Servers are declared in four places and a single config read is not an inventory: user scope and local scope both live in `~/.claude.json`, project scope lives in a `.mcp.json` committed to the repository, and plugins declare their own. Project-scoped servers only load once the workspace is trusted, so the trust decision recorded per project is part of the picture rather than a footnote. Attribution runs the other direction: transcripts record which MCP server, tool, plugin and skill produced each action, so a finding can name the component rather than only the session.

One comparison is deliberately not a finding. A server used in a transcript with no matching declaration looks like the obvious detection, but measurement shows the host injects servers at runtime that appear in no configuration file at all, so the check flags ordinary desktop use. It is reported as reconciliation instead, with the count stated plainly.

## Evidence coverage

Transcripts are swept by `cleanupPeriodDays`, default 30. `history.jsonl` is not, and routinely reaches back an order of magnitude further, which is why a run reports how much of the prompt history still has a transcript behind it. That number is the honest way to state how much of a timeline is missing before anyone reads a finding.

Pasted text lands in `paste-cache/` under a name that is a digest of the content, so an entry can be integrity-checked with nothing else to hand and a mismatch means the file changed after it was written. That plane covers a surface the prompt index does not: none of the cached pastes measured had a counterpart in `history.jsonl`, because they came from sessions the index never recorded.

The index is not complete, though, and the gap is not random. Measured across a real machine, every session started at the terminal appears in it and effectively none of the desktop sessions do. So for terminal work the record of what the agent was told outlives the record of what it did; for desktop work, when the transcript goes, the prompts go with it. The coverage report breaks the ratio down by entrypoint rather than averaging the two into a number that describes neither.

Retention itself is measured rather than assumed. The documented behaviour has contradicted the changelog across releases, and the spans observed on disk differ per plane by more than an order of magnitude, so a run prints the window it actually found for each one.

## Which agents

Claude Code in full, and Codex CLI for everything its transcripts support.

```bash
python3 -m toolmark.cli scan --claude-dir ~/.claude --codex-dir ~/.codex --out-dir ./out
```

The split that matters is between parsers and detectors. Detectors reason about commands, paths, configuration and permissions, so they port. The parser is the agent-specific half, and adding an agent means writing one.

Codex keeps a session per JSONL under `~/.codex/sessions/<yyyy>/<mm>/<dd>/` and `archived_sessions/`, in a flat `{timestamp, type, payload}` envelope. Measured rather than assumed, this is what carries over:

| Question | Codex |
|---|---|
| What ran, and did it succeed | Yes. Calls pair with output through `call_id`, and `exec_command_end` supplies the command and its exit code |
| Was it running unattended | Yes. `turn_context` carries `approval_policy` and `sandbox_policy`; an approval policy of `never` is no human in the loop |
| Which component acted | Yes, for MCP. `mcp_tool_call_end` names the server and the tool |
| What caused what | No. Records carry no parent link, and `turn_id` is absent from tool calls |

So the timeline and the detectors that reason about a single action port; the causal ones do not. Sessions are marked `causality="ordered"`, and `injection_chain` declines to run on them rather than treating adjacency as causation, which is the mistake it exists to avoid. The run says how many sessions were skipped for that reason.

Codex also carries its own version of nearly every plane below: `shell_snapshots/`, `history.jsonl`, `skills/`, `plugins/`, `rules/`, `memories/`, SQLite state stores, and an `auth.json` holding live credentials. Those are not parsed yet.

## Supply chain

An agent's reach is whatever its components can do, and those components are third-party code. The first confirmed malicious MCP server in the wild shipped fifteen clean releases before adding a line that copied every email to its author, so what is installed and what ran are separate questions.

Servers are declared in four places and a single config read is not an inventory: user scope and local scope both live in `~/.claude.json`, project scope lives in a `.mcp.json` committed to the repository, and plugins declare their own. Project-scoped servers only load once the workspace is trusted, so the trust decision recorded per project is part of the picture rather than a footnote. Attribution runs the other direction: transcripts record which MCP server, tool, plugin and skill produced each action, so a finding can name the component rather than only the session.

One comparison is deliberately not a finding. A server used in a transcript with no matching declaration looks like the obvious detection, but measurement shows the host injects servers at runtime that appear in no configuration file at all, so the check flags ordinary desktop use. It is reported as reconciliation instead, with the count stated plainly.

## Evidence coverage

Transcripts are swept by `cleanupPeriodDays`, default 30. `history.jsonl` is not, and routinely reaches back an order of magnitude further, which is why a run reports how much of the prompt history still has a transcript behind it. That number is the honest way to state how much of a timeline is missing before anyone reads a finding.

Pasted text lands in `paste-cache/` under a name that is a digest of the content, so an entry can be integrity-checked with nothing else to hand and a mismatch means the file changed after it was written. That plane covers a surface the prompt index does not: none of the cached pastes measured had a counterpart in `history.jsonl`, because they came from sessions the index never recorded.

The index is not complete, though, and the gap is not random. Measured across a real machine, every session started at the terminal appears in it and effectively none of the desktop sessions do. So for terminal work the record of what the agent was told outlives the record of what it did; for desktop work, when the transcript goes, the prompts go with it. The coverage report breaks the ratio down by entrypoint rather than averaging the two into a number that describes neither.

Retention itself is measured rather than assumed. The documented behaviour has contradicted the changelog across releases, and the spans observed on disk differ per plane by more than an order of magnitude, so a run prints the window it actually found for each one.

## Which agents

Claude Code today, in full: the causal tree plus all four artifact planes.

The split that matters is between parsers and detectors. Detectors reason about commands, paths, configuration and permissions, so they port to any agent. The parser is the agent-specific half, and adding an agent means writing one.

Porting is not uniform, and it is worth being concrete about why. Codex CLI keeps transcripts in `~/.codex/sessions/` and `archived_sessions/rollout-<timestamp>-<session-id>.jsonl`, with a flat `{timestamp, type, payload}` envelope and record types including `session_meta`, `user_message`, `custom_tool_call` and `custom_tool_call_output`. Tool calls and their outputs are all there, but records carry no parent link. The detectors port and the ordered timeline ports; the causal tree does not. On Codex you can say what happened in what order, not what caused what. That is a difference in evidential strength, not a porting detail.

Codex also carries its own version of nearly every plane above: `shell_snapshots/`, `history.jsonl`, `skills/`, `plugins/`, `rules/`, `memories/`, SQLite state stores, and an `auth.json` holding live credentials. Different layout, same investigative questions.

## How severity is decided

Severity answers "does this need looking at now", not "is this bad". The rules that decide it are worth knowing before you read a report, because they are also the rules that keep a normal developer machine quiet.

- Only action-bearing input fields are matched. A credential path in a `description`, in file content, or in an edit's replacement text is discussion about credentials, not access to them.
- Outcome matters. A credential read that failed is reported below one that succeeded, taken from `toolUseResult` rather than assumed from the attempt.
- Routine material is separated from damaging material. `.aws/credentials` and `.ssh/id_*` stand on their own; `.env` and `.npmrc` are ordinary in development and only escalate when the same command also sends data off the host. `.env.example` and its relatives never count, since templates carry variable names rather than values.
- `ssh host '<body>'` and `docker exec` are read as remote administration, so markers inside the body describe the remote host rather than a local read. That is overridden when the output pipes into a local data-send primitive, which is exfiltration whichever host produced the data.
- Expected infrastructure is downgraded rather than hidden. Hooks from plugins installed via a registered marketplace, and the `find`, `grep` and `pkill` shadows the agent installs itself, appear at low severity instead of vanishing.
- A session launched in an unattended permission mode is a baseline observation. A session that escalated into one mid-run is not.

Findings are noise-tuned against real usage, which is not the same as a detection rate. There is no labelled ground truth here, so no true-positive rate is claimed.

## Limits

- Nothing is pinned to an agent version. The schema drifts between releases, and a field can disappear inside one release as easily as across two, so the CLI measures the schema rather than comparing version strings. It reports the version range it saw, warns when a field the parser depends on is missing from the data, and flags top-level fields present in the transcripts that this build does not read yet. In practice that last check surfaces real gaps: hook execution records, attribution for MCP servers, tools, plugins and skills, and the ids of retracted or superseded messages.
- Retention differs per artifact plane and the documentation has not kept up with the changelog, so nothing here hardcodes a window. Every run prints the span it measured on disk. Collect before you triage regardless: some planes are swept within a day.
- `history.jsonl` records prompts entered at the terminal. Desktop sessions were absent from it in every case measured, so it cannot be treated as a complete prompt index.
- Hook execution records only cover stop time. Other hook events leave no equivalent summary in the transcript, so a `PreToolUse` handler that ran is not visible this way. In-process handlers also report themselves as `callback` with no identifying command, so they can be counted but never matched against a declaration.
- Shell function bodies are extracted by treating a `}` in column zero as the terminator. That holds for these generated snapshots and would not hold for hand-written shell.
- A `file-history` entry proves a write happened and preserves the content, but carries no timestamp beyond the filesystem mtime and no link to the tool call that made it. Correlation is by session id and path.
- This is not a collector. [TRACE](https://github.com/ionsec/trace) already collects AI and LLM endpoint artifacts across 27 targets with chain-of-custody hashing and STIX output. Point `--claude-dir` at a live host, a mounted image, or a collector's output.
- It is not a session viewer either. Several exist, including [qent/jsonl](https://github.com/qent/jsonl) and [claude-session-viewer](https://github.com/jtklinger/claude-session-viewer), and they render conversations for people to read.

## Tests

```bash
python3 -m unittest discover -s tests
```

No test dependencies. Most cases are synthetic transcripts reproducing real shapes, including the CVE-2026-25725 hook and a full injection chain.

One of them is different in kind. `test_end_to_end.py` builds an agent directory carrying one instance of every shape the tool looks for, runs the real CLI over it, and checks each detector produces its finding. Everything else measures behaviour on benign data, where the correct answer is silence; a detector that cannot fire at all looks exactly the same. This is what separates the two.

## Prior work

Artifact locations were first documented publicly by [Intrinsec](https://www.intrinsec.com/en/claude-code-forensics/). The five-plane agent artifact taxonomy comes from Jan Gruber and Jan-Niclas Hilgert, [Foundations for Agentic AI Investigations from the Forensic Analysis of OpenClaw](https://arxiv.org/abs/2604.05589), with code at [jgru/forensic-analysis-of-openclaw](https://github.com/jgru/forensic-analysis-of-openclaw).

MIT licensed.
