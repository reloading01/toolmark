"""Supply-chain inventory: which MCP servers, plugins and skills are installed,
where they were declared, and when they arrived.

An agent's reach is whatever its components can do, and those components are
third-party code. The first confirmed malicious MCP server in the wild shipped
fifteen clean releases before adding an exfiltration line, so "what is
installed" and "what ran" are separate questions that have to be answered
separately and then compared.

Servers can be declared in four places, which is why a single config read is
not an inventory:

* user scope, `~/.claude.json` under a top-level `mcpServers`
* local scope, `~/.claude.json` under `projects.<path>.mcpServers`
* project scope, `.mcp.json` at the project root, committed to the repository
* plugin scope, `.mcp.json` or `plugin.json` at a plugin root

Project-scoped servers only load once the workspace is trusted, so the trust
decision recorded per project is part of the picture rather than a detail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class McpServer:
    name: str
    scope: str
    source: str
    transport: str = ""
    command: str = ""
    url: str = ""
    project: str = ""
    config: dict = field(default_factory=dict)


@dataclass
class InstalledPlugin:
    name: str
    marketplace: str
    install_path: str = ""
    version: str = ""
    installed_at: str = ""
    last_updated: str = ""
    scope: str = ""
    marketplace_known: bool = True


@dataclass
class ProjectTrust:
    project: str
    trusted: bool = False
    enabled_mcp: list[str] = field(default_factory=list)
    disabled_mcp: list[str] = field(default_factory=list)
    has_project_mcp_file: bool = False


def _load_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _server_from_config(name: str, config: dict, scope: str, source: str, project: str = "") -> McpServer:
    command = str(config.get("command", ""))
    args = config.get("args")
    if isinstance(args, list) and command:
        command = " ".join([command] + [str(a) for a in args])
    return McpServer(
        name=name,
        scope=scope,
        source=source,
        transport=str(config.get("type") or config.get("transport") or ("stdio" if command else "")),
        command=command,
        url=str(config.get("url", "")),
        project=project,
        config=config,
    )


def collect_mcp_servers(claude_dir: Path, project_dirs: list[Path] | None = None) -> list[McpServer]:
    servers: list[McpServer] = []
    home = claude_dir.parent
    global_config = _load_json(home / ".claude.json") or {}

    for name, config in (global_config.get("mcpServers") or {}).items():
        if isinstance(config, dict):
            servers.append(_server_from_config(name, config, "user", str(home / ".claude.json")))

    for project_path, record in (global_config.get("projects") or {}).items():
        if not isinstance(record, dict):
            continue
        for name, config in (record.get("mcpServers") or {}).items():
            if isinstance(config, dict):
                servers.append(
                    _server_from_config(name, config, "local", str(home / ".claude.json"), project_path)
                )

    for project in project_dirs or []:
        path = project / ".mcp.json"
        data = _load_json(path) if path.exists() else None
        if data:
            for name, config in (data.get("mcpServers") or data).items():
                if isinstance(config, dict):
                    servers.append(_server_from_config(name, config, "project", str(path), str(project)))

    plugins_root = claude_dir / "plugins"
    if plugins_root.exists():
        for path in list(plugins_root.rglob(".mcp.json")) + list(plugins_root.rglob("plugin.json")):
            data = _load_json(path)
            if not data:
                continue
            for name, config in (data.get("mcpServers") or {}).items():
                if isinstance(config, dict):
                    servers.append(_server_from_config(name, config, "plugin", str(path)))
    return servers


def collect_plugins(claude_dir: Path) -> list[InstalledPlugin]:
    installed = _load_json(claude_dir / "plugins" / "installed_plugins.json") or {}
    marketplaces = _load_json(claude_dir / "plugins" / "known_marketplaces.json") or {}
    known = set(marketplaces.keys())

    plugins: list[InstalledPlugin] = []
    entries = installed.get("plugins")
    if not isinstance(entries, dict):
        return plugins
    for qualified_name, records in entries.items():
        marketplace = qualified_name.split("@")[-1]
        for record in records if isinstance(records, list) else []:
            if not isinstance(record, dict):
                continue
            plugins.append(
                InstalledPlugin(
                    name=qualified_name,
                    marketplace=marketplace,
                    install_path=str(record.get("installPath", "")),
                    version=str(record.get("version", "")),
                    installed_at=str(record.get("installedAt", "")),
                    last_updated=str(record.get("lastUpdated", "")),
                    scope=str(record.get("scope", "")),
                    marketplace_known=marketplace in known,
                )
            )
    return plugins


def collect_project_trust(claude_dir: Path) -> list[ProjectTrust]:
    """Project-scoped servers come from a file inside the repository, so they
    only load once the workspace is trusted. The trust decision is the gate."""
    home = claude_dir.parent
    global_config = _load_json(home / ".claude.json") or {}
    records: list[ProjectTrust] = []
    for project_path, record in (global_config.get("projects") or {}).items():
        if not isinstance(record, dict):
            continue
        enabled = record.get("enabledMcpServers") or record.get("enabledMcpjsonServers") or []
        disabled = record.get("disabledMcpServers") or record.get("disabledMcpjsonServers") or []
        records.append(
            ProjectTrust(
                project=project_path,
                trusted=bool(record.get("hasTrustDialogAccepted")),
                enabled_mcp=[str(x) for x in enabled if isinstance(x, str)],
                disabled_mcp=[str(x) for x in disabled if isinstance(x, str)],
                has_project_mcp_file=(Path(project_path) / ".mcp.json").exists(),
            )
        )
    return records


def parse_timestamp(value: str) -> float:
    """ISO-8601 to epoch seconds, tolerating the trailing Z and missing values."""
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def format_timestamp(epoch: float) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
