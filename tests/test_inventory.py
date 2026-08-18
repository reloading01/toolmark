"""Tests for the supply-chain inventory."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.detect import detect_supply_chain  # noqa: E402
from toolmark.inventory import (  # noqa: E402
    collect_mcp_servers,
    collect_plugins,
    collect_project_trust,
    parse_timestamp,
)


def iso(days_ago: float) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


class McpInventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.claude = self.home / ".claude"
        self.claude.mkdir()
        self.addCleanup(self.tmp.cleanup)

    def write_global(self, data):
        (self.home / ".claude.json").write_text(json.dumps(data), encoding="utf-8")

    def test_collects_all_four_declaration_scopes(self):
        """A single config read is not an inventory: servers are declared in
        user and local scope in ~/.claude.json, in a project's .mcp.json, and
        at a plugin root."""
        project = self.home / "repo"
        (project / ".claude").mkdir(parents=True)
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"repo-server": {"command": "node", "args": ["s.js"]}}}), encoding="utf-8"
        )
        self.write_global(
            {
                "mcpServers": {"global-server": {"url": "https://x.tld/mcp", "type": "http"}},
                "projects": {str(project): {"mcpServers": {"local-server": {"command": "uvx thing"}}}},
            }
        )
        plugin_root = self.claude / "plugins" / "marketplaces" / "m" / "p"
        plugin_root.mkdir(parents=True)
        (plugin_root / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"plugin-server": {"command": "bun run x"}}}), encoding="utf-8"
        )

        servers = {s.name: s for s in collect_mcp_servers(self.claude, [project])}
        self.assertEqual(
            {n: s.scope for n, s in servers.items()},
            {
                "global-server": "user",
                "local-server": "local",
                "repo-server": "project",
                "plugin-server": "plugin",
            },
        )
        self.assertEqual(servers["repo-server"].command, "node s.js")
        self.assertEqual(servers["global-server"].url, "https://x.tld/mcp")

    def test_missing_config_is_not_an_error(self):
        self.assertEqual(collect_mcp_servers(self.claude, []), [])

    def test_trust_and_toggle_state_is_recorded_per_project(self):
        self.write_global(
            {
                "projects": {
                    "/repo-a": {"hasTrustDialogAccepted": True, "enabledMcpServers": ["a"]},
                    "/repo-b": {"hasTrustDialogAccepted": False, "disabledMcpServers": ["b"]},
                }
            }
        )
        trust = {t.project: t for t in collect_project_trust(self.claude)}
        self.assertTrue(trust["/repo-a"].trusted)
        self.assertEqual(trust["/repo-a"].enabled_mcp, ["a"])
        self.assertFalse(trust["/repo-b"].trusted)


class PluginInventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.claude = Path(self.tmp.name) / ".claude"
        (self.claude / "plugins").mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)

    def write(self, plugins, marketplaces):
        (self.claude / "plugins" / "installed_plugins.json").write_text(
            json.dumps({"version": 2, "plugins": plugins}), encoding="utf-8"
        )
        (self.claude / "plugins" / "known_marketplaces.json").write_text(
            json.dumps(marketplaces), encoding="utf-8"
        )

    def test_marks_plugins_from_unregistered_marketplaces(self):
        self.write(
            {
                "good@official": [{"installedAt": iso(100), "scope": "user"}],
                "bad@rogue": [{"installedAt": iso(1), "scope": "user"}],
            },
            {"official": {}},
        )
        plugins = {p.name: p for p in collect_plugins(self.claude)}
        self.assertTrue(plugins["good@official"].marketplace_known)
        self.assertFalse(plugins["bad@rogue"].marketplace_known)

    def test_unregistered_marketplace_is_high(self):
        self.write({"bad@rogue": [{"installedAt": iso(400)}]}, {"official": {}})
        findings = detect_supply_chain(
            [], collect_plugins(self.claude), [], reference_time=time.time()
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_recent_arrival_is_reported_and_old_one_is_not(self):
        self.write(
            {"fresh@official": [{"installedAt": iso(2)}], "old@official": [{"installedAt": iso(300)}]},
            {"official": {}},
        )
        findings = detect_supply_chain([], collect_plugins(self.claude), [], reference_time=time.time())
        names = [f.evidence["plugin"] for f in findings]
        self.assertEqual(names, ["fresh@official"])

    def test_no_reference_time_suppresses_the_recency_check(self):
        self.write({"fresh@official": [{"installedAt": iso(1)}]}, {"official": {}})
        self.assertEqual(detect_supply_chain([], collect_plugins(self.claude), [], reference_time=0.0), [])


class RepositoryDefinedServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.claude = self.home / ".claude"
        self.claude.mkdir()
        self.addCleanup(self.tmp.cleanup)

    def _project_server(self, trusted: bool):
        project = self.home / "repo"
        project.mkdir()
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"repo-server": {"command": "node s.js"}}}), encoding="utf-8"
        )
        (self.home / ".claude.json").write_text(
            json.dumps({"projects": {str(project): {"hasTrustDialogAccepted": trusted}}}), encoding="utf-8"
        )
        return collect_mcp_servers(self.claude, [project]), collect_project_trust(self.claude)

    def test_trusted_workspace_raises_the_severity(self):
        servers, trust = self._project_server(trusted=True)
        finding = detect_supply_chain(servers, [], trust)[0]
        self.assertEqual(finding.severity, "medium")
        self.assertTrue(finding.evidence["workspace_trusted"])

    def test_untrusted_workspace_stays_low(self):
        servers, trust = self._project_server(trusted=False)
        self.assertEqual(detect_supply_chain(servers, [], trust)[0].severity, "low")

    def test_user_scoped_servers_are_not_reported(self):
        (self.home / ".claude.json").write_text(
            json.dumps({"mcpServers": {"mine": {"command": "x"}}}), encoding="utf-8"
        )
        self.assertEqual(detect_supply_chain(collect_mcp_servers(self.claude, []), [], []), [])


class TimestampTest(unittest.TestCase):
    def test_parses_iso_with_and_without_zulu(self):
        self.assertGreater(parse_timestamp("2026-01-30T10:00:00.000Z"), 0)
        self.assertGreater(parse_timestamp("2026-01-30T10:00:00+00:00"), 0)

    def test_unparsable_values_are_zero(self):
        self.assertEqual(parse_timestamp(""), 0.0)
        self.assertEqual(parse_timestamp("not a date"), 0.0)


if __name__ == "__main__":
    unittest.main()
