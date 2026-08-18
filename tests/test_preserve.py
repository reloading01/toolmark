"""Tests for the preservation archive."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.preserve import plan_paths, preserve  # noqa: E402


class ArchiveCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.claude = self.home / ".claude"
        (self.claude / "projects" / "p").mkdir(parents=True)
        (self.claude / "projects" / "p" / "a.jsonl").write_text("one", encoding="utf-8")
        (self.claude / "history.jsonl").write_text("hist", encoding="utf-8")
        self.archive = self.home / "archive"
        self.addCleanup(self.tmp.cleanup)

    def run_once(self):
        return preserve(plan_paths(self.claude), self.archive)


class PlanTest(ArchiveCase):
    def test_covers_trees_and_single_files(self):
        relatives = {rel for _, rel in plan_paths(self.claude)}
        self.assertIn("claude/projects/p/a.jsonl", relatives)
        self.assertIn("claude/history.jsonl", relatives)

    def test_plugin_manifests_are_kept_and_plugin_source_trees_are_not(self):
        hooks = self.claude / "plugins" / "marketplaces" / "m" / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "hooks.json").write_text("{}", encoding="utf-8")
        cache = self.claude / "plugins" / "cache" / "big"
        cache.mkdir(parents=True)
        (cache / "bundle.js").write_text("x" * 100, encoding="utf-8")

        relatives = {rel for _, rel in plan_paths(self.claude)}
        self.assertIn("claude/plugins/marketplaces/m/hooks/hooks.json", relatives)
        self.assertFalse(any("bundle.js" in rel for rel in relatives))

    def test_global_config_is_namespaced_outside_the_claude_tree(self):
        (self.home / ".claude.json").write_text("{}", encoding="utf-8")
        self.assertIn("claude.json", {rel for _, rel in plan_paths(self.claude)})

    def test_codex_sessions_are_namespaced_separately(self):
        codex = self.home / ".codex" / "sessions" / "2026"
        codex.mkdir(parents=True)
        (codex / "rollout-2026-01-01T00-00-00-abc.jsonl").write_text("{}", encoding="utf-8")
        relatives = {rel for _, rel in plan_paths(self.claude, self.home / ".codex")}
        self.assertIn("codex/sessions/2026/rollout-2026-01-01T00-00-00-abc.jsonl", relatives)


class PreserveTest(ArchiveCase):
    def test_first_run_adds_everything_and_second_run_adds_nothing(self):
        first, _ = self.run_once()
        self.assertEqual(first.added, 2)
        self.assertGreater(first.bytes_added, 0)

        second, records = self.run_once()
        self.assertEqual((second.added, second.changed, second.unchanged), (0, 0, 2))
        self.assertEqual(second.bytes_added, 0)
        self.assertEqual(records, [])

    def test_mirror_is_hard_linked_to_the_object_so_it_costs_no_space(self):
        self.run_once()
        mirrored = self.archive / "latest" / "claude" / "history.jsonl"
        blob = next((self.archive / "objects").rglob("*"))
        while blob.is_dir():
            blob = next(blob.iterdir())
        self.assertEqual(os.stat(mirrored).st_ino, os.stat(blob).st_ino)

    def test_changed_content_is_stored_beside_the_old_version_not_over_it(self):
        self.run_once()
        objects_before = {p for p in (self.archive / "objects").rglob("*") if p.is_file()}
        (self.claude / "history.jsonl").write_text("hist v2", encoding="utf-8")

        result, records = self.run_once()
        self.assertEqual(result.changed, 1)
        objects_after = {p for p in (self.archive / "objects").rglob("*") if p.is_file()}
        self.assertTrue(objects_before < objects_after, "the earlier version must still be held")
        self.assertEqual((self.archive / "latest" / "claude" / "history.jsonl").read_text(), "hist v2")
        self.assertEqual([r["status"] for r in records], ["changed"])

    def test_a_file_removed_from_the_host_stays_in_the_archive_and_is_reported(self):
        """The whole point of running early: once retention takes a file, the
        preserved copy is the only one left."""
        self.run_once()
        (self.claude / "projects" / "p" / "a.jsonl").unlink()

        result, _ = self.run_once()
        self.assertEqual(result.vanished, ["claude/projects/p/a.jsonl"])
        self.assertEqual((self.archive / "latest" / "claude" / "projects" / "p" / "a.jsonl").read_text(), "one")

    def test_identical_content_at_two_paths_is_stored_once(self):
        (self.claude / "projects" / "p" / "b.jsonl").write_text("one", encoding="utf-8")
        self.run_once()
        blobs = [p for p in (self.archive / "objects").rglob("*") if p.is_file()]
        self.assertEqual(len(blobs), 2, "two distinct contents across three files")

    def test_unreadable_source_is_recorded_and_does_not_stop_the_run(self):
        pairs = plan_paths(self.claude) + [(self.claude / "missing.jsonl", "claude/missing.jsonl")]
        result, _ = preserve(pairs, self.archive)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.added, 2)


if __name__ == "__main__":
    unittest.main()
