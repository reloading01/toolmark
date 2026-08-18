"""Tests for the chain-of-custody manifest."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.custody import build_manifest, collect_evidence, hash_file, now_iso  # noqa: E402


class HashTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_matches_hashlib_including_across_chunk_boundaries(self):
        payload = b"x" * (1024 * 1024 + 7)
        path = self.dir / "big.bin"
        path.write_bytes(payload)
        digest, size = hash_file(path)
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertEqual(size, len(payload))

    def test_empty_file_hashes_to_the_empty_digest(self):
        path = self.dir / "empty"
        path.write_bytes(b"")
        self.assertEqual(hash_file(path)[0], hashlib.sha256(b"").hexdigest())


class ClaudeRootCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / ".claude"
        (self.root / "projects" / "p").mkdir(parents=True)
        (self.root / "projects" / "p" / "a.jsonl").write_text("{}", encoding="utf-8")
        (self.root / "history.jsonl").write_text("{}", encoding="utf-8")
        self.addCleanup(self.tmp.cleanup)


class EvidenceTest(ClaudeRootCase):
    def test_assigns_each_item_to_its_plane(self):
        items = {Path(i.path).name: i for i in collect_evidence(
            [self.root / "projects" / "p" / "a.jsonl", self.root / "history.jsonl"], self.root
        )}
        self.assertEqual(items["a.jsonl"].plane, "projects")
        self.assertEqual(items["history.jsonl"].plane, "history.jsonl")

    def test_paths_outside_the_source_root_are_marked_external(self):
        outside = Path(self.tmp.name) / ".claude.json"
        outside.write_text("{}", encoding="utf-8")
        self.assertEqual(collect_evidence([outside], self.root)[0].plane, "external")

    def test_duplicates_are_hashed_once(self):
        path = self.root / "history.jsonl"
        self.assertEqual(len(collect_evidence([path, path, path], self.root)), 1)

    def test_missing_and_directory_paths_are_skipped(self):
        items = collect_evidence(
            [self.root / "absent.jsonl", self.root / "projects", self.root / "history.jsonl"], self.root
        )
        self.assertEqual(len(items), 1)


class ManifestTest(ClaudeRootCase):
    def build(self, redacted=True):
        evidence = collect_evidence(
            [self.root / "history.jsonl", self.root / "projects" / "p" / "a.jsonl"], self.root
        )
        outputs = collect_evidence([self.root / "history.jsonl"], self.root)
        return build_manifest(
            tool_version="9.9.9",
            source_root=self.root,
            started_at=now_iso(),
            evidence=evidence,
            outputs=outputs,
            redacted=redacted,
        )

    def test_records_the_procedure_and_the_acquisition_context(self):
        manifest = self.build()
        self.assertEqual(manifest["procedure"]["tool"], "toolmark")
        self.assertEqual(manifest["procedure"]["version"], "9.9.9")
        self.assertTrue(manifest["procedure"]["read_only"])
        for key in ("started_at", "completed_at", "operator", "host", "source_root"):
            self.assertIn(key, manifest["acquisition"])

    def test_summary_matches_the_items(self):
        manifest = self.build()
        self.assertEqual(manifest["summary"]["evidence_files"], len(manifest["evidence"]))
        self.assertEqual(
            manifest["summary"]["evidence_bytes"], sum(i["size"] for i in manifest["evidence"])
        )
        self.assertEqual(manifest["summary"]["planes"]["projects"]["files"], 1)

    def test_outputs_are_hashed_so_findings_cannot_be_edited_silently(self):
        manifest = self.build()
        self.assertEqual(len(manifest["outputs"]), 1)
        self.assertEqual(len(manifest["outputs"][0]["sha256"]), 64)

    def test_redaction_state_is_recorded(self):
        self.assertTrue(self.build(redacted=True)["procedure"]["output_redacted"])
        self.assertFalse(self.build(redacted=False)["procedure"]["output_redacted"])

    def test_manifest_states_that_it_does_not_cover_itself(self):
        self.assertIn("manifest.json", self.build()["procedure"]["self_coverage"])


if __name__ == "__main__":
    unittest.main()
