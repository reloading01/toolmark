"""Tests for withdrawn content and the compaction seam."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.detect import detect_withdrawn_content  # noqa: E402
from toolmark.parse import parse_session  # noqa: E402


def event(uuid, parent=None, **extra):
    record = {
        "uuid": uuid,
        "parentUuid": parent,
        "type": "assistant",
        "timestamp": f"t-{uuid}",
        "sessionId": "s1",
        "cwd": "/work",
    }
    record.update(extra)
    return record


def compact_boundary(uuid, logical_parent, trigger="auto", pre_tokens=900000):
    return {
        "uuid": uuid,
        "parentUuid": None,
        "logicalParentUuid": logical_parent,
        "type": "system",
        "subtype": "compact_boundary",
        "timestamp": f"t-{uuid}",
        "sessionId": "s1",
        "compactMetadata": {"trigger": trigger, "preTokens": pre_tokens, "durationMs": 1200},
    }


class TranscriptCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def session(self, records):
        path = self.dir / "s1.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record) + "\n")
        return parse_session(path)


class CompactionSeamTest(TranscriptCase):
    def test_logical_parent_keeps_the_graph_in_one_piece(self):
        """A compaction boundary has a null parentUuid, so without the logical
        link the transcript fragments into two disconnected trees."""
        session = self.session(
            [
                event("a1"),
                event("a2", "a1"),
                compact_boundary("c1", "a2"),
                event("a3", "c1"),
            ]
        )
        self.assertEqual(session.roots, ["a1"])
        self.assertEqual([e.uuid for e in session.ancestors("a3")], ["c1", "a2", "a1"])

    def test_boundary_metadata_is_captured(self):
        session = self.session([event("a1"), compact_boundary("c1", "a1", trigger="manual", pre_tokens=500)])
        self.assertEqual(len(session.compactions), 1)
        self.assertEqual(session.compactions[0].trigger, "manual")
        self.assertEqual(session.compactions[0].pre_tokens, 500)
        self.assertEqual(session.compactions[0].logical_parent_uuid, "a1")

    def test_boundary_with_an_unknown_logical_parent_still_roots_cleanly(self):
        session = self.session([compact_boundary("c1", "missing"), event("a1", "c1")])
        self.assertEqual(session.roots, ["c1"])

    def test_compaction_is_reported_at_low_severity(self):
        session = self.session([event("a1"), compact_boundary("c1", "a1")])
        findings = detect_withdrawn_content(session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].evidence["pre_tokens"], 900000)


class WithdrawnContentTest(TranscriptCase):
    def test_retracted_and_superseded_are_counted_together(self):
        session = self.session(
            [
                event("a1", retractedMessageUuids=["x", "y"], neutralizedByFork=True),
                event("a2", "a1", supersedesUuids=["z"]),
            ]
        )
        findings = [f for f in detect_withdrawn_content(session) if f.detector == "withdrawn_content"]
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].evidence["retracted"], ["x", "y"])
        self.assertEqual(findings[0].evidence["superseded"], ["z"])
        self.assertEqual(findings[0].evidence["neutralized_by_fork"], 1)

    def test_withdrawn_content_is_marked_unrecoverable(self):
        """None of the referenced identifiers were found anywhere on disk, so
        the finding must not imply the content can be pulled back."""
        session = self.session([event("a1", retractedMessageUuids=["gone"])])
        self.assertFalse(detect_withdrawn_content(session)[0].evidence["recoverable"])

    def test_clean_session_reports_nothing(self):
        session = self.session([event("a1"), event("a2", "a1")])
        self.assertEqual(detect_withdrawn_content(session), [])


if __name__ == "__main__":
    unittest.main()
