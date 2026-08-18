"""Tests for the Timesketch CSV export."""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.timesketch import COLUMNS, finding_row, normalise_datetime, timeline_row, write_csv  # noqa: E402

MANDATORY = ("message", "datetime", "timestamp_desc")


class DatetimeTest(unittest.TestCase):
    def test_zulu_becomes_an_offset_which_is_what_the_importer_wants(self):
        stamp, micros = normalise_datetime("2026-08-01T10:00:00.000Z")
        self.assertEqual(stamp, "2026-08-01T10:00:00+00:00")
        self.assertEqual(micros, 1785578400000000)

    def test_offset_form_is_preserved(self):
        self.assertEqual(normalise_datetime("2026-08-01T10:00:00+02:00")[0], "2026-08-01T10:00:00+02:00")

    def test_naive_timestamps_are_treated_as_utc(self):
        self.assertEqual(normalise_datetime("2026-08-01T10:00:00")[0], "2026-08-01T10:00:00+00:00")

    def test_unparseable_values_return_empty_rather_than_a_guess(self):
        for value in ("", "not a time", "t-a1"):
            self.assertEqual(normalise_datetime(value), ("", 0))


class RowTest(unittest.TestCase):
    def test_tool_call_row_carries_the_agent_fields(self):
        row = timeline_row(
            {
                "timestamp": "2026-08-01T10:00:00Z",
                "kind": "tool_call",
                "tool": "Bash",
                "input": {"command": "cat /etc/hosts"},
                "outcome": "ok",
                "agent_type": "general-purpose",
                "mcp_server": "srv",
                "permission_mode": "bypassPermissions",
            }
        )
        self.assertEqual(row["message"], "Bash cat /etc/hosts")
        self.assertEqual(row["timestamp_desc"], "agent tool call")
        self.assertEqual(row["data_type"], "toolmark:tool_call")
        self.assertEqual(row["agent_type"], "general-purpose")
        self.assertEqual(row["mcp_server"], "srv")

    def test_prompt_row_uses_the_prompt_text(self):
        row = timeline_row({"timestamp": "2026-08-01T10:00:00Z", "kind": "prompt", "prompt": "fix the parser"})
        self.assertEqual(row["message"], "prompt: fix the parser")
        self.assertEqual(row["timestamp_desc"], "prompt submitted")

    def test_file_path_is_used_when_there_is_no_command(self):
        row = timeline_row(
            {"timestamp": "2026-08-01T10:00:00Z", "kind": "tool_call", "tool": "Read", "input": {"file_path": "/a/b"}}
        )
        self.assertEqual(row["message"], "Read /a/b")

    def test_newlines_are_folded_so_the_csv_stays_one_row_per_event(self):
        row = timeline_row(
            {"timestamp": "2026-08-01T10:00:00Z", "kind": "tool_call", "tool": "Bash", "input": {"command": "a\nb\nc"}}
        )
        self.assertNotIn("\n", row["message"])

    def test_rows_without_a_timestamp_are_refused(self):
        self.assertIsNone(timeline_row({"timestamp": "", "kind": "tool_call", "tool": "Bash"}))
        self.assertIsNone(finding_row({"timestamp": "", "severity": "high", "title": "x"}))

    def test_finding_row_leads_with_severity(self):
        row = finding_row(
            {"timestamp": "2026-08-01T10:00:00Z", "severity": "high", "title": "Hook", "detail": "why", "detector": "d"}
        )
        self.assertTrue(row["message"].startswith("[high] Hook"))
        self.assertEqual(row["timestamp_desc"], "toolmark finding")
        self.assertEqual(row["detector"], "d")


class WriteCsvTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "timeline.csv"
        self.addCleanup(self.tmp.cleanup)

    def test_writes_mandatory_columns_and_reports_what_it_dropped(self):
        written, dropped = write_csv(
            self.path,
            [
                {"timestamp": "2026-08-01T10:00:00Z", "kind": "tool_call", "tool": "Bash", "input": {}},
                {"timestamp": "", "kind": "tool_call", "tool": "Bash", "input": {}},
            ],
            [{"timestamp": "2026-08-01T11:00:00Z", "severity": "low", "title": "t", "detail": "d"}],
        )
        self.assertEqual((written, dropped), (2, 1))

        rows = list(csv.DictReader(self.path.open(encoding="utf-8")))
        self.assertEqual(len(rows), 2)
        for row in rows:
            for column in MANDATORY:
                self.assertTrue(row[column], f"{column} must not be empty")

    def test_header_matches_the_declared_columns(self):
        write_csv(self.path, [], [])
        header = next(csv.reader(self.path.open(encoding="utf-8")))
        self.assertEqual(header, COLUMNS)
        for column in MANDATORY:
            self.assertIn(column, header)

    def test_unknown_keys_do_not_break_the_writer(self):
        written, _ = write_csv(
            self.path,
            [{"timestamp": "2026-08-01T10:00:00Z", "kind": "tool_call", "tool": "Bash", "input": {}, "extra": 1}],
            [],
        )
        self.assertEqual(written, 1)


if __name__ == "__main__":
    unittest.main()
