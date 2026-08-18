"""Tests for the triage report."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.report import build_report  # noqa: E402


def finding(detector="credential_access", severity="high", session="s1", title="T", timestamp="2026-08-01T10:00:00Z", **evidence):
    return {
        "detector": detector,
        "severity": severity,
        "title": title,
        "detail": "d",
        "source": "x.jsonl",
        "session_id": session,
        "timestamp": timestamp,
        "evidence": evidence,
    }


CONTEXT = {"source_root": "/root", "host": "h", "tool_version": "0.1.0", "session_projects": {"s1": "repo"}}


class ReportTest(unittest.TestCase):
    def test_header_carries_the_acquisition_context(self):
        report = build_report([finding()], CONTEXT)
        self.assertIn("# toolmark report", report)
        self.assertIn("/root", report)
        self.assertIn("toolmark 0.1.0", report)

    def test_sessions_are_ranked_by_high_severity_count_not_volume(self):
        findings = [finding(session="quiet", severity="high")] + [
            finding(session="noisy", severity="low") for _ in range(50)
        ]
        report = build_report(findings, CONTEXT)
        self.assertLess(report.index("`quiet`"), report.index("`noisy`"))

    def test_a_concentrated_picture_says_start_with_them(self):
        findings = [finding(session="s1", severity="high") for _ in range(10)]
        findings.append(finding(session="s2", severity="low"))
        self.assertIn("concentrate", build_report(findings, CONTEXT))

    def test_a_spread_picture_says_so_rather_than_pointing_at_a_session(self):
        """Naming a top session on a flat distribution invents a lead that the
        data does not support."""
        findings = [finding(session=f"s{n}", severity="medium") for n in range(40)]
        report = build_report(findings, CONTEXT)
        self.assertIn("spread thin", report)
        self.assertIn("routine activity", report)

    def test_project_name_reaches_the_table(self):
        self.assertIn("| repo |", build_report([finding()], CONTEXT))

    def test_sessions_without_a_high_finding_are_not_opened(self):
        report = build_report([finding(severity="medium")], CONTEXT)
        self.assertIn("No session carries a high-severity finding.", report)

    def test_host_wide_findings_get_their_own_section(self):
        report = build_report([finding(detector="path_hijack", session="", entry="/tmp/evil")], CONTEXT)
        self.assertIn("## Configuration and host", report)
        self.assertIn("/tmp/evil", report)

    def test_evidence_line_shows_the_command_for_a_credential_finding(self):
        report = build_report([finding(input={"command": "cat ~/.aws/credentials"})], CONTEXT)
        self.assertIn("cat ~/.aws/credentials", report)

    def test_injection_chain_line_shows_markers_and_consequences(self):
        report = build_report(
            [finding(detector="injection_chain", markers=["instruction_override"],
                     consequences=[{"kind": "credential_access"}])],
            CONTEXT,
        )
        self.assertIn("instruction_override", report)
        self.assertIn("credential_access", report)

    def test_gaps_are_listed_verbatim(self):
        report = build_report([finding()], {**CONTEXT, "gaps": ["nothing survives past 30 days"]})
        self.assertIn("## What this report cannot tell you", report)
        self.assertIn("nothing survives past 30 days", report)

    def test_long_evidence_is_clipped_to_one_line(self):
        report = build_report([finding(input={"command": "x" * 500})], CONTEXT)
        self.assertIn("...", report)
        self.assertTrue(all(len(line) < 300 for line in report.splitlines()))

    def test_empty_input_still_produces_a_readable_report(self):
        report = build_report([], CONTEXT)
        self.assertIn("0 findings across 0 sessions", report)

    def test_a_session_with_many_findings_is_truncated_with_a_pointer(self):
        findings = [finding(title=f"finding {n}") for n in range(20)]
        report = build_report(findings, CONTEXT)
        self.assertIn("more in findings.jsonl", report)


if __name__ == "__main__":
    unittest.main()
