"""Tests for blocked actions: what the agent tried and did not get to do."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.detect import detect_blocked_actions  # noqa: E402
from toolmark.parse import parse_session  # noqa: E402


def tool_use(uuid, call_id, command, parent=None):
    return {
        "uuid": uuid,
        "parentUuid": parent,
        "type": "assistant",
        "timestamp": f"t-{uuid}",
        "sessionId": "s1",
        "cwd": "/work",
        "message": {
            "content": [{"type": "tool_use", "id": call_id, "name": "Bash", "input": {"command": command}}]
        },
    }


def denial(uuid, source_uuid, kind="user-rejected"):
    return {
        "uuid": uuid,
        "parentUuid": source_uuid,
        "type": "user",
        "timestamp": f"t-{uuid}",
        "sessionId": "s1",
        "cwd": "/work",
        "toolDenialKind": kind,
        "sourceToolAssistantUUID": source_uuid,
        "toolUseResult": "User rejected tool use",
    }


def refusal(uuid, category="cyber", fallback="", original="claude-opus-5", retracted=()):
    record = {
        "uuid": uuid,
        "parentUuid": None,
        "type": "system",
        "subtype": "model_refusal_fallback" if fallback else "model_refusal_no_fallback",
        "timestamp": f"t-{uuid}",
        "sessionId": "s1",
        "apiRefusalCategory": category,
        "originalModel": original,
        "content": "Safeguards flagged this message.",
        "retractedMessageUuids": list(retracted),
    }
    if fallback:
        record["fallbackModel"] = fallback
    return record


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


class BlockedActionTest(TranscriptCase):
    def test_denial_is_linked_back_to_the_call_it_stopped(self):
        session = self.session([tool_use("a1", "c1", "cat ~/.ssh/id_rsa"), denial("d1", "a1")])
        findings = detect_blocked_actions(session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["tool"], "Bash")
        self.assertIn(".ssh/id_", findings[0].evidence["critical_markers"])

    def test_blocked_credential_access_is_high(self):
        session = self.session([tool_use("a1", "c1", "cat ~/.aws/credentials"), denial("d1", "a1")])
        self.assertEqual(detect_blocked_actions(session)[0].severity, "high")

    def test_ordinary_rejected_command_stays_low(self):
        session = self.session([tool_use("a1", "c1", "rm -rf build"), denial("d1", "a1")])
        self.assertEqual(detect_blocked_actions(session)[0].severity, "low")

    def test_plain_egress_without_credentials_is_not_escalated(self):
        """Fetching a URL is ordinary work; the same call credential_access
        makes, so the two detectors agree."""
        session = self.session([tool_use("a1", "c1", "curl https://example.com/docs"), denial("d1", "a1")])
        self.assertEqual(detect_blocked_actions(session)[0].severity, "low")

    def test_classifier_blocks_escalate_once_the_documented_threshold_is_reached(self):
        below = self.session(
            [
                tool_use("a1", "c1", "make", None),
                denial("d1", "a1", kind="automode-blocked"),
                tool_use("a2", "c2", "make", "d1"),
                denial("d2", "a2", kind="automode-blocked"),
            ]
        )
        self.assertTrue(all(f.severity == "medium" for f in detect_blocked_actions(below)))

        records = []
        parent = None
        for n in range(3):
            records.append(tool_use(f"a{n}", f"c{n}", "make", parent))
            records.append(denial(f"d{n}", f"a{n}", kind="automode-blocked"))
            parent = f"d{n}"
        self.assertTrue(all(f.severity == "high" for f in detect_blocked_actions(self.session(records))))

    def test_denial_without_a_resolvable_source_still_reports(self):
        session = self.session([denial("d1", "missing")])
        findings = detect_blocked_actions(session)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["tool"], "")


class ModelRefusalTest(TranscriptCase):
    def test_refusals_are_grouped_by_category(self):
        session = self.session([refusal("r1"), refusal("r2"), refusal("r3", category="other")])
        findings = {f.evidence["category"]: f for f in detect_blocked_actions(session)}
        self.assertEqual(findings["cyber"].evidence["refusals"], 2)
        self.assertEqual(findings["other"].evidence["refusals"], 1)

    def test_retry_on_a_fallback_model_is_high_and_names_the_route(self):
        session = self.session([refusal("r1", fallback="claude-opus-4-8")])
        finding = detect_blocked_actions(session)[0]
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.evidence["retried_on_fallback"], 1)
        self.assertEqual(finding.evidence["fallback_routes"], ["claude-opus-5 -> claude-opus-4-8"])

    def test_refusal_without_a_fallback_is_medium(self):
        session = self.session([refusal("r1")])
        self.assertEqual(detect_blocked_actions(session)[0].severity, "medium")

    def test_retracted_messages_are_counted(self):
        session = self.session([refusal("r1", retracted=("x", "y"))])
        self.assertEqual(detect_blocked_actions(session)[0].evidence["retracted_messages"], 2)

    def test_clean_session_reports_nothing(self):
        session = self.session([tool_use("a1", "c1", "make test")])
        self.assertEqual(detect_blocked_actions(session), [])


if __name__ == "__main__":
    unittest.main()
