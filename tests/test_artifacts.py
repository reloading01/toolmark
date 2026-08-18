"""Tests for the file-history and jobs artifact planes."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from toolmark.artifacts import (  # noqa: E402
    build_digest_index,
    iter_file_history,
    iter_jobs,
    parse_flags,
    path_digest,
    probe_candidates,
    resolve_versions,
)
from toolmark.detect import detect_config_tampering, detect_job_risks  # noqa: E402


class FileHistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.claude = Path(self.tmp.name) / ".claude"
        (self.claude / "file-history").mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)

    def store(self, session: str, path: str, versions: int) -> None:
        session_dir = self.claude / "file-history" / session
        session_dir.mkdir(parents=True, exist_ok=True)
        for n in range(1, versions + 1):
            (session_dir / f"{path_digest(path)}@v{n}").write_text(f"content v{n}", encoding="utf-8")

    def test_digest_is_truncated_sha256_of_the_absolute_path(self):
        path = "/work/src/main.py"
        self.assertEqual(path_digest(path), hashlib.sha256(path.encode()).hexdigest()[:16])
        self.assertEqual(len(path_digest(path)), 16)

    def test_reads_versions_and_ignores_unrelated_files(self):
        self.store("s1", "/work/a.py", versions=3)
        (self.claude / "file-history" / "s1" / "README").write_text("x", encoding="utf-8")
        (self.claude / "file-history" / "s1" / "bad@vNaN").write_text("x", encoding="utf-8")

        versions = iter_file_history(self.claude)
        self.assertEqual(len(versions), 3)
        self.assertEqual(sorted(v.version for v in versions), [1, 2, 3])
        self.assertTrue(all(v.session_id == "s1" for v in versions))

    def test_resolution_uses_paths_from_any_session(self):
        """Content is hard-linked across session directories, so a path seen in
        one transcript resolves entries filed under a session whose transcript
        is already gone."""
        self.store("has-transcript", "/work/shared.py", versions=1)
        self.store("transcript-deleted", "/work/shared.py", versions=1)

        versions = iter_file_history(self.claude)
        resolve_versions(versions, build_digest_index(["/work/shared.py"]))
        self.assertTrue(all(v.resolved_path == "/work/shared.py" for v in versions))

    def test_unknown_paths_stay_anonymous(self):
        self.store("s1", "/work/never-mentioned.py", versions=1)
        versions = iter_file_history(self.claude)
        resolve_versions(versions, build_digest_index(["/work/other.py"]))
        self.assertIsNone(versions[0].resolved_path)

    def test_probing_recovers_a_config_path_no_transcript_mentions(self):
        home = Path(self.tmp.name)
        settings = str(home / ".claude" / "settings.json")
        self.store("s1", settings, versions=2)

        versions = iter_file_history(self.claude)
        resolve_versions(versions, build_digest_index(probe_candidates(home, ["/work"])))
        self.assertTrue(all(v.resolved_path == settings for v in versions))
        self.assertTrue(versions[0].is_self_config)

    def test_ordinary_source_file_is_not_self_config(self):
        self.store("s1", "/work/app.py", versions=1)
        versions = iter_file_history(self.claude)
        resolve_versions(versions, build_digest_index(["/work/app.py"]))
        self.assertFalse(versions[0].is_self_config)

    def test_config_tampering_reports_every_retained_version(self):
        home = Path(self.tmp.name)
        settings = str(home / ".claude" / "settings.json")
        self.store("s1", settings, versions=3)

        versions = iter_file_history(self.claude)
        resolve_versions(versions, build_digest_index(probe_candidates(home, [])))
        findings = detect_config_tampering(versions)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(len(findings[0].evidence["versions"]), 3)
        self.assertEqual(findings[0].evidence["resolved_path"], settings)

    def test_no_config_edits_yields_no_findings(self):
        self.store("s1", "/work/app.py", versions=2)
        versions = iter_file_history(self.claude)
        resolve_versions(versions, build_digest_index(["/work/app.py"]))
        self.assertEqual(detect_config_tampering(versions), [])


class JobsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.claude = Path(self.tmp.name) / ".claude"
        (self.claude / "jobs").mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)

    def write_job(self, job_id: str, state: dict, timeline: list | None = None) -> None:
        job_dir = self.claude / "jobs" / job_id
        job_dir.mkdir(parents=True)
        (job_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        if timeline is not None:
            with (job_dir / "timeline.jsonl").open("w", encoding="utf-8") as fh:
                for row in timeline:
                    fh.write(json.dumps(row) + "\n")

    def test_parse_flags_pairs_values_with_their_flag(self):
        flags = parse_flags(["--permission-mode", "bypassPermissions", "--reply-on-resume", "--model", "opus"])
        self.assertEqual(flags["--permission-mode"], ["bypassPermissions"])
        self.assertEqual(flags["--reply-on-resume"], [])
        self.assertEqual(flags["--model"], ["opus"])

    def test_reads_state_and_timeline(self):
        self.write_job(
            "j1",
            {
                "state": "done",
                "detail": "check the container",
                "sessionId": "s1",
                "cwd": "/work",
                "cliVersion": "2.1.219",
                "fan": [{"kind": "shell", "label": "ls -la"}, {"kind": "other", "label": "ignored"}],
                "respawnFlags": ["--model", "opus"],
            },
            timeline=[{"at": 1, "state": "running"}, {"at": 2, "state": "done"}],
        )
        jobs = iter_jobs(self.claude)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].session_id, "s1")
        self.assertEqual(jobs[0].shell_tasks, ["ls -la"])
        self.assertEqual(len(jobs[0].timeline), 2)

    def test_unattended_mode_is_medium_and_skip_flag_is_high(self):
        self.write_job("j1", {"respawnFlags": ["--permission-mode", "bypassPermissions"]})
        self.write_job("j2", {"respawnFlags": ["--dangerously-skip-permissions"]})
        by_job = {f.evidence["job_id"]: f for f in detect_job_risks(iter_jobs(self.claude))}
        self.assertEqual(by_job["j1"].severity, "medium")
        self.assertEqual(by_job["j2"].severity, "high")

    def test_shell_fan_task_touching_credentials_is_reported(self):
        self.write_job(
            "j1",
            {"fan": [{"kind": "shell", "label": "cat ~/.aws/credentials"}, {"kind": "shell", "label": "npm test"}]},
        )
        findings = detect_job_risks(iter_jobs(self.claude))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn(".aws/credentials", findings[0].evidence["critical_markers"])

    def test_benign_job_yields_nothing(self):
        self.write_job("j1", {"respawnFlags": ["--model", "opus"], "fan": [{"kind": "shell", "label": "make build"}]})
        self.assertEqual(detect_job_risks(iter_jobs(self.claude)), [])

    def test_job_secrets_follow_the_redaction_flag(self):
        self.write_job("j1", {"fan": [{"kind": "shell", "label": "curl -H 'Authorization: Bearer AAAAAAAAAAAAAAAAAAAA' x .env"}]})
        jobs = iter_jobs(self.claude)
        masked = detect_job_risks(jobs)[0].evidence["command"]
        raw = detect_job_risks(jobs, redact_output=False)[0].evidence["command"]
        self.assertNotIn("AAAAAAAAAAAAAAAAAAAA", masked)
        self.assertIn("AAAAAAAAAAAAAAAAAAAA", raw)


if __name__ == "__main__":
    unittest.main()
