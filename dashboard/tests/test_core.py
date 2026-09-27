"""Unit tests for the dashboard's Qt-free core modules.

Stdlib unittest only, so they run without the app's PyQt6 venv:

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DASHBOARD_DIR.parent
sys.path.insert(0, str(DASHBOARD_DIR))

from core import cert_ctl, threat_log_parser  # noqa: E402
from core.colors import GREEN, RED  # noqa: E402
from core.env_file import EnvFile, seed_from_example  # noqa: E402
from core.line_buffer import LineBuffer  # noqa: E402


class EnvFileTests(unittest.TestCase):
    def test_real_templates_round_trip_byte_identical(self):
        # The editor promises to keep every comment and blank line intact.
        for rel in ("ids/.env.example", "siem/docker/.env.example"):
            path = REPO_ROOT / rel
            with self.subTest(template=rel):
                self.assertEqual(EnvFile.load(path).render(), path.read_text())

    def test_set_changes_only_the_value(self):
        text = "# header\nA=1  # keep me\nB='x # not a comment'\n"
        ef = EnvFile.from_text(text, Path("x"))
        self.assertEqual(ef.get("B"), "'x # not a comment'")
        ef.set("A", "2")
        self.assertEqual(ef.render(), "# header\nA=2  # keep me\nB='x # not a comment'\n")

    def test_set_appends_missing_key(self):
        ef = EnvFile.from_text("A=1\n", Path("x"))
        ef.set("NEW", "v")
        self.assertEqual(ef.render(), "A=1\nNEW=v\n")

    def test_merge_inserts_missing_key_with_its_comment_in_place(self):
        example = EnvFile.from_text("A=1\n\n# about B\nB=2\nC=3\n", Path("ex"))
        ef = EnvFile.from_text("A=real\nC=real\n", Path("x"))
        added = ef.merge_missing_from(example)
        self.assertEqual(added, ["B"])
        self.assertEqual(ef.render(), "A=real\n\n# about B\nB=2\nC=real\n")

    def test_merge_never_touches_existing_values(self):
        example = EnvFile.from_text("A=placeholder\n", Path("ex"))
        ef = EnvFile.from_text("A=secret\n", Path("x"))
        self.assertEqual(ef.merge_missing_from(example), [])
        self.assertEqual(ef.get("A"), "secret")

    def test_seed_from_example(self):
        with tempfile.TemporaryDirectory() as d:
            example = Path(d) / ".env.example"
            target = Path(d) / ".env"
            example.write_text("A=1\nB=2\n")

            ef = seed_from_example(target, example)
            self.assertEqual(ef.path, target)
            self.assertEqual(ef.as_dict(), {"A": "1", "B": "2"})
            self.assertFalse(target.exists(), "seeding must not write until save()")

            target.write_text("A=mine\n")
            ef = seed_from_example(target, example)
            self.assertEqual(ef.as_dict(), {"A": "mine", "B": "2"})
            self.assertEqual(ef.added_keys, ["B"])


class LineBufferTests(unittest.TestCase):
    def test_reassembles_split_lines(self):
        buf = LineBuffer()
        self.assertEqual(buf.feed("one\ntw"), ["one"])
        self.assertEqual(buf.feed("o\nthree"), ["two"])
        self.assertEqual(buf.feed("\n"), ["three"])

    def test_reset_drops_partial_line(self):
        buf = LineBuffer()
        buf.feed("partial")
        buf.reset()
        self.assertEqual(buf.feed("x\n"), ["x"])


class ThreatLogParserTests(unittest.TestCase):
    parse = staticmethod(threat_log_parser.parse_line)

    def test_header_summary_outcome(self):
        ev = self.parse("[LOCATION / HEADER] route_decision='honeypot' threat_score='85', client: 1.2.3.4")
        self.assertEqual((ev.kind, ev.label, ev.score, ev.color), ("outcome", "Routed to HONEYPOT", 85, RED))

    def test_final_decision_normalizes_denominator(self):
        ev = self.parse("[FINAL DECISION] 🍯 ROUTING TO HONEYPOT | Score: 90/80 | Reason: cve")
        self.assertEqual(ev.score, 90)
        self.assertEqual(ev.detail, "Score: 90/100 | Reason: cve")

    def test_routing_stage(self):
        ev = self.parse("[ROUTING] ✅ Clean request -> PRODUCTION | Score: 0 | IP: 1.2.3.4")
        self.assertEqual(ev.kind, "routing")
        self.assertEqual(ev.color, GREEN)

    def test_signal_delta(self):
        ev = self.parse("[THREAT ANALYZER] 🎯 CVE match (+40) | CVE-2023-28121")
        self.assertEqual((ev.kind, ev.label, ev.color), ("signal", "CVE match (+40)", RED))
        self.assertEqual(ev.detail, "CVE-2023-28121")

    def test_docker_timestamp_is_captured_through_ansi_reset(self):
        line = ("reverse_proxy-1  | \x1b[0m2026-08-09T10:32:37.684747138Z "
                "[LOCATION / HEADER] route_decision='production' threat_score='0'")
        ev = self.parse(line)
        self.assertEqual(ev.timestamp, "2026-08-09T10:32:37.684747138Z")
        self.assertEqual(ev.score, 0)

    def test_irrelevant_lines_are_ignored(self):
        self.assertIsNone(self.parse("[SESSION DEBUG] cookie_PHPSESSID=nil"))
        self.assertIsNone(self.parse("   "))


class CertSubjectTests(unittest.TestCase):
    def test_edge_cert_subject_does_not_name_the_honeypot(self):
        # The blind pentest identified the deception from O=HoneypotOrg.
        calls = []
        orig_run = cert_ctl._run
        with tempfile.TemporaryDirectory() as d:
            orig_dir = cert_ctl.EDGE_SSL_CERT_DIR
            cert_ctl.EDGE_SSL_CERT_DIR = Path(d)
            cert_ctl._run = lambda args, *a, **k: (calls.append(args),
                                                    (Path(d) / "server.key").touch(),
                                                    (Path(d) / "server.crt").touch())
            try:
                cert_ctl._gen_edge_nginx_cert()
            finally:
                cert_ctl._run = orig_run
                cert_ctl.EDGE_SSL_CERT_DIR = orig_dir
        subject = calls[0][calls[0].index("-subj") + 1]
        self.assertNotIn("honeypot", subject.lower())
        compose = (REPO_ROOT / "ids" / "docker-compose.yml").read_text()
        self.assertNotIn("honeypot", compose.split("-subj", 1)[1].splitlines()[0].lower())


if __name__ == "__main__":
    unittest.main()
