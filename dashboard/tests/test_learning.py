"""Tests for core/learning.py -- the Learn page's teaching content.

Run from dashboard/: python3 -m unittest discover -s tests
"""
import os
import re
import sys
import unittest

DASHBOARD_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DASHBOARD_DIR)

from core import learning  # noqa: E402
from core.exploits import EXPLOIT_PRESETS  # noqa: E402


def _sidebar_pages() -> list[str]:
    """PAGES from ui/main_window.py, read as text so the test needs no Qt."""
    with open(os.path.join(DASHBOARD_DIR, "ui", "main_window.py")) as f:
        src = f.read()
    block = re.search(r"^PAGES = \[(.*?)\]", src, re.S | re.M).group(1)
    return re.findall(r'"(\w+)"', block)


class ExploitLessonTests(unittest.TestCase):
    def test_every_preset_has_a_lesson(self):
        missing = [p.cve for p in EXPLOIT_PRESETS if learning.lesson_for(p.cve) is None]
        self.assertEqual(missing, [], "add an EXPLOIT_LESSONS entry for each new preset")

    def test_no_orphan_lessons(self):
        cves = {p.cve for p in EXPLOIT_PRESETS}
        self.assertEqual(set(learning.EXPLOIT_LESSONS) - cves, set())

    def test_lessons_name_owasp_and_attack_ids(self):
        for cve, lesson in learning.EXPLOIT_LESSONS.items():
            self.assertRegex(lesson.owasp, r"^A\d\d ", cve)
            self.assertRegex(lesson.attack, r"^T\d{4}(\.\d{3})? ", cve)


class PageGuideTests(unittest.TestCase):
    def test_every_sidebar_page_has_a_guide(self):
        pages = _sidebar_pages()
        self.assertIn("learn", pages)
        self.assertEqual(sorted(pages), sorted(learning.PAGE_GUIDES))

    def test_glossary_and_lab_pages_exist(self):
        for term in learning.GLOSSARY:
            if term.page:
                self.assertIn(term.page, learning.PAGE_GUIDES, term.term)
        for lab in learning.LABS:
            for step in lab.steps:
                if step.page:
                    self.assertIn(step.page, learning.PAGE_GUIDES, step.id)


class LabTests(unittest.TestCase):
    def test_step_ids_unique(self):
        ids = learning.all_step_ids()
        self.assertEqual(len(ids), len(set(ids)))

    def test_lab_steps_reference_real_presets(self):
        cves = {p.cve for p in EXPLOIT_PRESETS}
        for lab in learning.LABS:
            for step in lab.steps:
                for cve in re.findall(r"(?:CVE-\d{4}-\d+|GENERIC-WP-\d+)", step.text):
                    self.assertIn(cve, cves, step.id)

    def test_progress(self):
        lab = learning.LABS[0]
        self.assertEqual(learning.lab_progress(lab, []), (0, len(lab.steps)))
        self.assertEqual(learning.lab_progress(lab, [lab.steps[0].id, "unknown"]),
                         (1, len(lab.steps)))


class GlossaryTests(unittest.TestCase):
    def test_empty_query_returns_everything(self):
        self.assertEqual(len(learning.search_glossary("")), len(learning.GLOSSARY))

    def test_term_name_matches_first(self):
        hits = learning.search_glossary("honeypot")
        self.assertEqual(hits[0].term, "Honeypot")

    def test_all_words_must_match(self):
        hits = learning.search_glossary("sql injection")
        self.assertTrue(hits)
        self.assertTrue(all("sql" in f"{t.term} {t.definition} {t.in_this_project}".lower()
                            for t in hits))
        self.assertEqual(learning.search_glossary("zzz-no-such-term"), [])


class ExplainEventTests(unittest.TestCase):
    def test_labels_from_the_log_parser(self):
        # Labels as core/threat_log_parser builds them from real proxy lines.
        for label in [
            "CVE PATTERNS DETECTED (+50)",
            "URI patterns matched (+25)",
            "Automation detected (+15)",
            "Bad IP reputation (+40)",
            "Session bound to HONEYPOT",
            "Final decision: HONEYPOT",
            "Routed to PRODUCTION",
            "Final score: 30/100",
        ]:
            self.assertNotEqual(learning.explain_event(label), "", label)

    def test_specific_before_generic(self):
        self.assertIn("decoy", learning.explain_event("Final decision: HONEYPOT"))
        self.assertIn("real shop", learning.explain_event("Final decision: PRODUCTION"))

    def test_decayed_session_not_described_as_stuck(self):
        text = learning.explain_event("Session bound but accumulated/decayed score below threshold")
        self.assertIn("back to production", text)

    def test_unknown_label(self):
        self.assertEqual(learning.explain_event("something unrelated"), "")


if __name__ == "__main__":
    unittest.main()
