"""Tests for core/pool_test_report.py -- the pool-exclusivity verdict.

Run from dashboard/: python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pool_test_report import (EXCLUSIVE, INCOMPLETE, MERGED, SHARED_EXPECTED,  # noqa: E402
                                   SHARED_UNEXPECTED, FrameResult, analyze, sharing_justified)

SID = ["a" * 32, "b" * 32, "c" * 32]


def frames(*pools):
    return [FrameResult(label=f"F{i}", session_id=SID[i], pool=p) for i, p in enumerate(pools)]


def state(ready=(1, 2, 3), free=(), owners=None, capped=""):
    return {"ready": list(ready), "free": list(free), "capped": capped,
            "owners": owners or {n: 1 for n in ready}}


class VerdictTests(unittest.TestCase):
    def test_distinct_pools_are_exclusive(self):
        self.assertEqual(analyze(frames(1, 2, 3), state(free=[4])).status, EXCLUSIVE)

    def test_shared_with_free_pool_is_unexpected(self):
        v = analyze(frames(1, 1, 2), state(free=[3], owners={1: 2, 2: 1, 3: 0}))
        self.assertEqual(v.status, SHARED_UNEXPECTED)
        self.assertEqual(v.by_pool[1], ["F0", "F1"])

    def test_shared_when_growth_capped_is_expected(self):
        v = analyze(frames(1, 1, 2), state(ready=(1, 2), free=[1], capped="low memory"))
        self.assertEqual(v.status, SHARED_EXPECTED)

    def test_shared_when_every_pool_owned_is_expected(self):
        v = analyze(frames(1, 2, 1), state(ready=(1, 2), owners={1: 2, 2: 1}))
        self.assertEqual(v.status, SHARED_EXPECTED)

    def test_same_session_is_merged(self):
        f = frames(1, 1, 2)
        f[1].session_id = f[0].session_id
        self.assertEqual(analyze(f, state()).status, MERGED)

    def test_missing_session_or_pool_is_incomplete(self):
        f = frames(1, None, 2)
        self.assertEqual(analyze(f, state()).status, INCOMPLETE)
        f[1].session_id = ""
        self.assertEqual(analyze(f, state()).status, INCOMPLETE)

    def test_unreadable_state_never_justifies_sharing(self):
        self.assertFalse(sharing_justified({}))
        self.assertEqual(analyze(frames(1, 1, 2), {}).status, SHARED_UNEXPECTED)


if __name__ == "__main__":
    unittest.main()


class DecisionTests(unittest.TestCase):
    def test_parse_decision(self):
        from core.pool_test_report import Decision, parse_decision, StepResult, sticky_violations
        d = parse_decision("s", '{"threat_score": 85, "honeypot_bound": true, "honeypot_reason": "high_threat_score"}', "2")
        self.assertEqual((d.route, d.pool, d.score), ("HONEYPOT", 2, 85))
        self.assertIn("pool 2", d.text())
        self.assertEqual(parse_decision("s", "", "").route, "PRODUCTION")
        self.assertEqual(parse_decision("", "", "").route, "NO SESSION")
        self.assertEqual(parse_decision("s", "not json", "").route, "PRODUCTION")

    def test_pool_change_between_steps_is_unstable(self):
        from core.pool_test_report import Decision, StepResult, UNSTABLE
        mk = lambda *pools: StepResult("t", "", [], [Decision("s", "HONEYPOT", 90, "", p) for p in pools])
        v = analyze(frames(1, 2, 3), state(free=[4]), [mk(1, 2, 3), mk(1, 3, 3)])
        self.assertEqual(v.status, UNSTABLE)
        self.assertEqual(analyze(frames(1, 2, 3), state(free=[4]), [mk(1, 2, 3)]).status, EXCLUSIVE)


class PlanTests(unittest.TestCase):
    def test_plan_exploits_exist_and_are_browser_runnable(self):
        from core.exploits import EXPLOIT_PRESETS
        from core.pool_test_report import EXPLOIT_PLAN, FALLBACK_EXPLOITS
        by_cve = {p.cve: p for p in EXPLOIT_PRESETS}
        planned = [c for pair in EXPLOIT_PLAN for c in pair]
        self.assertEqual(len(planned), len(set(planned)), "windows must run different exploits")
        for cve in planned + FALLBACK_EXPLOITS:
            self.assertIn(cve, by_cve)
            self.assertEqual(by_cve[cve].method, "GET", cve)
            self.assertEqual(by_cve[cve].headers, {}, cve)
        self.assertFalse(set(planned) & set(FALLBACK_EXPLOITS))


class EvidenceTests(unittest.TestCase):
    def test_parsers_and_cross_traffic(self):
        from core import pool_evidence as pe
        log = ('172.21.0.5 - - [05/Oct/2026:07:44:12 +0000] "GET /?author=1 HTTP/1.1" 301 0 "-" "Mozilla/5.0 PoolTest/B"\n'
               '127.0.0.1 - - [05/Oct/2026:07:43:12 +0000] "GET / HTTP/1.1" 200 6 "-" "curl/8.14.1"\n'
               '172.21.0.5 - - [05/Oct/2026:07:44:13 +0000] "GET /a.css HTTP/1.1" 200 5 "-" "Mozilla/5.0 PoolTest/C"')
        ev = pe.ContainerEvidence(1, hits=pe.parse_access_log(log))
        self.assertEqual(ev.windows(), ["B", "C"])
        self.assertEqual([h.path for h in ev.notable()], ["/?author=1"])
        self.assertEqual(len(pe.cross_traffic([ev], {1: "B"})), 1)
        self.assertEqual(pe.parse_status("Questions\t5\nCom_select\t2\n"), {"Questions": 5, "Com_select": 2})
        self.assertEqual(pe.db_delta({"Questions": 1}, {"Questions": 4})["Questions"], 3)
        self.assertIsNone(pe.db_delta(None, {"Questions": 4}))
        self.assertEqual(pe.filter_files(["/var/www/html/x.php", "/tmp/a", "/run/b"]), ["/var/www/html/x.php"])
