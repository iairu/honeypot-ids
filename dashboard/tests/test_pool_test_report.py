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

    def test_shared_while_pools_are_still_being_built_is_expected(self):
        v = analyze(frames(1, 2, 1), state(ready=(1, 2), owners={1: 2, 2: 1}) | {"free": [3], "waiting": 1})
        self.assertEqual(v.status, SHARED_EXPECTED)
        self.assertIn("waiting", " ".join(v.findings))

    def test_unreadable_state_never_justifies_sharing(self):
        self.assertFalse(sharing_justified({}))
        self.assertEqual(analyze(frames(1, 1, 2), {}).status, SHARED_UNEXPECTED)



class DecisionTests(unittest.TestCase):
    def test_parse_decision(self):
        from core.pool_test_report import Decision, parse_decision, StepResult, sticky_violations
        d = parse_decision("s", '{"threat_score": 85, "honeypot_bound": true, "honeypot_reason": "high_threat_score"}', "2")
        self.assertEqual((d.route, d.pool, d.score), ("HONEYPOT", 2, 85))
        self.assertIn("pool 2", d.text())
        self.assertEqual(parse_decision("s", "", "").route, "PRODUCTION")
        self.assertEqual(parse_decision("", "", "").route, "NO SESSION")
        self.assertEqual(parse_decision("s", "not json", "").route, "PRODUCTION")
        w = parse_decision("s", '{"honeypot_bound": true}', "1", "7")
        self.assertTrue(w.waiting)
        self.assertIn("borrowed", w.text())
        self.assertFalse(parse_decision("s", "", "", "7").waiting)   # no pool, nothing borrowed

    def test_pool_change_between_steps_is_unstable(self):
        from core.pool_test_report import Decision, StepResult, UNSTABLE
        mk = lambda *pools: StepResult("t", "", [], [Decision("s", "HONEYPOT", 90, "", p) for p in pools])
        v = analyze(frames(1, 2, 3), state(free=[4]), [mk(1, 2, 3), mk(1, 3, 3)])
        self.assertEqual(v.status, UNSTABLE)
        self.assertEqual(analyze(frames(1, 2, 3), state(free=[4]), [mk(1, 2, 3)]).status, EXCLUSIVE)

    def test_move_off_a_borrowed_pool_is_not_a_violation(self):
        from core.pool_test_report import Decision, StepResult, sticky_violations
        borrowed = StepResult("attack", "", [], [Decision("s", "HONEYPOT", 90, "", 1, waiting=True)])
        own = StepResult("scale", "", [], [Decision("s", "HONEYPOT", 90, "", 4)])
        moved = StepResult("again", "", [], [Decision("s", "HONEYPOT", 90, "", 5)])
        self.assertEqual(sticky_violations([borrowed, own]), [])
        self.assertEqual(len(sticky_violations([borrowed, own, moved])), 1)


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

    def test_window_plan_covers_every_window_count(self):
        from core.pool_test_report import (CART_PLAN, EXPLOIT_PLAN, MAX_WINDOWS, MIN_WINDOWS,
                                           window_plan)
        self.assertEqual(window_plan(3), EXPLOIT_PLAN)
        self.assertGreaterEqual(len(CART_PLAN), MAX_WINDOWS)
        for n in range(MIN_WINDOWS, MAX_WINDOWS + 1):
            plan = window_plan(n)
            self.assertEqual(len(plan), n)
            firsts = [a for a, _b in plan]
            self.assertEqual(len(firsts), len(set(firsts)), f"{n} windows: first exploits repeat")
            self.assertTrue(all(a != b for a, b in plan))


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


class CartTests(unittest.TestCase):
    def _step(self, title, *carts):
        from core.pool_test_report import StepResult
        return StepResult(title, "", [], [], carts=list(carts))

    def test_parse_cart(self):
        from core.pool_test_report import parse_cart
        c = parse_cart('{"items":[{"name":"Mug","quantity":2}],"totals":{"total_price":"4400","currency_minor_unit":2,"currency_prefix":"$"}}')
        self.assertEqual(c.items, [("Mug", 2)])
        self.assertEqual(c.total, "$44.00")
        self.assertIn("2 items", c.text())
        self.assertIsNone(parse_cart("not json"))

    def test_cart_must_survive_routing(self):
        from core.pool_test_report import CART_LOST, CartState, cart_violations
        full, empty = CartState([("Mug", 2)], "$44"), CartState([], "$0")
        ok = [self._step("open", empty), self._step("fill", full), self._step("attack", full)]
        self.assertEqual(cart_violations(ok), [])
        bad = ok + [self._step("again", empty)]
        self.assertEqual(len(cart_violations(bad)), 1)
        v = analyze(frames(1, 2, 3), state(free=[4]), [self._step("fill", full, full, full), self._step("attack", full, empty, full)])
        self.assertEqual(v.status, CART_LOST)
        self.assertIn("Window 2", " ".join(v.findings))

    def test_plan_products_exist_and_are_simple(self):
        from core.pool_test_report import CART_PLAN
        import json, os
        cat = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "ids", "eshop_seed", "catalog.json")))
        by = {p["slug"]: p for p in cat["products"]}
        for window in CART_PLAN:
            for slug, qty in window:
                self.assertEqual(by[slug]["type"], "simple", slug)
                self.assertGreater(qty, 0)
        self.assertEqual(len({s for w in CART_PLAN for s, _ in w}), sum(len(w) for w in CART_PLAN))


class ScalingTests(unittest.TestCase):
    """Timeline, case A (borrowed while scaling) and case B (resource limit)."""

    def _data(self, timeline, events=(), duration=100.0):
        from core.pool_test_report import PoolTestData, Sample
        samples = [Sample(t, w, f"s{w}", r, p, wt)
                   for t, batch in timeline for w, (r, p, wt) in enumerate(batch)]
        return PoolTestData("now", "t", "u", "", frames(*[None] * len(timeline[0][1])),
                            duration=duration, samples=samples, events=list(events))

    def test_classify(self):
        from core.pool_test_report import BORROWED, OWN, PRODUCTION, SHARED, Sample, classify
        batch = [Sample(0, 0, "a", "HONEYPOT", 1, False), Sample(0, 1, "b", "HONEYPOT", 1, True),
                 Sample(0, 2, "c", "PRODUCTION", None, False), Sample(0, 3, "d", "HONEYPOT", 2, False),
                 Sample(0, 4, "e", "HONEYPOT", 2, False)]
        self.assertEqual(classify(batch), [OWN, BORROWED, PRODUCTION, SHARED, SHARED])

    def test_borrowed_then_own_is_case_a(self):
        from core.pool_test_report import BORROWED, OWN, scaling_summary
        H, P = ("HONEYPOT", 1, False), ("PRODUCTION", None, False)
        d = self._data([(0, [P, P]), (10, [H, ("HONEYPOT", 1, True)]), (40, [H, ("HONEYPOT", 2, False)])],
                       [{"type": "build_start", "pool": 2, "reason": "waiting session", "at": 11},
                        {"type": "build", "pool": 2, "start": 11, "seconds": 28, "ok": True, "at": 39,
                         "phases": [["seed volumes", 10], ["WordPress start", 15]]},
                        {"type": "handoff", "pool": 2, "session": "s1", "borrowed": 1, "waited": 29, "at": 39}])
        s = scaling_summary(d)
        self.assertEqual([seg[2] for seg in s.timelines[1]], ["production", BORROWED, OWN])
        (c,) = s.borrow
        self.assertEqual((c.window, c.borrowed, c.own_pool, c.end - c.start, c.waited), (1, 1, 2, 30, 29))
        self.assertEqual((s.builds[0].pool, s.builds[0].reason, s.builds[0].seconds), (2, "waiting session", 28))
        self.assertEqual(s.limit, [])

    def test_newcomer_on_a_pool_at_the_limit_is_case_b(self):
        from core.pool_test_report import scaling_summary
        P, H = ("PRODUCTION", None, False), ("HONEYPOT", 1, False)
        d = self._data([(0, [P, P]), (10, [H, P]), (50, [H, H])],
                       [{"type": "capped", "reason": "resource limit reached", "at": 30}])
        s = scaling_summary(d)
        self.assertEqual([(c.window, c.pool, c.shared_with) for c in s.limit], [(1, 1, [0])])
        self.assertEqual(s.capped, [(30.0, "resource limit reached")])

    def test_borrower_dropped_at_the_limit(self):
        from core.pool_test_report import scaling_summary
        P, H = ("PRODUCTION", None, False), ("HONEYPOT", 1, False)
        d = self._data([(0, [P, P]), (10, [H, ("HONEYPOT", 1, True)]), (30, [H, H])],
                       [{"type": "dropped_waiting", "sessions": ["s1"], "at": 25, "reason": "limit"}])
        s = scaling_summary(d)
        self.assertEqual([c.outcome for c in s.borrow], ["dropped"])
        self.assertEqual([(c.window, c.how) for c in s.limit], [(1, "dropped from the wait queue")])

    def test_load_stats(self):
        from core.pool_test_report import LoadTiming, load_stats
        st = load_stats([LoadTiming(0, 0, "x", ms, "own") for ms in (100, 200, 300)]
                        + [LoadTiming(0, 1, "x", 50, "")])
        self.assertEqual(set(st), {"own"})
        self.assertEqual((st["own"]["n"], st["own"]["median"], st["own"]["max"]), (3, 200, 300))


class ScaledownReportTests(unittest.TestCase):
    def test_pool_usage_parses_compose_and_runtime_containers(self):
        import json
        from core.resource_stats import parse_pool_usage
        lines = "\n".join(json.dumps(x) for x in [
            {"Name": "honeypot-ids-system-v1-honeypot_eshop_2-1", "MemUsage": "512MiB / 1GiB", "CPUPerc": "10.5%"},
            {"Name": "honeypot-ids-system-v1-honeypot_database_2-1", "MemUsage": "256MiB / 512MiB", "CPUPerc": "1.5%"},
            {"Name": "honeypot_eshop_5", "MemUsage": "100MiB / 1GiB", "CPUPerc": "3%"},
            {"Name": "honeypot-ids-system-v1-honeypot_database-1", "MemUsage": "64MiB / 512MiB", "CPUPerc": "0%"},
            {"Name": "honeypot-ids-system-v1-production_eshop-1", "MemUsage": "900MiB / 1GiB", "CPUPerc": "50%"},
        ]) + "\nnot json"
        u = parse_pool_usage(lines)
        self.assertEqual((u.containers, u.pools), (4, 3))
        self.assertEqual(u.per_pool_mem[2], 768 * 2 ** 20)
        self.assertAlmostEqual(u.cpu_percent, 15.0)

    def test_removals_and_usage_lookup(self):
        from core.pool_test_report import PoolTestData, UsageSample, scaling_summary, usage_at
        d = PoolTestData("now", "t", "u", "", [], duration=60, events=[
            {"type": "released", "pool": 4, "sessions": ["a", "b"], "reason": "released on request", "at": 40},
            {"type": "scaledown", "pool": 4, "idle": 3, "forced": True, "seconds": 2.5, "at": 42}],
            usage=[UsageSample(t, 2, 1, 100.0 * t, 0) for t in (0, 30, 45)])
        s = scaling_summary(d)
        self.assertEqual([(r.pool, r.seconds, r.forced) for r in s.removals], [(4, 2.5, True)])
        self.assertEqual(s.released, [(40.0, 4, 2, "released on request")])
        self.assertEqual(usage_at(d.usage, 40).t, 30)
        self.assertEqual(usage_at(d.usage, 40, after=True).t, 45)


class ProductIds(unittest.TestCase):
    def test_reads_ids_by_slug_from_the_store_api(self):
        from core.pool_test_report import parse_product_ids
        body = '[{"id": 178, "slug": "logo-cap"}, {"id": 136, "slug": "ceramic-pour-over-dripper"}]'
        self.assertEqual(parse_product_ids(body, ["ceramic-pour-over-dripper", "logo-cap"]),
                         {"ceramic-pour-over-dripper": 136, "logo-cap": 178})

    def test_missing_product_or_unreadable_response_raises(self):
        from core.pool_test_report import parse_product_ids
        with self.assertRaises(RuntimeError):
            parse_product_ids('[{"id": 1, "slug": "a"}]', ["a", "b"])
        with self.assertRaises(RuntimeError):
            parse_product_ids("<html>", ["a"])



class PoolEvidenceRuntimePools(unittest.TestCase):
    """Pools pool_manager built at runtime are not compose services: reading
    them must fall back from `docker compose exec/logs` to plain docker."""

    def test_falls_back_to_docker_when_compose_does_not_know_the_pool(self):
        from unittest import mock
        from core import pool_evidence as pe
        target = mock.MagicMock()
        target.build.side_effect = lambda *a: (["compose", *a], None)
        target.build_shell.side_effect = lambda cmd: (["sh", "-c", cmd], None)
        calls = []

        def run(argv, error, **_kw):
            calls.append(argv)
            if argv[0] == "compose":
                raise error('service "honeypot_eshop_4" is not running')
            return mock.Mock(stdout="2026-10-08T17:30:00Z\n")
        with mock.patch.object(pe, "run_checked", side_effect=run):
            out = pe._exec(target, "honeypot_eshop_4", "date -u")
            log = pe._logs(target, "honeypot_eshop_4", "2026-10-08T17:30:00Z")
        self.assertEqual(out.strip(), "2026-10-08T17:30:00Z")
        self.assertTrue(log)
        self.assertIn("docker exec honeypot_eshop_4 sh -c 'date -u'", calls[1][2])
        self.assertIn("docker logs --since 2026-10-08T17:30:00Z honeypot_eshop_4", calls[3][2])

    def test_logs_retry_through_docker_when_compose_prints_nothing(self):
        from unittest import mock
        from core import pool_evidence as pe
        target = mock.MagicMock()
        target.build.side_effect = lambda *a: (["compose", *a], None)
        target.build_shell.side_effect = lambda cmd: (["sh", "-c", cmd], None)
        line = '172.21.0.9 - - [09/Oct/2026:06:30:00 +0000] "GET /x HTTP/1.1" 200 5 "-" "UA PoolTest/D"\n'

        def run(argv, error, **_kw):   # compose: unknown service -> exit 0, no output
            return mock.Mock(stdout="" if argv[0] == "compose" else line)
        with mock.patch.object(pe, "run_checked", side_effect=run):
            log = pe._logs(target, "honeypot_eshop_4", "2026-10-09T06:00:00Z")
        self.assertEqual([h.window for h in pe.parse_access_log(log)], ["D"])

    def test_pool_built_during_the_run_gets_its_own_baseline(self):
        from unittest import mock
        from core import pool_evidence as pe
        baseline = {"since": "2026-10-08T17:00:00Z", "db": {1: {"Questions": 5}}, "pool_since": {}}
        with mock.patch.object(pe, "_exec", return_value="2026-10-08T17:31:00Z\n"), \
                mock.patch.object(pe, "db_status", return_value={"Questions": 900}):
            pe.extend_baseline(mock.MagicMock(), baseline, [1, 4])
        self.assertEqual(baseline["db"][1], {"Questions": 5})          # untouched
        self.assertEqual(baseline["db"][4], {"Questions": 900})
        self.assertEqual(baseline["pool_since"], {4: "2026-10-08T17:31:00Z"})


if __name__ == "__main__":
    unittest.main()
