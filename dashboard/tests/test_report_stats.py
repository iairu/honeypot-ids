"""Unit tests for core/report_stats.py (the reports' probability metrics).

Reference values come from standard tables / scipy.stats.

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import report_stats as st  # noqa: E402


class DistributionTests(unittest.TestCase):
    def test_t_critical_values_match_tables(self):
        for df, expected in ((1, 12.706), (4, 2.776), (9, 2.262), (30, 2.042), (1000, 1.962)):
            with self.subTest(df=df):
                self.assertAlmostEqual(st.t_crit(df), expected, places=3)

    def test_two_sided_tail(self):
        self.assertAlmostEqual(st.t_sf2(2.262157, 9), 0.05, places=5)
        self.assertAlmostEqual(st.t_sf2(0.0, 5), 1.0, places=9)


class RateTests(unittest.TestCase):
    def test_wilson_half(self):
        r = st.wilson(5, 10)
        self.assertAlmostEqual(r.lo, 0.2366, places=4)
        self.assertAlmostEqual(r.hi, 0.7634, places=4)

    def test_wilson_all_and_none_stay_in_range(self):
        r = st.wilson(12, 12)
        self.assertEqual(r.hi, 1.0)
        self.assertAlmostEqual(r.lo, 0.7575, places=4)
        r = st.wilson(0, 5)
        self.assertEqual(r.lo, 0.0)
        self.assertAlmostEqual(r.hi, 0.4345, places=4)

    def test_wilson_empty(self):
        self.assertIsNone(st.wilson(0, 0))
        self.assertEqual(st.fmt_rate(None), "n/a (no data)")


class SummaryTests(unittest.TestCase):
    def test_mean_ci(self):
        s = st.summarize([1, 2, 3, 4, 5])
        self.assertAlmostEqual(s.mean, 3.0)
        self.assertAlmostEqual(s.sd, 1.5811, places=4)
        self.assertAlmostEqual(s.lo, 1.0368, places=4)
        self.assertAlmostEqual(s.hi, 4.9632, places=4)
        self.assertAlmostEqual(s.p95, 4.8)

    def test_single_value_has_no_ci(self):
        s = st.summarize([7])
        self.assertIsNone(s.lo)
        self.assertIn("no CI", st.fmt_mean_ci(s))

    def test_autocorrelation_widens_the_ci(self):
        # A slow ramp: neighbours nearly identical, so far fewer independent samples.
        vals = [i / 10 for i in range(100)]
        plain = st.summarize(vals)
        adj = st.summarize(vals, autocorr=True)
        self.assertLess(adj.n_eff, 10)
        self.assertGreater(adj.hi - adj.lo, 3 * (plain.hi - plain.lo))

    def test_empty(self):
        self.assertIsNone(st.summarize([]))


class ComparisonTests(unittest.TestCase):
    def test_welch_matches_scipy(self):
        c = st.welch([1, 2, 3, 2, 1], [5, 6, 7, 6, 5])
        self.assertAlmostEqual(c.t, 7.5593, places=4)
        self.assertAlmostEqual(c.df, 8.0, places=6)
        self.assertAlmostEqual(c.p, 6.55e-05, delta=1e-6)

    def test_welch_autocorr_is_less_confident(self):
        before = [2.0, 2.5, 2.1, 2.4, 2.2, 2.3, 2.0, 2.6]
        after = [30.0] * 10 + [3.0] * 30  # a burst then back to normal
        plain = st.welch(before, after)
        adj = st.welch(before, after, autocorr=True)
        self.assertAlmostEqual(adj.diff, plain.diff)
        self.assertGreater(adj.p, plain.p)

    def test_floor_clips_ci(self):
        s = st.summarize([30.0] * 10 + [3.0] * 30, autocorr=True, floor=0.0)
        self.assertEqual(s.lo, 0.0)

    def test_welch_needs_two_per_side(self):
        self.assertIsNone(st.welch([1], [2, 3]))

    def test_identical_constant_groups(self):
        self.assertEqual(st.welch([3, 3], [3, 3]).p, 1.0)

    def test_trend(self):
        t = st.trend([1, 2, 3, 4], [10, 20, 31, 39])
        self.assertAlmostEqual(t.slope, 9.8)
        self.assertLess(t.lo, 9.8)
        self.assertGreater(t.hi, 9.8)
        self.assertLess(t.p, 0.01)

    def test_flat_trend_not_significant(self):
        t = st.trend([1, 2, 3, 4, 5, 6], [5, 6, 5, 6, 5, 6])
        self.assertGreater(t.p, 0.05)
        self.assertIn("chance", st.p_meaning(t.p))


class DecayFitTests(unittest.TestCase):
    def test_recovers_configured_half_life(self):
        samples = [(t, 60 * 0.5 ** (t / 30)) for t in range(0, 121, 20)]
        fit = st.fit_decay(samples, model_half_life=30, peak=60)
        self.assertAlmostEqual(fit.half_life, 30.0, places=6)
        self.assertAlmostEqual(fit.r2, 1.0, places=6)
        self.assertAlmostEqual(fit.rmse_vs_model, 0.0, places=6)

    def test_noisy_ci_brackets_truth(self):
        samples = [(t, 60 * 0.5 ** (t / 30) + (1 if i % 2 else -1))
                   for i, t in enumerate(range(0, 121, 20))]
        fit = st.fit_decay(samples, 30, 60)
        self.assertLess(fit.lo, fit.half_life)
        self.assertGreater(fit.hi, fit.half_life)

    def test_flat_scores_show_no_decay(self):
        fit = st.fit_decay([(0, 50), (20, 50), (40, 50), (60, 50)])
        self.assertIsNone(fit.half_life)

    def test_zero_scores_dropped(self):
        self.assertIsNone(st.fit_decay([(0, 40), (10, 0), (20, 0)]))


class FormatTests(unittest.TestCase):
    def test_p_values(self):
        self.assertEqual(st.fmt_p(0.0001), "p &lt; 0.001")
        self.assertEqual(st.fmt_p(0.0345), "p = 0.035")
        self.assertEqual(st.fmt_p(None), "p = n/a")

    def test_table_skips_when_empty(self):
        self.assertEqual(st.stats_table_html([]), "")
        self.assertIn("<b>1</b>", st.stats_table_html([("a", "1", "b")]))


if __name__ == "__main__":
    unittest.main()
