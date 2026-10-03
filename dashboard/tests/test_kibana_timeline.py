"""Tests for core/kibana_timeline.py: the exploit report's Kibana request
timeline objects and URL.

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import kibana_timeline as kt  # noqa: E402


class KibanaTimelineTests(unittest.TestCase):
    def test_objects_are_importable_ndjson_with_own_ids(self):
        objs = [json.loads(line) for line in kt.saved_objects_ndjson().splitlines()]
        self.assertEqual([(o["type"], o["id"]) for o in objs],
                         [("visualization", kt.VIZ_ID), ("dashboard", kt.DASHBOARD_ID)])
        # Never the Honeypot dashboards' ids (siem/kibana/build_dashboards.py).
        for o in objs:
            self.assertTrue(o["id"].startswith("exploit-report-"))
        vis = json.loads(objs[0]["attributes"]["visState"])
        hist = next(a for a in vis["aggs"] if a["type"] == "date_histogram")
        self.assertEqual(hist["params"]["interval"], kt.BUCKET)
        self.assertEqual(objs[0]["references"][0]["id"], kt.DATA_VIEW_ID)
        self.assertEqual(objs[1]["references"][0]["id"], kt.VIZ_ID)

    def test_url_is_embedded_and_fixed_to_the_window(self):
        url = kt.timeline_url("https://localhost:5601/", 1791007300.25, 1791007317.25)
        self.assertTrue(url.startswith(
            f"https://localhost:5601/app/dashboards#/view/{kt.DASHBOARD_ID}?embed=true"))
        self.assertIn("from:'2026-10-03T06:01:40.250Z'", url)
        self.assertIn("to:'2026-10-03T06:01:57.250Z'", url)


if __name__ == "__main__":
    unittest.main()
