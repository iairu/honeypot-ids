"""Tests for the committed Kibana dashboards (siem/kibana): the NDJSON that
kibana_dashboards_setup imports must be exactly what build_dashboards.py
defines, and every panel must point at a visualization that exists.

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
KIBANA_DIR = REPO_ROOT / "siem" / "kibana"


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_dashboards", KIBANA_DIR / "build_dashboards.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_dashboards"] = mod
    spec.loader.exec_module(mod)
    return mod


class KibanaDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()

    def test_committed_ndjson_is_up_to_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            fresh = Path(tmp) / "out.ndjson"
            self.bd.write_ndjson(fresh)
            committed = self.bd.NDJSON_PATH.read_text(encoding="utf-8")
            self.assertEqual(
                fresh.read_text(encoding="utf-8"), committed,
                "saved_objects/honeypot-dashboards.ndjson is stale: run "
                "`python3 siem/kibana/build_dashboards.py --ndjson`")

    def test_every_panel_references_a_defined_visualization(self):
        defined = {"visualization": {vid for vid, _ in self.bd.VISUALIZATIONS},
                   "search": {sid for sid, _ in self.bd.SEARCHES}}
        for dash_id, body in self.bd.DASHBOARDS:
            panels = json.loads(body["attributes"]["panelsJSON"])
            for panel, ref in zip(panels, body["references"]):
                with self.subTest(dashboard=dash_id, viz=ref["id"]):
                    self.assertIn(ref["id"], defined[ref["type"]])
                    self.assertEqual(panel["type"], ref["type"])

    def test_no_visualization_is_orphaned(self):
        used = {ref["id"] for _, body in self.bd.DASHBOARDS for ref in body["references"]}
        self.assertEqual(sorted({vid for vid, _ in self.bd.VISUALIZATIONS} - used), [])

    def test_dashboards_do_not_share_panels(self):
        # Each dashboard answers its own question; the old four repeated the
        # same panel shapes. A visualization belongs to exactly one dashboard.
        seen: dict[str, str] = {}
        for dash_id, body in self.bd.DASHBOARDS:
            for ref in body["references"]:
                with self.subTest(viz=ref["id"]):
                    self.assertNotIn(ref["id"], seen, f"also on {seen.get(ref['id'])}")
                seen[ref["id"]] = dash_id

    def test_top_uris_marks_attack_pattern_or_safe(self):
        body = dict(self.bd.VISUALIZATIONS)["viz-web-top-uris"]
        aggs = json.loads(body["attributes"]["visState"])["aggs"]
        fields = [a["params"].get("field") for a in aggs]
        self.assertIn("uri.keyword", fields)
        self.assertIn("uri_class.keyword", fields)

    def test_decision_dashboard_exists_and_is_exported(self):
        self.assertIn("dashboard-threat-decisions", self.bd.DASHBOARD_IDS)
        export = (KIBANA_DIR / "export_dashboards.py").read_text(encoding="utf-8")
        for dash_id in self.bd.DASHBOARD_IDS:
            with self.subTest(dashboard=dash_id):
                self.assertIn(f'"{dash_id}"', export)

    def test_dashboard_app_links_every_dashboard(self):
        page = (REPO_ROOT / "dashboard" / "ui" / "page_kibana.py").read_text(encoding="utf-8")
        notes = (REPO_ROOT / "dashboard" / "core" / "kibana_report.py").read_text(encoding="utf-8")
        for dash_id in self.bd.DASHBOARD_IDS:
            path = f"/app/dashboards#/view/{dash_id}"
            with self.subTest(dashboard=dash_id):
                self.assertIn(path, page)
                self.assertIn(path, notes)


class ThreatIntelTests(unittest.TestCase):
    """The Threat Intelligence dashboard is built on fields only the enrich
    transform's threat-intelligence block in vector.yaml creates."""

    FIELDS = ("attacker_ip", "sensor", "attacker_tool", "attacker_tool_class",
              "threat_verdict", "attack_technique", "attack_tactic", "threat.stage",
              "threat.technique.id", "vulnerability.id")

    @classmethod
    def setUpClass(cls):
        cls.bd = _load_builder()
        cls.vector = (REPO_ROOT / "siem/vector/vector.yaml").read_text(encoding="utf-8")

    def test_dashboard_exists(self):
        self.assertIn("dashboard-threat-intel", self.bd.DASHBOARD_IDS)

    def test_vector_sets_every_field(self):
        for field in self.FIELDS:
            with self.subTest(field=field):
                self.assertIn(f"  .{field} = ", self.vector)

    def test_panels_only_use_fields_vector_sets(self):
        # Every *.keyword / numeric field a TI panel aggregates on must be one
        # vector.yaml writes, or one an existing parse already provides.
        known = set(self.FIELDS) | {"timestamp", "threat_score", "session_id"}
        for vid, body in self.bd.VISUALIZATIONS:
            if not vid.startswith("viz-ti-"):
                continue
            for agg in json.loads(body["attributes"]["visState"])["aggs"]:
                field = agg["params"].get("field")
                if field:
                    with self.subTest(viz=vid, field=field):
                        self.assertIn(field.removesuffix(".keyword"), known)

    def test_ioc_list_is_one_row_per_attacker(self):
        body = dict(self.bd.VISUALIZATIONS)["viz-ti-indicators"]
        buckets = [a for a in json.loads(body["attributes"]["visState"])["aggs"]
                   if a["schema"] == "bucket"]
        self.assertEqual([a["params"]["field"] for a in buckets], ["attacker_ip.keyword"])

    def test_vector_unit_tests_cover_the_block(self):
        tests = (REPO_ROOT / "siem/vector/tests/threat_intel.yaml").read_text(encoding="utf-8")
        for field in ("attacker_tool", "threat.technique.id", "vulnerability.id", "threat_verdict"):
            with self.subTest(field=field):
                self.assertIn(f".{field}", tests)


class DecisionLogFieldTests(unittest.TestCase):
    """nginx's security log format and Vector's parser must agree on the
    routing-decision fields the Threat Decisions dashboard is built on."""

    FIELDS = ("request_score", "decayed_score", "offenses", "decay_state",
              "uri_class", "patterns", "reason")

    def test_both_nginx_layers_log_the_fields(self):
        for conf in (REPO_ROOT / "ids/reverse_proxy_enhanced/nginx.conf",
                     REPO_ROOT / "ids/db_proxy/reverse_proxy_enhanced/nginx.conf"):
            text = conf.read_text(encoding="utf-8")
            for field in self.FIELDS:
                with self.subTest(conf=conf.parent.parent.name, field=field):
                    self.assertIn(f'{field}="$', text)

    def test_vector_parses_the_fields(self):
        text = (REPO_ROOT / "siem/vector/vector.yaml").read_text(encoding="utf-8")
        for field in self.FIELDS:
            with self.subTest(field=field):
                self.assertIn(f'{field}="(?P<', text)


if __name__ == "__main__":
    unittest.main()
