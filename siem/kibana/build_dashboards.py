#!/usr/bin/env python3
"""Creates (or overwrites) the two committed Honeypot Kibana dashboards and
their underlying data view/visualizations via the Saved Objects API.

This is the *authoring* tool -- run it once by hand against a live Kibana
whenever the dashboards themselves need to change (new panel, different
aggregation, etc.), then re-export with export_dashboards.py and commit the
refreshed saved_objects/honeypot-dashboards.ndjson. It is NOT part of the
automatic provisioning path -- that's kibana_dashboards_setup's job in
docker-compose.yml, which only ever imports the already-committed NDJSON.

All object IDs are fixed/stable (not auto-generated) so that:
  - re-running this script is idempotent (overwrite=true),
  - dashboard/ui/page_kibana.py's bookmark buttons, which hardcode
    dashboard-web-threat-overview / dashboard-ids-alerts, keep working.

Usage: KIBANA_URL, ELASTIC_USERNAME, ELASTIC_PASSWORD env vars (or pass
--kibana-url/--user/--password), then:
    python3 build_dashboards.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import requests

DATA_VIEW_ID = "honeypot-data-view"


def _viz(vis_id: str, title: str, vis_type: str, aggs: list[dict], *,
         query: str = "", filters: list[dict] | None = None,
         params_extra: dict | None = None) -> tuple[str, dict]:
    """Builds a classic-type visualization saved object body.

    Classic (not Lens) visualizations were chosen deliberately, same as the
    original build -- see ARCHITECTURE.md's Dashboards section: their
    visState/aggs JSON schema has stayed stable across Kibana versions,
    where Lens's internal state has not.
    """
    params = {"addTooltip": True, "addLegend": True, "legendPosition": "right"}
    if params_extra:
        params.update(params_extra)
    vis_state = {
        "title": title,
        "type": vis_type,
        "params": params,
        "aggs": aggs,
    }
    body = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": query, "language": "kuery"},
                    "filter": filters or [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                })
            },
        },
        "references": [
            {"id": DATA_VIEW_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}
        ],
    }
    return vis_id, body


def _count_metric_agg() -> dict:
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def _date_histogram_agg(agg_id: str = "2") -> dict:
    return {
        "id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
        "params": {"field": "timestamp", "timeRange": {"from": "now-24h", "to": "now"},
                    "useNormalizedEsInterval": True, "interval": "auto", "drop_partials": False,
                    "min_doc_count": 1, "extended_bounds": {}},
    }


def _terms_agg(field: str, agg_id: str = "2", size: int = 10, schema: str = "segment",
                order_by: str = "1") -> dict:
    return {
        "id": agg_id, "enabled": True, "type": "terms", "schema": schema,
        "params": {"field": field, "orderBy": order_by, "order": "desc", "size": size,
                    "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False},
    }


def _metric_agg(agg_type: str, field: str, agg_id: str) -> dict:
    """A non-count metric (cardinality/max/min/avg), schema=metric -- same
    shape as _count_metric_agg() but for a real field."""
    return {"id": agg_id, "enabled": True, "type": agg_type, "schema": "metric", "params": {"field": field}}


def _histogram_agg(field: str, interval: int, agg_id: str = "2") -> dict:
    return {
        "id": agg_id, "enabled": True, "type": "histogram", "schema": "segment",
        "params": {"field": field, "interval": interval, "min_doc_count": True, "extended_bounds": {}},
    }


# The honeypot-* data view spans EVERY shipped log type (docker, suricata,
# nginx_access, nginx_security, nginx_error, redis all land in their own
# honeypot-<log_type>-YYYY.MM.DD index, but one data view covers all of
# them by wildcard) -- confirmed live that an unfiltered query counts
# 21,207 docs across all types where only 166 were actually nginx_security
# requests, and that `event_type:alert` alone (no log_type filter) picks
# up 44 cross-type matches vs. 41 real Suricata alerts (a docker-sourced
# log line's message text apparently free-text-matched "alert" too, since
# `event_type` is a text field, not just a keyword one). Every panel below
# explicitly scopes to its own log_type accordingly, rather than relying
# on which fields happen to only exist on the intended type.
_IDS_Q = 'log_type:"suricata" and event_type:"alert"'
_WEB_Q = 'log_type:"nginx_security"'

# session_id-bearing nginx_security requests -- the per-request threat-scored
# traffic each attacker session is made of (§3.5/§6). attacker_sophistication_
# classified events (nginx_error, parsed by the enrich transform's
# log_security_event() JSON parsing -- see vector.yaml) carry the same
# session_id, hoisted to the top level specifically so these two dashboards
# can correlate on one field name.
_SESSION_Q = 'log_type:"nginx_security" and session_id:*'
_SOPHISTICATION_Q = 'log_type:"nginx_error" and security_event_type:"attacker_sophistication_classified"'

# All log_security_event()-sourced events (honeytoken hits, session
# compromise, CVE pattern matches, high-threat requests, honeypot routing
# decisions, sophistication classification) -- see init.lua's
# _G.utils.log_security_event() and the enrich transform's nginx_error
# parsing block in vector.yaml.
_ATTACK_Q = 'log_type:"nginx_error" and security_event_type:*'

VISUALIZATIONS = [
    # -- IDS Alerts (Suricata) --------------------------------------------
    _viz("viz-ids-total-alerts", "Total Alerts", "metric",
         [_count_metric_agg()], query=_IDS_Q),
    _viz("viz-ids-alerts-over-time", "Alerts Over Time", "histogram",
         [_count_metric_agg(), _date_histogram_agg()], query=_IDS_Q),
    _viz("viz-ids-alerts-by-category", "Alerts by Category", "pie",
         [_count_metric_agg(), _terms_agg("alert.category.keyword", size=10)],
         query=_IDS_Q),
    _viz("viz-ids-alerts-by-severity", "Alerts by Severity", "pie",
         [_count_metric_agg(), _terms_agg("alert.severity", size=10)],
         query=_IDS_Q),
    _viz("viz-ids-top-signatures", "Top Signatures", "table",
         [_count_metric_agg(), _terms_agg("alert.signature.keyword", agg_id="2", size=10, schema="bucket")],
         query=_IDS_Q),
    _viz("viz-ids-top-source-ips", "Top Source IPs", "table",
         [_count_metric_agg(), _terms_agg("src_ip.keyword", agg_id="2", size=10, schema="bucket")],
         query=_IDS_Q),

    # -- Web Traffic & Threat Overview -------------------------------------
    _viz("viz-web-total-requests", "Total Requests", "metric",
         [_count_metric_agg()], query=_WEB_Q),
    _viz("viz-web-requests-over-time", "Requests Over Time by Route", "histogram",
         [_count_metric_agg(), _date_histogram_agg(), _terms_agg("route.keyword", agg_id="3", size=5, schema="group")],
         query=_WEB_Q),
    _viz("viz-web-routing-pie", "Production vs Honeypot Routing", "pie",
         [_count_metric_agg(), _terms_agg("route.keyword", size=5)], query=_WEB_Q),
    _viz("viz-web-threat-score-histogram", "Threat Score Distribution", "histogram",
         [_count_metric_agg(), _histogram_agg("threat_score", 10)], query=_WEB_Q),
    _viz("viz-web-top-uris", "Top URIs", "table",
         [_count_metric_agg(), _terms_agg("uri.keyword", agg_id="2", size=10, schema="bucket")], query=_WEB_Q),
    _viz("viz-web-top-user-agents", "Top User-Agents", "table",
         [_count_metric_agg(), _terms_agg("user_agent.keyword", agg_id="2", size=10, schema="bucket")], query=_WEB_Q),
    _viz("viz-web-top-suspicious-ips", "Top IPs Flagged Suspicious", "table",
         [_count_metric_agg(), _terms_agg("remote_addr.keyword", agg_id="2", size=10, schema="bucket")],
         query=f"{_WEB_Q} and suspicious:true"),

    # -- Session Analysis ---------------------------------------------------
    _viz("viz-session-total-sessions", "Total Distinct Sessions", "metric",
         [_metric_agg("cardinality", "session_id.keyword", "1")], query=_SESSION_Q),
    _viz("viz-session-over-time", "Distinct Sessions Active Over Time", "histogram",
         [_metric_agg("cardinality", "session_id.keyword", "1"), _date_histogram_agg()],
         query=_SESSION_Q),
    _viz("viz-session-requests-table", "Requests & Duration per Session", "table",
         [_count_metric_agg(), _metric_agg("min", "timestamp", "2"), _metric_agg("max", "timestamp", "3"),
          _terms_agg("session_id.keyword", agg_id="4", size=15, schema="bucket", order_by="1")],
         query=_SESSION_Q),
    _viz("viz-session-top-threat", "Top Sessions by Peak Threat Score", "table",
         [_metric_agg("max", "threat_score", "1"),
          _terms_agg("session_id.keyword", agg_id="2", size=15, schema="bucket", order_by="1")],
         query=_SESSION_Q),
    _viz("viz-session-sophistication-pie", "Sophistication Classifications", "pie",
         [_count_metric_agg(), _terms_agg("security_event.classification.keyword", size=10)],
         query=_SOPHISTICATION_Q),
    _viz("viz-session-sophistication-confidence", "Sophistication Confidence Over Time", "histogram",
         [_metric_agg("avg", "security_event.confidence", "1"), _date_histogram_agg()],
         query=_SOPHISTICATION_Q),

    # -- Attack Patterns ------------------------------------------------------
    _viz("viz-attack-total-events", "Total Security Events", "metric",
         [_count_metric_agg()], query=_ATTACK_Q),
    _viz("viz-attack-events-over-time", "Security Events Over Time by Type", "histogram",
         [_count_metric_agg(), _date_histogram_agg(),
          _terms_agg("security_event_type.keyword", agg_id="3", size=8, schema="group")],
         query=_ATTACK_Q),
    _viz("viz-attack-events-by-type", "Events by Type", "pie",
         [_count_metric_agg(), _terms_agg("security_event_type.keyword", size=10)], query=_ATTACK_Q),
    _viz("viz-attack-routing-reasons", "Honeypot Routing Reasons", "pie",
         [_count_metric_agg(), _terms_agg("security_event.reason.keyword", size=10)],
         query=f'{_ATTACK_Q} and security_event_type:"routing_to_honeypot"'),
    _viz("viz-attack-top-cves", "Top CVEs Detected", "table",
         [_count_metric_agg(), _terms_agg("security_event.cve.keyword", agg_id="2", size=10, schema="bucket")],
         query=f'{_ATTACK_Q} and security_event_type:"cve_pattern_detected"'),
    _viz("viz-attack-top-ips", "Top Attacking IPs", "table",
         [_count_metric_agg(), _terms_agg("remote_addr.keyword", agg_id="2", size=10, schema="bucket")],
         query=_ATTACK_Q),
    _viz("viz-attack-honeytoken-types", "Honeytoken Hits by Type", "table",
         [_count_metric_agg(), _terms_agg("security_event.token_type.keyword", agg_id="2", size=10, schema="bucket")],
         query=f'{_ATTACK_Q} and security_event_type:"honeytoken_used"'),
]


def _panel(panel_index: str, x: int, y: int, w: int, h: int, ref_name: str) -> dict:
    return {
        "version": "8.17.3", "type": "visualization",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
        "panelIndex": panel_index, "embeddableConfig": {}, "panelRefName": ref_name,
    }


def _dashboard(dash_id: str, title: str, description: str, layout: list[tuple[str, int, int, int, int]]) -> tuple[str, dict]:
    """layout: list of (viz_id, x, y, w, h) in panel order."""
    panels = []
    references = []
    for idx, (viz_id, x, y, w, h) in enumerate(layout, start=1):
        panel_index = str(idx)
        ref_name = f"panel_{panel_index}"
        panels.append(_panel(panel_index, x, y, w, h, ref_name))
        references.append({"id": viz_id, "name": ref_name, "type": "visualization"})

    body = {
        "attributes": {
            "title": title,
            "description": description,
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False,
                                         "syncCursor": True, "syncTooltips": False,
                                         "hidePanelTitles": False}),
            "timeRestore": True,
            "timeFrom": "now-24h",
            "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": references,
    }
    return dash_id, body


DASHBOARDS = [
    _dashboard(
        "dashboard-ids-alerts", "Honeypot: IDS Alerts (Suricata)",
        "Suricata alert volume, categories, severities, top signatures and source IPs.",
        [
            ("viz-ids-total-alerts", 0, 0, 12, 8),
            ("viz-ids-alerts-over-time", 12, 0, 36, 8),
            ("viz-ids-alerts-by-category", 0, 8, 16, 15),
            ("viz-ids-alerts-by-severity", 16, 8, 16, 15),
            ("viz-ids-top-signatures", 32, 8, 16, 15),
            ("viz-ids-top-source-ips", 0, 23, 48, 15),
        ],
    ),
    _dashboard(
        "dashboard-web-threat-overview", "Honeypot: Web Traffic & Threat Overview",
        "All nginx traffic: request volume, production-vs-honeypot routing, threat scores, top URIs/User-Agents/suspicious IPs.",
        [
            ("viz-web-total-requests", 0, 0, 12, 8),
            ("viz-web-requests-over-time", 12, 0, 36, 8),
            ("viz-web-routing-pie", 0, 8, 16, 15),
            ("viz-web-threat-score-histogram", 16, 8, 32, 15),
            ("viz-web-top-uris", 0, 23, 16, 15),
            ("viz-web-top-user-agents", 16, 23, 16, 15),
            ("viz-web-top-suspicious-ips", 32, 23, 16, 15),
        ],
    ),
    _dashboard(
        "dashboard-session-analysis", "Honeypot: Session Analysis",
        "Per-session request volume and duration, peak threat scores, and attacker-sophistication classification.",
        [
            ("viz-session-total-sessions", 0, 0, 12, 8),
            ("viz-session-over-time", 12, 0, 36, 8),
            ("viz-session-requests-table", 0, 8, 24, 15),
            ("viz-session-top-threat", 24, 8, 24, 15),
            ("viz-session-sophistication-pie", 0, 23, 16, 15),
            ("viz-session-sophistication-confidence", 16, 23, 32, 15),
        ],
    ),
    _dashboard(
        "dashboard-attack-patterns", "Honeypot: Attack Patterns",
        "log_security_event()-sourced events: honeypot routing reasons, CVE matches, honeytoken hits, top attacking IPs.",
        [
            ("viz-attack-total-events", 0, 0, 12, 8),
            ("viz-attack-events-over-time", 12, 0, 36, 8),
            ("viz-attack-events-by-type", 0, 8, 16, 15),
            ("viz-attack-routing-reasons", 16, 8, 16, 15),
            ("viz-attack-top-cves", 32, 8, 16, 15),
            ("viz-attack-top-ips", 0, 23, 24, 15),
            ("viz-attack-honeytoken-types", 24, 23, 24, 15),
        ],
    ),
]


def put(session: requests.Session, base: str, obj_type: str, obj_id: str, body: dict) -> None:
    resp = session.post(f"{base}/api/saved_objects/{obj_type}/{obj_id}?overwrite=true",
                         json=body, verify=False, timeout=30)
    if resp.status_code >= 300:
        print(f"FAILED {obj_type}/{obj_id}: {resp.status_code} {resp.text}", file=sys.stderr)
        resp.raise_for_status()
    print(f"OK {obj_type}/{obj_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kibana-url", default=os.environ.get("KIBANA_URL", "https://localhost:5601"))
    parser.add_argument("--user", default=os.environ.get("ELASTIC_USERNAME", "elastic"))
    parser.add_argument("--password", default=os.environ.get("ELASTIC_PASSWORD"))
    args = parser.parse_args()

    if not args.password:
        print("ELASTIC_PASSWORD not set (env var or --password)", file=sys.stderr)
        sys.exit(1)

    requests.packages.urllib3.disable_warnings()  # self-signed cert, deliberate -k equivalent
    session = requests.Session()
    session.auth = (args.user, args.password)
    session.headers["kbn-xsrf"] = "true"

    put(session, args.kibana_url, "index-pattern", DATA_VIEW_ID,
        {"attributes": {"title": "honeypot-*", "timeFieldName": "timestamp"}})

    for viz_id, body in VISUALIZATIONS:
        put(session, args.kibana_url, "visualization", viz_id, body)

    for dash_id, body in DASHBOARDS:
        put(session, args.kibana_url, "dashboard", dash_id, body)

    print("\nAll saved objects created/updated.")


if __name__ == "__main__":
    main()
