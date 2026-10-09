"""Kibana request timeline for the exploit report: one small, wide Kibana
panel per exploit showing every request the reverse proxy logged from
RESOURCE_PRE_SECONDS before the exploit to RESOURCE_CAPTURE_SECONDS after
it, stacked by route (production / honeypot).

The panel lives on its own saved objects (a visualization and a one-panel
dashboard, both with fixed "exploit-report-*" ids) so it never collides with
the Honeypot dashboards that siem/kibana/build_dashboards.py owns. The
dashboard app imports them itself through the logged-in SIEM Analytics page right
before the first capture (ui/kibana_timeline_capture.py), so nothing has to
be redeployed on the SIEM for the report to use them.

Qt-free so it can be unit tested without PyQt6.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

# The data view siem/kibana/build_dashboards.py creates (honeypot-*).
DATA_VIEW_ID = "honeypot-data-view"
VIZ_ID = "exploit-report-request-timeline"
DASHBOARD_ID = "exploit-report-request-timeline-dashboard"
# Bars this wide; 17 s / 0.5 s = 34 bars, well under Kibana's histogram:maxBars.
BUCKET = "500ms"
# reverse proxy request lines (nginx log_format security, parsed by Vector).
_QUERY = 'log_type:"nginx_security"'


def _viz_body() -> dict:
    aggs = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {"customLabel": "Requests"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "useNormalizedEsInterval": False,
                    "interval": BUCKET, "drop_partials": False, "min_doc_count": 1,
                    "extended_bounds": {}, "customLabel": "Time"}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "route.keyword", "orderBy": "1", "order": "desc", "size": 5,
                    "otherBucket": False, "otherBucketLabel": "Other",
                    "missingBucket": False, "customLabel": "Route"}},
    ]
    params = {
        "type": "histogram",
        "grid": {"categoryLines": False, "valueAxis": "ValueAxis-1"},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                          "show": True, "style": {}, "scale": {"type": "linear"},
                          "labels": {"show": True, "filter": True, "truncate": 100},
                          "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                       "position": "left", "show": True, "style": {},
                       "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                       "title": {"text": "Requests"}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                          "data": {"label": "Requests", "id": "1"},
                          "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                          "lineWidth": 2, "interpolate": "linear", "showCircles": True}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False, "labels": {"show": False},
        "detailedTooltip": True,
        "thresholdLine": {"show": False, "value": 0, "width": 1, "style": "dashed",
                          "color": "#E7664C"},
    }
    title = "Exploit report: requests around the exploit by route"
    return {
        "attributes": {
            "title": title,
            "description": "Captured by the dashboard's exploit report, one per exploit.",
            "visState": json.dumps({"title": title, "type": "histogram",
                                    "params": params, "aggs": aggs}),
            "uiStateJSON": json.dumps({"vis": {"colors": {"production": "#54B399",
                                                          "honeypot": "#E7664C"}}}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": _QUERY, "language": "kuery"}, "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
        },
        "references": [{"id": DATA_VIEW_ID, "type": "index-pattern",
                        "name": "kibanaSavedObjectMeta.searchSourceJSON.index"}],
    }


def _dashboard_body() -> dict:
    panel = {"version": "8.17.3", "type": "visualization",
             "gridData": {"x": 0, "y": 0, "w": 48, "h": 10, "i": "1"},
             "panelIndex": "1", "embeddableConfig": {}, "panelRefName": "panel_1"}
    return {
        "attributes": {
            "title": "Exploit report: request timeline",
            "description": "One panel the exploit report screenshots for each exploit "
                           "(time range set by the report).",
            "panelsJSON": json.dumps([panel]),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False,
                                       "syncCursor": True, "syncTooltips": False,
                                       "hidePanelTitles": False}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": [{"id": VIZ_ID, "name": "panel_1", "type": "visualization"}],
    }


def saved_objects_ndjson() -> str:
    """The visualization and dashboard as an import-ready NDJSON string."""
    lines = []
    for obj_type, obj_id, body in (("visualization", VIZ_ID, _viz_body()),
                                   ("dashboard", DASHBOARD_ID, _dashboard_body())):
        lines.append(json.dumps({
            "attributes": body["attributes"], "coreMigrationVersion": "8.8.0",
            "id": obj_id, "managed": False, "references": body["references"],
            "type": obj_type}, sort_keys=True))
    return "\n".join(lines) + "\n"


def _iso(epoch: float) -> str:
    return (datetime.fromtimestamp(epoch, tz=timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(epoch * 1000) % 1000:03d}Z")


def timeline_url(kibana_base: str, start_epoch: float, end_epoch: float) -> str:
    """The one-panel dashboard in embed mode (no Kibana chrome), fixed to
    ``start_epoch`` .. ``end_epoch``."""
    g = (f"(refreshInterval:(pause:!t,value:0),"
         f"time:(from:'{_iso(start_epoch)}',to:'{_iso(end_epoch)}'))")
    return (f"{kibana_base.rstrip('/')}/app/dashboards#/view/{DASHBOARD_ID}"
            f"?embed=true&hide-filter-bar=true&_g={g}")
