#!/usr/bin/env python3
"""Exports the two Honeypot dashboards (and everything they reference --
the data view, all 13 panel visualizations) to saved_objects/
honeypot-dashboards.ndjson, the file kibana_dashboards_setup imports on
every `docker compose up`.

Run this after build_dashboards.py, or after hand-editing a panel live in
Kibana, to refresh the committed NDJSON. Deliberately does NOT include the
`defaultRoute` config object -- see build_dashboards.py's docstring for why
that's set via a direct settings API call instead.

Usage: KIBANA_URL, ELASTIC_USERNAME, ELASTIC_PASSWORD env vars (or pass
--kibana-url/--user/--password), then:
    python3 export_dashboards.py
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import requests

DASHBOARD_IDS = ["dashboard-ids-alerts", "dashboard-web-threat-overview"]
OUTPUT_PATH = Path(__file__).resolve().parent / "saved_objects" / "honeypot-dashboards.ndjson"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kibana-url", default=os.environ.get("KIBANA_URL", "https://localhost:5601"))
    parser.add_argument("--user", default=os.environ.get("ELASTIC_USERNAME", "elastic"))
    parser.add_argument("--password", default=os.environ.get("ELASTIC_PASSWORD"))
    args = parser.parse_args()

    if not args.password:
        print("ELASTIC_PASSWORD not set (env var or --password)", file=sys.stderr)
        sys.exit(1)

    requests.packages.urllib3.disable_warnings()
    resp = requests.post(
        f"{args.kibana_url}/api/saved_objects/_export",
        json={"objects": [{"type": "dashboard", "id": d} for d in DASHBOARD_IDS],
              "includeReferencesDeep": True},
        auth=(args.user, args.password),
        headers={"kbn-xsrf": "true"},
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_bytes(resp.content)
    print(f"Wrote {OUTPUT_PATH} ({len(resp.content)} bytes)")


if __name__ == "__main__":
    main()
