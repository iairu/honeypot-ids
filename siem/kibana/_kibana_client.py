"""Shared Kibana connection setup for build_dashboards.py and
export_dashboards.py -- the identical argparse (KIBANA_URL/ELASTIC_USERNAME/
ELASTIC_PASSWORD, with --kibana-url/--user/--password overrides) and the
authenticated requests.Session both scripts opened by hand.

verify=False / disable_warnings: every SIEM service here uses the private
CA from gen_elk_certs.sh, with no publicly-trusted chain -- the deliberate
-k equivalent, same trust model as the rest of this repo's tooling.
"""
from __future__ import annotations

import argparse
import os
import sys

import requests


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--kibana-url", default=os.environ.get("KIBANA_URL", "https://localhost:5601"))
    parser.add_argument("--user", default=os.environ.get("ELASTIC_USERNAME", "elastic"))
    parser.add_argument("--password", default=os.environ.get("ELASTIC_PASSWORD"))


def parse_connection_args() -> argparse.Namespace:
    """Standard arg parsing + the required-password check both scripts do."""
    parser = argparse.ArgumentParser()
    add_connection_args(parser)
    args = parser.parse_args()
    if not args.password:
        print("ELASTIC_PASSWORD not set (env var or --password)", file=sys.stderr)
        sys.exit(1)
    return args


def make_session(user: str, password: str) -> requests.Session:
    """An authenticated Session with kbn-xsrf set and TLS warnings silenced
    (self-signed cert -- callers still pass verify=False per request)."""
    requests.packages.urllib3.disable_warnings()
    session = requests.Session()
    session.auth = (user, password)
    session.headers["kbn-xsrf"] = "true"
    return session
