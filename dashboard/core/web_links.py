"""Which services have a browsable web UI, and how to build the URL for
a given target (local -> 127.0.0.1, remote -> the configured remote host).
Only services whose port is actually published to the host are listed --
e.g. Vector's GraphQL playground (8686) exists but isn't published by
either compose file, so it's deliberately not included here."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class WebUI:
    label: str
    scheme: str
    port: int
    path: str = "/"


_ESHOP_VIA_NGINX = WebUI(
    "Open site via nginx (routing decides production vs. honeypot pool)",
    "https", 443, "/",
)

WEB_UI_SERVICES: dict[tuple[str, str], WebUI] = {
    ("edge", "reverse_proxy"): WebUI("Open site (production/honeypot)", "https", 443, "/"),
    ("siem", "kibana"): WebUI("Open Kibana", "https", 5601, "/"),
    ("siem", "es01"): WebUI("Open Elasticsearch (API root)", "https", 9200, "/"),
    # The eshop containers have no port of their own published to the host --
    # nginx (reverse_proxy) is the only entrypoint that reaches them, and
    # which backend actually answers (production or a specific honeypot
    # pool) is decided by pool_router.lua's routing logic, not by URL. These
    # entries exist so clicking "Open web UI" on an eshop node in the health
    # diagram still does something useful (the same nginx endpoint) instead
    # of the button just being absent for those nodes.
    ("edge", "production_eshop"): _ESHOP_VIA_NGINX,
    ("edge", "honeypot_eshop_1"): _ESHOP_VIA_NGINX,
    ("edge", "honeypot_eshop_2"): _ESHOP_VIA_NGINX,
    ("edge", "honeypot_eshop_3"): _ESHOP_VIA_NGINX,
}


def web_ui_for(project: str, service: str) -> WebUI | None:
    return WEB_UI_SERVICES.get((project, service))


def build_url(project: str, service: str, host: str) -> str | None:
    ui = web_ui_for(project, service)
    if ui is None:
        return None
    return f"{ui.scheme}://{host}:{ui.port}{ui.path}"
