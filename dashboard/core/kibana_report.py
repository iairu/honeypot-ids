"""Kibana PDF export: one section per Kibana page button on the Kibana page
(ui/page_kibana._BOOKMARKS), each with a short explanation of what the page
shows and a full-page screenshot of it.

The screenshots themselves are captured by ui/kibana_export.KibanaCapture
(it needs a live, logged-in QWebEngineView); this module only turns the
captured images into the PDF, so it stays usable headlessly.

A full-page capture of a dashboard is usually far taller than one A4 page,
and QTextDocument never splits an image across pages -- so each capture is
sliced into page-sized strips here and laid out one after another.
"""
from __future__ import annotations

import html as _html
from dataclasses import dataclass
from datetime import datetime

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QFont, QImage, QTextDocument

from core.exploit_report_pdf import _FONT_CSS_STACK, _report_font_family
from core.thesis_export import _finish_pdf

# What each Kibana page button shows, keyed by its path relative to the
# Kibana root (same keys as ui/page_kibana._BOOKMARKS). Panel names match
# siem/kibana/build_dashboards.py.
PAGE_NOTES: dict[str, str] = {
    "/app/home": (
        "Kibana's landing page for the SIEM stack. It is the entry point to the saved "
        "dashboards and to Discover below, and confirms the SIEM (Vector &rarr; "
        "Elasticsearch &rarr; Kibana) is up and the dashboard is logged in."
    ),
    "/app/dashboards#/view/dashboard-web-threat-overview": (
        "All traffic that passed through the reverse proxy (nginx access logs). "
        "<b>Total Requests</b> and <b>Requests Over Time by Route</b> show volume split by "
        "where each request was sent; <b>Production vs Honeypot Routing</b> is the share "
        "diverted to the decoy shop; <b>Threat Score Distribution</b> is the histogram of "
        "per-request threat scores; the three tables list the top URIs, User-Agents and "
        "the IPs most often flagged suspicious."
    ),
    "/app/dashboards#/view/dashboard-ids-alerts": (
        "Network-level alerts from the Suricata IDS, independent of the reverse proxy's "
        "own scoring. <b>Total Alerts</b> and <b>Alerts Over Time</b> give volume; the pies "
        "break alerts down by Suricata category and severity; <b>Top Signatures</b> names "
        "the rules that fired most and <b>Top Source IPs</b> the hosts that triggered them. "
        "These alerts also feed the IP-reputation signal of the scoring pipeline."
    ),
    "/app/dashboards#/view/dashboard-session-analysis": (
        "Behaviour per tracked session rather than per request. <b>Total Distinct "
        "Sessions</b> and <b>Distinct Sessions Active Over Time</b> give the population; "
        "<b>Requests &amp; Duration per Session</b> and <b>Top Sessions by Peak Threat "
        "Score</b> single out the busiest and most hostile sessions (the peak is the "
        "session score after accumulation and decay); the sophistication panels show how "
        "attackers were classified and with what confidence over time."
    ),
    "/app/dashboards#/view/dashboard-attack-patterns": (
        "Security events the reverse proxy logged explicitly (log_security_event). "
        "<b>Events by Type</b> and <b>Security Events Over Time by Type</b> show what kind "
        "of events occurred and when; <b>Honeypot Routing Reasons</b> explains why requests "
        "were diverted (CVE match, high score, bad IP, sticky session); <b>Top CVEs "
        "Detected</b>, <b>Top Attacking IPs</b> and <b>Honeytoken Hits by Type</b> show which "
        "exploits were attempted, by whom, and which planted honeytokens were touched."
    ),
    "/app/discover": (
        "Raw log search over the <code>honeypot-*</code> data view: every event Vector "
        "shipped into Elasticsearch, newest first, with a histogram of event volume over "
        "the selected time range. Used to drill into the individual documents behind any "
        "panel on the dashboards above."
    ),
}


@dataclass
class KibanaShot:
    label: str          # the Kibana page button's label
    path: str           # path relative to the Kibana root
    url: str            # full URL that was captured
    image: QImage | None
    error: str = ""     # why there is no image, if there isn't one


def _esc(text: str) -> str:
    return _html.escape(text or "")


def _slices(img: QImage, max_aspect: float) -> list[QImage]:
    """Cut ``img`` into horizontal strips at most ``width * max_aspect`` tall."""
    strip_h = max(1, int(img.width() * max_aspect))
    if img.height() <= strip_h:
        return [img]
    return [img.copy(0, y, img.width(), min(strip_h, img.height() - y))
            for y in range(0, img.height(), strip_h)]


def render_kibana_pdf(shots: list[KibanaShot], out_path: str, kibana_url: str) -> int:
    """Write the Kibana export PDF. Returns the number of pages captured."""
    family = _report_font_family()
    doc = QTextDocument()
    doc.setDefaultFont(QFont(family, 11))
    width = 620
    # Strips about as tall as an A4 page's text area allows at this width,
    # leaving room for the heading/explanation on the first strip's page.
    max_aspect = 1.5

    parts: list[str] = [f'<div style="font-family: {_FONT_CSS_STACK};">']
    parts.append('<h1 style="color:#222;">Kibana (SIEM) pages</h1>')
    parts.append('<p style="color:#555;">Generated '
                 f'{_esc(datetime.now().strftime("%Y-%m-%d %H:%M"))} from '
                 f'<code>{_esc(kibana_url)}</code>. One section per page button on the '
                 "dashboard's Kibana page: what the page shows, then a full-page screenshot "
                 'of it as it looked at export time (dashboards use their saved time range, '
                 'the last 24 hours). Tall pages continue over several strips.</p><hr/>')

    captured = 0
    for i, shot in enumerate(shots, start=1):
        parts.append(f'<h2 style="color:#222;">{i}. {_esc(shot.label)}</h2>')
        note = PAGE_NOTES.get(shot.path, "")
        if note:
            parts.append(f'<p style="color:#444;">{note}</p>')
        parts.append(f'<p style="color:#888; font-size:9pt;">{_esc(shot.url)}</p>')
        if shot.image is None or shot.image.isNull():
            parts.append('<p style="color:#c62828;"><b>Not captured:</b> '
                         f'{_esc(shot.error or "the page did not load")}</p>')
            continue
        captured += 1
        for j, strip in enumerate(_slices(shot.image, max_aspect)):
            key = f"kibana-{i}-{j}"
            doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(f"shot://{key}"), strip)
            h = int(width * strip.height() / max(1, strip.width()))
            parts.append(f'<p><img src="shot://{key}" width="{width}" height="{h}"/></p>')

    parts.append('</div>')
    doc.setHtml("<body>" + "".join(parts) + "</body>")
    _finish_pdf(doc, out_path)
    return captured
