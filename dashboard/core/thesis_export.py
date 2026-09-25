"""Auto-generated "Implementation" thesis chapter -> PDF.

Collects a curated set of the project's more interesting algorithms straight
from the live source tree, condenses each one (drops comments, docstrings,
debug logging and blank runs so only the algorithmic essence remains), and
renders them -- with a short prose description each -- into a single PDF laid
out like a thesis implementation chapter. The Baskerville family already
bundled for the exploit report is reused for the prose so both documents match.

GUI-thread only (QtGui/QtPrintSupport), same as exploit_report_pdf. The manifest
(HIGHLIGHTS) intentionally lists more entries than any one branch has: an entry
whose file or symbol is missing is silently skipped, so the same manifest works
on every branch and only renders what actually exists there.
"""
from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime

from PyQt6.QtCore import QMarginsF, QSizeF, QUrl
from PyQt6.QtGui import QFont, QImage, QTextDocument
from PyQt6.QtPrintSupport import QPrinter

from core.paths import REPO_ROOT, EDGE_COMPOSE_FILE, SIEM_COMPOSE_FILE
# Reuse the exact Baskerville registration/selection the exploit report uses.
from core.exploit_report_pdf import _report_font_family, _FONT_CSS_STACK, _esc


@dataclass
class Highlight:
    """One code excerpt to feature in the chapter."""
    section: str          # chapter section heading it groups under
    title: str            # the excerpt's own heading
    description: str      # prose explaining what the algorithm does / why it matters
    path: str             # repo-relative source path
    lang: str             # "py" | "lua" | "php" | "sh" | "text"
    symbols: list[str] = field(default_factory=list)  # py/lua: names to extract, in order
    lines: tuple[int, int] | None = None               # 1-based inclusive fallback range
    condense: bool = True  # strip comments/docstrings/logging + collapse blanks


# The curated chapter. Grouped by `section`, rendered in list order.
HIGHLIGHTS: list[Highlight] = [
    # --- Threat scoring & decay (reverse-proxy Lua) ---
    Highlight(
        section="Threat scoring and decay",
        title="Escalation-aware score decay",
        description=(
            "A flat exponential half-life lets a confirmed attacker earn back a clean "
            "score at the same rate as a single stray probe. The decay policy instead "
            "scales the half-life by how much abuse a source has actually committed: "
            "each recorded offense stretches the half-life, and once a source crosses an "
            "offense count or its score ever reaches the maximum it is permanently "
            "flagged (decay stops entirely). The module is deliberately pure -- no global "
            "or nginx state, every knob passed in -- so both the session- and IP-side "
            "decay paths share it and it stays unit-testable."),
        path="ids/reverse_proxy_enhanced/lua/decay_policy.lua",
        lang="lua",
        symbols=["_M.half_life_multiplier", "_M.is_permaflagged", "_M.decay"],
    ),
    Highlight(
        section="Threat scoring and decay",
        title="Per-session suspicion decay (read-time)",
        description=(
            "A session's suspicion score is stored as a monotonic peak that only ever "
            "ratchets up on a fresh signal; the fade is applied at read time against the "
            "timestamp of the last signal, never persisted. That way sustained clean "
            "behaviour lets a session earn its way back toward production routing without "
            "a background job ever rewriting the stored value."),
        path="ids/reverse_proxy_enhanced/lua/router_rules.lua",
        lang="lua",
        symbols=["_M.decayed_score"],
    ),
    Highlight(
        section="Threat scoring and decay",
        title="IP-reputation decay",
        description=(
            "The IP-reputation counterpart to the session decay above: the same read-time "
            "exponential fade applied to a threat_ips entry's stored raw score, sharing the "
            "escalation policy so a repeat offender's reputation fades progressively more "
            "slowly (or not at all)."),
        path="ids/reverse_proxy_enhanced/lua/suricata_rules.lua",
        lang="lua",
        symbols=["_M.decayed_score"],
    ),
    # --- Exploit-report measurement (dashboard) ---
    Highlight(
        section="Exploit-report measurement",
        title="Bracketed resource capture around an exploit",
        description=(
            "To show an exploit's resource footprint against its own baseline, the capture "
            "brackets the moment the exploit fires: a short pre-window of fast CPU/memory "
            "samples, the exploit at t=0, then a longer post-window that additionally sweeps "
            "log-file sizes (throttled, since that sweep is heavy). Every sample is "
            "timestamped at the start of its own collection -- collection itself takes ~2s, "
            "so timestamping afterwards would collapse the whole pre-window onto t=0 -- and "
            "the pre-window's log sizes are back-filled from the first post reading, since "
            "log volume barely moves in two seconds."),
        path="dashboard/core/exploit_report.py",
        lang="py",
        symbols=["ReportWorker._capture_around"],
    ),
    Highlight(
        section="Exploit-report measurement",
        title="Observing threat-score decay",
        description=(
            "Decay is observed, not simulated: benign homepage requests are issued across a "
            "bounded window and the effective score is read straight off each response's "
            "header. A clean request does not move the session's last-signal anchor, so this "
            "watches the real fade rather than resetting it."),
        path="dashboard/core/exploit_report.py",
        lang="py",
        symbols=["ReportWorker._sample_decay"],
    ),
    Highlight(
        section="Exploit-report measurement",
        title="Live per-container resource sampling",
        description=(
            "A single pass over the running containers turning `docker stats` output into a "
            "per-service view of CPU, memory and (merged in separately) log-file size, used "
            "both by the live Resources page and by the exploit report's graphs."),
        path="dashboard/core/resource_stats.py",
        lang="py",
        symbols=["collect_live"],
    ),
    # --- Report rendering (dashboard) ---
    Highlight(
        section="Report rendering",
        title="Well-separated series colours",
        description=(
            "When an unknown number of container series share one chart, evenly spaced hues "
            "clump into indistinguishable neighbours. Stepping the hue by the golden-ratio "
            "conjugate instead keeps every newly added series maximally far from the ones "
            "already drawn."),
        path="dashboard/core/exploit_report_pdf.py",
        lang="py",
        symbols=["_resource_series_color"],
    ),
    Highlight(
        section="Report rendering",
        title="Time-series chart rendering",
        description=(
            "The resource graphs are painted directly rather than via a chart library: the "
            "sample times (which run negative before the exploit) and values are mapped onto "
            "the plot rectangle, one thin line is drawn per container plus a bold average, "
            "and a dashed marker is placed at t=0 to separate the pre-exploit baseline from "
            "the spike."),
        path="dashboard/core/exploit_report_pdf.py",
        lang="py",
        symbols=["_resource_chart"],
    ),
    # --- Per-request database routing (db-proxy branch only) ---
    Highlight(
        section="Per-request database routing",
        title="WordPress database-selection drop-in",
        description=(
            "On the single-eshop database-proxy topology one WordPress front end serves both "
            "the production and the honeypot database, chosen per request from a trusted "
            "header the reverse proxy sets after it has classified the request. This db.php "
            "drop-in is what makes the same PHP runtime talk to whichever database that "
            "decision names."),
        path="ids/production_eshop_files/wp-content/db.php",
        lang="php",
    ),
]


# ---- service inventory ----

# What each Compose service does. Keyed by the service's base name (any trailing
# _<number> replica suffix stripped), so the numbered honeypot pools share one
# entry. Services absent on a branch simply never come up.
SERVICE_DESCRIPTIONS: dict[str, str] = {
    # edge / honeypot stack (ids/docker-compose.yml)
    "init_setup": "One-shot bootstrap: prepares shared volumes, permissions and "
                  "generated config the other containers expect before they start.",
    "reverse_proxy": "OpenResty/nginx front door. Its Lua modules classify every request "
                     "(threat scoring, CVE/pattern matching, session and IP reputation) and "
                     "route it to production or a honeypot, and it emits the score/route "
                     "headers the dashboard reads.",
    "production_eshop": "The real WooCommerce/WordPress storefront that legitimate traffic "
                        "is served from.",
    "production_database": "MySQL database backing the production eshop.",
    "production_db_seed": "One-shot WP-CLI job that seeds the production database with the "
                          "demo shop's content on first run.",
    "honeypot_eshop": "Honeypot copy of the WordPress storefront that suspicious traffic is "
                      "diverted to, isolating attackers from the real shop (one per pool).",
    "honeypot_database": "MySQL database backing a honeypot eshop, kept separate from "
                         "production so an intruder only ever touches decoy data.",
    "honeypot_db_seed": "One-shot WP-CLI job that seeds a honeypot database with demo "
                        "content so the decoy shop looks real.",
    "honeypot_db_migration": "One-shot schema/data migration that brings a honeypot database "
                             "up to the expected structure before seeding.",
    "honeypot_db_init": "One-shot initialiser for the honeypot database on the single-eshop "
                        "topology (schema + the 'Demo Honeypot eShop' identity).",
    "honeypot_content_sync": "Periodically replicates chosen production content into the "
                             "honeypot database(s) so the decoy stays believable without "
                             "leaking live customer data.",
    "session_store": "Redis instance holding per-session and per-IP threat state (scores, "
                     "last-signal timestamps, pool bindings) shared across reverse_proxy "
                     "workers.",
    "suricata_ids": "Suricata network IDS sniffing traffic and raising alerts that feed the "
                    "reverse proxy's IP-reputation (threat_ips) scoring.",
    "backup_service": "Scheduled backups of the databases and other persistent state.",
    "vector_outbound": "Vector agent shipping this host's logs/events to the SIEM over TLS.",
    # SIEM stack (siem/docker/docker-compose.yml)
    "es01": "Elasticsearch node storing the SIEM's indexed logs and alerts.",
    "init-password": "One-shot job that provisions Elasticsearch/Kibana credentials on first "
                     "start.",
    "kibana": "Kibana UI for exploring the collected logs, alerts and dashboards.",
    "kibana_dashboards_setup": "One-shot job that imports the project's saved Kibana "
                               "dashboards and index patterns.",
    "vector_inbound": "Vector receiver on the SIEM side that ingests what the edge's "
                      "vector_outbound ships and writes it into Elasticsearch.",
}


def _base_service_name(name: str) -> str:
    return re.sub(r"_\d+$", "", name)


def _compose_services(path) -> list[tuple[str, str]]:
    """(service_name, image) for each service in a Compose file, in file order.

    A small hand parser (PyYAML isn't a dependency here): walk the block under
    the top-level `services:` key, taking the 2-space-indented keys as service
    names and the first `image:` under each. Stops at the next top-level key."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    services: list[tuple[str, str]] = []
    in_services = False
    cur: str | None = None
    image = ""
    for raw in text.splitlines():
        if re.match(r"^\S", raw):  # a top-level key
            if raw.startswith("services:"):
                in_services = True
                continue
            if in_services:  # left the services block
                break
            continue
        if not in_services:
            continue
        m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", raw)
        if m:
            if cur is not None:
                services.append((cur, image))
            cur, image = m.group(1), ""
            continue
        if cur is not None and not image:
            mi = re.match(r"^\s+image:\s*(\S+)", raw)
            if mi:
                image = mi.group(1).strip().strip('"\'')
    if cur is not None:
        services.append((cur, image))
    return services


def _describe_service(name: str) -> str:
    return (SERVICE_DESCRIPTIONS.get(name)
            or SERVICE_DESCRIPTIONS.get(_base_service_name(name))
            or "")


def service_overview() -> list[tuple[str, list[dict]]]:
    """Per-stack service groups for this checkout: [(stack_label, rows)], where
    each row is {names, label, image, description}. Numbered replicas of the
    same base service (honeypot_database_1..3) collapse into one row."""
    out: list[tuple[str, list[dict]]] = []
    for label, compose in (("Edge / honeypot stack", EDGE_COMPOSE_FILE),
                            ("SIEM stack", SIEM_COMPOSE_FILE)):
        services = _compose_services(compose)
        if not services:
            continue
        groups: list[dict] = []
        index: dict[str, int] = {}
        for name, image in services:
            base = _base_service_name(name)
            if base in index:
                groups[index[base]]["names"].append(name)
            else:
                index[base] = len(groups)
                groups.append({"base": base, "names": [name], "image": image})
        rows: list[dict] = []
        for g in groups:
            n = len(g["names"])
            row_label = g["names"][0] if n == 1 else f"{g['base']}_1..{n}  (×{n})"
            rows.append({
                "label": row_label,
                "image": g["image"],
                "description": _describe_service(g["names"][0]) or "&mdash;",
            })
        out.append((label, rows))
    return out


# ---- extraction ----

def _read(path: str) -> str | None:
    p = REPO_ROOT / path
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _find_py_node(body: list, parts: list[str]):
    """Walk nested defs/classes for a dotted name (e.g. Class.method)."""
    want, rest = parts[0], parts[1:]
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and node.name == want:
            if not rest:
                return node
            return _find_py_node(node.body, rest)
    return None


def _extract_python(source: str, dotted: str) -> str | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    node = _find_py_node(tree.body, dotted.split("."))
    if node is None:
        return None
    return ast.get_source_segment(source, node)


def _extract_lua(source: str, name: str) -> str | None:
    """Extract a module-level `function <name>(...) ... end`.

    These modules define their functions at column 0 with a matching column-0
    `end`, so the closing line is the first unindented `end` after the header --
    a reliable anchor without a full Lua parser."""
    lines = source.splitlines()
    header = re.compile(r"^\s*(local\s+)?function\s+" + re.escape(name) + r"\s*[\(<]")
    start = next((i for i, l in enumerate(lines) if header.search(l)), None)
    if start is None:
        return None
    for j in range(start + 1, len(lines)):
        if re.match(r"^end\b\s*$", lines[j]):
            return "\n".join(lines[start:j + 1])
    return "\n".join(lines[start:])  # unterminated -- take the rest


_PY_DOCSTRING = re.compile(r'^\s*(?:[rRbBuU]{0,2})("""|\'\'\')')
# Single-line statements that are pure debug/logging noise, per language.
_NOISE = {
    "lua": re.compile(r'^\s*ngx\.log\s*\('),
    "py": re.compile(r'^\s*(?:logging|logger|log)\.[a-z_]+\s*\('),
}


def _condense(code: str, lang: str) -> str:
    """Drop comments, docstrings, single-line debug logging and blank runs, then
    dedent -- so the excerpt shows the algorithm, not the housekeeping."""
    code = code.replace("\t", "    ")
    line_comments = {"lua": ("--",), "sh": ("#",), "py": ("#",),
                     "php": ("//", "#")}.get(lang, ())
    out: list[str] = []
    in_doc = False
    doc_delim = ""
    in_block = False  # PHP / C-style /* ... */ block comment
    for line in code.splitlines():
        stripped = line.strip()
        if lang == "php":
            if in_block:
                if "*/" in line:
                    in_block = False
                continue
            if stripped.startswith("/*"):
                if "*/" not in line:
                    in_block = True
                continue
            if stripped.startswith("*"):  # docblock continuation line
                continue
        if lang == "py":
            if in_doc:
                if doc_delim in line:
                    in_doc = False
                continue
            m = _PY_DOCSTRING.match(line)
            if m:
                doc_delim = m.group(1)
                # single-line docstring ("""...""") closes on the same line
                if line.count(doc_delim) < 2:
                    in_doc = True
                continue
        if any(stripped.startswith(c) for c in line_comments):
            continue
        noise = _NOISE.get(lang)
        if noise and noise.match(line) and line.rstrip().endswith(")"):
            continue
        out.append(line.rstrip())
    # collapse runs of blank lines to a single one; trim ends.
    collapsed: list[str] = []
    for line in out:
        if not line and collapsed and not collapsed[-1]:
            continue
        collapsed.append(line)
    while collapsed and not collapsed[0]:
        collapsed.pop(0)
    while collapsed and not collapsed[-1]:
        collapsed.pop()
    return textwrap.dedent("\n".join(collapsed))


def extract(hl: Highlight) -> str | None:
    """The condensed code excerpt for a highlight, or None if unavailable."""
    source = _read(hl.path)
    if source is None:
        return None
    chunks: list[str] = []
    if hl.symbols:
        for sym in hl.symbols:
            seg = _extract_python(source, sym) if hl.lang == "py" else _extract_lua(source, sym)
            if seg:
                chunks.append(seg)
        if not chunks:
            return None
        code = "\n\n".join(chunks)
    elif hl.lines:
        a, b = hl.lines
        code = "\n".join(source.splitlines()[a - 1:b])
    else:
        code = source
    code = _condense(code, hl.lang) if hl.condense else code.replace("\t", "    ")
    return code or None


def available_highlights() -> list[tuple[Highlight, str]]:
    """(highlight, code) for every manifest entry that resolves on this branch."""
    out = []
    for hl in HIGHLIGHTS:
        code = extract(hl)
        if code:
            out.append((hl, code))
    return out


# ---- rendering ----

_LANG_LABEL = {"py": "Python", "lua": "Lua", "php": "PHP", "sh": "shell", "text": ""}


def _code_block(code: str) -> str:
    return (
        '<table width="100%" cellspacing="0" cellpadding="6" '
        'style="background-color:#f5f5f2; border:1px solid #cccccc;"><tr><td>'
        '<pre style="font-family:\'DejaVu Sans Mono\',\'Courier New\',monospace; '
        f'font-size:8pt; color:#1a1a1a;">{_esc(code)}</pre>'
        '</td></tr></table>')


def _services_section_html(doc: QTextDocument, health_screenshot: str) -> str:
    """The 'Services and health' section: a per-service explanation table for
    every service on this branch, plus the Health-page screenshot if supplied."""
    stacks = service_overview()
    parts: list[str] = []
    parts.append('<p style="color:#555;">The system is a set of Docker Compose services. '
                 'Each service on this branch is listed below with what it does; the numbered '
                 'honeypot pools are collapsed into one row with their replica count.</p>')
    for label, rows in stacks:
        parts.append(f'<h3 style="color:#333;">{_esc(label)}</h3>')
        parts.append('<table width="100%" cellspacing="0" cellpadding="4" border="1" '
                     'style="border-collapse:collapse; color:#444;">'
                     '<tr style="background-color:#eeeeea;">'
                     '<th align="left">Service</th><th align="left">Image</th>'
                     '<th align="left">Role</th></tr>')
        for r in rows:
            image_cell = _esc(r["image"]) if r["image"] else "&mdash;"
            parts.append(
                '<tr>'
                f'<td style="font-family:monospace;">{_esc(r["label"])}</td>'
                f'<td style="font-family:monospace; color:#666;">{image_cell}</td>'
                f'<td>{r["description"]}</td>'
                '</tr>')
        parts.append('</table>')

    if health_screenshot:
        img = QImage(health_screenshot)
        if not img.isNull():
            doc.addResource(QTextDocument.ResourceType.ImageResource,
                            QUrl("thesis://health"), img)
            parts.append('<p style="color:#555;">Live health view of the running services '
                         '(dashboard Health page):</p>')
            parts.append('<img src="thesis://health" width="660"/>')
    return "".join(parts)


def render_thesis_pdf(out_path: str, health_screenshot: str = "") -> int:
    """Render the Implementation chapter PDF. Returns the number of code excerpts
    included (0 => nothing resolved, caller should warn rather than write junk).

    If ``health_screenshot`` points at a readable image, it is embedded in the
    'Services and health' section."""
    items = available_highlights()
    family = _report_font_family()
    doc = QTextDocument()
    doc.setDefaultFont(QFont(family, 11))

    parts: list[str] = [f'<div style="font-family: {_FONT_CSS_STACK};">']
    parts.append('<h1 style="color:#222;">Implementation</h1>')
    parts.append('<p style="color:#555;">Generated '
                 f'{_esc(datetime.now().strftime("%Y-%m-%d %H:%M"))} from the project source '
                 'tree. This chapter first summarises the services that make up the system, '
                 'then collects the more interesting algorithms in the honeypot IDS and '
                 'reverse proxy. Each code excerpt is taken verbatim from the source and then '
                 'condensed &ndash; comments, docstrings, debug logging and blank runs removed '
                 '&ndash; so only the algorithmic essence is shown; the full listing is at the '
                 'cited path.</p><hr/>')

    section = 0

    # Section: services & health overview.
    section += 1
    parts.append(f'<h2 style="color:#222;">{section}. Services and health</h2>')
    parts.append(_services_section_html(doc, health_screenshot))

    # Sections: featured algorithms, grouped by section in first-appearance order.
    order: list[str] = []
    for hl, _ in items:
        if hl.section not in order:
            order.append(hl.section)

    for name in order:
        section += 1
        parts.append(f'<h2 style="color:#222;">{section}. {_esc(name)}</h2>')
        for hl, code in [it for it in items if it[0].section == name]:
            parts.append(f'<h3 style="color:#333;">{_esc(hl.title)}</h3>')
            parts.append(f'<p style="color:#555;">{_esc(hl.description)}</p>')
            parts.append(_code_block(code))
            lang = _LANG_LABEL.get(hl.lang, hl.lang)
            src = f'{_esc(hl.path)}' + (f' &middot; {lang}' if lang else '')
            parts.append(f'<p style="color:#888; font-size:9pt;">Source: {src}</p>')

    parts.append('</div>')
    doc.setHtml("<body>" + "".join(parts) + "</body>")

    from PyQt6.QtGui import QPageSize, QPageLayout
    printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(out_path)
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.DevicePixel).size()))
    doc.print(printer)
    return len(items)
