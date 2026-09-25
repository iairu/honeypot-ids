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

from PyQt6.QtCore import QMarginsF, QSizeF
from PyQt6.QtGui import QFont, QTextDocument
from PyQt6.QtPrintSupport import QPrinter

from core.paths import REPO_ROOT
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


def render_thesis_pdf(out_path: str) -> int:
    """Render the Implementation chapter PDF. Returns the number of excerpts
    included (0 => nothing resolved, caller should warn rather than write junk)."""
    items = available_highlights()
    family = _report_font_family()
    doc = QTextDocument()
    doc.setDefaultFont(QFont(family, 11))

    parts: list[str] = [f'<div style="font-family: {_FONT_CSS_STACK};">']
    parts.append('<h1 style="color:#222;">Implementation</h1>')
    parts.append('<p style="color:#555;">Generated '
                 f'{_esc(datetime.now().strftime("%Y-%m-%d %H:%M"))} from the project source '
                 'tree. This chapter collects the more interesting algorithms in the honeypot '
                 'IDS and reverse proxy. Each excerpt is taken verbatim from the source and '
                 'then condensed &ndash; comments, docstrings, debug logging and blank runs '
                 'removed &ndash; so only the algorithmic essence is shown; the full listing '
                 'is at the cited path.</p><hr/>')

    # Group by section in first-appearance order.
    order: list[str] = []
    for hl, _ in items:
        if hl.section not in order:
            order.append(hl.section)

    for si, section in enumerate(order, start=1):
        parts.append(f'<h2 style="color:#222;">{si}. {_esc(section)}</h2>')
        for hl, code in [it for it in items if it[0].section == section]:
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
