"""Learn page: the dashboard's teaching layer for cybersecurity students.

Four tabs, all driven by core/learning.py:
  - Start here: how the system works in five steps, plus a tour of every
    sidebar page (what it's for / try this / notice) with links that jump
    straight to that page.
  - Guided labs: short checklists that walk through the pages in order;
    ticked steps persist in AppState.learn_completed_steps.
  - Glossary: searchable terms, each with a plain definition and what it
    means in this project.
  - Exploit lessons: one lesson per exploit preset (attack class, OWASP Top
    10, MITRE ATT&CK, how it works, defence).

Links of the form ``page:<id>`` anywhere on this page emit
open_page_requested(id); MainWindow switches the sidebar to that page.
The HTML builders (page_guide_html, exploit_lesson_html) are module-level
so other pages can show the same text in their own help popups.
"""
from __future__ import annotations

import html

from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton,
    QSplitter, QTabWidget, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.exploits import EXPLOIT_PRESETS, ExploitPreset
from core.learning import (
    GLOSSARY, LABS, PAGE_GUIDES, GlossaryTerm, lab_progress, lesson_for, search_glossary,
)
from core.state import AppState

_STEP_ROLE = Qt.ItemDataRole.UserRole


def _esc(text: str) -> str:
    return html.escape(text or "")


def page_guide_html(page_id: str, label: str, link: bool = False) -> str:
    guide = PAGE_GUIDES.get(page_id)
    if guide is None:
        return ""
    title = _esc(label)
    if link:
        title = f'<a href="page:{page_id}">{title}</a>'
    return (f"<h3>{title}</h3>"
            f"<p>{_esc(guide.summary)}</p>"
            f"<p><b>Try this:</b> {_esc(guide.try_this)}<br/>"
            f"<b>Notice:</b> {_esc(guide.notice)}</p>")


def exploit_lesson_html(preset: ExploitPreset) -> str:
    parts = [f"<h3>{_esc(preset.name)}</h3>",
             f"<p><b>{_esc(preset.cve)}</b> &middot; severity <b>{_esc(preset.severity)}</b>"
             f" &middot; <code>{_esc(preset.method)} {_esc(preset.path)}</code></p>",
             f"<p>{_esc(preset.description)}</p>"]
    lesson = lesson_for(preset.cve)
    if lesson is not None:
        parts.append(
            "<table cellspacing='0' cellpadding='3'>"
            f"<tr><td><b>Attack class</b></td><td>{_esc(lesson.attack_class)}</td></tr>"
            f"<tr><td><b>OWASP Top 10</b></td><td>{_esc(lesson.owasp)}</td></tr>"
            f"<tr><td><b>MITRE ATT&amp;CK</b></td><td>{_esc(lesson.attack)}</td></tr>"
            "</table>"
            f"<h4>How it works</h4><p>{_esc(lesson.how_it_works)}</p>"
            f"<h4>How to defend</h4><p>{_esc(lesson.defence)}</p>")
    parts.append("<h4>What the honeypot does</h4><p>The reverse proxy recognises this "
                 "request's pattern, adds points to the session's threat score and routes "
                 "it to the decoy shop, where the attack 'works' against fake data. Watch "
                 "it happen on the Exploits page's Threat analyzer tab.</p>")
    return "".join(parts)


def _glossary_html(term: GlossaryTerm) -> str:
    out = (f"<h3>{_esc(term.term)}</h3><p>{_esc(term.definition)}</p>"
           f"<h4>In this project</h4><p>{_esc(term.in_this_project)}</p>")
    if term.page and term.page != "learn":
        out += f'<p><a href="page:{term.page}">See it on the dashboard &rarr;</a></p>'
    return out


_START_HTML = """
<h2>Welcome</h2>
<p>This dashboard runs a <b>honeypot-based intrusion detection system</b> for a WordPress
eshop. You can attack it safely from here and watch, step by step, how the attack is
detected, diverted and logged. New to the field? Work through the <b>Guided labs</b> tab
in order, and keep the <b>Glossary</b> open for unfamiliar terms. Press <b>F1</b> on any
page for help about that page.</p>

<h3>How a request travels</h3>
<ol>
<li><b>Client</b> sends an HTTP request to the shop.</li>
<li>The <b>reverse proxy</b> (OpenResty + Lua) scores it: URL patterns, headers, known CVE
exploits, IP reputation, automation tools, uploads. Each signal adds points.</li>
<li>If the session's score reaches the <b>threshold (80/100)</b>, or a CVE or bad IP is
seen, the session goes to the <b>honeypot</b>, a decoy copy of the shop. Otherwise it goes to
<b>production</b>.</li>
<li>Once on the honeypot the session <b>stays there</b> (sticky), so the attacker doesn't
notice. Scores slowly <b>decay</b> so innocent users recover.</li>
<li>Every decision, plus <b>Suricata</b> network alerts, is shipped to the <b>SIEM</b>
(Vector, Elasticsearch, Kibana) for analysis.</li>
</ol>
<p><i>Safety note:</i> the exploit presets are real attack patterns. Only fire them at
systems you run yourself, like this lab.</p>
<h2>Tour of the dashboard</h2>
"""


class LearnPage(QWidget):
    open_page_requested = pyqtSignal(str)

    def __init__(self, state: AppState, page_labels: dict[str, str], parent=None):
        super().__init__(parent)
        self.state = state
        self._page_labels = page_labels
        layout = QVBoxLayout(self)

        title = QLabel("Learn")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, stretch=1)
        self.tabs.addTab(self._build_start_tab(), "Start here")
        self.tabs.addTab(self._build_labs_tab(), "Guided labs")
        self.tabs.addTab(self._build_glossary_tab(), "Glossary")
        self.tabs.addTab(self._build_lessons_tab(), "Exploit lessons")

    # ---- shared ----

    def _browser(self) -> QTextBrowser:
        browser = QTextBrowser()
        browser.setOpenLinks(False)
        browser.anchorClicked.connect(self._on_link)
        return browser

    def _on_link(self, url: QUrl) -> None:
        text = url.toString()
        if text.startswith("page:"):
            self.open_page_requested.emit(text[len("page:"):])

    # ---- Start here ----

    def _build_start_tab(self) -> QWidget:
        browser = self._browser()
        tour = "".join(page_guide_html(pid, label, link=True)
                       for pid, label in self._page_labels.items() if pid != "learn")
        browser.setHtml(_START_HTML + tour)
        return browser

    # ---- Guided labs ----

    def _build_labs_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("Tick each step as you finish it. Double-click a step to "
                                "open the page it happens on."))
        self.labs_tree = QTreeWidget()
        self.labs_tree.setHeaderHidden(True)
        self.labs_tree.setWordWrap(True)
        self._lab_items: list[tuple[QTreeWidgetItem, object]] = []
        done = set(self.state.learn_completed_steps)
        for lab in LABS:
            top = QTreeWidgetItem([lab.title])
            top.setToolTip(0, lab.goal)
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            for step in lab.steps:
                child = QTreeWidgetItem([step.text])
                child.setData(0, _STEP_ROLE, step)
                child.setToolTip(0, step.text)
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                child.setCheckState(0, Qt.CheckState.Checked if step.id in done
                                    else Qt.CheckState.Unchecked)
                top.addChild(child)
            self.labs_tree.addTopLevelItem(top)
            self._lab_items.append((top, lab))
        self._refresh_lab_titles()
        self.labs_tree.expandAll()
        self.labs_tree.itemChanged.connect(self._on_step_changed)
        self.labs_tree.itemDoubleClicked.connect(self._on_step_double_clicked)
        layout.addWidget(self.labs_tree, stretch=1)

        row = QHBoxLayout()
        row.addStretch()
        reset_btn = QPushButton("Reset lab progress")
        reset_btn.clicked.connect(self._reset_labs)
        row.addWidget(reset_btn)
        layout.addLayout(row)
        return widget

    def _refresh_lab_titles(self) -> None:
        done = self.state.learn_completed_steps
        for top, lab in self._lab_items:
            n, total = lab_progress(lab, done)
            mark = "  ✓" if n == total else ""
            top.setText(0, f"{lab.title}  ({n}/{total}){mark}")

    def _on_step_changed(self, item: QTreeWidgetItem, _column: int) -> None:
        step = item.data(0, _STEP_ROLE)
        if step is None:
            return
        done = [s for s in self.state.learn_completed_steps if s != step.id]
        if item.checkState(0) == Qt.CheckState.Checked:
            done.append(step.id)
        self.state.learn_completed_steps = done
        self.state.save()
        self.labs_tree.blockSignals(True)
        self._refresh_lab_titles()
        self.labs_tree.blockSignals(False)

    def _on_step_double_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        step = item.data(0, _STEP_ROLE)
        if step is None or not step.page:
            return
        if step.page == "learn":
            self.tabs.setCurrentIndex(2)
        else:
            self.open_page_requested.emit(step.page)

    def _reset_labs(self) -> None:
        self.state.learn_completed_steps = []
        self.state.save()
        self.labs_tree.blockSignals(True)
        for top, _lab in self._lab_items:
            for i in range(top.childCount()):
                top.child(i).setCheckState(0, Qt.CheckState.Unchecked)
        self._refresh_lab_titles()
        self.labs_tree.blockSignals(False)

    # ---- Glossary ----

    def _build_glossary_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.glossary_search = QLineEdit()
        self.glossary_search.setPlaceholderText("Search terms, e.g. injection, decay, SIEM")
        self.glossary_search.setClearButtonEnabled(True)
        self.glossary_search.textChanged.connect(self._filter_glossary)
        layout.addWidget(self.glossary_search)

        splitter = QSplitter()
        self.glossary_list = QListWidget()
        self.glossary_list.currentItemChanged.connect(self._show_term)
        splitter.addWidget(self.glossary_list)
        self.glossary_view = self._browser()
        splitter.addWidget(self.glossary_view)
        splitter.setSizes([260, 700])
        layout.addWidget(splitter, stretch=1)
        self._filter_glossary("")
        return widget

    def _filter_glossary(self, query: str) -> None:
        self.glossary_list.clear()
        for term in search_glossary(query):
            item = QListWidgetItem(term.term)
            item.setData(_STEP_ROLE, term)
            self.glossary_list.addItem(item)
        if self.glossary_list.count():
            self.glossary_list.setCurrentRow(0)
        else:
            self.glossary_view.setHtml("<p>No matching terms.</p>")

    def _show_term(self, item: QListWidgetItem | None, _prev=None) -> None:
        if item is None:
            return
        self.glossary_view.setHtml(_glossary_html(item.data(_STEP_ROLE)))

    def show_term(self, name: str) -> None:
        """Opens the Glossary tab on the term called ``name``, if it exists."""
        self.tabs.setCurrentIndex(2)
        self.glossary_search.clear()
        for i, term in enumerate(GLOSSARY):
            if term.term == name:
                self.glossary_list.setCurrentRow(i)
                return

    # ---- Exploit lessons ----

    def _build_lessons_tab(self) -> QWidget:
        splitter = QSplitter()
        self.lesson_list = QListWidget()
        for preset in EXPLOIT_PRESETS:
            item = QListWidgetItem(f"{preset.cve}  {preset.name}")
            item.setData(_STEP_ROLE, preset)
            self.lesson_list.addItem(item)
        self.lesson_list.currentItemChanged.connect(self._show_lesson)
        splitter.addWidget(self.lesson_list)
        self.lesson_view = self._browser()
        splitter.addWidget(self.lesson_view)
        splitter.setSizes([320, 640])
        self.lesson_list.setCurrentRow(0)
        return splitter

    def _show_lesson(self, item: QListWidgetItem | None, _prev=None) -> None:
        if item is None:
            return
        self.lesson_view.setHtml(exploit_lesson_html(item.data(_STEP_ROLE)))
