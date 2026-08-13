"""Cross-referenced service diagram: one node per container (grouped by
target), colored by health status, connected by lines representing the
real relationships between services (reverse proxy -> backends -> DBs,
edge Vector -> SIEM Vector aggregator -> Elasticsearch -> Kibana, etc.).
"""
from __future__ import annotations

from PyQt6.QtCore import QRectF, QUrl, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QDesktopServices, QFont, QFontMetrics, QPainter, QPen
from PyQt6.QtWidgets import (
    QGraphicsLineItem, QGraphicsObject, QGraphicsScene,
    QGraphicsSimpleTextItem, QGraphicsView,
)

from core.web_links import build_url, web_ui_for
from ui import theme
from ui.error_monitor import ErrorLogMonitor

NODE_W, NODE_H = 150, 44
WEB_UI_ICON_SIZE = 16
WEB_UI_ICON_MARGIN = 3
EXPORT_ICON_SIZE = 16
EXPORT_ICON_MARGIN = 3
ERROR_BADGE_MARGIN = 3
ERROR_BADGE_HEIGHT = 14
ERROR_BADGE_COLOR = QColor("#d9302c")
COL_GAP, ROW_GAP = 24, 18
GROUP_PADDING = 30
GROUP_GAP_Y = 60


def _error_badge_font() -> QFont:
    font = QFont()
    font.setPointSize(8)
    font.setBold(True)
    return font

# Canvas background / group title / group border -- unlike STATUS_COLORS
# (self-contained, saturated node fills with white text, readable on either
# theme), these paint the diagram's own surrounding chrome and looked
# broken (a big dark rectangle) once light theme support existed.
def _canvas_bg() -> QColor:
    return QColor(theme.scheme_colors()["bg"])


def _title_color() -> QColor:
    return QColor(theme.scheme_colors()["fg"])


def _border_color() -> QColor:
    return QColor(theme.scheme_colors()["border"])

STATUS_COLORS = {
    "healthy": QColor("#3fa34d"),        # running + healthy
    "running": QColor("#3f9fd9"),        # running, no healthcheck
    "unhealthy": QColor("#d9534f"),      # running but unhealthy
    "exited_ok": QColor("#7d7d7d"),      # exited, code 0 (expected one-shot)
    "exited_bad": QColor("#c9302c"),     # exited, nonzero code
    "created": QColor("#e0a030"),        # created but never started (see classify())
    "down": QColor("#2b2b2b"),           # not present at all
}

# Static relationship map, by service NAME (applied within each target's own
# cluster -- an edge never crosses between e.g. edge-local and edge-remote,
# except the two explicit cross-target edges added below for the Vector
# shipper -> aggregator link).
EDGE_RELATIONSHIPS = [
    ("reverse_proxy", "production_eshop"),
    ("reverse_proxy", "honeypot_eshop_1"),
    ("reverse_proxy", "honeypot_eshop_2"),
    ("reverse_proxy", "honeypot_eshop_3"),
    ("reverse_proxy", "session_store"),
    ("production_eshop", "production_database"),
    ("honeypot_eshop_1", "honeypot_database_1"),
    ("honeypot_eshop_2", "honeypot_database_2"),
    ("honeypot_eshop_3", "honeypot_database_3"),
    ("init_setup", "production_eshop"),
    ("init_setup", "honeypot_eshop_1"),
    ("init_setup", "honeypot_eshop_2"),
    ("init_setup", "honeypot_eshop_3"),
    ("honeypot_db_migration", "honeypot_database_1"),
    ("honeypot_db_migration", "honeypot_database_2"),
    ("honeypot_db_migration", "honeypot_database_3"),
    ("backup_service", "production_database"),
    ("backup_service", "production_eshop"),
    ("honeypot_content_sync", "production_database"),
    ("honeypot_content_sync", "honeypot_database_1"),
    ("honeypot_content_sync", "honeypot_database_2"),
    ("honeypot_content_sync", "honeypot_database_3"),
    ("honeypot_content_sync", "session_store"),
    ("suricata_ids", "vector"),
    ("vector", "es01"),
    ("es01", "kibana"),
    ("init-password", "es01"),
]

# Cross-target edges: (from_project, from_service) -> (to_project, to_service).
# Only drawn when both targets are the ones currently shown (both local, or
# whichever combination the user has configured/visible).
CROSS_TARGET_EDGES = [
    (("edge", "vector"), ("siem", "vector")),
]


def classify(container: dict | None) -> str:
    if container is None:
        return "down"
    state = container.get("State", "")
    health = container.get("Health", "")
    exit_code = str(container.get("ExitCode", "0"))
    if state == "running":
        if health == "unhealthy":
            return "unhealthy"
        if health == "healthy":
            return "healthy"
        return "running"
    if state == "exited":
        return "exited_ok" if exit_code in ("0", "") else "exited_bad"
    if state == "created":
        # `docker compose up` creates every container in the dependency
        # graph up front, then starts them in order -- if that process
        # itself gets interrupted partway (closed terminal/app, killed
        # mid-command), whatever hasn't been started yet is left sitting
        # here indefinitely; it does NOT self-heal, and confirmed live
        # this is otherwise visually indistinguishable from "down" (not
        # created at all), which reads as "nothing's wrong yet, just
        # hasn't been started on purpose" -- very different from "up got
        # interrupted, re-run it."
        return "created"
    return "down"


def is_ready(container: dict | None) -> bool:
    """True once a container is done starting, for start/restart progress
    bars (page_services.py, page_health.py): a one-shot job that exited
    cleanly, or a running container that either has no healthcheck or has
    already passed one. Deliberately stricter than classify()=="running",
    which also covers Health=="starting" -- a container still mid-
    healthcheck is running but NOT ready yet, and that gap (State=running,
    Health=starting) is exactly what a progress bar needs to show instead
    of jumping to 100% the moment containers are merely created."""
    if container is None:
        return False
    state = container.get("State")
    if state == "exited":
        return str(container.get("ExitCode", "0")) in ("0", "")
    return state == "running" and container.get("Health", "") in ("", "healthy")


def is_problem(container: dict | None) -> bool:
    """True for a container classify() considers actively broken (as
    opposed to merely not-ready-yet) -- used to color progress bars red."""
    return classify(container) in ("unhealthy", "exited_bad")


def status_detail(container: dict | None) -> str:
    if container is None:
        return "not created / never started"
    return container.get("Status", container.get("State", "unknown"))


class ServiceNode(QGraphicsObject):
    clicked = pyqtSignal(str, str)  # target_key, service
    export_logs_clicked = pyqtSignal(str, str)  # target_key, service
    error_badge_clicked = pyqtSignal(str, str)  # target_key, service

    def __init__(
        self, target_key: str, project_label: str, service: str,
        x: float, y: float, project: str, host: str,
    ):
        super().__init__()
        self.target_key = target_key
        self.project_label = project_label
        self.service = service
        self.setPos(x, y)
        self.setAcceptHoverEvents(True)
        self._status = "down"
        self._detail = ""
        self._selected = False
        self._error_count = 0
        self.web_ui_url = build_url(project, service, host)
        self._web_ui_label = web_ui_for(project, service).label if self.web_ui_url else None

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, NODE_W, NODE_H)

    def _web_ui_icon_rect(self) -> QRectF:
        return QRectF(
            NODE_W - WEB_UI_ICON_SIZE - WEB_UI_ICON_MARGIN, WEB_UI_ICON_MARGIN,
            WEB_UI_ICON_SIZE, WEB_UI_ICON_SIZE,
        )

    def _export_icon_rect(self) -> QRectF:
        return QRectF(
            EXPORT_ICON_MARGIN, EXPORT_ICON_MARGIN,
            EXPORT_ICON_SIZE, EXPORT_ICON_SIZE,
        )

    def _error_badge_text(self) -> str:
        return f"!{self._error_count}"

    def _error_badge_rect(self) -> QRectF:
        # Bottom-right corner -- top-left (export) and top-right (web UI,
        # when present) are already spoken for. Width follows the digit
        # count via QFontMetrics rather than a fixed size, so a node that's
        # been up a long time and accumulated a 3+ digit count doesn't get
        # its number clipped.
        fm = QFontMetrics(_error_badge_font())
        w = fm.horizontalAdvance(self._error_badge_text()) + 8
        return QRectF(
            NODE_W - w - ERROR_BADGE_MARGIN, NODE_H - ERROR_BADGE_HEIGHT - ERROR_BADGE_MARGIN,
            w, ERROR_BADGE_HEIGHT,
        )

    def set_status(self, status: str, detail: str) -> None:
        self._status = status
        self._detail = detail
        self._refresh_tooltip()
        self.update()

    def set_error_count(self, count: int) -> None:
        if count == self._error_count:
            return
        self._error_count = count
        self._refresh_tooltip()
        self.update()

    def _refresh_tooltip(self) -> None:
        tooltip = f"{self.service}\n{self._detail}"
        if self.web_ui_url:
            tooltip += f"\n\n↗ top-right icon: {self._web_ui_label}"
        tooltip += "\n⬇ top-left icon: export logs to a file"
        if self._error_count:
            tooltip += (
                f"\n❗ bottom-right badge: {self._error_count} log line"
                f"{'s' if self._error_count != 1 else ''} containing \"error\" seen"
            )
        self.setToolTip(tooltip)

    def set_selected_look(self, selected: bool) -> None:
        self._selected = selected
        self.update()

    def paint(self, painter: QPainter, option, widget=None) -> None:
        color = STATUS_COLORS.get(self._status, QColor("#555555"))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#ffffff") if self._selected else QColor("#111111"))
        pen.setWidth(3 if self._selected else 1)
        painter.setPen(pen)
        painter.setBrush(QBrush(color))
        painter.drawRoundedRect(self.boundingRect(), 8, 8)

        painter.setPen(QPen(QColor("#ffffff")))
        font = QFont()
        font.setPointSize(9)
        painter.setFont(font)
        text_rect = self.boundingRect().adjusted(6, 4, -6, -4)
        text_rect.setLeft(text_rect.left() + EXPORT_ICON_SIZE)
        if self.web_ui_url:
            text_rect.setRight(text_rect.right() - WEB_UI_ICON_SIZE)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, self.service)

        icon_font = QFont()
        icon_font.setPointSize(9)
        icon_font.setBold(True)

        if self.web_ui_url:
            icon_rect = self._web_ui_icon_rect()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(255, 255, 255, 60)))
            painter.drawRoundedRect(icon_rect, 3, 3)
            painter.setPen(QPen(QColor("#ffffff")))
            painter.setFont(icon_font)
            painter.drawText(icon_rect, Qt.AlignmentFlag.AlignCenter, "↗")

        export_rect = self._export_icon_rect()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(255, 255, 255, 60)))
        painter.drawRoundedRect(export_rect, 3, 3)
        painter.setPen(QPen(QColor("#ffffff")))
        painter.setFont(icon_font)
        painter.drawText(export_rect, Qt.AlignmentFlag.AlignCenter, "⬇")

        if self._error_count > 0:
            badge_rect = self._error_badge_rect()
            painter.setPen(QPen(QColor("#ffffff")))
            painter.setBrush(QBrush(ERROR_BADGE_COLOR))
            painter.drawRoundedRect(badge_rect, 4, 4)
            painter.setPen(QPen(QColor("#ffffff")))
            painter.setFont(_error_badge_font())
            painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, self._error_badge_text())

    def mousePressEvent(self, event) -> None:
        if self.web_ui_url and self._web_ui_icon_rect().contains(event.pos()):
            QDesktopServices.openUrl(QUrl(self.web_ui_url))
            return
        if self._export_icon_rect().contains(event.pos()):
            self.export_logs_clicked.emit(self.target_key, self.service)
            return
        if self._error_count > 0 and self._error_badge_rect().contains(event.pos()):
            self.error_badge_clicked.emit(self.target_key, self.service)
            return
        self.clicked.emit(self.target_key, self.service)
        super().mousePressEvent(event)


class HealthDiagram(QGraphicsView):
    node_selected = pyqtSignal(str, str)  # target_key, service
    export_logs_requested = pyqtSignal(str, str)  # target_key, service
    error_badge_selected = pyqtSignal(str, str)  # target_key, service

    def __init__(self, error_monitor: ErrorLogMonitor | None = None, parent=None):
        super().__init__(parent)
        self.scene_ = QGraphicsScene(self)
        self.setScene(self.scene_)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

        self.nodes: dict[tuple[str, str], ServiceNode] = {}
        self._selected_key: tuple[str, str] | None = None
        self._last_rebuild_args: tuple | None = None
        self._error_monitor = error_monitor
        if error_monitor is not None:
            # Lines flow in continuously (any target's auto-tailing log
            # panel, not just this page) -- a lightweight per-node badge
            # update rather than a full rebuild() (which tears down and
            # re-lays-out the entire scene) on every single matching line.
            error_monitor.counts_changed.connect(self.refresh_error_counts)

        self._apply_theme_colors()
        theme.on_change(self._on_theme_changed)

    def _apply_theme_colors(self) -> None:
        self.setBackgroundBrush(QBrush(_canvas_bg()))

    def _on_theme_changed(self) -> None:
        self._apply_theme_colors()
        if self._last_rebuild_args is not None:
            targets, results = self._last_rebuild_args
            self.rebuild(targets, results)

    def rebuild(self, targets, results: dict[str, list[dict]]) -> None:
        self._last_rebuild_args = (targets, results)
        """targets: list[Target]; results: target_key -> list of container dicts."""
        self.scene_.clear()
        self.nodes.clear()

        y_cursor = 0.0
        group_origins: dict[str, tuple[float, float, int]] = {}  # target_key -> (x0, y0, n_cols)

        for target in targets:
            containers = results.get(target.key, [])
            by_service = {c.get("Service"): c for c in containers}
            services = sorted(by_service.keys()) or ["(no containers found)"]
            host = target.remote.host if target.is_remote else "127.0.0.1"

            n_cols = max(1, min(4, len(services)))
            n_rows = (len(services) + n_cols - 1) // n_cols

            group_w = n_cols * NODE_W + (n_cols - 1) * COL_GAP + 2 * GROUP_PADDING
            group_h = n_rows * NODE_H + (n_rows - 1) * ROW_GAP + 2 * GROUP_PADDING + 24

            title = QGraphicsSimpleTextItem(target.label)
            title.setBrush(QBrush(_title_color()))
            font = title.font()
            font.setPointSize(11)
            font.setBold(True)
            title.setFont(font)
            title.setPos(0, y_cursor)
            self.scene_.addItem(title)

            group_top = y_cursor + 24
            group_origins[target.key] = (GROUP_PADDING, group_top + GROUP_PADDING, n_cols)

            for i, service in enumerate(services):
                col, row = i % n_cols, i // n_cols
                x = GROUP_PADDING + col * (NODE_W + COL_GAP)
                y = group_top + GROUP_PADDING + row * (NODE_H + ROW_GAP)

                node = ServiceNode(target.key, target.label, service, x, y, target.project, host)
                container = by_service.get(service)
                status = classify(container)
                node.set_status(status, status_detail(container))
                if self._error_monitor is not None:
                    node.set_error_count(self._error_monitor.count_for(target.key, service))
                node.clicked.connect(self._on_node_clicked)
                node.export_logs_clicked.connect(self.export_logs_requested)
                node.error_badge_clicked.connect(self._on_error_badge_clicked)
                self.scene_.addItem(node)
                self.nodes[(target.key, service)] = node

            border = self.scene_.addRect(
                0, group_top, group_w, group_h - 24,
                QPen(_border_color()), QBrush(Qt.BrushStyle.NoBrush),
            )
            border.setZValue(-10)

            y_cursor = group_top + group_h + GROUP_GAP_Y

        self._draw_edges(group_origins)

        if self._selected_key in self.nodes:
            self.nodes[self._selected_key].set_selected_look(True)

    def _draw_edges(self, group_origins: dict[str, tuple[float, float, int]]) -> None:
        for from_service, to_service in EDGE_RELATIONSHIPS:
            for target_key in group_origins:
                self._draw_edge_if_present(target_key, from_service, target_key, to_service)

        for (from_proj, from_svc), (to_proj, to_svc) in CROSS_TARGET_EDGES:
            for from_key in [k for k in group_origins if k.startswith(from_proj)]:
                for to_key in [k for k in group_origins if k.startswith(to_proj)]:
                    self._draw_edge_if_present(from_key, from_svc, to_key, to_svc)

    def _draw_edge_if_present(self, from_key, from_service, to_key, to_service) -> None:
        n1 = self.nodes.get((from_key, from_service))
        n2 = self.nodes.get((to_key, to_service))
        if n1 is None or n2 is None:
            return
        p1 = n1.pos() + n1.boundingRect().center()
        p2 = n2.pos() + n2.boundingRect().center()
        line = QGraphicsLineItem(p1.x(), p1.y(), p2.x(), p2.y())
        line.setPen(QPen(QColor("#555555"), 1, Qt.PenStyle.DashLine))
        line.setZValue(-5)
        self.scene_.addItem(line)

    def refresh_error_counts(self) -> None:
        """Updates every existing node's error badge in place, without
        touching layout/edges -- see the counts_changed connection above."""
        if self._error_monitor is None:
            return
        for (target_key, service), node in self.nodes.items():
            node.set_error_count(self._error_monitor.count_for(target_key, service))

    def _select_node(self, target_key: str, service: str) -> None:
        if self._selected_key in self.nodes:
            self.nodes[self._selected_key].set_selected_look(False)
        self._selected_key = (target_key, service)
        if self._selected_key in self.nodes:
            self.nodes[self._selected_key].set_selected_look(True)

    def _on_node_clicked(self, target_key: str, service: str) -> None:
        self._select_node(target_key, service)
        self.node_selected.emit(target_key, service)

    def _on_error_badge_clicked(self, target_key: str, service: str) -> None:
        # Selects the node too (same visual highlight, same detail-panel
        # target) -- only which log VIEW comes up differs, via the
        # separate error_badge_selected signal instead of node_selected.
        self._select_node(target_key, service)
        self.error_badge_selected.emit(target_key, service)

    def wheelEvent(self, event) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)
