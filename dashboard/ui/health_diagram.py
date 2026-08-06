"""Cross-referenced service diagram: one node per container (grouped by
target), colored by health status, connected by lines representing the
real relationships between services (reverse proxy -> backends -> DBs,
edge Vector -> SIEM Vector aggregator -> Elasticsearch -> Kibana, etc.).
"""
from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QGraphicsItem, QGraphicsLineItem, QGraphicsObject, QGraphicsScene,
    QGraphicsSimpleTextItem, QGraphicsView,
)

NODE_W, NODE_H = 150, 44
COL_GAP, ROW_GAP = 24, 18
GROUP_PADDING = 30
GROUP_GAP_Y = 60

STATUS_COLORS = {
    "healthy": QColor("#3fa34d"),        # running + healthy
    "running": QColor("#3f9fd9"),        # running, no healthcheck
    "unhealthy": QColor("#d9534f"),      # running but unhealthy
    "exited_ok": QColor("#7d7d7d"),      # exited, code 0 (expected one-shot)
    "exited_bad": QColor("#c9302c"),     # exited, nonzero code
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
    return "down"


def status_detail(container: dict | None) -> str:
    if container is None:
        return "not created / never started"
    return container.get("Status", container.get("State", "unknown"))


class ServiceNode(QGraphicsObject):
    clicked = pyqtSignal(str, str)  # target_key, service

    def __init__(self, target_key: str, project_label: str, service: str, x: float, y: float):
        super().__init__()
        self.target_key = target_key
        self.project_label = project_label
        self.service = service
        self.setPos(x, y)
        self.setAcceptHoverEvents(True)
        self._status = "down"
        self._detail = ""
        self._selected = False

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, NODE_W, NODE_H)

    def set_status(self, status: str, detail: str) -> None:
        self._status = status
        self._detail = detail
        self.setToolTip(f"{self.service}\n{detail}")
        self.update()

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
        painter.drawText(self.boundingRect().adjusted(6, 4, -6, -4), Qt.AlignmentFlag.AlignCenter, self.service)

    def mousePressEvent(self, event) -> None:
        self.clicked.emit(self.target_key, self.service)
        super().mousePressEvent(event)


class HealthDiagram(QGraphicsView):
    node_selected = pyqtSignal(str, str)  # target_key, service

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene_ = QGraphicsScene(self)
        self.setScene(self.scene_)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#181818")))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

        self.nodes: dict[tuple[str, str], ServiceNode] = {}
        self._selected_key: tuple[str, str] | None = None

    def rebuild(self, targets, results: dict[str, list[dict]]) -> None:
        """targets: list[Target]; results: target_key -> list of container dicts."""
        self.scene_.clear()
        self.nodes.clear()

        y_cursor = 0.0
        group_origins: dict[str, tuple[float, float, int]] = {}  # target_key -> (x0, y0, n_cols)

        for target in targets:
            containers = results.get(target.key, [])
            by_service = {c.get("Service"): c for c in containers}
            services = sorted(by_service.keys()) or ["(no containers found)"]

            n_cols = max(1, min(4, len(services)))
            n_rows = (len(services) + n_cols - 1) // n_cols

            group_w = n_cols * NODE_W + (n_cols - 1) * COL_GAP + 2 * GROUP_PADDING
            group_h = n_rows * NODE_H + (n_rows - 1) * ROW_GAP + 2 * GROUP_PADDING + 24

            title = QGraphicsSimpleTextItem(target.label)
            title.setBrush(QBrush(QColor("#e0e0e0")))
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

                node = ServiceNode(target.key, target.label, service, x, y)
                container = by_service.get(service)
                status = classify(container)
                node.set_status(status, status_detail(container))
                node.clicked.connect(self._on_node_clicked)
                self.scene_.addItem(node)
                self.nodes[(target.key, service)] = node

            border = self.scene_.addRect(
                0, group_top, group_w, group_h - 24,
                QPen(QColor("#3a3a3a")), QBrush(Qt.BrushStyle.NoBrush),
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

    def _on_node_clicked(self, target_key: str, service: str) -> None:
        if self._selected_key in self.nodes:
            self.nodes[self._selected_key].set_selected_look(False)
        self._selected_key = (target_key, service)
        if self._selected_key in self.nodes:
            self.nodes[self._selected_key].set_selected_look(True)
        self.node_selected.emit(target_key, service)

    def wheelEvent(self, event) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)
