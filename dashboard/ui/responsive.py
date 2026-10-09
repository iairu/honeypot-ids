"""Small helpers that let pages adapt to narrow windows, the way a
responsive web layout reflows at a breakpoint instead of overflowing."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QScrollArea, QSplitter, QWidget


class ResponsiveSplitter(QSplitter):
    """Side by side at or above `breakpoint` pixels wide, stacked
    vertically below it."""

    def __init__(self, breakpoint: int, parent=None):
        super().__init__(Qt.Orientation.Horizontal, parent)
        self._breakpoint = breakpoint

    def resizeEvent(self, event) -> None:
        wanted = (Qt.Orientation.Horizontal if event.size().width() >= self._breakpoint
                  else Qt.Orientation.Vertical)
        if wanted != self.orientation():
            self.setOrientation(wanted)
            self.setSizes([1000] * self.count())
        super().resizeEvent(event)


def scrollable(page: QWidget) -> QScrollArea:
    """`page` inside a frameless scroll area: it fills the viewport while
    the window is big enough and scrolls once the window is smaller than
    the page's minimum size, instead of the page setting the window's
    minimum size."""
    area = QScrollArea()
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidgetResizable(True)
    area.setWidget(page)
    return area
