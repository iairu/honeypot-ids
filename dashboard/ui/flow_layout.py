"""A layout that wraps its children onto additional rows as needed, instead
of forcing its parent widget wider to fit everything on one line -- Qt has
no built-in equivalent (QHBoxLayout never wraps). Adapted from Qt's own
"Flow Layout" C++ example for PyQt6's API.

Used by page_kibana.py's bookmark row: an arbitrary/growing number of
dashboard bookmark buttons must not be the reason the whole window has to
stretch past screen width.
"""
from __future__ import annotations

from PyQt6.QtCore import QMargins, QPoint, QRect, QSize, Qt
from PyQt6.QtWidgets import QLayout, QSizePolicy, QStyle, QWidgetItem


class FlowLayout(QLayout):
    def __init__(self, parent=None, margin: int = 0, h_spacing: int = 6, v_spacing: int = 6):
        super().__init__(parent)
        self._h_spacing = h_spacing
        self._v_spacing = v_spacing
        self._items: list[QWidgetItem] = []
        self.setContentsMargins(QMargins(margin, margin, margin, margin))

    def addItem(self, item) -> None:
        self._items.append(item)

    def horizontalSpacing(self) -> int:
        return self._h_spacing

    def verticalSpacing(self) -> int:
        return self._v_spacing

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int):
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index: int):
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self) -> Qt.Orientation:
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
        return size

    def _do_layout(self, rect: QRect, test_only: bool) -> int:
        margins = self.contentsMargins()
        effective_rect = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        x = effective_rect.x()
        y = effective_rect.y()
        line_height = 0

        for item in self._items:
            widget = item.widget()
            h_space = self.horizontalSpacing()
            if h_space == -1:
                h_space = widget.style().layoutSpacing(
                    QSizePolicy.ControlType.PushButton, QSizePolicy.ControlType.PushButton,
                    Qt.Orientation.Horizontal,
                )
            v_space = self.verticalSpacing()
            if v_space == -1:
                v_space = widget.style().layoutSpacing(
                    QSizePolicy.ControlType.PushButton, QSizePolicy.ControlType.PushButton,
                    Qt.Orientation.Vertical,
                )

            next_x = x + item.sizeHint().width() + h_space
            if next_x - h_space > effective_rect.right() and line_height > 0:
                x = effective_rect.x()
                y = y + line_height + v_space
                next_x = x + item.sizeHint().width() + h_space
                line_height = 0

            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), item.sizeHint()))

            x = next_x
            line_height = max(line_height, item.sizeHint().height())

        return y + line_height - rect.y() + margins.bottom()
