"""Vector figures for the PDF reports.

The report charts and diagrams are drawn with QPainter. They used to be
painted into a QImage and embedded with doc.addResource + <img>, so every
chart ended up in the PDF as a bitmap: blurry when zoomed, text not
selectable. Here they are recorded into a QPicture instead (a paint device
that stores the painter commands), and replayed straight onto the PDF printer
when the document is printed, so lines, fills and text stay vector.

Usage, in place of QImage + QPainter:

    fig, p = new_figure(900, 300)
    ... paint with p ...
    p.end()
    add_figure(doc, "report://cpu", fig)     # instead of doc.addResource(...)
    parts.append('<img src="report://cpu" width="520"/>')   # HTML unchanged
    ...
    doc.setHtml(html)
    embed_figures(doc)                        # once, after setHtml

embed_figures() swaps each <img> whose src was registered with add_figure for
an inline QTextDocument object that paints the recorded picture at the size
the <img> asked for (width attribute, height kept in proportion). Anything it
doesn't recognise (screenshots) stays a normal image. Each figure is also
added as a raster resource, so an <img> that is never swapped (no
embed_figures call) still shows the figure.
"""
from __future__ import annotations

from PyQt6.QtCore import QObject, QRectF, QSizeF, QUrl
from PyQt6.QtGui import (QColor, QImage, QPainter, QPicture, QTextCharFormat,
                         QTextCursor, QTextDocument, QTextFormat, QTextObjectInterface)

# QTextFormat object type for embedded vector figures.
_OBJECT_TYPE = QTextFormat.ObjectTypes.UserObject + 7
# QTextFormat user property carrying the figure's url.
_URL_PROP = QTextFormat.Property.UserProperty + 7
_WIDTH_PROP = QTextFormat.Property.UserProperty + 8
_HEIGHT_PROP = QTextFormat.Property.UserProperty + 9


class VectorFigure:
    """A recorded drawing of a fixed logical size (``width`` x ``height``)."""

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.picture = QPicture()

    def paint(self, painter: QPainter, rect: QRectF) -> None:
        """Replay the drawing scaled into ``rect``."""
        painter.save()
        painter.translate(rect.topLeft())
        painter.scale(rect.width() / self.width, rect.height() / self.height)
        painter.setClipRect(QRectF(0, 0, self.width, self.height))
        painter.drawPicture(0, 0, self.picture)
        painter.restore()

    def to_image(self, scale: float = 1.0) -> QImage:
        """Rasterise (for places that need a bitmap)."""
        img = QImage(max(1, int(self.width * scale)), max(1, int(self.height * scale)),
                     QImage.Format.Format_ARGB32)
        img.fill(QColor("#ffffff"))
        p = QPainter(img)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.paint(p, QRectF(0, 0, img.width(), img.height()))
        p.end()
        return img


def new_figure(width: int, height: int, background: str = "#ffffff") -> tuple[VectorFigure, QPainter]:
    """A blank figure and an active painter on it (call ``p.end()`` when done)."""
    fig = VectorFigure(width, height)
    p = QPainter(fig.picture)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.fillRect(QRectF(0, 0, width, height), QColor(background))
    return fig, p


class _FigureHandler(QObject, QTextObjectInterface):
    def __init__(self, figures: dict, parent=None):
        super().__init__(parent)
        self._figures = figures

    def intrinsicSize(self, doc, pos_in_document, fmt):  # noqa: N802 -- Qt API
        return QSizeF(float(fmt.property(_WIDTH_PROP)), float(fmt.property(_HEIGHT_PROP)))

    def drawObject(self, painter, rect, doc, pos_in_document, fmt):  # noqa: N802 -- Qt API
        fig = self._figures.get(fmt.property(_URL_PROP))
        if fig is not None:
            fig.paint(painter, rect)


def _registry(doc: QTextDocument) -> dict:
    reg = getattr(doc, "_vector_figures", None)
    if reg is None:
        reg = {}
        doc._vector_figures = reg  # noqa: SLF001 -- kept alive with the document
    return reg


def add_figure(doc: QTextDocument, url: str, fig: VectorFigure) -> None:
    """Register ``fig`` under ``url`` (an <img src> in the document's HTML)."""
    _registry(doc)[url] = fig
    doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(url), fig.to_image())


def embed_figures(doc: QTextDocument) -> int:
    """Replace every registered <img> in ``doc`` with its vector figure.
    Call after setHtml. Returns how many were replaced."""
    reg = _registry(doc)
    if not reg:
        return 0
    handler = getattr(doc, "_vector_figure_handler", None)
    if handler is None:
        handler = _FigureHandler(reg, doc)
        doc._vector_figure_handler = handler  # noqa: SLF001
        doc.documentLayout().registerHandler(_OBJECT_TYPE, handler)

    # Collect first, then edit back to front so positions stay valid.
    found = []
    block = doc.begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            frag = it.fragment()
            if frag.isValid():
                fmt = frag.charFormat()
                if fmt.isImageFormat():
                    img_fmt = fmt.toImageFormat()
                    fig = reg.get(img_fmt.name())
                    if fig is not None:
                        found.append((frag.position(), frag.length(), img_fmt, fig))
            it += 1
        block = block.next()

    for pos, length, img_fmt, fig in reversed(found):
        w = img_fmt.width() if img_fmt.width() > 0 else float(fig.width)
        h = img_fmt.height() if img_fmt.height() > 0 else w * fig.height / fig.width
        obj = QTextCharFormat(img_fmt)
        obj.setObjectType(_OBJECT_TYPE)
        obj.setProperty(_URL_PROP, img_fmt.name())
        obj.setProperty(_WIDTH_PROP, w)
        obj.setProperty(_HEIGHT_PROP, h)
        cur = QTextCursor(doc)
        cur.setPosition(pos)
        cur.setPosition(pos + length, QTextCursor.MoveMode.KeepAnchor)
        # One image fragment can hold several adjacent identical images.
        cur.insertText("￼" * length, obj)
    return len(found)
