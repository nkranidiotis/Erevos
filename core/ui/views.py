import math
from PyQt6.QtWidgets import (
    QGraphicsView, QGraphicsScene, QGraphicsTextItem, QPlainTextEdit, QFrame,
    QGraphicsProxyWidget,
)
from PyQt6.QtGui import (
    QPainter, QFont, QFontMetrics, QPen, QBrush, QColor, QMouseEvent,
    QPainterPath,
)
from PyQt6.QtCore import Qt, QPointF, QRectF, pyqtSignal

from core.ui.styles import NAVY, BLUE_DEEP


class FunctionBoxView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setMinimumSize(600, 400)
        self._scale = 1.0
        self._name = ""
        self._va = 0
        self._asm = ""

    def clear(self):
        self.scene().clear()
        self._scale = 1.0
        self.resetTransform()

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        if delta == 0:
            return super().wheelEvent(event)
        factor = 1.20 if delta > 0 else 1 / 1.20
        new_scale = max(0.25, min(6.0, self._scale * factor))
        factor = new_scale / self._scale
        self._scale = new_scale
        self.scale(factor, factor)

    def set_function(self, name: str, va: int, asm_text: str):
        self._name, self._va, self._asm = name, va, (asm_text or "")
        self._render_box()

    def _render_box(self):
        self.clear()
        scene = self.scene()
        margin = 24
        text_width = 900

        header_text = f"{self._name}  @ 0x{self._va:08X}"
        header_item = QGraphicsTextItem(header_text)
        header_font = QFont("Consolas", 12, QFont.Weight.DemiBold)
        header_item.setFont(header_font)
        scene.addItem(header_item)
        fm = QFontMetrics(header_font)
        header_h = fm.height() + 12
        header_item.setPos(margin, margin)

        body = self._asm if self._asm.strip() else "<no disassembly>"
        code_edit = QPlainTextEdit()
        code_edit.setReadOnly(True)
        code_edit.setFrameStyle(QFrame.Shape.NoFrame)
        code_edit.setFont(QFont("Consolas", 10))
        code_edit.setPlainText(body)
        code_edit.setFixedWidth(text_width)
        lines = max(1, min(2000, body.count("\n") + 1))
        line_h = QFontMetrics(QFont("Consolas", 10)).height()
        est_h = min(800, max(200, lines * line_h + 10))
        code_edit.setFixedHeight(est_h)

        proxy = scene.addWidget(code_edit)
        proxy.setZValue(1)
        proxy.setPos(margin, margin + header_h + 6)

        rect_w = int(text_width + 2 * margin)
        rect_h = int(header_h + 3 * margin + est_h)

        bg = scene.addRect(10, 10, rect_w, rect_h)
        bg.setZValue(-1)
        bg.setBrush(Qt.GlobalColor.white)
        bg.setPen(Qt.GlobalColor.black)

        hb = scene.addRect(10, 10, rect_w, header_h + 12)
        hb.setZValue(-0.5)
        hb.setBrush(QColor(200, 230, 230))
        hb.setPen(Qt.GlobalColor.black)

        self.setSceneRect(0, 0, rect_w + 20, rect_h + 20)
        self.resetTransform()
        self._scale = 1.0
        self.fitInView(self.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self.scale(1.4, 1.4)


class CfgGraphView(QGraphicsView):
    cfgChanged   = pyqtSignal()
    blockClicked = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.SmartViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setObjectName("CfgView")
        self._scale = 1.0
        self._block_items = {}
        self._last_cfg = None

    def clear(self):
        self.scene().clear()
        self._scale = 1.0
        self.resetTransform()
        self._block_items = {}
        self._last_cfg = None

    def wheelEvent(self, event):
        d = event.angleDelta().y()
        if d == 0:
            return super().wheelEvent(event)
        factor = 1.15 if d > 0 else 1/1.15
        new_scale = max(0.3, min(4.0, self._scale * factor))
        factor = new_scale / self._scale
        self._scale = new_scale
        self.scale(factor, factor)

    def _get_block_insns(self, disasm, start_va_hex: str, end_va_hex: str, max_insns=6):
        if not disasm:
            return []
        try:
            start = int(start_va_hex, 16)
            end = int(end_va_hex, 16)
            size = max(0, end - start)
            cap = min(size, 0x8000)
            text = disasm.disasm_at(start, size=cap)
            if not text:
                return []
            lines = [ln for ln in text.splitlines() if ln.strip()]
            return lines[:max_insns]
        except Exception:
            return []

    def render_cfg(self, cfg: dict, disasm=None):
        self.clear()
        if not cfg:
            self.cfgChanged.emit()
            return

        self._last_cfg = cfg
        nodes = cfg.get("nodes", []) or []
        edges = cfg.get("edges", []) or []

        scene = self.scene()
        scene.setBackgroundBrush(QBrush(QColor("#FFFFFF")))

        if not nodes:
            placeholder = scene.addText("No basic blocks for this function yet.\nSelect a function in Erevos View.")
            placeholder.setDefaultTextColor(QColor("#94A3B8"))
            f = QFont("Segoe UI", 11); placeholder.setFont(f)
            self.fitInView(scene.itemsBoundingRect().adjusted(-20,-20,20,20), Qt.AspectRatioMode.KeepAspectRatio)
            self.cfgChanged.emit()
            return

        node_by_id = {n.get("id"): n for n in nodes}
        succ = {nid: [] for nid in node_by_id}
        pred = {nid: [] for nid in node_by_id}
        for e in edges:
            s, d = e.get("src"), e.get("dst")
            if s in succ and d in node_by_id:
                succ[s].append(d)
                pred[d].append(s)

        entry_id = nodes[0].get("id")
        for nid, plist in pred.items():
            if not plist:
                entry_id = nid; break

        level_of = {entry_id: 0}
        queue = [entry_id]
        while queue:
            cur = queue.pop(0)
            for n in succ.get(cur, []):
                if n not in level_of:
                    level_of[n] = level_of[cur] + 1
                    queue.append(n)
        max_lvl = max(level_of.values()) if level_of else 0
        for nid in node_by_id:
            if nid not in level_of:
                max_lvl += 1
                level_of[nid] = max_lvl

        levels = {}
        for nid, lvl in level_of.items():
            levels.setdefault(lvl, []).append(nid)
        for lvl in levels:
            levels[lvl].sort(key=lambda x: 0 if x == entry_id else (1 if not succ.get(x) else 2))

        exit_ids = {nid for nid, s in succ.items() if not s}

        BLOCK_W = 130
        BLOCK_H = 56
        H_GAP   = 50
        V_GAP   = 80
        TOP_PAD = 30
        LEFT_PAD = 40

        positions = {}
        max_row_w = 0
        for lvl in sorted(levels.keys()):
            row = levels[lvl]
            row_w = len(row) * BLOCK_W + (len(row) - 1) * H_GAP
            max_row_w = max(max_row_w, row_w)

        for lvl in sorted(levels.keys()):
            row = levels[lvl]
            row_w = len(row) * BLOCK_W + (len(row) - 1) * H_GAP
            x_start = LEFT_PAD + (max_row_w - row_w) / 2
            y = TOP_PAD + lvl * (BLOCK_H + V_GAP)
            for i, nid in enumerate(row):
                x = x_start + i * (BLOCK_W + H_GAP)
                positions[nid] = QRectF(x, y, BLOCK_W, BLOCK_H)

        edge_pen = QPen(QColor("#9CA9BC"), 4.5)
        edge_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        edge_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)

        for e in edges:
            s, d = e.get("src"), e.get("dst")
            if s not in positions or d not in positions:
                continue
            r1 = positions[s]; r2 = positions[d]
            p1 = QPointF(r1.center().x(), r1.bottom())
            p2 = QPointF(r2.center().x(), r2.top())
            mid_y = (p1.y() + p2.y()) / 2
            c1 = QPointF(p1.x(), mid_y)
            c2 = QPointF(p2.x(), mid_y)
            path = QPainterPath(p1)
            path.cubicTo(c1, c2, p2)
            scene.addPath(path, edge_pen, QBrush(Qt.GlobalColor.transparent))

            adx = p2.x() - c2.x(); ady = p2.y() - c2.y()
            alen = math.sqrt(adx * adx + ady * ady)
            if alen > 0.001:
                adx /= alen; ady /= alen
                ARROW_L, ARROW_W = 11, 5
                base = QPointF(p2.x() - adx * ARROW_L, p2.y() - ady * ARROW_L)
                left  = QPointF(base.x() - ady * ARROW_W, base.y() + adx * ARROW_W)
                right = QPointF(base.x() + ady * ARROW_W, base.y() - adx * ARROW_W)
                arr_path = QPainterPath()
                arr_path.moveTo(p2); arr_path.lineTo(left); arr_path.lineTo(right); arr_path.closeSubpath()
                scene.addPath(arr_path, QPen(Qt.PenStyle.NoPen), QBrush(QColor("#9CA9BC")))

        font_title = QFont("Segoe UI", 11, QFont.Weight.Bold)
        font_addr = QFont("Consolas", 8)

        self._block_items = {}
        for nid, rect in positions.items():
            n = node_by_id.get(nid, {})
            is_entry = (nid == entry_id)
            is_exit  = (nid in exit_ids and not is_entry)

            if is_entry:
                fill = QColor("#1E3A8A"); border = QColor("#1E3A8A"); txt_color = QColor("#FFFFFF"); addr_color = QColor("#BFDBFE")
            elif is_exit:
                fill = QColor("#FEE2E2"); border = QColor("#FCA5A5"); txt_color = QColor("#991B1B"); addr_color = QColor("#B91C1C")
            else:
                fill = QColor("#FFFFFF"); border = QColor("#B9C4D4"); txt_color = QColor("#0F172A"); addr_color = QColor("#94A3B8")

            block_path = QPainterPath()
            block_path.addRoundedRect(rect, 8, 8)
            scene.addPath(block_path, QPen(border, 1.4), QBrush(fill))

            title = f"BB {nid}"
            title_item = QGraphicsTextItem(title)
            title_item.setFont(font_title)
            title_item.setDefaultTextColor(txt_color)
            tw = title_item.boundingRect().width()
            title_item.setPos(rect.center().x() - tw / 2, rect.top() + 6)
            scene.addItem(title_item)

            start_str = n.get("start", "")
            addr_item = QGraphicsTextItem(start_str)
            addr_item.setFont(font_addr)
            addr_item.setDefaultTextColor(addr_color)
            aw = addr_item.boundingRect().width()
            addr_item.setPos(rect.center().x() - aw / 2, rect.top() + 28)
            scene.addItem(addr_item)

            self._block_items[nid] = {"rect": rect, "start": start_str, "id": nid}

        scene.setSceneRect(scene.itemsBoundingRect().adjusted(-30, -30, 30, 30))
        self.fitInView(scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self._scale = 1.0
        self.cfgChanged.emit()

    def mousePressEvent(self, ev: QMouseEvent):
        # Single click: select the block and populate the Node Info panel — do NOT navigate away.
        pt = self.mapToScene(ev.position().toPoint())
        for bid, info in self._block_items.items():
            r: QRectF = info.get("rect")
            if r and r.contains(pt):
                self.blockClicked.emit(bid)
                break
        super().mousePressEvent(ev)

    def mouseDoubleClickEvent(self, ev: QMouseEvent):
        # Double click: open the block in Erevos View.
        pt = self.mapToScene(ev.position().toPoint())
        for bid, info in self._block_items.items():
            r: QRectF = info.get("rect")
            if r and r.contains(pt):
                self.blockClicked.emit(bid)
                start = info.get("start")
                if start:
                    w = self.window()
                    try:
                        va = int(start, 16)
                        if hasattr(w, "_open_in_erevos_view"):
                            w._open_in_erevos_view(va, f"BB_{bid}")
                    except Exception:
                        pass
                break
        super().mouseDoubleClickEvent(ev)
