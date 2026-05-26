import math
import random
from PyQt6.QtWidgets import (
    QWidget, QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QSizePolicy,
)
from PyQt6.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QFontMetrics, QPixmap,
    QPainterPath, QPolygonF, QRadialGradient,
)
from PyQt6.QtCore import Qt, QPointF, QRectF, pyqtSignal

from core.ui.styles import (
    NAVY, NAVY_DEEP, BLUE, BLUE_LIGHT, TEXT_PRIMARY, TEXT_MUTED, TEXT_BODY,
    CARD_BORDER, CARD_BORDER_MUTED, WHITE, BG_LIGHT,
    TAG_MALWARE_BG, TAG_MALWARE_FG,
    GREEN, LIME, AMBER, ORANGE, RED, MONO,
)


def hline(color=CARD_BORDER_MUTED):
    f = QFrame(); f.setFrameShape(QFrame.Shape.HLine); f.setFixedHeight(1)
    f.setStyleSheet(f"background-color: {color}; border: none;")
    return f


class SkullLogo(QWidget):
    """Brand logo. Loads ui/logo.png; falls back to a minimal painted glyph if missing."""
    _LOGO_PATH = None

    def __init__(self, size=36, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        if SkullLogo._LOGO_PATH is None:
            import sys
            from pathlib import Path as _P
            base = getattr(sys, "_MEIPASS", None)
            if base:
                cand = _P(base) / "ui" / "logo.png"
            else:
                cand = _P(__file__).resolve().parents[2] / "ui" / "logo.png"
            SkullLogo._LOGO_PATH = str(cand) if cand.exists() else ""
        self._pixmap = QPixmap(SkullLogo._LOGO_PATH) if SkullLogo._LOGO_PATH else QPixmap()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        if not self._pixmap.isNull():
            scaled = self._pixmap.scaled(
                self.width(), self.height(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            x = (self.width() - scaled.width()) // 2
            y = (self.height() - scaled.height()) // 2
            p.drawPixmap(x, y, scaled)
            return
        # Fallback: simple circular badge
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("white"))
        p.drawEllipse(2, 2, self.width()-4, self.height()-4)
        p.setBrush(QColor(NAVY))
        p.drawEllipse(int(self.width()*0.30), int(self.height()*0.35), int(self.width()*0.12), int(self.height()*0.18))
        p.drawEllipse(int(self.width()*0.58), int(self.height()*0.35), int(self.width()*0.12), int(self.height()*0.18))


class Dot(QWidget):
    def __init__(self, color=BLUE, size=8, parent=None):
        super().__init__(parent); self.color = color; self.setFixedSize(size, size)

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(self.color))
        p.drawEllipse(0, 0, self.width(), self.height())


class Tag(QLabel):
    def __init__(self, text, bg=TAG_MALWARE_BG, fg=TAG_MALWARE_FG, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(f"background-color: {bg}; color: {fg}; border-radius: 4px; padding: 3px 10px; font-size: 10.5px; font-weight: 700; border: 1px solid {fg}40;")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


class Card(QFrame):
    def __init__(self, title=None, kicker=None, parent=None, padding=(18,16,18,16)):
        super().__init__(parent); self.setObjectName('Card'); self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(*padding); self._layout.setSpacing(12)
        if title is not None:
            header = QHBoxLayout(); header.setSpacing(8)
            t = QLabel(title.upper()); t.setObjectName('CardTitle'); header.addWidget(t)
            if kicker:
                k = QLabel(kicker); k.setObjectName('CardSubtitle'); header.addWidget(k)
            header.addStretch(); self._layout.addLayout(header)

    def addLayout(self, layout): self._layout.addLayout(layout)
    def addWidget(self, widget, *args, **kwargs): self._layout.addWidget(widget, *args, **kwargs)
    def addStretch(self, *args): self._layout.addStretch(*args)
    def addSpacing(self, n): self._layout.addSpacing(n)
    def layout(self): return self._layout


def make_console_card(owner, height=110):
    wrap = QFrame(); wrap.setObjectName('Card')
    wrap.setStyleSheet(f"QFrame#Card {{ background-color:#0B121F; border:1px solid #18243A; border-radius:6px; }}")
    v = QVBoxLayout(wrap); v.setContentsMargins(16,12,16,12); v.setSpacing(6)
    h = QHBoxLayout()
    title = QLabel('CONSOLE LOG'); title.setStyleSheet('color:#D8DEE9; font-size:11px; font-weight:700; letter-spacing:1.4px;')
    h.addWidget(title); h.addStretch()
    clear_btn = QPushButton('Clear Log')
    clear_btn.setStyleSheet(f"QPushButton {{ background: transparent; color:{TEXT_MUTED}; border:none; font-size:11px; }} QPushButton:hover {{ color:white; }}")
    clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    h.addWidget(clear_btn)
    v.addLayout(h)
    te = QTextEdit(); te.setObjectName('Console'); te.setReadOnly(True); te.setFixedHeight(height)
    v.addWidget(te)

    def _clear_all():
        try: owner.console_bar.clear()
        except Exception: pass
        for c in getattr(owner, '_page_consoles', []) or []:
            try: c.clear()
            except Exception: pass

    clear_btn.clicked.connect(_clear_all)
    if not hasattr(owner, '_page_consoles'):
        owner._page_consoles = []
    owner._page_consoles.append(te)
    return wrap, te


class MiniMapWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(130)
        self.setMaximumHeight(170)
        self._source = None
        self._thumb = None
        self._scene_rect = None
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def attach(self, view):
        self._source = view
        try:
            view.cfgChanged.connect(self._refresh_thumb)
            view.horizontalScrollBar().valueChanged.connect(self.update)
            view.verticalScrollBar().valueChanged.connect(self.update)
        except Exception:
            pass

    def _refresh_thumb(self):
        if not self._source:
            return
        try:
            scene = self._source.scene()
            if not scene:
                self._thumb = None; self.update(); return
            rect = scene.itemsBoundingRect()
            if rect.isEmpty():
                self._thumb = None; self.update(); return
            self._scene_rect = rect
            target_w = max(1, self.width() - 16)
            target_h = max(1, self.height() - 16)
            sw = rect.width() if rect.width() > 0 else 1
            sh = rect.height() if rect.height() > 0 else 1
            scale = min(target_w / sw, target_h / sh, 1.0)
            pw = max(1, int(sw * scale))
            ph = max(1, int(sh * scale))
            pix = QPixmap(pw, ph)
            pix.fill(Qt.GlobalColor.white)
            painter = QPainter(pix)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            scene.render(painter, target=QRectF(0, 0, pw, ph), source=rect)
            painter.end()
            self._thumb = pix
            self.update()
        except Exception:
            self._thumb = None
            self.update()

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        self._refresh_thumb()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor("#F7FAFD"))
        p.setPen(QPen(QColor("#E4E9F2"), 1))
        p.drawRoundedRect(QRectF(0, 0, self.width()-1, self.height()-1), 6, 6)
        if not self._thumb or not self._source or not self._scene_rect:
            p.setPen(QColor("#94A3B8"))
            f = QFont("Segoe UI", 9); p.setFont(f)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No CFG yet")
            return
        tx = (self.width() - self._thumb.width()) // 2
        ty = (self.height() - self._thumb.height()) // 2
        p.drawPixmap(tx, ty, self._thumb)
        try:
            view = self._source
            vp_poly = view.mapToScene(view.viewport().rect())
            vp_rect = vp_poly.boundingRect()
            sr = self._scene_rect
            if sr.width() <= 0 or sr.height() <= 0:
                return
            sx = self._thumb.width() / sr.width()
            sy = self._thumb.height() / sr.height()
            rx = tx + (vp_rect.x() - sr.x()) * sx
            ry = ty + (vp_rect.y() - sr.y()) * sy
            rw = vp_rect.width() * sx
            rh = vp_rect.height() * sy
            rx = max(tx, min(tx + self._thumb.width() - 4, rx))
            ry = max(ty, min(ty + self._thumb.height() - 4, ry))
            rw = max(8, min(self._thumb.width() - (rx - tx), rw))
            rh = max(8, min(self._thumb.height() - (ry - ty), rh))
            p.setBrush(QColor(37, 99, 235, 40))
            p.setPen(QPen(QColor("#2563EB"), 1.5))
            p.drawRect(QRectF(rx, ry, rw, rh))
        except Exception:
            pass

    def mousePressEvent(self, ev):
        if not self._source or not self._thumb or not self._scene_rect:
            return
        try:
            tx = (self.width() - self._thumb.width()) // 2
            ty = (self.height() - self._thumb.height()) // 2
            x = ev.position().x() - tx
            y = ev.position().y() - ty
            if 0 <= x <= self._thumb.width() and 0 <= y <= self._thumb.height():
                sr = self._scene_rect
                sx = sr.width() / self._thumb.width()
                sy = sr.height() / self._thumb.height()
                target_x = sr.x() + x * sx
                target_y = sr.y() + y * sy
                self._source.centerOn(target_x, target_y)
                self.update()
        except Exception:
            pass


class RiskGauge(QWidget):
    def __init__(self, value=0, label='RISK', size=200, compact=False, parent=None):
        super().__init__(parent)
        self.value = max(0, min(100, value))
        self.label = label
        self.compact = compact
        self.setMinimumSize(size, int(size*0.72) if not compact else int(size*0.82))

    def setValue(self, v):
        self.value = max(0, min(100, int(v))); self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        margin = 14 if not self.compact else 10
        diameter = min(w - 2*margin, (h-30)*2); diameter = max(60, diameter)
        cx = w/2; cy = margin + diameter/2
        r_outer = diameter/2; thickness = max(10, diameter*0.11)
        arc_rect = QRectF(cx-r_outer+thickness/2, cy-r_outer+thickness/2, diameter-thickness, diameter-thickness)
        pen = QPen(QColor('#E6EAF2'), thickness); pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        p.setPen(pen); p.drawArc(arc_rect, 0, 180*16)
        for start, span, color in [(144,36,QColor(GREEN)),(108,36,QColor(LIME)),(72,36,QColor(AMBER)),(36,36,QColor(ORANGE)),(0,36,QColor(RED))]:
            pen = QPen(color, thickness); pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            p.setPen(pen); p.drawArc(arc_rect, int(start*16), int(span*16))
        p.setPen(QPen(QColor('#CBD5E1'), 1))
        for i in range(11):
            ang = math.radians(180-18*i); r1 = r_outer-thickness-2; r2 = r1-4
            p.drawLine(QPointF(cx+r1*math.cos(ang), cy-r1*math.sin(ang)), QPointF(cx+r2*math.cos(ang), cy-r2*math.sin(ang)))
        needle_deg = 180-(self.value/100.0)*180; ang = math.radians(needle_deg)
        needle_len = r_outer-thickness-8; ex = cx+needle_len*math.cos(ang); ey = cy-needle_len*math.sin(ang)
        perp = ang+math.pi/2; base_w = thickness*0.22
        bx1 = cx+base_w*math.cos(perp); by1 = cy-base_w*math.sin(perp)
        bx2 = cx-base_w*math.cos(perp); by2 = cy+base_w*math.sin(perp)
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(TEXT_PRIMARY))
        p.drawPolygon(QPolygonF([QPointF(bx1,by1), QPointF(bx2,by2), QPointF(ex,ey)]))
        hub_r = thickness*0.32; p.setBrush(QColor('white'))
        p.setPen(QPen(QColor(TEXT_PRIMARY), 2)); p.drawEllipse(QPointF(cx, cy), hub_r, hub_r)
        font_big = QFont('Segoe UI', 30 if not self.compact else 24, QFont.Weight.Bold)
        p.setFont(font_big); p.setPen(QColor(TEXT_PRIMARY)); fm = QFontMetrics(font_big)
        val_text = str(self.value)
        vx = cx-fm.horizontalAdvance(val_text)/2-10; vy_top = cy+6
        p.drawText(QRectF(vx, vy_top, fm.horizontalAdvance(val_text)+4, fm.height()), Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignTop, val_text)
        font_small = QFont('Segoe UI', 12); p.setFont(font_small); p.setPen(QColor(TEXT_MUTED))
        p.drawText(QRectF(vx+fm.horizontalAdvance(val_text)+6, vy_top+12, 60, 20), Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignTop, '/ 100')
        font_lbl = QFont('Segoe UI', 10, QFont.Weight.Bold); p.setFont(font_lbl); p.setPen(QColor(RED))
        p.drawText(QRectF(0, vy_top+fm.height()+2, w, 16), Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop, self.label.upper())


class CallGraphWidget(QWidget):
    """Live call-graph visualization.

    Call ``set_call_graph(model, summary, entry_va)`` to render real data.
    Emits ``nodeClicked(int)`` (VA) on single click and ``nodeDoubleClicked(int)``
    on double click. Hovering shows the function symbol in a tooltip.
    """
    nodeClicked        = pyqtSignal(int)
    nodeDoubleClicked  = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(210)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMouseTracking(True)
        self._nodes = []      # [{x,y,r,va,name,suspicious,is_entry}]
        self._edges = []      # [(idx_a, idx_b)]
        self._entry_idx = -1
        self._placeholder = True
        self._gen_placeholder()

    # -------- placeholder (when no PE loaded) --------
    def _gen_placeholder(self):
        rnd = random.Random(7)
        self._nodes = [{'x': 0.5, 'y': 0.5, 'r': 18, 'va': 0, 'name': '', 'suspicious': False, 'is_entry': True}]
        ring1 = 8
        for i in range(ring1):
            a = 2*math.pi*i/ring1 + rnd.uniform(-0.1,0.1)
            r = 0.20 + rnd.uniform(-0.02,0.02)
            self._nodes.append({
                'x': 0.5+r*math.cos(a), 'y': 0.5+r*math.sin(a)*0.85,
                'r': rnd.uniform(7,11), 'va': 0, 'name': '',
                'suspicious': False, 'is_entry': False,
            })
        self._edges = [(0, i) for i in range(1, ring1+1)]
        self._entry_idx = 0
        self._placeholder = True

    # -------- public API --------
    def set_call_graph(self, model: dict, summary: dict, entry_va=None):
        """Render real call graph data. Model has 'nodes' and 'edges' lists."""
        if not model or not model.get('nodes'):
            self._gen_placeholder()
            self.update()
            return

        nodes_in = model.get('nodes') or []
        edges_in = model.get('edges') or []
        suspicious_funcs = set()
        for row in (summary or {}).get('top_hub_functions', []) or []:
            if row.get('suspicious'):
                suspicious_funcs.add(str(row.get('address') or ''))

        # Build positions: hubs in inner ring, leaves in outer ring
        indeg = {}
        for e in edges_in:
            dst = e.get('callee') or e.get('dst')
            if dst is not None:
                indeg[dst] = indeg.get(dst, 0) + 1

        def _addr(n):
            return n.get('address') or n.get('addr') or n.get('id') or ''

        sorted_nodes = sorted(nodes_in, key=lambda n: -indeg.get(_addr(n), 0))
        max_nodes = min(60, len(sorted_nodes))
        sorted_nodes = sorted_nodes[:max_nodes]
        addr_to_idx = {}
        positioned = []

        ep_str = f"0x{int(entry_va):08X}" if entry_va is not None else None
        # Place entry at center if found
        ep_node = None
        if ep_str:
            for n in sorted_nodes:
                if str(_addr(n)).lower() == ep_str.lower():
                    ep_node = n
                    break

        if ep_node is not None:
            positioned.append({
                'x': 0.5, 'y': 0.5, 'r': 18,
                'va': self._va_from_addr(_addr(ep_node)),
                'name': str(ep_node.get('name') or _addr(ep_node)),
                'suspicious': str(_addr(ep_node)) in suspicious_funcs,
                'is_entry': True,
            })
            addr_to_idx[str(_addr(ep_node))] = 0
            self._entry_idx = 0
            others = [n for n in sorted_nodes if n is not ep_node]
        else:
            others = sorted_nodes
            self._entry_idx = -1

        # Split rest into two rings by indegree
        ring_inner_count = min(12, len(others) // 2 + 1)
        for i, n in enumerate(others[:ring_inner_count]):
            angle = 2*math.pi*i/max(1, ring_inner_count)
            r = 0.22
            positioned.append({
                'x': 0.5 + r*math.cos(angle), 'y': 0.5 + r*math.sin(angle)*0.85,
                'r': 9.0, 'va': self._va_from_addr(_addr(n)),
                'name': str(n.get('name') or _addr(n)),
                'suspicious': str(_addr(n)) in suspicious_funcs,
                'is_entry': False,
            })
            addr_to_idx[str(_addr(n))] = len(positioned) - 1

        outer = others[ring_inner_count:]
        for i, n in enumerate(outer):
            angle = 2*math.pi*i/max(1, len(outer))
            r = 0.38
            positioned.append({
                'x': 0.5 + r*math.cos(angle), 'y': 0.5 + r*math.sin(angle)*0.82,
                'r': 6.0, 'va': self._va_from_addr(_addr(n)),
                'name': str(n.get('name') or _addr(n)),
                'suspicious': str(_addr(n)) in suspicious_funcs,
                'is_entry': False,
            })
            addr_to_idx[str(_addr(n))] = len(positioned) - 1

        self._nodes = positioned

        # Build edge index pairs
        self._edges = []
        for e in edges_in:
            src = str(e.get('caller') or e.get('src') or '')
            dst = str(e.get('callee') or e.get('dst') or '')
            if src in addr_to_idx and dst in addr_to_idx:
                self._edges.append((addr_to_idx[src], addr_to_idx[dst]))

        self._placeholder = False
        self.update()

    def clear_graph(self):
        self._gen_placeholder()
        self.update()

    @staticmethod
    def _va_from_addr(addr):
        try:
            s = str(addr).lower()
            if s.startswith('0x'):
                return int(s, 16)
            return int(s, 16)
        except Exception:
            return 0

    # -------- painting --------
    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        xy = lambda n: QPointF(n['x']*w, n['y']*h)
        # Edges
        p.setPen(QPen(QColor('#CBD5E1'), 1.1))
        for a, b in self._edges:
            if 0 <= a < len(self._nodes) and 0 <= b < len(self._nodes):
                p.drawLine(xy(self._nodes[a]), xy(self._nodes[b]))
        # Nodes (non-entry)
        for i, n in enumerate(self._nodes):
            if i == self._entry_idx:
                continue
            pt = xy(n)
            if n.get('suspicious'):
                color = QColor(RED); ring_color = QColor('#FECACA')
            else:
                is_primary = n.get('r', 6) >= 8
                color = QColor(BLUE if is_primary else '#4B6CB7')
                ring_color = QColor('#BFDBFE' if is_primary else '#DBEAFE')
            p.setBrush(ring_color); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(pt, n['r']+2.6, n['r']+2.6)
            p.setBrush(color); p.drawEllipse(pt, n['r'], n['r'])
        # Entry node (center)
        if self._entry_idx >= 0 and self._entry_idx < len(self._nodes):
            center = xy(self._nodes[self._entry_idx])
            grad = QRadialGradient(center, 28)
            grad.setColorAt(0.0, QColor(30,58,138,200))
            grad.setColorAt(1.0, QColor(30,58,138,0))
            p.setBrush(QBrush(grad)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(center, 26, 26)
            p.setBrush(QColor(NAVY_DEEP)); p.drawEllipse(center, 16, 16)
            p.setBrush(QColor('white')); p.drawEllipse(QRectF(center.x()-6, center.y()-6, 12, 12))
            p.setBrush(QColor(NAVY_DEEP))
            p.drawEllipse(QRectF(center.x()-3, center.y()-3, 2.5, 2.5))
            p.drawEllipse(QRectF(center.x()+0.5, center.y()-3, 2.5, 2.5))
        if self._placeholder:
            p.setPen(QColor(TEXT_MUTED))
            p.setFont(QFont('Segoe UI', 9))
            p.drawText(QRectF(0, h-22, w, 18),
                       Qt.AlignmentFlag.AlignHCenter,
                       'Preview — load a PE to populate the live call graph')

    # -------- interaction --------
    def _hit(self, pos):
        w, h = self.width(), self.height()
        for n in self._nodes:
            cx, cy = n['x']*w, n['y']*h
            if (pos.x()-cx)**2 + (pos.y()-cy)**2 <= (n['r']+4)**2:
                return n
        return None

    def mousePressEvent(self, ev):
        if self._placeholder:
            return
        n = self._hit(ev.position())
        if n and n.get('va'):
            self.nodeClicked.emit(int(n['va']))
        super().mousePressEvent(ev)

    def mouseDoubleClickEvent(self, ev):
        if self._placeholder:
            return
        n = self._hit(ev.position())
        if n and n.get('va'):
            self.nodeDoubleClicked.emit(int(n['va']))
        super().mouseDoubleClickEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._placeholder:
            self.setToolTip('')
            return
        n = self._hit(ev.position())
        if n and n.get('name'):
            suffix = ' (suspicious)' if n.get('suspicious') else ''
            self.setToolTip(f"{n['name']}{suffix}")
        else:
            self.setToolTip('')
