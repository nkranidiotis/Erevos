#!/usr/bin/env python3
"""
EREVOS — Enterprise High-Fidelity UI Mock (PyQt6)
=================================================

Standalone prototype of a professional static PE disassembler interface.
No backend dependencies; all data is mocked.

Run:
    python erevos_enterprise_hifi_mock.py

Design targets a modern enterprise look (light background, white cards, dark header):
    - 4px to 6px border radii (middle-ground, not too square, not too round)
    - Flat design without muddy drop shadows
    - Custom painted risk gauge, call graph, and CFG graph
    - Navy Blue top navigation bar and highlight accents mirroring the provided concept art
"""

import os
import sys
import math
import random
from pathlib import Path

from PyQt6.QtCore import (
    Qt, QPoint, QPointF, QRect, QRectF, QSize, QTimer, pyqtSignal
)
from PyQt6.QtGui import (
    QBrush, QColor, QFont, QFontMetrics, QIcon, QLinearGradient, QPainter,
    QPainterPath, QPen, QPixmap, QPolygonF, QRadialGradient
)
from PyQt6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QFrame, QGraphicsDropShadowEffect,
    QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QPushButton, QScrollArea, QSizePolicy,
    QStackedWidget, QTableWidget, QTableWidgetItem, QTextEdit, QToolButton,
    QVBoxLayout, QWidget
)


# ============================================================================
# THEME
# ============================================================================

# Navy shell palette
NAVY_DEEP    = "#0B1220"
NAVY         = "#101A2E"
NAVY_LIGHT   = "#16223C"
NAVY_BORDER  = "#1E2A44"
NAVY_ACTIVE  = "#1B2844"

# Application Background (Light)
APP_BG       = "#F1F5F9"

# Light palette (cards)
WHITE        = "#FFFFFF"
BG_LIGHT     = "#F7FAFD"
BG_HOVER     = "#F1F5F9"
CARD_BORDER  = "#E4E9F2"
CARD_BORDER_MUTED = "#EEF1F6"
DIVIDER      = "#EEF1F6"

# Text
TEXT_PRIMARY   = "#0F172A"
TEXT_BODY      = "#1F2937"
TEXT_SECONDARY = "#64748B"
TEXT_MUTED     = "#94A3B8"
TEXT_FAINT     = "#B5BFCD"
TEXT_ON_NAVY   = "#D8DEE9"

# Accents
BLUE        = "#2563EB"
BLUE_LIGHT  = "#3B82F6"
BLUE_DEEP   = "#1E3A8A"
BLUE_SOFT   = "#EFF6FF"
CYAN        = "#0891B2"
TEAL        = "#0D9488"
PURPLE      = "#7C3AED"
GREEN       = "#10B981"
GREEN_SOFT  = "#ECFDF5"
LIME        = "#84CC16"
YELLOW      = "#EAB308"
AMBER       = "#F59E0B"
ORANGE      = "#F97316"
RED         = "#DC2626"
RED_LIGHT   = "#EF4444"
RED_SOFT    = "#FEF2F2"

# Tag palette
TAG_MALWARE_BG  = "#FEE2E2"; TAG_MALWARE_FG  = "#991B1B"
TAG_SUS_BG      = "#FEF3C7"; TAG_SUS_FG      = "#92400E"
TAG_PACKED_BG   = "#E0E7FF"; TAG_PACKED_FG   = "#3730A3"

MONO = "Menlo, Consolas, 'DejaVu Sans Mono', 'Courier New', monospace"
SANS = "'Inter', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"


APP_QSS = f"""
* {{
    font-family: {SANS};
    color: {TEXT_PRIMARY};
}}
QMainWindow {{
    background-color: {NAVY};
}}
QWidget#PageRoot {{
    background-color: {APP_BG};
}}
QScrollArea, QScrollArea > QWidget > QWidget {{
    background-color: {APP_BG};
    border: none;
}}

/* ---------- Top bar ---------- */
#TopBar {{
    background-color: {NAVY};
    border-bottom: 1px solid {NAVY_BORDER};
}}
QLabel#Brand {{
    color: white;
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 3px;
}}
QLabel#BrandSub {{
    color: {TEXT_MUTED};
    font-size: 9px;
    letter-spacing: 2.4px;
    font-weight: 600;
}}
QPushButton#NavBtn {{
    color: {TEXT_ON_NAVY};
    background: transparent;
    border: none;
    padding: 12px 20px 10px 20px;
    margin: 0px 2px;
    font-size: 13px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
}}
QPushButton#NavBtn:hover {{
    color: white;
}}
QPushButton#NavBtn:checked {{
    color: white;
    font-weight: 600;
    border-bottom: 2px solid {BLUE_LIGHT};
}}
QPushButton#ReportBtn {{
    background-color: {WHITE};
    color: {NAVY};
    border: 1px solid {CARD_BORDER};
    border-radius: 4px;
    padding: 9px 18px;
    font-weight: 700;
    font-size: 10.5px;
    letter-spacing: 0.8px;
}}
QPushButton#ReportBtn:hover {{
    background-color: {BG_HOVER};
}}

/* ---------- Cards ---------- */
QFrame#Card {{
    background-color: {WHITE};
    border: 1px solid {CARD_BORDER};
    border-radius: 6px;
}}
QFrame#SubCard {{
    background-color: {BG_LIGHT};
    border: 1px solid {CARD_BORDER_MUTED};
    border-radius: 6px;
}}
QLabel#CardTitle {{
    color: {TEXT_PRIMARY};
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.4px;
}}
QLabel#CardSubtitle {{
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.6px;
}}
QLabel#Kicker {{
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.4px;
}}
QLabel#FieldLabel {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
    font-weight: 500;
}}
QLabel#FieldValue {{
    color: {TEXT_PRIMARY};
    font-size: 12.5px;
    font-weight: 600;
}}
QLabel#FieldValueMono {{
    color: {TEXT_PRIMARY};
    font-size: 12px;
    font-weight: 600;
    font-family: {MONO};
}}
QLabel#BigNumber {{
    color: {TEXT_PRIMARY};
    font-size: 26px;
    font-weight: 800;
}}
QLabel#MetricLabel {{
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.3px;
}}
QLabel#MetricSub {{
    color: {TEXT_MUTED};
    font-size: 10.5px;
    font-weight: 500;
}}
QLabel#Bullet {{
    color: {TEXT_BODY};
    font-size: 12.5px;
}}
QLabel#Body {{
    color: {TEXT_BODY};
    font-size: 12.5px;
}}
QLabel#Muted {{
    color: {TEXT_SECONDARY};
    font-size: 11.5px;
}}
QLabel#RiskBadge {{
    color: {RED};
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.2px;
}}
QLabel#RiskBadgeSmall {{
    color: {RED};
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 1px;
}}

/* ---------- Action buttons ---------- */
QPushButton#ActionBtn {{
    background-color: {WHITE};
    color: {TEXT_PRIMARY};
    border: 1px solid {CARD_BORDER};
    border-radius: 4px;
    padding: 9px 12px;
    font-size: 12px;
    font-weight: 600;
    text-align: left;
}}
QPushButton#ActionBtn:hover {{
    background-color: {BLUE_SOFT};
    border-color: {BLUE_LIGHT};
    color: {BLUE_DEEP};
}}
QPushButton#PrimaryBtn {{
    background-color: {NAVY};
    color: white;
    border: none;
    border-radius: 4px;
    padding: 9px 14px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
}}
QPushButton#PrimaryBtn:hover {{
    background-color: {NAVY_LIGHT};
}}
QPushButton#GhostBtn {{
    background-color: {WHITE};
    color: {TEXT_PRIMARY};
    border: 1px solid {CARD_BORDER};
    border-radius: 4px;
    padding: 7px 14px;
    font-size: 11px;
    font-weight: 600;
}}
QPushButton#GhostBtn:hover {{
    border-color: {BLUE_LIGHT};
    color: {BLUE_DEEP};
}}
QPushButton#TabBtn {{
    background: transparent;
    color: {TEXT_MUTED};
    border: none;
    padding: 6px 8px;
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0px;
}}
QPushButton#TabBtn:checked {{
    color: {TEXT_PRIMARY};
    border-bottom: 2px solid {BLUE};
}}
QPushButton#TabBtn:hover {{
    color: {TEXT_PRIMARY};
}}

/* ---------- Inputs ---------- */
QLineEdit#Search {{
    background-color: {WHITE};
    color: {TEXT_PRIMARY};
    border: 1px solid {CARD_BORDER};
    border-radius: 4px;
    padding: 7px 10px 7px 26px;
    font-size: 12px;
}}
QLineEdit#Search:focus {{
    border-color: {BLUE_LIGHT};
}}

/* ---------- Checkboxes ---------- */
QCheckBox {{
    color: {TEXT_BODY};
    font-size: 12px;
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {TEXT_MUTED};
    border-radius: 3px;
    background: white;
}}
QCheckBox::indicator:checked {{
    background: {BLUE};
    border-color: {BLUE};
    image: none;
}}

/* ---------- Tables ---------- */
QTableWidget {{
    background-color: {WHITE};
    border: none;
    gridline-color: transparent;
    font-size: 12px;
    color: {TEXT_BODY};
}}
QTableWidget::item {{
    padding: 6px 4px;
    border: none;
}}
QTableWidget::item:selected {{
    background-color: {BLUE_SOFT};
    color: {TEXT_PRIMARY};
}}
QHeaderView::section {{
    background-color: {WHITE};
    color: {TEXT_MUTED};
    border: none;
    border-bottom: 1px solid {CARD_BORDER_MUTED};
    padding: 6px 4px;
    font-weight: 700;
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}}

/* ---------- Lists ---------- */
QListWidget {{
    background-color: {WHITE};
    border: none;
    outline: none;
    font-size: 12px;
    color: {TEXT_BODY};
    font-family: {MONO};
}}
QListWidget::item {{
    padding: 8px 10px;
    border-bottom: 1px solid {CARD_BORDER_MUTED};
}}
QListWidget::item:selected {{
    background-color: {NAVY};
    color: {WHITE};
    border-radius: 4px;
}}
QListWidget::item:hover:!selected {{
    background-color: {BG_HOVER};
}}

/* ---------- Scrollbars ---------- */
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 4px 0;
}}
QScrollBar::handle:vertical {{
    background: {TEXT_FAINT};
    min-height: 24px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{
    background: {TEXT_MUTED};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    margin: 0 4px;
}}
QScrollBar::handle:horizontal {{
    background: {TEXT_FAINT};
    min-width: 24px;
    border-radius: 4px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ---------- Console (dark) ---------- */
QTextEdit#Console {{
    background-color: #0B121F;
    color: #B7C5D9;
    border: none;
    font-family: {MONO};
    font-size: 11.5px;
    padding: 8px 10px;
    selection-background-color: {BLUE_DEEP};
}}
QTextEdit#Disasm {{
    background-color: {WHITE};
    color: {TEXT_PRIMARY};
    border: none;
    font-family: {MONO};
    font-size: 12.5px;
    padding: 4px 6px;
    selection-background-color: {BLUE_SOFT};
}}
QTextEdit#Hex {{
    background-color: {WHITE};
    color: {TEXT_PRIMARY};
    border: none;
    font-family: {MONO};
    font-size: 12px;
    padding: 4px 6px;
    selection-background-color: {BLUE_SOFT};
}}
"""


# ============================================================================
# UTILITY: Pixel-perfect layout helpers
# ============================================================================

def hline(color=CARD_BORDER_MUTED):
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(f"background-color: {color}; border: none;")
    return f


def ico_label(text, size=14, color=TEXT_SECONDARY):
    """Simple unicode/emoji icon label."""
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {color}; font-size: {size}px; background: transparent;")
    return lbl


# ============================================================================
# CUSTOM PAINTED WIDGETS
# ============================================================================

class SkullLogo(QWidget):
    """Minimalist vector skull for the top-left brand mark."""

    def __init__(self, size=36, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # Optional override
        override = Path(__file__).with_name("erevos_logo.png") if "__file__" in globals() else None
        if override and override.exists():
            pix = QPixmap(str(override)).scaled(
                w, h,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            p.drawPixmap((w - pix.width()) // 2, (h - pix.height()) // 2, pix)
            return

        # --- painted skull ---
        cx, cy = w / 2, h / 2
        head_w = w * 0.82
        head_h = h * 0.78
        head_rect = QRectF(cx - head_w / 2, cy - head_h / 2 - 1, head_w, head_h)

        # Head
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("white"))
        path = QPainterPath()
        path.addRoundedRect(head_rect, head_w * 0.42, head_h * 0.42)
        # Jaw (lower rectangle)
        jaw_w = head_w * 0.55
        jaw_h = head_h * 0.22
        jaw_rect = QRectF(cx - jaw_w / 2, cy + head_h * 0.18, jaw_w, jaw_h)
        jaw_path = QPainterPath()
        jaw_path.addRoundedRect(jaw_rect, 2, 2)
        path = path.united(jaw_path)
        p.drawPath(path)

        # Eye sockets (Match Navy exactly so they blend into the TopBar)
        p.setBrush(QColor(NAVY))
        eye_w, eye_h = head_w * 0.22, head_h * 0.24
        lx = cx - head_w * 0.22 - eye_w / 2
        rx = cx + head_w * 0.22 - eye_w / 2
        ey = cy - head_h * 0.10
        p.drawEllipse(QRectF(lx, ey, eye_w, eye_h))
        p.drawEllipse(QRectF(rx, ey, eye_w, eye_h))

        # Nose (small triangle)
        nose = QPolygonF([
            QPointF(cx, cy + head_h * 0.05),
            QPointF(cx - head_w * 0.05, cy + head_h * 0.18),
            QPointF(cx + head_w * 0.05, cy + head_h * 0.18),
        ])
        p.drawPolygon(nose)

        # Teeth gaps
        p.setPen(QPen(QColor(NAVY), max(1, int(h * 0.03))))
        tx0 = cx - jaw_w * 0.30
        tx1 = cx + jaw_w * 0.30
        ty0 = jaw_rect.top() + 2
        ty1 = jaw_rect.bottom() - 2
        for i in range(1, 4):
            x = tx0 + (tx1 - tx0) * i / 4
            p.drawLine(QPointF(x, ty0), QPointF(x, ty1))


class Tag(QLabel):
    """Colored pill/tag label."""

    def __init__(self, text, bg=TAG_MALWARE_BG, fg=TAG_MALWARE_FG, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(
            f"background-color: {bg}; color: {fg}; "
            f"border-radius: 4px; padding: 3px 10px; "
            f"font-size: 10.5px; font-weight: 700; letter-spacing: 0.4px; "
            f"border: 1px solid {fg}40;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


class Dot(QWidget):
    """Small colored dot indicator."""

    def __init__(self, color=BLUE, size=8, parent=None):
        super().__init__(parent)
        self.color = color
        self.setFixedSize(size, size)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(self.color))
        p.drawEllipse(0, 0, self.width(), self.height())


class Card(QFrame):
    """Base card container with optional title."""

    def __init__(self, title=None, kicker=None, parent=None, padding=(18, 16, 18, 16)):
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(*padding)
        self._layout.setSpacing(12)

        if title is not None:
            header = QHBoxLayout()
            header.setSpacing(8)
            t = QLabel(title.upper())
            t.setObjectName("CardTitle")
            header.addWidget(t)
            if kicker:
                k = QLabel(kicker)
                k.setObjectName("CardSubtitle")
                header.addWidget(k)
            header.addStretch()
            self._layout.addLayout(header)

    def addLayout(self, layout):
        self._layout.addLayout(layout)

    def addWidget(self, widget, *args, **kwargs):
        self._layout.addWidget(widget, *args, **kwargs)

    def addStretch(self, *args):
        self._layout.addStretch(*args)

    def addSpacing(self, n):
        self._layout.addSpacing(n)

    def layout(self):
        return self._layout


class RiskGauge(QWidget):
    """Semicircular risk gauge with needle and tick marks."""

    def __init__(self, value=85, label="HIGH RISK",
                 size=200, compact=False, parent=None):
        super().__init__(parent)
        self.value = max(0, min(100, value))
        self.label = label
        self.compact = compact
        self.setMinimumSize(size, int(size * 0.72) if not compact else int(size * 0.82))

    def setValue(self, v):
        self.value = max(0, min(100, v))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        margin = 14 if not self.compact else 10
        diameter = min(w - 2 * margin, (h - 30) * 2)
        diameter = max(60, diameter)
        cx = w / 2
        cy = margin + diameter / 2
        r_outer = diameter / 2
        thickness = max(10, diameter * 0.11)
        arc_rect = QRectF(cx - r_outer + thickness / 2,
                          cy - r_outer + thickness / 2,
                          diameter - thickness,
                          diameter - thickness)

        # Background arc
        pen = QPen(QColor("#E6EAF2"), thickness)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        p.setPen(pen)
        p.drawArc(arc_rect, 0, 180 * 16)

        # Color segments (green -> red), on top of bg
        segments = [
            (144, 36, QColor(GREEN)),
            (108, 36, QColor(LIME)),
            (72,  36, QColor(AMBER)),
            (36,  36, QColor(ORANGE)),
            (0,   36, QColor(RED)),
        ]
        for start, span, color in segments:
            pen = QPen(color, thickness)
            pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            p.setPen(pen)
            p.drawArc(arc_rect, int(start * 16), int(span * 16))

        # Inner white circle to give a two-tone arc feeling
        inner_thickness = thickness * 0.55
        inner_rect = QRectF(arc_rect.x() + (thickness - inner_thickness) / 2,
                            arc_rect.y() + (thickness - inner_thickness) / 2,
                            arc_rect.width() - (thickness - inner_thickness),
                            arc_rect.height() - (thickness - inner_thickness))

        # Ticks
        p.setPen(QPen(QColor("#CBD5E1"), 1))
        for i in range(0, 11):
            ang = math.radians(180 - 18 * i)
            r1 = r_outer - thickness - 2
            r2 = r1 - 4
            x1 = cx + r1 * math.cos(ang)
            y1 = cy - r1 * math.sin(ang)
            x2 = cx + r2 * math.cos(ang)
            y2 = cy - r2 * math.sin(ang)
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Needle
        needle_deg = 180 - (self.value / 100.0) * 180
        ang = math.radians(needle_deg)
        needle_len = r_outer - thickness - 8
        ex = cx + needle_len * math.cos(ang)
        ey = cy - needle_len * math.sin(ang)

        # needle as tapered triangle
        # base perpendicular to angle
        perp = ang + math.pi / 2
        base_w = thickness * 0.22
        bx1 = cx + base_w * math.cos(perp)
        by1 = cy - base_w * math.sin(perp)
        bx2 = cx - base_w * math.cos(perp)
        by2 = cy + base_w * math.sin(perp)

        needle = QPolygonF([
            QPointF(bx1, by1),
            QPointF(bx2, by2),
            QPointF(ex, ey),
        ])
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(TEXT_PRIMARY))
        p.drawPolygon(needle)

        # Hub
        hub_r = thickness * 0.32
        p.setBrush(QColor("white"))
        p.setPen(QPen(QColor(TEXT_PRIMARY), 2))
        p.drawEllipse(QPointF(cx, cy), hub_r, hub_r)

        # Value text
        font_big = QFont(SANS.split(",")[0].strip().strip("'"), 26 if self.compact else 34)
        font_big.setBold(True)
        p.setFont(font_big)
        p.setPen(QColor(TEXT_PRIMARY))
        fm = QFontMetrics(font_big)
        val_text = f"{self.value}"
        vx = cx - fm.horizontalAdvance(val_text) / 2 - 10
        vy_top = cy + (4 if self.compact else 6)
        p.drawText(QRectF(vx, vy_top, fm.horizontalAdvance(val_text) + 4,
                          fm.height()),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                   val_text)

        # /100 suffix
        font_small = QFont(SANS.split(",")[0].strip().strip("'"),
                           11 if self.compact else 13)
        p.setFont(font_small)
        p.setPen(QColor(TEXT_MUTED))
        fm2 = QFontMetrics(font_small)
        suffix = "/ 100"
        p.drawText(QRectF(vx + fm.horizontalAdvance(val_text) + 6,
                          vy_top + (fm.ascent() - fm2.ascent()) + 4,
                          60, fm2.height()),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                   suffix)

        # Risk label under value
        font_lbl = QFont(SANS.split(",")[0].strip().strip("'"),
                         9 if self.compact else 10)
        font_lbl.setBold(True)
        p.setFont(font_lbl)
        p.setPen(QColor(RED))
        p.drawText(QRectF(0, vy_top + fm.height() + 2, w, 16),
                   Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                   self.label.upper())


class CallGraphWidget(QWidget):
    """Abstract network graph with a central skull node and radial neighbors."""

    def __init__(self, parent=None, node_count=40, seed=7):
        super().__init__(parent)
        self.setMinimumHeight(210)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._nodes, self._edges = self._gen(node_count, seed)

    def _gen(self, n, seed):
        rnd = random.Random(seed)
        nodes = []
        # Central skull node at (0.5, 0.5)
        nodes.append({"x": 0.5, "y": 0.5, "r": 18, "kind": "skull"})

        # Ring 1 — close neighbors
        ring1 = 8
        for i in range(ring1):
            a = 2 * math.pi * i / ring1 + rnd.uniform(-0.1, 0.1)
            r = 0.20 + rnd.uniform(-0.02, 0.02)
            nodes.append({
                "x": 0.5 + r * math.cos(a),
                "y": 0.5 + r * math.sin(a) * 0.85,
                "r": rnd.uniform(7, 11),
                "kind": "primary",
            })
        # Ring 2 — outer
        ring2 = n - ring1 - 1
        for i in range(ring2):
            a = 2 * math.pi * rnd.random()
            r = 0.36 + rnd.uniform(-0.06, 0.08)
            nodes.append({
                "x": 0.5 + r * math.cos(a),
                "y": 0.5 + r * math.sin(a) * 0.82,
                "r": rnd.uniform(4.5, 8),
                "kind": "secondary",
            })

        # Edges: connect central to ring1, ring1 to closest ring2
        edges = []
        for i in range(1, ring1 + 1):
            edges.append((0, i))
        # Some ring1 -> ring1 connections
        for i in range(1, ring1 + 1):
            if rnd.random() < 0.35:
                j = 1 + ((i + rnd.randint(1, 2)) % ring1)
                edges.append((i, j))
        # Each ring2 connects to a nearby ring1 or center
        for k in range(ring1 + 1, len(nodes)):
            # find nearest among first ring
            nx, ny = nodes[k]["x"], nodes[k]["y"]
            best, best_d = 0, 9
            for i in range(1, ring1 + 1):
                d = (nodes[i]["x"] - nx) ** 2 + (nodes[i]["y"] - ny) ** 2
                if d < best_d:
                    best_d = d; best = i
            edges.append((best, k))
            # Occasional extra edges
            if rnd.random() < 0.12:
                other = rnd.randint(ring1 + 1, len(nodes) - 1)
                if other != k:
                    edges.append((k, other))
        return nodes, edges

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # Convert normalized coords to pixels
        def xy(n):
            return QPointF(n["x"] * w, n["y"] * h)

        # edges
        pen = QPen(QColor("#CBD5E1"), 1.1)
        p.setPen(pen)
        for a, b in self._edges:
            p.drawLine(xy(self._nodes[a]), xy(self._nodes[b]))

        # nodes (back-to-front so skull is on top)
        for n in self._nodes[1:]:
            pt = xy(n)
            if n["kind"] == "primary":
                color = QColor(BLUE)
                ring_color = QColor("#BFDBFE")
            else:
                color = QColor("#4B6CB7")
                ring_color = QColor("#DBEAFE")
            # outer halo
            p.setBrush(ring_color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(pt, n["r"] + 2.6, n["r"] + 2.6)
            # inner
            p.setBrush(color)
            p.drawEllipse(pt, n["r"], n["r"])

        # central skull node
        center = xy(self._nodes[0])
        # halo
        grad = QRadialGradient(center, 28)
        grad.setColorAt(0.0, QColor(30, 58, 138, 200))
        grad.setColorAt(1.0, QColor(30, 58, 138, 0))
        p.setBrush(QBrush(grad))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(center, 26, 26)
        # dark disc
        p.setBrush(QColor(NAVY_DEEP))
        p.drawEllipse(center, 16, 16)
        
        # Simple skull (Fixed float/QRectF)
        p.setBrush(QColor("white"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QRectF(center.x() - 8, center.y() - 10, 16, 16))
        p.drawRect(QRectF(center.x() - 5, center.y() + 2, 10, 6))
        
        p.setBrush(QColor(NAVY_DEEP))
        p.drawEllipse(QRectF(center.x() - 4, center.y() - 4, 3, 3))
        p.drawEllipse(QRectF(center.x() + 1, center.y() - 4, 3, 3))


class CFGGraphWidget(QWidget):
    """Hierarchical control flow graph painter.

    nodes: list of dicts { id, label, level, x, y (computed), color }
    edges: list of (src, dst) tuples
    """

    def __init__(self, nodes=None, edges=None, parent=None,
                 compact=False, show_labels=True):
        super().__init__(parent)
        self.compact = compact
        self.show_labels = show_labels
        self.setMinimumHeight(140 if compact else 320)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        if nodes is None:
            nodes = [
                {"id": "BB 0", "label": "0x140008EF8", "level": 0, "col": 0.5,
                 "kind": "entry"},
                {"id": "BB 1", "label": "0x140008F23", "level": 1, "col": 0.13,
                 "kind": "block"},
                {"id": "BB 2", "label": "0x14000880C", "level": 1, "col": 0.38,
                 "kind": "block"},
                {"id": "BB 3", "label": "0x140008D3C", "level": 1, "col": 0.62,
                 "kind": "block"},
                {"id": "BB 4", "label": "0x140008E6C", "level": 1, "col": 0.87,
                 "kind": "exit"},
            ]
        if edges is None:
            edges = [(0, 1), (0, 2), (0, 3), (0, 4)]
        self.nodes = nodes
        self.edges = edges

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # grid dots for a "canvas" feel
        p.fillRect(self.rect(), QColor(WHITE))
        dot_color = QColor("#E8EDF4")
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(dot_color)
        step = 20
        for gx in range(step, w, step):
            for gy in range(step, h, step):
                p.drawEllipse(QPointF(gx, gy), 1.0, 1.0)

        levels = max(n["level"] for n in self.nodes) + 1
        top_pad = 24 if self.compact else 34
        bot_pad = 24 if self.compact else 36
        node_w = 92 if self.compact else 118
        node_h = 40 if self.compact else 54
        usable_h = h - top_pad - bot_pad
        if levels > 1:
            row_gap = usable_h / (levels - 1) if levels > 1 else 0
        else:
            row_gap = 0

        # compute positions
        positions = {}
        for idx, n in enumerate(self.nodes):
            x = n["col"] * w
            if levels == 1:
                y = top_pad + usable_h / 2
            else:
                y = top_pad + n["level"] * row_gap
            positions[idx] = (x, y)

        # draw edges first
        edge_pen = QPen(QColor("#94A3B8"), 1.6)
        edge_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(edge_pen)
        for a, b in self.edges:
            (x1, y1) = positions[a]
            (x2, y2) = positions[b]
            # connect bottom of a to top of b
            sx, sy = x1, y1 + node_h / 2
            tx, ty = x2, y2 - node_h / 2
            # curved path
            path = QPainterPath()
            path.moveTo(sx, sy)
            mid = (sy + ty) / 2
            path.cubicTo(sx, mid, tx, mid, tx, ty)
            p.drawPath(path)
            # arrow head
            p.setBrush(QColor("#94A3B8"))
            arrow = QPolygonF([
                QPointF(tx, ty + 1),
                QPointF(tx - 4, ty - 6),
                QPointF(tx + 4, ty - 6),
            ])
            p.setPen(Qt.PenStyle.NoPen)
            p.drawPolygon(arrow)
            p.setPen(edge_pen)

        # draw nodes
        for idx, n in enumerate(self.nodes):
            x, y = positions[idx]
            rect = QRectF(x - node_w / 2, y - node_h / 2, node_w, node_h)
            path = QPainterPath()
            
            # Using 4px for a slightly rounded, yet squared off appearance
            path.addRoundedRect(rect, 4, 4)
            
            if n.get("kind") == "entry":
                fill = QColor(BLUE_DEEP); fg = QColor("white"); border = QColor(BLUE_DEEP)
            elif n.get("kind") == "exit":
                fill = QColor(RED_SOFT); fg = QColor(RED); border = QColor("#FCA5A5")
            else:
                fill = QColor(WHITE); fg = QColor(TEXT_PRIMARY); border = QColor("#B9C4D4")

            # Fill + border
            p.setBrush(fill)
            p.setPen(QPen(border, 1.2))
            p.drawPath(path)

            if self.show_labels:
                # Title
                title_font = QFont(SANS.split(",")[0].strip().strip("'"),
                                   10 if self.compact else 11)
                title_font.setBold(True)
                p.setFont(title_font)
                p.setPen(fg)
                p.drawText(rect.adjusted(0, 4, 0, 0),
                           Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                           n["id"])
                # Address
                addr_font = QFont("Menlo", 8 if self.compact else 9)
                p.setFont(addr_font)
                p.setPen(fg if n.get("kind") == "entry" else QColor(TEXT_MUTED))
                p.drawText(rect.adjusted(0, 0, 0, -4),
                           Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                           n["label"])


class MiniMap(QWidget):
    """Tiny abstract minimap for CFG view."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(120)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), QColor(BG_LIGHT))
        # scatter small blocks
        rng = random.Random(12)
        for _ in range(22):
            x = rng.uniform(6, w - 22)
            y = rng.uniform(6, h - 16)
            bw = rng.uniform(10, 20)
            bh = rng.uniform(6, 12)
            path = QPainterPath()
            path.addRoundedRect(QRectF(x, y, bw, bh), 2, 2)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor("#CBD5E1"))
            p.drawPath(path)
        # viewport rectangle
        vp = QRectF(w * 0.18, h * 0.22, w * 0.38, h * 0.5)
        p.setBrush(QColor(59, 130, 246, 35))
        p.setPen(QPen(QColor(BLUE), 1.4))
        p.drawRect(vp)


# ============================================================================
# DISASSEMBLY / HEX SOURCES (mock data + HTML formatting)
# ============================================================================

# Disassembly mock listing used across pages
DISASM_LINES = [
    ("0x140008EF8", "call", "0x1400055C4", "",           False),
    ("0x140008EFD", "mov",  "ebx, eax",    "",           False),
    ("0x140008EFF", "call", "0x1400011E0", "",           False),
    ("0x140008F04", "mov",  "r8d, rax",    "",           False),
    ("0x140008F07", "mov",  "r9d, ebx",    "",           False),
    ("0x140008F0A", "lea",  "rcx, [rip + 0x3e9e]", "",   False),
    ("0x140008F13", "mov",  "eax, 0x14010000",     "",   False),
    ("0x140008F18", "mov",  "ebx, eax",    "",           False),
    ("0x140008F1A", "call", "0x140097000",  "",          False),
    ("0x140008F1F", "test", "al, al",      "",           False),
    ("0x140008F21", "jne",  "0x1400088E05", "",          True),
    ("0x140008F25", "mov",  "ecx, ebx",    "",           False),
    ("0x140008F25", "call", "0x140012220",  "",          False),
    ("0x140008F2A", "test", "dil, dil",    "",           False),
    ("0x140008F2D", "jne",  "0x1400099A0F", "",          False),
    ("0x140008F33", "call", "0x1400121CC",  "",          False),
    ("0x140008F38", "xor",  "edx, edx",    "",           False),
    ("0x140008F3A", "mov",  "cl, 1",       "",           False),
    ("0x140008F3C", "call", "0x14000938C",  "",          False),
    ("0x140008F41", "mov",  "eax, ebx",    "",           False),
    ("0x140008F43", "jmp",  "0x140008EED",  "",          False),
    ("0x140008F48", "mov",  "ebx, eax",    "",           False),
    ("0x140008F4A", "call", "0x140097000",  "",          False),
]


def _hl(text, color):
    return f'<span style="color:{color};">{text}</span>'


def disasm_html(current_line=10):
    """Return HTML that renders a syntax-hinted disassembly listing."""
    lines_html = []
    for i, (addr, mnem, op, _, _) in enumerate(DISASM_LINES):
        # Choose colors by mnemonic category
        if mnem in ("call",):
            mnem_c = "#0891B2"
            op_c = "#B91C1C" if op.startswith("0x") else TEXT_PRIMARY
        elif mnem in ("jne", "jmp", "je", "jz", "jnz"):
            mnem_c = "#7C3AED"
            op_c = "#B91C1C"
        elif mnem in ("mov", "lea"):
            mnem_c = "#0F766E"
            op_c = TEXT_PRIMARY
        elif mnem in ("xor", "test", "and", "or"):
            mnem_c = "#9333EA"
            op_c = TEXT_PRIMARY
        else:
            mnem_c = TEXT_PRIMARY
            op_c = TEXT_PRIMARY

        # Current line marker
        prefix = "&#9654; " if i == current_line else "&nbsp;&nbsp;"
        bg = ' style="background-color:#FEF3C7;"' if i == current_line else ""

        html_line = (
            f'<div{bg}>'
            f'<span style="color:#94A3B8;">{prefix}</span>'
            f'{_hl(addr, "#2563EB")}'
            f'<span style="color:#94A3B8;">: &nbsp;&nbsp;</span>'
            f'{_hl(mnem.ljust(6), mnem_c)}'
            f'&nbsp;&nbsp;&nbsp;'
            f'{_hl(op, op_c)}'
            f'</div>'
        )
        lines_html.append(html_line)

    body = "".join(lines_html)
    return (
        f'<div style="font-family:{MONO}; font-size:12.5px; line-height:170%;">'
        f'{body}'
        f'</div>'
    )


# Hex dump mock data
HEX_ROWS = [
    ("140008EF0", "55 48 8B EC 48 83 EC 20 48 8B 4C 24 30 48 8B 15",  "UH..H.. H.L$0H.."),
    ("140008F00", "01 00 FF 15 5C 48 00 00 48 8B C8 74 0C 48 8B 15",  "....\\H..H..t.H.."),
    ("140008F10", "6E 4F 1A 00 48 8D 15 6B 74 1E 68 48 8D 15 6B 74",  "nO..H..kt.hH..kt"),
    ("140008F20", "00 00 00 00 2B 2F 00 00 00 E8 9A 00 00 48 8B C3",  "....+/.......H.."),
    ("140008F30", "48 8B 15 70 4F 1A 00 48 8B 15 00 33 1E 68 48 8B",  "H..pO..H...3.hH."),
    ("140008F40", "48 8B 15 6C EC 1A 00 48 8B 15 6C 1E 00 68 48 8B",  "H..l...H..l..hH."),
    ("140008F50", "48 8B 15 FE EC 1A 00 48 8B 15 1C EA 00 68 48 8B",  "H......H.....hH."),
    ("140008F60", "F0 48 8B FB 48 8B CC 48 8D 15 CF E8 00 68 48 8B",  ".H..H..H.....hH."),
]


def hex_html(highlight_rva=None, highlight_cols=None):
    """Render the hex dump as HTML with header row and optional highlights."""
    highlight_cols = highlight_cols or set()
    rows_html = []
    # header
    cols = "&nbsp;".join(f'<span style="color:#94A3B8;">{x:02X}</span>'
                         for x in range(16))
    rows_html.append(
        f'<div style="color:#94A3B8; font-weight:700; padding:4px 0;">'
        f'<span style="display:inline-block;width:96px;">RVA</span>'
        f'<span>{cols}</span>'
        f'<span style="float:right;padding-right:8px;">ASCII</span></div>'
    )
    for rva, hexpart, ascii_part in HEX_ROWS:
        bg = ""
        row_style = ""
        if highlight_rva and highlight_rva in rva:
            bg = "background-color:#FFFBEB;"
            row_style = f' style="{bg}"'
        bytes_list = hexpart.split(" ")
        byte_spans = []
        for idx, b in enumerate(bytes_list):
            style = ""
            if (rva, idx) in highlight_cols:
                style = 'background-color:#CFFAFE; color:#0E7490; font-weight:700;'
            elif idx == 0:
                style = ""
            byte_spans.append(f'<span style="{style}">{b}</span>')
        bytes_html = "&nbsp;".join(byte_spans)
        rows_html.append(
            f'<div{row_style}>'
            f'<span style="display:inline-block;width:96px;color:#2563EB;">{rva}</span>'
            f'<span>{bytes_html}</span>'
            f'<span style="float:right;color:#475569;padding-right:8px;">'
            f'{ascii_part.replace(" ", "&nbsp;").replace("<","&lt;")}</span>'
            f'</div>'
        )
    body = "".join(rows_html)
    return (f'<div style="font-family:{MONO}; font-size:12px; '
            f'line-height:180%;">{body}</div>')


# ============================================================================
# TOP NAV BAR
# ============================================================================

# NOTE: Changed from QWidget to QFrame so the stylesheet background renders!
class TopBar(QFrame):

    navChanged = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("TopBar")
        self.setFixedHeight(68)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(22, 10, 22, 10)
        outer.setSpacing(16)

        # Brand
        brand_box = QHBoxLayout()
        brand_box.setSpacing(12)
        self.logo = SkullLogo(36)
        brand_vbox = QVBoxLayout()
        brand_vbox.setSpacing(0)
        brand_vbox.setContentsMargins(0, 0, 0, 0)
        name = QLabel("EREVOS")
        name.setObjectName("Brand")
        sub = QLabel("STATIC PE DISASSEMBLER")
        sub.setObjectName("BrandSub")
        brand_vbox.addWidget(name)
        brand_vbox.addWidget(sub)
        brand_box.addWidget(self.logo)
        brand_box.addLayout(brand_vbox)
        outer.addLayout(brand_box)

        outer.addSpacing(30)

        # Nav tabs
        self.buttons = []
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        # Measure each label at the bold/checked weight so the button
        # reserves enough width and doesn't clip when state toggles.
        bold_font = QFont()
        bold_font.setPointSize(10)
        bold_font.setWeight(QFont.Weight.DemiBold)
        fm = QFontMetrics(bold_font)
        for i, name in enumerate(["Dashboard", "Erevos View",
                                  "Analysis", "Hex", "CFG"]):
            b = QPushButton(name)
            b.setObjectName("NavBtn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            # Text width at bold + 40px for 20px padding on each side
            text_w = fm.horizontalAdvance(name)
            b.setMinimumWidth(text_w + 40)
            if i == 0:
                b.setChecked(True)
            self.group.addButton(b, i)
            self.buttons.append(b)
            outer.addWidget(b)
        self.group.idClicked.connect(self.navChanged.emit)

        outer.addStretch()

        # Report button
        self.report_btn = QPushButton("⚑  GENERATE\nFORENSIC REPORT")
        self.report_btn.setObjectName("ReportBtn")
        self.report_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.report_btn.setMinimumHeight(44)
        self.report_btn.setMinimumWidth(170)
        outer.addWidget(self.report_btn)

    def setIndex(self, idx):
        if 0 <= idx < len(self.buttons):
            self.buttons[idx].setChecked(True)


# ============================================================================
# DASHBOARD PAGE
# ============================================================================

def kv_row(label, value, mono=False):
    row = QHBoxLayout()
    row.setSpacing(8)
    l = QLabel(label)
    l.setObjectName("FieldLabel")
    l.setFixedWidth(108)
    v = QLabel(value)
    v.setObjectName("FieldValueMono" if mono else "FieldValue")
    v.setWordWrap(True)
    row.addWidget(l)
    row.addWidget(v, 1)
    return row


def bullet_row(text, color=BLUE):
    row = QHBoxLayout()
    row.setSpacing(10)
    row.setContentsMargins(0, 0, 0, 0)
    d = Dot(color=color, size=6)
    d.setFixedSize(6, 6)
    wrapper = QVBoxLayout()
    wrapper.setContentsMargins(0, 7, 0, 0)
    wrapper.addWidget(d)
    row.addLayout(wrapper)
    lbl = QLabel(text)
    lbl.setObjectName("Bullet")
    row.addWidget(lbl, 1)
    return row


class ConfidenceRow(QWidget):
    """Icon + name + confidence chip."""

    def __init__(self, icon, name, confidence, parent=None):
        super().__init__(parent)
        lvl = {"High": (GREEN, GREEN_SOFT),
               "Medium": (AMBER, "#FEF3C7"),
               "Low": (TEXT_SECONDARY, BG_LIGHT)}.get(confidence, (BLUE, BLUE_SOFT))
        fg, bg = lvl
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(10)

        ic = QLabel(icon)
        ic.setFixedSize(24, 24)
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic.setStyleSheet(
            f"background-color:{BLUE_SOFT}; color:{BLUE_DEEP}; "
            f"border-radius:5px; font-size:12px; font-weight:600;")
        h.addWidget(ic)

        nm = QLabel(name)
        nm.setObjectName("Body")
        nm.setStyleSheet("font-weight:600;")
        h.addWidget(nm, 1)

        chip = QLabel(f"{confidence} Confidence")
        chip.setStyleSheet(
            f"color:{fg}; background-color:{bg}; "
            f"border-radius:4px; padding:3px 10px; "
            f"font-size:10.5px; font-weight:700;")
        h.addWidget(chip)


class MetricTile(Card):

    def __init__(self, label, value, subtitle, parent=None):
        super().__init__(parent=parent, padding=(18, 16, 18, 16))
        self._layout.setSpacing(4)
        lbl = QLabel(label.upper())
        lbl.setObjectName("MetricLabel")
        self.addWidget(lbl)
        self.addSpacing(4)
        v = QLabel(value)
        v.setObjectName("BigNumber")
        self.addWidget(v)
        sub = QLabel(subtitle)
        sub.setObjectName("MetricSub")
        self.addWidget(sub)


class DashboardPage(QScrollArea):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        root = QWidget()
        root.setObjectName("PageRoot")
        self.setWidget(root)

        outer = QVBoxLayout(root)
        outer.setContentsMargins(22, 18, 22, 22)
        outer.setSpacing(16)

        # ---- Row 1: File Info | Risk Score | Classification | Quick Actions
        row1 = QGridLayout()
        row1.setSpacing(16)
        row1.setColumnStretch(0, 4)
        row1.setColumnStretch(1, 3)
        row1.setColumnStretch(2, 3)
        row1.setColumnStretch(3, 3)
        row1.addWidget(self._file_info_card(), 0, 0)
        row1.addWidget(self._risk_score_card(), 0, 1)
        row1.addWidget(self._classification_card(), 0, 2)
        row1.addWidget(self._quick_actions_card(), 0, 3)
        outer.addLayout(row1)

        # ---- Row 2: metric tiles ----
        row2 = QHBoxLayout()
        row2.setSpacing(16)
        for label, value, sub in [
            ("Functions", "3,124", "Total Discovered"),
            ("Strings", "1,842", "Total Discovered"),
            ("Imports (APIs)", "512", "Total Imported"),
            ("Xrefs", "2,781", "Total References"),
            ("Sections", "8", "Total Sections"),
        ]:
            row2.addWidget(MetricTile(label, value, sub))
        outer.addLayout(row2)

        # ---- Row 3: call graph + behavior/threat ----
        row3 = QHBoxLayout()
        row3.setSpacing(16)
        row3.addWidget(self._call_graph_card(), 5)

        right = QHBoxLayout()
        right.setSpacing(16)
        right.addWidget(self._behavior_card(), 1)
        right.addWidget(self._threat_card(), 1)
        right_wrap = QWidget()
        right_wrap.setLayout(right)
        row3.addWidget(right_wrap, 6)
        outer.addLayout(row3)

        # ---- Row 4: recent activity + key functions ----
        row4 = QHBoxLayout()
        row4.setSpacing(16)
        row4.addWidget(self._recent_activity_card(), 1)
        row4.addWidget(self._key_functions_card(), 1)
        outer.addLayout(row4)

        outer.addStretch()

    # ----------- individual cards -----------

    def _file_info_card(self):
        c = Card(title="File Information")
        rows = [
            ("File Name",   "AnonSurf.exe", False),
            ("File Size",   "1.28 MB (1,344,656 bytes)", False),
            ("Architecture","x64", False),
            ("Image Base",  "0x140000000", True),
            ("Entry Point", "0x140008EF8", True),
            ("MD5",         "d41d8cd98f00b204e9800998ecf8427e", True),
            ("SHA256",      "3f784dde7c… 5776f9a7c1", True),
            ("Compile Time","2024-04-21 17:45:32 UTC", False),
            ("Subsystem",   "Windows GUI", False),
        ]
        for lbl, val, mono in rows:
            c.addLayout(kv_row(lbl, val, mono))

        # Tags row
        tag_title = QLabel("TAGS")
        tag_title.setObjectName("Kicker")
        c.addSpacing(2)
        c.addWidget(tag_title)

        tags_row = QHBoxLayout()
        tags_row.setSpacing(6)
        tags_row.addWidget(Tag("malware",    TAG_MALWARE_BG, TAG_MALWARE_FG))
        tags_row.addWidget(Tag("suspicious", TAG_SUS_BG,     TAG_SUS_FG))
        tags_row.addWidget(Tag("packed",     TAG_PACKED_BG,  TAG_PACKED_FG))
        tags_row.addStretch()
        c.addLayout(tags_row)
        c.addStretch()
        return c

    def _risk_score_card(self):
        c = Card(title="Risk Score")
        c._layout.setSpacing(4)
        c.addSpacing(2)
        gauge = RiskGauge(value=85, label="HIGH RISK", size=220)
        c.addWidget(gauge, 1)
        return c

    def _classification_card(self):
        c = Card(title="Classification")
        hdr = QLabel("High Risk")
        hdr.setStyleSheet(f"color:{RED}; font-size:18px; font-weight:800;")
        c.addWidget(hdr)
        c.addSpacing(4)

        key = QLabel("KEY INDICATORS")
        key.setObjectName("Kicker")
        c.addWidget(key)

        for label in ["Calls suspicious APIs", "Modifies memory",
                      "Potential persistence", "Network activity detected"]:
            c.addLayout(bullet_row(label, color=BLUE))
        c.addStretch()
        return c

    def _quick_actions_card(self):
        c = Card(title="Quick Actions")
        for icon, label in [
            ("◧", "Erevos View"),
            ("▥", "Analysis Workspace"),
            ("⋮⋮", "Hex View"),
            ("↬", "CFG Graph"),
            ("⇪", "Export Report"),
        ]:
            btn = QPushButton(f"  {icon}   {label}")
            btn.setObjectName("ActionBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setMinimumHeight(38)
            c.addWidget(btn)
        c.addStretch()
        return c

    def _call_graph_card(self):
        c = Card(title="Call Graph", kicker="(Top 50 Nodes)")
        graph = CallGraphWidget()
        c.addWidget(graph, 1)
        bottom = QHBoxLayout()
        vf = QPushButton("VIEW FULL GRAPH")
        vf.setObjectName("PrimaryBtn")
        vf.setMinimumHeight(32)
        vf.setCursor(Qt.CursorShape.PointingHandCursor)
        bottom.addWidget(vf)
        bottom.addStretch()
        c.addLayout(bottom)
        return c

    def _behavior_card(self):
        c = Card(title="Behavior Patterns")
        items = [
            ("🔒", "Persistence Mechanism", "High"),
            ("🌐", "Network Communication", "High"),
            ("▣",  "Process Injection",     "Medium"),
            ("◈",  "Anti-Analysis / Evasion", "High"),
        ]
        for icon, name, conf in items:
            c.addWidget(ConfidenceRow(icon, name, conf))
        btn = QPushButton("VIEW ALL PATTERNS")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(34)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        c.addSpacing(4)
        c.addWidget(btn)
        return c

    def _threat_card(self):
        c = Card(title="Threat Narrative", kicker="(Summary)")
        body = QLabel(
            "This executable exhibits behavior consistent with a potentially "
            "malicious downloader. It communicates with remote servers, "
            "attempts persistence via registry modifications, and performs "
            "process injection."
        )
        body.setObjectName("Body")
        body.setWordWrap(True)
        body.setStyleSheet(f"color:{TEXT_BODY}; font-size:12.5px; line-height:150%;")
        c.addWidget(body, 1)
        btn = QPushButton("VIEW FULL NARRATIVE")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(34)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        c.addWidget(btn)
        return c

    def _recent_activity_card(self):
        c = Card(title="Recent Activity")
        tbl = QTableWidget(4, 3)
        tbl.setHorizontalHeaderLabels(["TIME", "ACTIVITY", "DETAILS"])
        tbl.verticalHeader().setVisible(False)
        tbl.setShowGrid(False)
        tbl.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        tbl.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        rows = [
            ("10:42:11", "Analysis Completed", "3,124 functions, 1,842 strings, 512 imports"),
            ("10:41:59", "File Loaded",        "AnonSurf.exe (x64)"),
            ("10:41:55", "Report Generated",   "Forensic report saved successfully"),
            ("10:41:42", "Behavior Scan",      "4 patterns matched"),
        ]
        for r, (t, a, d) in enumerate(rows):
            tbl.setItem(r, 0, QTableWidgetItem(t))
            tbl.setItem(r, 1, QTableWidgetItem(a))
            tbl.setItem(r, 2, QTableWidgetItem(d))
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tbl.setMinimumHeight(180)
        c.addWidget(tbl, 1)
        return c

    def _key_functions_card(self):
        c = Card(title="Key Functions", kicker="(Top 5 by Risk)")
        tbl = QTableWidget(5, 4)
        tbl.setHorizontalHeaderLabels(
            ["ADDRESS", "FUNCTION NAME", "RISK SCORE", "INDICATORS"])
        tbl.verticalHeader().setVisible(False)
        tbl.setShowGrid(False)
        tbl.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        tbl.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        rows = [
            ("0x140008EF8", "entry_point",    "95", "Suspicious APIs, Network"),
            ("0x140012120", "load_config",    "90", "Registry, File System"),
            ("0x140013DF0", "check_security", "85", "Anti-Analysis, Obfuscation"),
            ("0x140015300", "sub_140015300",  "80", "Process Injection, Memory Write"),
            ("0x140017000", "init_routine",   "75", "Network, Persistence"),
        ]
        for r, (a, n, s, ind) in enumerate(rows):
            it_a = QTableWidgetItem(a)
            it_a.setForeground(QColor(BLUE))
            tbl.setItem(r, 0, it_a)
            it_n = QTableWidgetItem(n)
            f = it_n.font(); f.setFamily(MONO.split(",")[0].strip()); it_n.setFont(f)
            tbl.setItem(r, 1, it_n)
            it_s = QTableWidgetItem(s)
            it_s.setForeground(QColor(RED))
            f2 = it_s.font(); f2.setBold(True); it_s.setFont(f2)
            tbl.setItem(r, 2, it_s)
            tbl.setItem(r, 3, QTableWidgetItem(ind))
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tbl.setMinimumHeight(220)
        c.addWidget(tbl, 1)
        return c



# ============================================================================
# EREVOS VIEW PAGE — reverse engineering main interface
# ============================================================================

FUNCTIONS_LIST = [
    ("0x140008EF8", "entry_point", True),
    ("0x140008F10", "sub_140008F10", False),
    ("0x140008720", "sub_140008720", False),
    ("0x140012120", "load_config", False),
    ("0x1400016F00", "check_security", False),
    ("0x140009256D0", "sub_140009256D0", False),
    ("0x140015300", "suit_routine", False),
    ("0x140016B00", "sub_140016B00", False),
    ("0x1400162A0", "sub_1400162A0", False),
    ("0x1400172A0", "sub_1400172A0", False),
    ("0x14001A5F0", "on_event", False),
    ("0x14001B820", "sub_14001B820", False),
    ("0x14001C940", "resolve_import", False),
    ("0x14001D010", "sub_14001D010", False),
    ("0x14001E340", "sub_14001E340", False),
]


class FunctionListWidget(QListWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        for addr, name, starred in FUNCTIONS_LIST:
            text = f"  {addr}\n  {name}"
            item = QListWidgetItem(text)
            item.setSizeHint(QSize(200, 48))
            self.addItem(item)
        self.setCurrentRow(0)


def search_box(placeholder="Search..."):
    """Input with a small search icon rendered as a prefix label overlay."""
    wrap = QWidget()
    wrap.setObjectName("SearchWrap")
    wrap.setStyleSheet(f"background: transparent;")
    h = QHBoxLayout(wrap)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(0)

    container = QWidget()
    container.setStyleSheet(
        f"background-color:{BG_LIGHT}; border:1px solid {CARD_BORDER}; "
        f"border-radius:4px;")
    ch = QHBoxLayout(container)
    ch.setContentsMargins(10, 0, 10, 0)
    ch.setSpacing(6)
    icon = QLabel("⌕")
    icon.setStyleSheet(f"color:{TEXT_MUTED}; font-size:14px; background:transparent;")
    ch.addWidget(icon)
    edit = QLineEdit()
    edit.setPlaceholderText(placeholder)
    edit.setStyleSheet(
        f"background:transparent; border:none; color:{TEXT_PRIMARY}; "
        f"font-size:12px; padding:7px 2px;")
    ch.addWidget(edit, 1)

    h.addWidget(container)
    return wrap


def filter_checkbox(text):
    cb = QCheckBox(text)
    return cb


def api_semantic_row(title, subtitle):
    wrap = QVBoxLayout()
    wrap.setSpacing(1)
    t = QLabel(title)
    t.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:12.5px; font-weight:700;")
    s = QLabel(subtitle)
    s.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
    wrap.addWidget(t)
    wrap.addWidget(s)
    return wrap


class ErevosViewPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("PageRoot")
        outer = QHBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 22)
        outer.setSpacing(16)

        # --- Left: functions + filters ---
        left_col = QVBoxLayout()
        left_col.setSpacing(16)
        left_col.addWidget(self._functions_card(), 3)
        left_col.addWidget(self._filters_card(), 1)
        left_wrap = QWidget()
        left_wrap.setFixedWidth(260)
        left_wrap.setLayout(left_col)
        outer.addWidget(left_wrap)

        # --- Center: disassembly ---
        outer.addWidget(self._center_disasm_card(), 5)

        # --- Right: function intelligence + API semantics ---
        right_col = QVBoxLayout()
        right_col.setSpacing(16)
        right_col.addWidget(self._function_intel_card(), 3)
        right_col.addWidget(self._api_semantics_card(), 2)
        right_wrap = QWidget()
        right_wrap.setFixedWidth(340)
        right_wrap.setLayout(right_col)
        outer.addWidget(right_wrap)

    def _functions_card(self):
        c = Card(title="Functions")
        c._layout.setSpacing(10)
        c._layout.setContentsMargins(14, 14, 14, 14)
        c.addWidget(search_box("Search functions..."))
        c.addWidget(FunctionListWidget(), 1)
        return c

    def _filters_card(self):
        c = Card(title="Filters")
        c._layout.setContentsMargins(14, 14, 14, 14)
        c._layout.setSpacing(6)
        for t in ["Renamed", "Commented", "Bookmarked", "Suspicious API"]:
            c.addWidget(filter_checkbox(t))
        c.addSpacing(6)
        inb = QHBoxLayout()
        lbl = QLabel("Inbound ≥")
        lbl.setObjectName("FieldLabel")
        val = QLabel("0")
        val.setStyleSheet(
            f"background-color:{BG_LIGHT}; border:1px solid {CARD_BORDER}; "
            f"border-radius:4px; padding:2px 8px; color:{TEXT_PRIMARY}; "
            f"font-weight:600;")
        inb.addWidget(lbl)
        inb.addWidget(val)
        inb.addStretch()
        c.addLayout(inb)
        c.addSpacing(6)
        c.addWidget(search_box("Filter functions..."))
        return c

    def _center_disasm_card(self):
        c = Card(title=None, padding=(14, 14, 14, 12))
        # Header
        header = QHBoxLayout()
        header.setSpacing(8)
        title = QLabel("EREVOS VIEW")
        title.setObjectName("CardTitle")
        sep = QLabel("—")
        sep.setStyleSheet(f"color:{TEXT_MUTED};")
        fn = QLabel("entry_point @ ")
        fn.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:12px; font-weight:600;")
        addr = QLabel("0x140008EF8")
        addr.setStyleSheet(f"color:{BLUE}; font-size:12px; font-weight:700; "
                           f"font-family:{MONO};")
        header.addWidget(title)
        header.addWidget(sep)
        header.addWidget(fn)
        header.addWidget(addr)
        header.addStretch()
        c.addLayout(header)

        c.addWidget(hline())

        # Disassembly body
        self.disasm = QTextEdit()
        self.disasm.setObjectName("Disasm")
        self.disasm.setReadOnly(True)
        self.disasm.setHtml(disasm_html(current_line=10))
        c.addWidget(self.disasm, 1)

        # Footer action bar
        footer = QHBoxLayout()
        footer.setSpacing(8)
        for label in ["⮕  Go To", "★  Bookmark", "💬  Comment"]:
            btn = QPushButton(label)
            btn.setObjectName("GhostBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setMinimumHeight(30)
            footer.addWidget(btn)
        footer.addStretch()
        lineinfo = QLabel("Line 33 of 3,124")
        lineinfo.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
        footer.addWidget(lineinfo)
        gv = QLabel("◉ Graph View")
        gv.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11px;")
        footer.addWidget(gv)
        c.addLayout(footer)
        return c

    def _function_intel_card(self):
        c = Card(title="Function Intelligence")

        name = QLabel("entry_point")
        name.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:20px; font-weight:800;")
        c.addWidget(name)
        addr = QLabel("0x140008EF8")
        addr.setStyleSheet(f"color:{TEXT_MUTED}; font-family:{MONO}; font-size:12px;")
        c.addWidget(addr)

        # Mini gauge + risk label
        gauge_row = QHBoxLayout()
        gauge_row.setSpacing(10)
        info = QVBoxLayout()
        info.setSpacing(2)
        k = QLabel("Risk Score")
        k.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11.5px;")
        info.addWidget(k)
        big = QLabel("85")
        big.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:28px; font-weight:800;")
        small = QLabel("/ 100")
        small.setStyleSheet(f"color:{TEXT_MUTED}; font-size:12px;")
        row = QHBoxLayout()
        row.setSpacing(4)
        row.addWidget(big)
        row.addWidget(small)
        row.addStretch()
        info.addLayout(row)
        badge = QLabel("High Risk")
        badge.setStyleSheet(f"color:{RED}; font-size:11px; font-weight:700;")
        info.addWidget(badge)
        gauge_row.addLayout(info)
        gauge = RiskGauge(value=85, label="", compact=True, size=140)
        gauge.setMinimumWidth(130)
        gauge.setMaximumHeight(110)
        gauge_row.addWidget(gauge)
        c.addLayout(gauge_row)

        # Tabs
        tabs = QHBoxLayout()
        tabs.setSpacing(8)
        self.tab_group = QButtonGroup(self)
        tab_font = QFont()
        tab_font.setPointSize(9)
        tab_font.setWeight(QFont.Weight.Bold)
        tab_fm = QFontMetrics(tab_font)
        for i, name in enumerate(["SUMMARY", "BEHAVIOR", "API", "STRINGS"]):
            b = QPushButton(name)
            b.setObjectName("TabBtn")
            b.setCheckable(True)
            if i == 0: b.setChecked(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            # Width = text + 16px for padding on both sides
            b.setMinimumWidth(tab_fm.horizontalAdvance(name) + 16)
            tabs.addWidget(b)
            self.tab_group.addButton(b)
        tabs.addStretch()
        c.addLayout(tabs)
        c.addWidget(hline())

        # Key indicators
        k = QLabel("Key Indicators")
        k.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:12px; font-weight:700;")
        c.addWidget(k)
        for label in ["Calls suspicious APIs", "Modifies memory",
                      "Potential persistence", "Network activity"]:
            c.addLayout(bullet_row(label, color=BLUE))

        c.addSpacing(4)
        btn = QPushButton("VIEW FULL ANALYSIS")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(34)
        c.addWidget(btn)

        return c

    def _api_semantics_card(self):
        c = Card(title="API Semantics", kicker="(3)")
        items = [
            ("VirtualAlloc",  "Memory Allocation"),
            ("CreateThread",  "Thread Creation"),
            ("WinHttpOpen",   "Network Communication"),
        ]
        for title, sub in items:
            c.addLayout(api_semantic_row(title, sub))
        c.addStretch()
        return c


# ============================================================================
# ANALYSIS WORKSPACE PAGE — multi-panel
# ============================================================================

class AnalysisPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("PageRoot")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 22)
        outer.setSpacing(16)

        # Top region - two columns
        top = QHBoxLayout()
        top.setSpacing(16)

        # Left side: Disasm over CFG
        left = QVBoxLayout()
        left.setSpacing(16)
        left.addWidget(self._disasm_card(), 6)
        left.addWidget(self._cfg_preview_card(), 4)
        left_wrap = QWidget()
        left_wrap.setLayout(left)
        top.addWidget(left_wrap, 6)

        # Right side: function intelligence + strings + data flow
        right = QVBoxLayout()
        right.setSpacing(16)
        right.addWidget(self._function_intel_card())
        row = QHBoxLayout()
        row.setSpacing(16)
        row.addWidget(self._strings_card(), 1)
        row.addWidget(self._data_flow_card(), 1)
        right.addLayout(row)
        right_wrap = QWidget()
        right_wrap.setLayout(right)
        top.addWidget(right_wrap, 6)

        outer.addLayout(top, 1)

        # Console at bottom
        outer.addWidget(self._console_card(), 0)

    def _disasm_card(self):
        c = Card(title=None, padding=(16, 14, 16, 12))
        header = QHBoxLayout()
        h1 = QLabel("DISASSEMBLY (ASM)")
        h1.setObjectName("CardTitle")
        dash = QLabel("—")
        dash.setStyleSheet(f"color:{TEXT_MUTED};")
        fn = QLabel("entry_point @ ")
        fn.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:12px; font-weight:600;")
        addr = QLabel("0x140008EF8")
        addr.setStyleSheet(f"color:{BLUE}; font-size:12px; font-weight:700; "
                           f"font-family:{MONO};")
        header.addWidget(h1)
        header.addWidget(dash)
        header.addWidget(fn)
        header.addWidget(addr)
        header.addStretch()
        c.addLayout(header)
        c.addWidget(hline())

        te = QTextEdit()
        te.setObjectName("Disasm")
        te.setReadOnly(True)
        te.setHtml(disasm_html(current_line=8))
        c.addWidget(te, 1)
        return c

    def _cfg_preview_card(self):
        c = Card(title="CFG Graph", kicker="— entry_point",
                 padding=(16, 14, 16, 12))
        graph = CFGGraphWidget(compact=True)
        c.addWidget(graph, 1)
        return c

    def _function_intel_card(self):
        c = Card(title="Function Intelligence")

        top = QHBoxLayout()
        info = QVBoxLayout()
        info.setSpacing(2)
        name = QLabel("entry_point")
        name.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:20px; font-weight:800;")
        addr = QLabel("0x140008EF8")
        addr.setStyleSheet(f"color:{TEXT_MUTED}; font-family:{MONO}; font-size:12px;")
        info.addWidget(name)
        info.addWidget(addr)
        top.addLayout(info)

        right = QVBoxLayout()
        right.setSpacing(2)
        k = QLabel("Risk Score")
        k.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11.5px;")
        row = QHBoxLayout()
        big = QLabel("85")
        big.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:28px; font-weight:800;")
        small = QLabel("/ 100")
        small.setStyleSheet(f"color:{TEXT_MUTED}; font-size:12px;")
        row.addWidget(big); row.addWidget(small); row.addStretch()
        right.addWidget(k); right.addLayout(row)
        top.addLayout(right)

        gauge = RiskGauge(value=85, label="", compact=True, size=130)
        gauge.setMaximumHeight(100)
        gauge.setMinimumWidth(120)
        top.addWidget(gauge)
        c.addLayout(top)

        c.addWidget(hline())
        k2 = QLabel("Key Indicators")
        k2.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:12px; font-weight:700;")
        c.addWidget(k2)
        for label in ["Calls suspicious APIs", "Modifies memory",
                      "Potential persistence", "Network activity"]:
            c.addLayout(bullet_row(label, color=BLUE))

        btn = QPushButton("VIEW FULL ANALYSIS")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(34)
        c.addSpacing(4)
        c.addWidget(btn)
        return c

    def _strings_card(self):
        c = Card(title="Strings Referenced")
        items = [
            ("0x1401F3A0", "'C:\\Windows\\system32\\…'"),
            ("0x1401FA40", "http://malicious-domain.com"),
            ("0x1401F5E0", "/api/data/collect"),
            ("0x1401F570", "Mozilla/5.0 (Windows NT 10.0; …"),
            ("0x1401F5E0", "'Xor - Error: %d'"),
        ]
        for addr, val in items:
            row = QHBoxLayout()
            a = QLabel(addr)
            a.setStyleSheet(f"color:{BLUE}; font-family:{MONO}; font-size:11.5px;")
            v = QLabel(val)
            v.setStyleSheet(f"color:{TEXT_BODY}; font-family:{MONO}; font-size:11.5px;")
            v.setWordWrap(False)
            a.setFixedWidth(90)
            row.addWidget(a)
            row.addWidget(v, 1)
            c.addLayout(row)
        c.addSpacing(4)
        btn = QPushButton("VIEW ALL STRINGS")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(32)
        c.addWidget(btn)
        return c

    def _data_flow_card(self):
        c = Card(title="Data Flow Insights")
        note = QLabel("Heuristic Note: Estimated")
        note.setStyleSheet(f"color:{TEXT_PRIMARY}; font-weight:700; font-size:12px;")
        c.addWidget(note)
        for label, color in [
            ("API Argument Insights: 14", BLUE),
            ("Strings Flows: 8",          PURPLE),
            ("Memory Writes: 23",         AMBER),
            ("Network Endpoints: 2",      GREEN),
        ]:
            c.addLayout(bullet_row(label, color=color))
        c.addSpacing(4)
        btn = QPushButton("VIEW FULL DATA FLOW")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(32)
        c.addWidget(btn)
        return c

    def _console_card(self):
        wrap = QFrame()
        wrap.setObjectName("Card")
        wrap.setStyleSheet(
            f"QFrame#Card {{ background-color:#0B121F; "
            f"border:1px solid #18243A; border-radius:6px; }}"
        )
        v = QVBoxLayout(wrap)
        v.setContentsMargins(16, 12, 16, 12)
        v.setSpacing(6)

        hdr = QHBoxLayout()
        t = QLabel("CONSOLE LOG")
        t.setStyleSheet("color:#D8DEE9; font-size:11px; font-weight:700; "
                        "letter-spacing:1.4px;")
        hdr.addWidget(t)
        hdr.addStretch()
        clr = QPushButton("Clear Log")
        clr.setStyleSheet(
            f"QPushButton {{ background: transparent; color:{TEXT_MUTED}; "
            f"border:none; font-size:11px; }} "
            f"QPushButton:hover {{ color:white; }}")
        clr.setCursor(Qt.CursorShape.PointingHandCursor)
        hdr.addWidget(clr)
        v.addLayout(hdr)

        te = QTextEdit()
        te.setObjectName("Console")
        te.setReadOnly(True)
        te.setFixedHeight(110)
        te.setHtml(
            '<div style="font-family:'+MONO+'; font-size:11.5px; line-height:170%;">'
            '<span style="color:#6EE7B7;">● 10:41:59 &nbsp;&nbsp;</span>'
            '<span style="color:#CBD5E1;">File loaded successfully: AnonSurf.exe (x64)</span><br>'
            '<span style="color:#6EE7B7;">● 10:42:01 &nbsp;&nbsp;</span>'
            '<span style="color:#CBD5E1;">Analysis completed: 3,124 functions discovered</span><br>'
            '<span style="color:#6EE7B7;">● 10:42:05 &nbsp;&nbsp;</span>'
            '<span style="color:#CBD5E1;">CFG graph generated successfully</span><br>'
            '<span style="color:#6EE7B7;">● 10:42:11 &nbsp;&nbsp;</span>'
            '<span style="color:#CBD5E1;">Behavior analysis completed</span>'
            '</div>'
        )
        v.addWidget(te)
        return wrap



# ============================================================================
# HEX VIEW PAGE
# ============================================================================

SECTIONS = [
    (".text",   "0x0007F000", True),
    (".rdata",  "0x00012000", False),
    (".data",   "0x00004000", False),
    (".pdata",  "0x00006000", False),
    (".rsrc",   "0x00008000", False),
    (".reloc",  "0x00008000", False),
    (".tls",    "0x00001000", False),
    (".idata",  "0x00011000", False),
]


class HexViewPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("PageRoot")
        outer = QHBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 22)
        outer.setSpacing(16)

        # Left column: Sections, Options
        left = QVBoxLayout()
        left.setSpacing(16)
        left.addWidget(self._sections_card(), 3)
        left.addWidget(self._options_card(), 2)
        left_wrap = QWidget()
        left_wrap.setFixedWidth(230)
        left_wrap.setLayout(left)
        outer.addWidget(left_wrap)

        # Center: Hex dump
        center = QVBoxLayout()
        center.setSpacing(16)
        center.addWidget(self._hex_dump_card(), 3)
        # Three mini-panels below
        mini = QHBoxLayout()
        mini.setSpacing(16)
        mini.addWidget(self._strings_apis_card(), 1)
        mini.addWidget(self._imports_card(), 1)
        center.addLayout(mini)
        center_wrap = QWidget()
        center_wrap.setLayout(center)
        outer.addWidget(center_wrap, 5)

        # Right: Decoded View, Bookmarks
        right = QVBoxLayout()
        right.setSpacing(16)
        right.addWidget(self._decoded_card())
        right.addWidget(self._bookmarks_card())
        right_wrap = QWidget()
        right_wrap.setFixedWidth(320)
        right_wrap.setLayout(right)
        outer.addWidget(right_wrap)

    def _sections_card(self):
        c = Card(title="Sections")
        for name, offset, active in SECTIONS:
            row = QFrame()
            row.setStyleSheet(
                f"QFrame {{ background-color: "
                f"{'#EFF6FF' if active else 'transparent'}; "
                f"border-radius:6px; "
                f"border-left:{'3px solid ' + BLUE if active else '3px solid transparent'}; "
                f"}}"
            )
            h = QHBoxLayout(row)
            h.setContentsMargins(10, 6, 10, 6)
            n = QLabel(name)
            n.setStyleSheet(
                f"color:{BLUE_DEEP if active else TEXT_PRIMARY}; "
                f"font-family:{MONO}; font-size:12px; "
                f"font-weight:{'700' if active else '500'};")
            o = QLabel(offset)
            o.setStyleSheet(
                f"color:{TEXT_MUTED}; font-family:{MONO}; font-size:11.5px;")
            h.addWidget(n)
            h.addStretch()
            h.addWidget(o)
            c.addWidget(row)
        c.addStretch()
        return c

    def _options_card(self):
        c = Card(title="Hex Options")
        opts = [
            ("Show ASCII",        True),
            ("Highlight Strings", False),
            ("Highlight APIs",    True),
            ("Highlight Jumps",   False),
        ]
        for t, checked in opts:
            cb = QCheckBox(t)
            cb.setChecked(checked)
            c.addWidget(cb)
        c.addStretch()
        return c

    def _hex_dump_card(self):
        c = Card(title=None, padding=(16, 14, 16, 14))
        hdr = QHBoxLayout()
        t = QLabel("HEX DUMP — .text")
        t.setObjectName("CardTitle")
        hdr.addWidget(t)
        hdr.addStretch()
        c.addLayout(hdr)
        c.addWidget(hline())

        te = QTextEdit()
        te.setObjectName("Hex")
        te.setReadOnly(True)
        te.setHtml(hex_html(highlight_rva="140008F20",
                            highlight_cols={("140008F20", 4),
                                            ("140008F20", 5),
                                            ("140008F20", 12),
                                            ("140008F20", 13)}))
        c.addWidget(te, 1)
        return c

    def _strings_apis_card(self):
        c = Card(title="Strings (APIs)")
        rows = [
            ("http://malicious-domain.com", "ASCII"),
            ("/api/data/collect",           "ASCII"),
            ("Xor - Error: %d",             "ASCII"),
            ("User-Agent: Mozilla/5.0",     "ASCII"),
        ]
        for val, typ in rows:
            row = QHBoxLayout()
            v = QLabel(val)
            v.setStyleSheet(
                f"color:{TEXT_BODY}; font-family:{MONO}; font-size:11px;")
            t = QLabel(typ)
            t.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10.5px;")
            row.addWidget(v, 1)
            row.addWidget(t)
            c.addLayout(row)
        return c

    def _imports_card(self):
        c = Card(title="Imports (APIs)")
        rows = [
            ("0x14001100A", "VirtualAlloc",    "Kernel32.dll"),
            ("0x140011120", "CreateThread",    "Kernel32.dll"),
            ("0x140011010", "WinHttpOpen",     "WinHttp.dll"),
            ("0x1400102A0", "RegSetValueExW",  "Advapi32.dll"),
        ]
        for rva, name, dll in rows:
            row = QHBoxLayout()
            r = QLabel(rva)
            r.setStyleSheet(
                f"color:{BLUE}; font-family:{MONO}; font-size:11px;")
            r.setFixedWidth(92)
            n = QLabel(name)
            n.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:11.5px; font-weight:600;")
            d = QLabel(dll)
            d.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10.5px;")
            row.addWidget(r)
            row.addWidget(n, 1)
            row.addWidget(d)
            c.addLayout(row)
        c.addSpacing(4)
        btn = QPushButton("VIEW ALL IMPORTS")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(30)
        c.addWidget(btn)
        return c

    def _decoded_card(self):
        c = Card(title="Decoded View")
        a = QLabel("Data at 0x140008F20")
        a.setStyleSheet(f"color:{TEXT_PRIMARY}; font-weight:700; font-size:12.5px;")
        c.addWidget(a)
        c.addWidget(hline())

        for lbl, val, color in [
            ("Type",        "CALL",         TEXT_PRIMARY),
            ("Target",      "0x14001100A",  BLUE),
            ("Symbol",      "VirtualAlloc", BLUE),
        ]:
            row = QHBoxLayout()
            l = QLabel(lbl)
            l.setObjectName("FieldLabel")
            l.setFixedWidth(80)
            v = QLabel(val)
            v.setStyleSheet(f"color:{color}; font-size:12px; font-weight:600; "
                            f"font-family:{MONO if lbl != 'Type' else SANS};")
            row.addWidget(l); row.addWidget(v, 1)
            c.addLayout(row)

        # Description
        d_lbl = QLabel("Description")
        d_lbl.setObjectName("FieldLabel")
        c.addWidget(d_lbl)
        desc = QLabel("Allocates memory\nin the virtual address\nspace of a process.")
        desc.setStyleSheet(f"color:{TEXT_BODY}; font-size:12px; line-height:140%;")
        desc.setWordWrap(True)
        c.addWidget(desc)

        c.addSpacing(4)
        btn = QPushButton("Go to Reference")
        btn.setObjectName("GhostBtn")
        btn.setMinimumHeight(30)
        c.addWidget(btn)
        return c

    def _bookmarks_card(self):
        c = Card(title="Bookmarks")
        rows = [
            ("Entry Point",       "0x140008EF8", "Code"),
            ("Check Security",    "0x140013DF0", "Function"),
            ("Suspicious API",    "0x14001100A", "API"),
            ("Persistence Check", "0x140012120", "Function"),
        ]
        # Column headers
        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        for col, w in [("NAME", 130), ("RVA", 104), ("TYPE", 56)]:
            l = QLabel(col)
            l.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10px; "
                            f"font-weight:700; letter-spacing:0.8px;")
            l.setFixedWidth(w)
            hdr.addWidget(l)
        hdr.addStretch()
        c.addLayout(hdr)
        c.addWidget(hline())

        # Font metrics for eliding Name column if needed
        name_font = QFont()
        name_font.setPointSize(9)
        name_font.setWeight(QFont.Weight.DemiBold)
        name_fm = QFontMetrics(name_font)

        for name, rva, typ in rows:
            row = QHBoxLayout()
            row.setSpacing(10)
            elided = name_fm.elidedText(name, Qt.TextElideMode.ElideRight, 126)
            n = QLabel(elided)
            n.setToolTip(name)
            n.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:12px; font-weight:600;")
            n.setFixedWidth(130)
            r = QLabel(rva)
            r.setStyleSheet(f"color:{BLUE}; font-family:{MONO}; font-size:11px;")
            r.setFixedWidth(104)
            t = QLabel(typ)
            t.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11px;")
            t.setFixedWidth(56)
            row.addWidget(n); row.addWidget(r); row.addWidget(t); row.addStretch()
            c.addLayout(row)

        c.addSpacing(4)
        btn = QPushButton("MANAGE BOOKMARKS")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(32)
        c.addWidget(btn)
        return c


# ============================================================================
# CFG PAGE — large graph view
# ============================================================================

def build_cfg_nodes():
    """Multi-level mock CFG with a handful of branches."""
    nodes = [
        {"id": "BB 0",  "label": "0x140008EF8", "level": 0, "col": 0.5,  "kind": "entry"},
        {"id": "BB 1",  "label": "0x140008F23", "level": 1, "col": 0.30, "kind": "block"},
        {"id": "BB 2",  "label": "0x140008F5C", "level": 1, "col": 0.70, "kind": "block"},
        {"id": "BB 3",  "label": "0x140008FA0", "level": 2, "col": 0.18, "kind": "block"},
        {"id": "BB 4",  "label": "0x140008FC4", "level": 2, "col": 0.42, "kind": "block"},
        {"id": "BB 5",  "label": "0x140009018", "level": 2, "col": 0.58, "kind": "block"},
        {"id": "BB 6",  "label": "0x140009070", "level": 2, "col": 0.82, "kind": "block"},
        {"id": "BB 7",  "label": "0x1400090E0", "level": 3, "col": 0.30, "kind": "block"},
        {"id": "BB 8",  "label": "0x140009150", "level": 3, "col": 0.50, "kind": "block"},
        {"id": "BB 9",  "label": "0x1400091C0", "level": 3, "col": 0.70, "kind": "block"},
        {"id": "BB 10", "label": "0x140009248", "level": 4, "col": 0.50, "kind": "exit"},
    ]
    edges = [
        (0, 1), (0, 2),
        (1, 3), (1, 4),
        (2, 5), (2, 6),
        (3, 7), (4, 7), (4, 8), (5, 8), (5, 9), (6, 9),
        (7, 10), (8, 10), (9, 10),
    ]
    return nodes, edges


class CFGPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("PageRoot")
        outer = QHBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 22)
        outer.setSpacing(16)

        # Left column
        left = QVBoxLayout()
        left.setSpacing(16)
        left.addWidget(self._overview_card())
        left.addWidget(self._legend_card())
        left.addWidget(self._complexity_card(), 1)
        lw = QWidget(); lw.setFixedWidth(250); lw.setLayout(left)
        outer.addWidget(lw)

        # Center — large graph
        outer.addWidget(self._graph_card(), 5)

        # Right
        right = QVBoxLayout()
        right.setSpacing(16)
        right.addWidget(self._node_info_card())
        right.addWidget(self._minimap_card())
        rw = QWidget(); rw.setFixedWidth(290); rw.setLayout(right)
        outer.addWidget(rw)

    def _overview_card(self):
        c = Card(title="CFG Overview")
        rows = [
            ("Function",     "entry_point"),
            ("Entry Address","0x140008EF8"),
            ("Blocks",       "11"),
            ("Edges",        "15"),
            ("Depth",        "4"),
            ("Exits",        "1"),
        ]
        for lbl, val in rows:
            c.addLayout(kv_row(lbl, val, mono=(lbl == "Entry Address")))
        return c

    def _legend_card(self):
        c = Card(title="Legend")
        items = [
            ("Entry Block",    BLUE_DEEP, True),
            ("Basic Block",    "#B9C4D4", False),
            ("Exit Block",     "#FCA5A5", False),
            ("Suspicious API", AMBER,     False),
        ]
        for label, color, strong in items:
            row = QHBoxLayout()
            row.setSpacing(10)
            box = QLabel()
            box.setFixedSize(18, 14)
            box.setStyleSheet(
                f"background-color:{color}; border-radius:3px; "
                f"border:1px solid {'#94A3B8' if not strong else color};")
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color:{TEXT_BODY}; font-size:12px;")
            row.addWidget(box); row.addWidget(lbl, 1)
            c.addLayout(row)
        return c

    def _complexity_card(self):
        c = Card(title="Complexity")
        rows = [
            ("Cyclomatic",    "6"),
            ("Nesting Depth", "3"),
            ("Loops",         "2"),
            ("Dead Code",     "0 blocks"),
        ]
        for lbl, val in rows:
            c.addLayout(kv_row(lbl, val))

        c.addSpacing(6)
        note = QLabel("Low to moderate complexity suggests a structured control "
                      "flow with a limited number of branch combinations.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11.5px; "
                           f"line-height:150%;")
        c.addWidget(note)
        c.addStretch()
        return c

    def _graph_card(self):
        c = Card(title=None, padding=(16, 14, 16, 14))
        hdr = QHBoxLayout()
        t = QLabel("CFG — entry_point")
        t.setObjectName("CardTitle")
        hdr.addWidget(t)
        hdr.addStretch()
        for lbl in ["Fit", "−", "100%", "+", "Export"]:
            b = QPushButton(lbl)
            b.setObjectName("GhostBtn")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(28)
            b.setFixedHeight(28)
            hdr.addWidget(b)
        c.addLayout(hdr)
        c.addWidget(hline())
        
        nodes, edges = build_cfg_nodes()
        graph = CFGGraphWidget(nodes=nodes, edges=edges)
        c.addWidget(graph, 1)
        return c

    def _node_info_card(self):
        c = Card(title="Node Info")
        n = QLabel("BB 0")
        n.setStyleSheet(f"color:{TEXT_PRIMARY}; font-size:20px; font-weight:800;")
        a = QLabel("0x140008EF8  (Entry Block)")
        a.setStyleSheet(f"color:{TEXT_MUTED}; font-family:{MONO}; font-size:11.5px;")
        c.addWidget(n); c.addWidget(a)
        c.addWidget(hline())

        rows = [
            ("Instructions", "14"),
            ("Bytes",        "48"),
            ("Successors",   "2 (BB 1, BB 2)"),
            ("Predecessors", "0"),
            ("Calls",        "3 APIs"),
        ]
        for lbl, val in rows:
            c.addLayout(kv_row(lbl, val))

        c.addSpacing(4)
        k = QLabel("Preview")
        k.setObjectName("Kicker")
        c.addWidget(k)

        preview = QTextEdit()
        preview.setObjectName("Disasm")
        preview.setReadOnly(True)
        preview.setFixedHeight(130)
        preview.setHtml(disasm_html(current_line=-1))
        c.addWidget(preview)

        btn = QPushButton("OPEN IN EREVOS VIEW")
        btn.setObjectName("PrimaryBtn")
        btn.setMinimumHeight(32)
        c.addWidget(btn)
        return c

    def _minimap_card(self):
        c = Card(title="Mini Map")
        mm = MiniMap()
        c.addWidget(mm)
        n = QLabel("Viewport region highlighted. Drag to pan the main graph.")
        n.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px; line-height:140%;")
        n.setWordWrap(True)
        c.addWidget(n)
        return c


# ============================================================================
# MAIN WINDOW
# ============================================================================

class ErevosMainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Erevos — Static PE Disassembler")
        self.setMinimumSize(1380, 860)
        self.resize(1440, 900)

        central = QWidget()
        central.setObjectName("PageRoot")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Top bar
        self.top = TopBar()
        root.addWidget(self.top)

        # Pages
        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)

        self.pages = [
            DashboardPage(),
            ErevosViewPage(),
            AnalysisPage(),
            HexViewPage(),
            CFGPage(),
        ]
        for p in self.pages:
            self.stack.addWidget(p)

        self.top.navChanged.connect(self.stack.setCurrentIndex)


# ============================================================================
# ENTRY POINT & SMOKE TEST
# ============================================================================

def smoke_test():
    """Instantiate every page without showing to confirm no crashes."""
    app = QApplication.instance() or QApplication([])
    w = ErevosMainWindow()
    for i in range(w.stack.count()):
        w.stack.setCurrentIndex(i)
        w.stack.currentWidget().adjustSize()
    w.deleteLater()
    return True


def main():
    # Make HiDPI images crisp
    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setApplicationName("Erevos")
    app.setStyleSheet(APP_QSS)

    win = ErevosMainWindow()
    win.show()

    if os.environ.get("EREVOS_SMOKE") == "1":
        # Cycle pages once, then quit
        def _cycle(i=0):
            if i >= win.stack.count():
                app.quit(); return
            win.stack.setCurrentIndex(i)
            QTimer.singleShot(80, lambda: _cycle(i + 1))
        QTimer.singleShot(50, _cycle)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()