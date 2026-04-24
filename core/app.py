from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QMainWindow, QFileDialog,
    QListWidget, QTabWidget, QTextEdit, QLabel, QSplitter, QToolBar, QStatusBar,
    QLineEdit, QMessageBox, QMenuBar, QStyle, QPlainTextEdit, QInputDialog,
    QListWidgetItem, QCheckBox, QSpinBox, QPushButton, QStackedWidget, QGridLayout,
    QGraphicsView, QGraphicsScene, QGraphicsTextItem, QMenu, QGraphicsProxyWidget, QFrame 
)
from PyQt6.QtGui import (
    QKeySequence, QFont, QAction, QColor, QTextCursor, QTextCharFormat,
    QPainter, QFontMetrics, QPen, QBrush, QMouseEvent, QPixmap
)
from PyQt6.QtCore import Qt, QSize, QPointF, QRectF
from pathlib import Path
import traceback
import re
import json
# Critical tab (risk/hot) adapter
from core.modules.risk import build_risk_views
from core.modules.session_state import SessionState, normalize_function_intel_summary, normalize_threat_narrative
from core.modules.xrefs_foundation import (
    build_code_xrefs_from_text,
    find_refs_from_function,
    extract_structured_xrefs,
    summarize_xrefs,
)
from core.modules.function_intel import (
    build_function_profiles,
    summarize_function_intelligence,
    generate_all_behavior_summaries,
)
from core.modules.call_graph_intel import build_call_graph_model, analyze_call_graph
from core.modules.cfg_intel import build_function_cfg_model, analyze_function_cfg
from core.modules.naming_intel import generate_all_name_suggestions, select_high_confidence_applications
from core.modules.data_flow_intel import analyze_function_data_flow
from core.modules.api_semantics_intel import interpret_api_semantics
from core.modules.behavior_patterns_intel import detect_behavior_patterns
from core.modules.threat_narrative_intel import build_threat_narrative

# Try import pedisasm - if not present, we'll show a friendly message in UI
try:
    from core.pedisasm import PEDisassembler
    PED_AVAILABLE = True
except Exception as e:
    PED_AVAILABLE = False
    PED_IMPORT_ERROR = e

# Optional modules
try:
    from core.modules.asm_highlighter import attach_highlighter
except Exception:
    attach_highlighter = None

try:
    from core.modules.risk import score_functions
except Exception:
    score_functions = None

try:
    from core.modules.resources import summarize_resources
except Exception:
    summarize_resources = None

try:
    from core.modules.cfg import build_cfg
except Exception:
    build_cfg = None

try:
    from core.modules.xrefs import find_data_xrefs_to_va, extract_strings_with_locations
except Exception:
    find_data_xrefs_to_va = extract_strings_with_locations = None

try:
    from core.modules.packer import analyze_packer
except Exception:
    analyze_packer = None


# ------------------- Zoomable function box (Erevos View) -------------------
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
        text_width = 900  # wrap so long lines don’t explode the scene

        # Header
        header_text = f"{self._name}  @ 0x{self._va:08X}"
        header_item = QGraphicsTextItem(header_text)
        header_font = QFont("Consolas", 12, QFont.Weight.DemiBold)
        header_item.setFont(header_font)
        scene.addItem(header_item)
        fm = QFontMetrics(header_font)
        header_h = fm.height() + 12
        header_item.setPos(margin, margin)

        # Code block (use QPlainTextEdit embedded in scene)
        body = self._asm if self._asm.strip() else "<no disassembly>"

        code_edit = QPlainTextEdit()
        code_edit.setReadOnly(True)
        code_edit.setFrameStyle(QFrame.Shape.NoFrame)
        code_edit.setFont(QFont("Consolas", 10))
        code_edit.setPlainText(body)

        # Width + height estimate
        code_edit.setFixedWidth(text_width)
        lines = max(1, min(2000, body.count("\n") + 1))
        line_h = QFontMetrics(QFont("Consolas", 10)).height()
        est_h = min(800, max(200, lines * line_h + 10))
        code_edit.setFixedHeight(est_h)

        proxy = scene.addWidget(code_edit)
        proxy.setZValue(1)
        proxy.setPos(margin, margin + header_h + 6)

        # Background & header strip
        rect_w = int(text_width + 2 * margin)
        rect_h = int(header_h + 3 * margin + est_h)

        bg = scene.addRect(10, 10, rect_w, rect_h)
        bg.setZValue(-1)
        bg.setBrush(Qt.GlobalColor.white)  # QSS styles view bg; this is card box
        bg.setPen(Qt.GlobalColor.black)

        hb = scene.addRect(10, 10, rect_w, header_h + 12)
        hb.setZValue(-0.5)
        hb.setBrush(QColor(200, 230, 230))
        hb.setPen(Qt.GlobalColor.black)

        # Fit view and zoom in
        self.setSceneRect(0, 0, rect_w + 20, rect_h + 20)
        self.resetTransform()
        self._scale = 1.0
        self.fitInView(self.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self.scale(1.4, 1.4)


from PyQt6.QtGui import QPen, QBrush, QFont, QMouseEvent
from PyQt6.QtCore import Qt, QPointF, QRectF

class CfgGraphView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.SmartViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setObjectName("CfgView")
        self._scale = 1.0
        self._block_items = {}   # map node id -> dict with items (header, body, rect)
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

    # ---------- helper: get a few instructions for a block using the disasm ----------
    def _get_block_insns(self, disasm, start_va_hex: str, end_va_hex: str, max_insns=6):
        """
        disasm: PEDisassembler instance (must implement disasm_at(va, size=...))
        start_va_hex/end_va_hex: strings like "0x0040A0CC"
        returns list[str] lines (mnemonic lines)
        """
        if not disasm:
            return []
        try:
            start = int(start_va_hex, 16)
            end = int(end_va_hex, 16)
            size = max(0, end - start)
            # try to disassemble the whole block size; if too big cap it
            cap = min(size, 0x8000)
            text = disasm.disasm_at(start, size=cap)
            if not text:
                return []
            lines = [ln for ln in text.splitlines() if ln.strip()]
            return lines[:max_insns]
        except Exception:
            return []

    # ---------- main renderer ----------
    def render_cfg(self, cfg: dict, disasm=None):
        """
        cfg: { 'function_start': '0x..', 'nodes':[{'id':0,'start':'0x..','end':'0x..'},...],
               'edges':[{'src':0,'dst':1},...], 'metrics': {...} }
        disasm: PEDisassembler instance (optional) to fetch insns to show in blocks
        """
        self.clear()
        if not cfg:
            return

        self._last_cfg = cfg
        nodes = cfg.get("nodes", [])
        edges = cfg.get("edges", [])
        if not nodes:
            t = self.scene().addText("<no basic blocks>")
            t.setDefaultTextColor(Qt.GlobalColor.black)
            self.fitInView(self.scene().itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)
            return

        # simple layout parameters
        col_count = 1 if len(nodes) <= 8 else 2 if len(nodes) <= 20 else 3
        col_w, row_h = 360, 180
        margin_x, margin_y = 40, 40

        centers = {}
        self._block_items = {}
        box_pen = QPen(Qt.GlobalColor.black)
        header_brush = QBrush(QColor(160, 240, 240))
        body_brush = QBrush(Qt.GlobalColor.white)

        font_header = QFont("Consolas", 10, QFont.Weight.DemiBold)
        font_body = QFont("Consolas", 9)

        scene = self.scene()
        for idx, n in enumerate(nodes):
            col = idx % col_count
            row = idx // col_count
            x = margin_x + col * (col_w + margin_x)
            y = margin_y + row * (row_h + margin_y)

            # add box background & small header bar
            rect = scene.addRect(x, y, col_w, row_h, box_pen, body_brush)
            hdr_rect = scene.addRect(x, y, col_w, 22, box_pen, header_brush)

            # header text (clickable style)
            title = f"BB {n.get('id')}  [{n.get('start','?')}..{n.get('end','?')}]"
            hdr = QGraphicsTextItem(title)
            hdr.setFont(font_header)
            hdr.setDefaultTextColor(Qt.GlobalColor.black)
            hdr.setPos(x + 6, y + 1)
            scene.addItem(hdr)

            # block body: use disasm to get N lines
            insns = self._get_block_insns(disasm, n.get('start','0x0'), n.get('end','0x0'), max_insns=8)
            body_text = "\n".join(insns) if insns else ("<no disasm>" if insns == [] else "")
            body = QGraphicsTextItem(body_text)
            body.setFont(font_body)
            body.setDefaultTextColor(Qt.GlobalColor.black)
            body.setPos(x + 6, y + 28)
            scene.addItem(body)

            centers[n["id"]] = QPointF(x + col_w/2, y + row_h/2)
            # store clickable metadata
            self._block_items[n["id"]] = {"rect": QRectF(x, y, col_w, row_h), "start": n.get("start"), "id": n.get("id")}

        # draw edges (lines with arrowheads)
        edge_pen = QPen(Qt.GlobalColor.black); edge_pen.setWidth(2)
        for e in edges:
            s = centers.get(e.get("src")); d = centers.get(e.get("dst"))
            if not s or not d:
                continue
            line_item = scene.addLine(s.x(), s.y(), d.x(), d.y(), edge_pen)
            line_item.setZValue(-1)
            # optional arrow head: draw a small triangle near dest
            # (skip complexity for now)

        # metrics footer
        m = cfg.get("metrics", {})
        footer = scene.addText(f"blocks={m.get('blocks','?')}  edges={m.get('edges','?')}  cyclomatic={m.get('cyclomatic','?')}")
        footer.setFont(font_body)
        footer.setDefaultTextColor(Qt.GlobalColor.black)
        footer.setPos(10, scene.itemsBoundingRect().bottom() + 10)

        self.fitInView(scene.itemsBoundingRect().adjusted(-20, -20, 20, 20), Qt.AspectRatioMode.KeepAspectRatio)

    # ---------- allow clicking headers to jump to block start in Erevos view ----------
    def mousePressEvent(self, ev: QMouseEvent):
        # map click to scene coords and check if inside a block rect
        pt = self.mapToScene(ev.position().toPoint())
        for bid, info in self._block_items.items():
            r: QRectF = info.get("rect")
            if r and r.contains(pt):
                start = info.get("start")
                if start:
                    # ask parent window to open Erevos view at that VA
                    w = self.window()
                    try:
                        va = int(start, 16)
                        name = f"BB_{bid}"
                        if hasattr(w, "_open_in_erevos_view"):
                            w._open_in_erevos_view(va, name)
                    except Exception:
                        pass
                break
        super().mousePressEvent(ev)


class SkullLogo(QWidget):
    def __init__(self, size=36, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        logo_path = Path(__file__).resolve().parents[1] / "ui" / "logo.png"
        if logo_path.exists():
            pix = QPixmap(str(logo_path)).scaled(
                w, h,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            p.drawPixmap((w - pix.width()) // 2, (h - pix.height()) // 2, pix)
            return
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#1f2d3a"))
        p.drawEllipse(0, 0, w, h)


class _Card(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        if title:
            t = QLabel(title)
            t.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            lay.addWidget(t)
        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(self.body)

    def addWidget(self, w: QWidget, stretch: int = 0):
        self.body.addWidget(w, stretch)


class _TopBar(QWidget):
    def __init__(self, mw: "MainWindow"):
        super().__init__(mw)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.addWidget(SkullLogo(28))
        lay.addWidget(QLabel("Erevos"))
        lay.addStretch(1)
        open_btn = QPushButton("Open")
        open_btn.clicked.connect(mw.action_open)
        lay.addWidget(open_btn)


class _DashboardPage(QWidget):
    def __init__(self, mw: "MainWindow"):
        super().__init__(mw)
        lay = QVBoxLayout(self)
        c1 = _Card("Critical Risk")
        mw.critical_risk = QTextEdit()
        mw.critical_risk.setReadOnly(True)
        mw.critical_risk.setFont(QFont("Consolas", 10))
        c1.addWidget(mw.critical_risk)
        lay.addWidget(c1, 1)
        c2 = _Card("Threat Narrative")
        mw.threat_narrative_view = QTextEdit()
        mw.threat_narrative_view.setReadOnly(True)
        mw.threat_narrative_view.setFont(QFont("Consolas", 10))
        c2.addWidget(mw.threat_narrative_view)
        lay.addWidget(c2, 1)


class _ErevosViewPage(QWidget):
    def __init__(self, mw: "MainWindow"):
        super().__init__(mw)
        root = QHBoxLayout(self)
        left = _Card("Functions")
        mw.func_list = QListWidget()
        mw.func_list.setFont(QFont("Consolas", 10))
        mw.func_list.itemClicked.connect(mw.on_func_selected)
        mw.func_list.itemDoubleClicked.connect(mw.on_func_double_clicked)
        mw.func_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        mw.func_list.customContextMenuRequested.connect(mw.on_func_context_menu)
        left.addWidget(mw.func_list, 1)
        mw.func_search_box = QLineEdit()
        mw.func_search_box.setPlaceholderText("Filter functions (address or name)...")
        mw.func_search_box.textChanged.connect(mw.filter_functions)
        left.addWidget(mw.func_search_box)
        root.addWidget(left, 1)

        center = QVBoxLayout()
        dis = _Card("Disassembly (ASM)")
        mw.asm_view = QTextEdit()
        mw.asm_view.setReadOnly(True)
        mw.asm_view.setFont(QFont("Consolas", 10))
        mw.asm_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        mw.asm_view.customContextMenuRequested.connect(mw.on_asm_context_menu)
        if attach_highlighter:
            mw.asm_highlighter = attach_highlighter(mw.asm_view)
        dis.addWidget(mw.asm_view, 1)
        center.addWidget(dis, 2)
        det = _Card("Function Details")
        mw.function_details_view = QTextEdit()
        mw.function_details_view.setReadOnly(True)
        mw.function_details_view.setFont(QFont("Consolas", 10))
        det.addWidget(mw.function_details_view, 1)
        center.addWidget(det, 1)
        root.addLayout(center, 2)


class _AnalysisPage(QWidget):
    def __init__(self, mw: "MainWindow"):
        super().__init__(mw)
        lay = QVBoxLayout(self)
        c1 = _Card("Erevos View")
        mw.erevos_view = FunctionBoxView()
        c1.addWidget(mw.erevos_view, 1)
        lay.addWidget(c1, 2)
        row = QHBoxLayout()
        c2 = _Card("Resources")
        mw.resources_view = QTextEdit()
        mw.resources_view.setReadOnly(True)
        mw.resources_view.setFont(QFont("Consolas", 10))
        c2.addWidget(mw.resources_view, 1)
        row.addWidget(c2, 1)
        c3 = _Card("Console")
        mw.console_bar = QPlainTextEdit()
        mw.console_bar.setObjectName("Console")
        mw.console_bar.setReadOnly(True)
        mw.console_bar.setFont(QFont("Consolas", 10))
        c3.addWidget(mw.console_bar, 1)
        row.addWidget(c3, 1)
        lay.addLayout(row, 1)


class _HexViewPage(QWidget):
    def __init__(self, mw: "MainWindow"):
        super().__init__(mw)
        lay = QGridLayout(self)
        cards = []
        for title in ("Hex View", "Imports", "Strings", "Bookmarks"):
            c = _Card(title)
            cards.append(c)
        mw.hex_view = QTextEdit(); mw.hex_view.setReadOnly(True); mw.hex_view.setFont(QFont("Consolas", 10))
        mw.hex_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        mw.hex_view.customContextMenuRequested.connect(mw.on_asm_context_menu)
        cards[0].addWidget(mw.hex_view, 1)
        mw.imports_view = QTextEdit(); mw.imports_view.setReadOnly(True); mw.imports_view.setFont(QFont("Consolas", 10))
        mw.imports_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        mw.imports_view.customContextMenuRequested.connect(mw.on_import_context_menu)
        cards[1].addWidget(mw.imports_view, 1)
        mw.str_view = QTextEdit(); mw.str_view.setReadOnly(True); mw.str_view.setFont(QFont("Consolas", 10))
        mw.str_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        mw.str_view.customContextMenuRequested.connect(mw.on_string_context_menu)
        mw.str_view.mouseDoubleClickEvent = lambda ev: (mw._show_string_usage_from_cursor(), QTextEdit.mouseDoubleClickEvent(mw.str_view, ev))
        cards[2].addWidget(mw.str_view, 1)
        mw.bookmarks_view = QListWidget(); mw.bookmarks_view.setFont(QFont("Consolas", 10))
        mw.bookmarks_view.itemDoubleClicked.connect(mw.on_bookmark_double_clicked)
        cards[3].addWidget(mw.bookmarks_view, 1)
        lay.addWidget(cards[0], 0, 0)
        lay.addWidget(cards[1], 0, 1)
        lay.addWidget(cards[2], 1, 0)
        lay.addWidget(cards[3], 1, 1)


class _CFGPage(QWidget):
    def __init__(self, mw: "MainWindow"):
        super().__init__(mw)
        lay = QVBoxLayout(self)
        c1 = _Card("CFG Graph")
        mw.cfg_graph = CfgGraphView()
        c1.addWidget(mw.cfg_graph, 1)
        lay.addWidget(c1, 2)
        c2 = _Card("CFG Intelligence")
        mw.cfg_intel_view = QTextEdit()
        mw.cfg_intel_view.setReadOnly(True)
        mw.cfg_intel_view.setFont(QFont("Consolas", 10))
        mw.cfg_intel_view.mouseDoubleClickEvent = lambda ev: (mw._goto_va_from_cursor(mw.cfg_intel_view), QTextEdit.mouseDoubleClickEvent(mw.cfg_intel_view, ev))
        c2.addWidget(mw.cfg_intel_view, 1)
        lay.addWidget(c2, 1)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Erevos - Static PE Disassembler")
        self.resize(1500, 950)
        self.disasm = None
        self.current_file = None
        self.session = SessionState()
        self.session_path = None
        self.current_asm_lines = []
        self._xrefs = []
        self._xrefs_summary = {}
        self._function_profiles = {}
        self._function_intel_summary = {}
        self._behavior_summaries = {}
        self._call_graph_model = {}
        self._call_graph_summary = {}
        self._cfg_intel_summary = {}
        self._naming_suggestions = {}
        self._applied_suggested_names = {}
        self._data_flow_by_function = {}
        self._api_semantics_by_function = {}
        self._behavior_patterns = {}
        self._threat_narrative = {}

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        # Menu + Toolbar
        self._create_menu()
        self._create_toolbar()

        # Build pages with dependency injection (pages instantiate backend-owned widgets).
        self.functions_label = QLabel("Functions")
        self.functions_label.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self.functions_label.setObjectName("FunctionsHeader")
        self.filter_renamed = QCheckBox("Renamed")
        self.filter_commented = QCheckBox("Commented")
        self.filter_bookmarked = QCheckBox("Bookmarked")
        self.filter_suspicious = QCheckBox("Suspicious API")
        self.filter_inbound_spin = QSpinBox()
        self.filter_inbound_spin.setPrefix("Inbound≥")
        self.filter_inbound_spin.setRange(0, 9999)
        self.filter_ref_string = QLineEdit()
        self.filter_ref_string.setPlaceholderText("Referenced string contains...")
        for w in (
            self.filter_renamed,
            self.filter_commented,
            self.filter_bookmarked,
            self.filter_suspicious,
            self.filter_inbound_spin,
        ):
            w.stateChanged.connect(self.filter_functions)
        self.filter_inbound_spin.valueChanged.connect(self.filter_functions)
        self.filter_ref_string.textChanged.connect(self.filter_functions)
        self.imports_view = QTextEdit(); self.imports_view.setReadOnly(True); self.imports_view.setFont(QFont("Consolas", 10))
        self.exports_view = QTextEdit(); self.exports_view.setReadOnly(True); self.exports_view.setFont(QFont("Consolas", 10))
        self.critical_hot = QTextEdit(); self.critical_hot.setReadOnly(True); self.critical_hot.setFont(QFont("Consolas", 10))
        self.xrefs_to_view = QListWidget(); self.xrefs_to_view.setFont(QFont("Consolas", 10)); self.xrefs_to_view.itemDoubleClicked.connect(self.on_xref_item_double_clicked)
        self.xrefs_from_view = QListWidget(); self.xrefs_from_view.setFont(QFont("Consolas", 10)); self.xrefs_from_view.itemDoubleClicked.connect(self.on_xref_item_double_clicked)
        self.call_graph_view = QListWidget(); self.call_graph_view.setFont(QFont("Consolas", 10)); self.call_graph_view.itemDoubleClicked.connect(self.on_call_graph_item_double_clicked)

        self.stack = QStackedWidget()
        self.tabs = self.stack  # compatibility alias for existing setCurrentWidget calls

        self.page_dashboard = _DashboardPage(self)
        self.page_erevos = _ErevosViewPage(self)
        self.page_analysis = _AnalysisPage(self)
        self.page_hex = _HexViewPage(self)
        self.page_cfg = _CFGPage(self)

        aux = QWidget()
        aux_l = QVBoxLayout(aux)
        aux_l.addWidget(self.imports_view)
        aux_l.addWidget(self.exports_view)
        aux_l.addWidget(self.xrefs_to_view)
        aux_l.addWidget(self.xrefs_from_view)
        aux_l.addWidget(self.call_graph_view)
        aux_l.addWidget(self.critical_hot)

        for w in (self.page_dashboard, self.page_erevos, self.page_analysis, self.page_hex, self.page_cfg, aux):
            self.stack.addWidget(w)

        nav = QWidget()
        nav_l = QVBoxLayout(nav)
        for title, page in [
            ("Dashboard", self.page_dashboard),
            ("Erevos", self.page_erevos),
            ("Analysis", self.page_analysis),
            ("Hex/IO", self.page_hex),
            ("CFG", self.page_cfg),
        ]:
            b = QPushButton(title)
            b.clicked.connect(lambda _, p=page: self.stack.setCurrentWidget(p))
            nav_l.addWidget(b)
        nav_l.addStretch(1)
        nav_l.addWidget(self.filter_renamed)
        nav_l.addWidget(self.filter_commented)
        nav_l.addWidget(self.filter_bookmarked)
        nav_l.addWidget(self.filter_suspicious)
        nav_l.addWidget(self.filter_inbound_spin)
        nav_l.addWidget(self.filter_ref_string)

        body = QHBoxLayout()
        body.addWidget(nav, 0)
        body.addWidget(self.stack, 1)
        main.addWidget(_TopBar(self), 0)
        main.addLayout(body, 1)

        # Status bar
        self.status = QStatusBar(); self.setStatusBar(self.status)

        # Apply default style if present
        try:
            qss = Path(__file__).parent.parent.joinpath('ui', 'styles.qss')
            if qss.exists():
                self.setStyleSheet(qss.read_text())
        except Exception:
            pass

        # PED availability notice
        if not PED_AVAILABLE:
            self.console(f"Warning: core.pedisasm not available. Import error: {PED_IMPORT_ERROR}")
            # open_action assigned in _create_menu
        else:
            self.console("Erevos initialized. Ready.")

        # Drag & drop
        self.setAcceptDrops(True)

        # search state
        self._search = {"last": "", "positions": [], "index": -1}

    def _disasm_function_text(self, va: int) -> str:
        try:
            # Figure an end bound from the next function start, if we have one
            addrs = sorted(self._functions.keys()) if hasattr(self, "_functions") else []
            end = None
            if addrs and va in addrs:
                idx = addrs.index(va)
                if idx + 1 < len(addrs):
                    end = addrs[idx + 1]

            # Preferred size: next-start - va, else a sane default
            if end and end > va:
                size = max(0x200, min(0x4000, end - va))
            else:
                size = 0x1200  # default window

            # Try with a couple of sizes (some funcs decode better with more context)
            for s in (size, max(size, 0x2000), 0x3000):
                txt = self.disasm.disasm_at(va, size=s)  # <= uses your working routine
                if txt and txt.strip() and "0x" in txt:
                    return txt

            # As last resort, still return *something* so the box isn't empty
            txt = self.disasm.disasm_at(va, size=0x800)
            return txt if (txt and txt.strip()) else "<no disassembly>"
        except Exception as e:
            return f"<disassembly error: {e}>"

    # ----------------- UI creation -----------------
    def _create_menu(self):
        menubar = QMenuBar(self); self.setMenuBar(menubar)
        file_menu = menubar.addMenu("&File")
        open_action = QAction("Open PE...", self); open_action.setShortcut(QKeySequence.StandardKey.Open); open_action.triggered.connect(self.action_open)
        file_menu.addAction(open_action)
        file_menu.addSeparator()
        export_action = QAction("Export HTML Report...", self); export_action.triggered.connect(self.action_export_html)
        file_menu.addAction(export_action)
        file_menu.addAction(QAction("Save Session", self, triggered=self.action_save_session))
        file_menu.addAction(QAction("Load Session", self, triggered=self.action_load_session))
        file_menu.addSeparator()
        exit_action = QAction("Exit", self); exit_action.setShortcut(QKeySequence.StandardKey.Quit); exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menubar.addMenu("&View")
        view_menu.addAction(QAction("Refresh", self, triggered=self.action_refresh))
        view_menu.addAction(QAction("Global Search...", self, triggered=self.action_global_search))

        tools_menu = menubar.addMenu("&Tools")
        tools_menu.addAction(QAction("Export disasm (TXT)...", self, triggered=self.action_export_txt))
        tools_menu.addAction(QAction("Analyze Packer/Obfuscation", self, triggered=self.action_packer))

        help_menu = menubar.addMenu("&Help")
        help_menu.addAction(QAction("About Erevos", self, triggered=self.action_about))

        self.open_action = open_action

    def _create_toolbar(self):
        toolbar = QToolBar("Main"); toolbar.setIconSize(QSize(16, 16)); self.addToolBar(toolbar)
        style = self.style()
        open_icon = style.standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton)
        save_icon = style.standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        reload_icon = style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload)
        toolbar.addAction(QAction(open_icon, "Open", self, triggered=self.action_open))
        toolbar.addAction(QAction(save_icon, "Export TXT", self, triggered=self.action_export_txt))
        toolbar.addAction(QAction(reload_icon, "Refresh", self, triggered=self.action_refresh))
        toolbar.addSeparator()
        self.tb_search = QLineEdit(); self.tb_search.setPlaceholderText("Search strings / asm...")
        self.tb_search.returnPressed.connect(self.toolbar_search)
        toolbar.addWidget(self.tb_search)

    # ----------------- Actions -----------------
    def action_open(self):
        if not PED_AVAILABLE:
            QMessageBox.critical(self, "Error", "Disassembler core is unavailable.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Open PE file", "", "PE files (*.exe *.dll);;All files (*)")
        if not path:
            return
        self.load_pe(path)

    def action_refresh(self):
        if not self.current_file:
            return
        self.load_pe(self.current_file)

    def action_export_txt(self):
        if not self.disasm:
            QMessageBox.information(self, "Export", "No file loaded.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export disassembly to TXT",
            f"{Path(self.current_file).stem}_disasm.txt", "Text files (*.txt)"
        )
        if not path:
            return
        try:
            out = []
            funcs = self._functions if hasattr(self, "_functions") else {}
            for va, name in funcs.items():
                out.append(f"Function {name} @ 0x{va:08X}\n")
                out.append(self.disasm.disasm_at(va, size=0x800))
                out.append("\n\n")
            Path(path).write_text("".join(out), encoding="utf-8")
            QMessageBox.information(self, "Export", f"Exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export error", str(e))

    def action_export_html(self):
        if not self.current_file:
            QMessageBox.information(self, "Export", "No file loaded.")
            return
        try:
            from core.modules.report import generate_report
        except Exception:
            QMessageBox.warning(self, "Export", "Report module not available.")
            return
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report",
            f"{Path(self.current_file).stem}_report.html",
            "HTML files (*.html)"
        )
        if not save_path:
            return
        try:
            generate_report(
                self.current_file,
                top=30,
                max_strings=200,
                html_path=save_path,
                analyst_artifacts={
                    "renamed_functions": self.session.renamed_functions,
                    "comments": self.session.comments,
                    "labels": self.session.labels,
                    "bookmarks": self.session.bookmarks,
                    "function_intelligence_summary": self._function_intel_summary,
                    "behavior_summaries": self._behavior_summaries,
                    "call_graph_summary": self._call_graph_summary,
                    "cfg_intel_summary": self._cfg_intel_summary,
                    "naming_suggestions": self._naming_suggestions,
                    "applied_suggested_names": self._applied_suggested_names,
                    "data_flow_insights": self._data_flow_by_function,
                    "api_semantics_insights": self._api_semantics_by_function,
                    "behavior_patterns": self._behavior_patterns,
                    "threat_narrative": self._threat_narrative,
                },
            )
            QMessageBox.information(self, "Export", f"HTML report saved to {save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export error", str(e))

    def action_packer(self):
        if not self.current_file or not analyze_packer:
            QMessageBox.information(self, "Packer", "No file loaded or module unavailable.")
            return
        try:
            res = analyze_packer(self.current_file)
            txt = [f"Packer score: {res.get('score','-')}"]
            if res.get("reasons"):
                txt.append("Reasons: " + ", ".join(res["reasons"]))
            if res.get("hints"):
                txt.append("Hints: " + ", ".join(res["hints"]))
            self.critical_risk.setPlainText("\n".join(txt))
            self.tabs.setCurrentWidget(self.page_dashboard)
        except Exception as e:
            QMessageBox.critical(self, "Packer error", str(e))

    def action_about(self):
        QMessageBox.information(
            self, "About Erevos",
            "Erevos — Static PE Disassembler\nBuilt with PyQt6 and Capstone\nAuthor: R.I.A."
        )

    def toolbar_search(self):
        q = self.tb_search.text()
        if not q:
            self._clear_highlights(self._current_textedit())
            self._search = {"last": "", "positions": [], "index": -1}
            return
        edit = self._current_textedit()
        if edit is None:
            self.console("Search: current tab not searchable")
            return
        if q == self._search["last"] and self._search["positions"]:
            self._search["index"] = (self._search["index"] + 1) % len(self._search["positions"])
            self._jump_to(edit, self._search["positions"][self._search["index"]], len(q))
            self.console(f"Search: next match ({self._search['index']+1}/{len(self._search['positions'])})")
            return
        positions = self._find_all_positions(edit.toPlainText(), q)
        self._search = {"last": q, "positions": positions, "index": 0 if positions else -1}
        self._highlight_all(edit, positions, len(q))
        if positions:
            self._jump_to(edit, positions[0], len(q))
            self.console(f"Search: found {len(positions)} match(es)")
        else:
            self.console(f"Search: not found: {q}")

    # ---------- Search helpers ----------
    def _current_textedit(self):
        w = self.tabs.currentWidget()
        if isinstance(w, QTabWidget):
            w = w.currentWidget()
        return w if isinstance(w, (QTextEdit, QPlainTextEdit)) else None

    def _find_all_positions(self, text: str, needle: str):
        text_l = text.lower(); n = needle.lower()
        if not n:
            return []
        pos = 0; out = []
        while True:
            i = text_l.find(n, pos)
            if i == -1:
                break
            out.append(i); pos = i + max(1, len(n))
        return out

    def _highlight_all(self, edit, positions, length):
        if not isinstance(edit, (QTextEdit, QPlainTextEdit)):
            return
        fmt = QTextCharFormat(); fmt.setBackground(QColor(192, 229, 255))
        selections = []
        doc = edit.document()
        for p in positions:
            c = QTextCursor(doc); c.setPosition(p); c.setPosition(p + length, QTextCursor.MoveMode.KeepAnchor)
            sel = QTextEdit.ExtraSelection(); sel.cursor = c; sel.format = fmt
            selections.append(sel)
        edit.setExtraSelections(selections)

    def _clear_highlights(self, edit):
        if isinstance(edit, (QTextEdit, QPlainTextEdit)):
            edit.setExtraSelections([])

    def _jump_to(self, edit, pos: int, length: int):
        c = edit.textCursor(); c.setPosition(pos); c.setPosition(pos + length, QTextCursor.MoveMode.KeepAnchor)
        edit.setTextCursor(c); edit.ensureCursorVisible()

    # ----------------- Load / display PE -----------------
    def load_pe(self, path):
        try:
            self.console(f"Loading: {path}")
            self.disasm = PEDisassembler(path)
            self.current_file = path
            self.session_path = SessionState.session_path_for_sample(path)
            self._load_session_for_current_file()
            self.status.showMessage(
                f"Loaded: {Path(path).name} | Arch: {self.disasm.arch} | ImageBase: 0x{self.disasm.pe.OPTIONAL_HEADER.ImageBase:08X}",
                8000
            )
            # populate panels
            self.imports_view.setPlainText("\n".join(self.disasm.get_imports()))
            self.exports_view.setPlainText("\n".join(self.disasm.get_exports()))
            self.str_view.setPlainText("\n".join(self.disasm.get_strings()[:5000]))

            # Order matters: functions → hot → risk
            self._populate_functions()
            self._populate_resources()
            self._populate_full_disasm()
            self._rebuild_xrefs()
            self._rebuild_function_intelligence()
            self._rebuild_call_graph()
            self._rebuild_naming_intelligence()
            self._populate_functions()
            self._populate_critical()
            self._refresh_bookmarks_panel()

            self.console(f"Loaded {path}. Found {len(self._functions)} function(s).")
        except Exception as e:
            tb = traceback.format_exc()
            self.console(f"Error loading file: {e}\n{tb}")
            QMessageBox.critical(self, "Error", f"Failed to load PE: {e}")

    def _populate_full_disasm(self):
        try:
            sec = self.disasm.text_section
            if not sec:
                self.asm_view.setPlainText("<no .text section>")
                return
            base = self.disasm.pe.OPTIONAL_HEADER.ImageBase
            start_va = base + sec.VirtualAddress
            data = sec.get_data() or b""
            self.console(f"Disassembling full .text ({len(data)} bytes)…")
            out = []
            step = 0x2000
            for off in range(0, len(data), step):
                chunk = data[off:off + step]
                for ins in self.disasm.md.disasm(chunk, start_va + off):
                    out.append(f"0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}")
                if len(out) > 200000:
                    out.append("… <truncated>")
                    break
            self.asm_view.setPlainText("\n".join(out))
            self._reannotate_disassembly_views()
        except Exception as e:
            self.asm_view.setPlainText(f"Full disassembly error: {e}")

    def _populate_critical(self):
        """Fill Critical tab (Risk + Hot) from current disasm using adapter."""
        try:
            if not self.disasm:
                self.critical_risk.setPlainText("— no file loaded —")
                self.critical_hot.setPlainText("— no file loaded —")
                return
            risk_txt, hot_txt = build_risk_views(self.disasm)
            self.critical_risk.setPlainText(risk_txt)
            self.critical_hot.setPlainText(hot_txt)
        except Exception as e:
            self.critical_risk.setPlainText(f"Risk error: {e}")
            self.critical_hot.setPlainText(f"Hot error: {e}")


    def _populate_resources(self):
        try:
            if not summarize_resources:
                self.resources_view.setPlainText("resources module not available")
                return

            res = summarize_resources(self.disasm.pe)  # dict with: manifest, version_info, string_tables, resources
            lines = []

            # ---------- Manifest summary ----------
            mans = res.get("manifest") or []
            if mans:
                lines.append("[Manifest summary]")
                for m in mans:
                    summ = m.get("summary", {}) or {}
                    # dpiAware (list)
                    if summ.get("dpiAware"):
                        vals = ", ".join(summ["dpiAware"])
                        lines.append(f"  dpiAware: {vals}")
                    # requestedExecutionLevel + description
                    if "requestedExecutionLevel" in summ:
                        lvl = summ["requestedExecutionLevel"]
                        desc = summ.get("requestedExecutionLevelDesc") or ""
                        if desc:
                            lines.append(f"  requestedExecutionLevel: {lvl}  ({desc})")
                        else:
                            lines.append(f"  requestedExecutionLevel: {lvl}")
                    # uiAccess
                    if "uiAccess" in summ:
                        lines.append(f"  uiAccess: {summ['uiAccess']}")
                    # supported OS (names if present, otherwise GUIDs)
                    compat_names = summ.get("compat_names") or []
                    compat_guids = summ.get("compat") or []
                    if compat_names:
                        lines.append(f"  supportedOS: {', '.join(compat_names)}")
                    if compat_guids and not compat_names:
                        lines.append(f"  supportedOS GUIDs: {', '.join(compat_guids)}")
                lines.append("")  # spacer

            # ---------- Version info ----------
            vi = res.get("version_info") or {}
            if vi:
                lines.append("[Version info]")
                # Prefer pretty strings if present
                if "FileVersion" in vi:
                    lines.append(f"  FileVersion: {vi['FileVersion']}")
                if "ProductVersion" in vi:
                    lines.append(f"  ProductVersion: {vi['ProductVersion']}")
                # Also show a few common string fields if available
                for key in ("CompanyName", "FileDescription", "ProductName", "OriginalFilename", "LegalCopyright"):
                    if key in vi and vi[key]:
                        lines.append(f"  {key}: {vi[key]}")
                lines.append("")  # spacer

            # ---------- String tables (small preview) ----------
            stabs = res.get("string_tables") or []
            if stabs:
                lines.append("[String tables]")
                # Show up to 2 tables, a few entries each
                for i, t in enumerate(stabs[:2], start=1):
                    entries = t.get("entries", {}) or {}
                    lines.append(f"  Table {i} (lang={t.get('lang')}, sublang={t.get('sublang')}):")
                    shown = 0
                    for k, v in entries.items():
                        if shown >= 6:
                            lines.append("    …")
                            break
                        vv = v.replace("\r", " ").replace("\n", " ")
                        if len(vv) > 120:
                            vv = vv[:120] + "…"
                        lines.append(f"    [{k:02d}] {vv}")
                        shown += 1
                lines.append("")

            # Fallback
            if not lines:
                lines = ["No resource summaries available."]

            self.resources_view.setPlainText("\n".join(lines))

        except Exception as e:
            self.resources_view.setPlainText(f"Resources error: {e}")

    def _populate_functions(self):
        funcs = {}
        try:
            base = self.disasm.pe.OPTIONAL_HEADER.ImageBase
            ep = self.disasm.get_entry_point()
            funcs[ep] = "entry_point"
            if hasattr(self.disasm.pe, "DIRECTORY_ENTRY_EXPORT") and self.disasm.pe.DIRECTORY_ENTRY_EXPORT:
                for s in self.disasm.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    va = base + (s.address or 0)
                    name = s.name.decode(errors="ignore") if s.name else f"ordinal_{s.ordinal}"
                    funcs[va] = name
            if self.disasm.text_section:
                data = self.disasm.text_section.get_data() or b""
                tva = base + self.disasm.text_section.VirtualAddress
                for i in range(max(0, len(data) - 6)):
                    if data[i:i + 3] in (b"\x55\x8B\xEC", b"\x55\x48"):
                        va = tva + i
                        funcs.setdefault(va, f"sub_{va:08X}")
        except Exception:
            pass
        self._functions = dict(sorted(funcs.items()))
        self._refresh_function_list()

    def _refresh_function_list(self):
        self.func_list.clear()
        for va, name in getattr(self, "_functions", {}).items():
            if not self._function_passes_filters(va, name):
                continue
            key = f"0x{va:08X}"
            self.session.original_functions.setdefault(key, name)
            prof = getattr(self, "_function_profiles", {}).get(va)
            cnt = int(getattr(prof, "inbound_xrefs", 0) or 0)
            suffix = f" [xrefs:{cnt}]" if cnt else ""
            item = QListWidgetItem(f"0x{va:08X}    {self._display_func_name(va, name)}{suffix}")
            item.setData(Qt.ItemDataRole.UserRole, va)
            self.func_list.addItem(item)

    def _function_passes_filters(self, va: int, name: str) -> bool:
        key = f"0x{va:08X}"
        q = (self.func_search_box.text() if hasattr(self, "func_search_box") else "").strip().lower()
        dname = self._display_func_name(va, name)
        base = f"0x{va:08X} {dname}".lower()
        if q and q not in base:
            return False
        prof = getattr(self, "_function_profiles", {}).get(va)
        if self.filter_renamed.isChecked() and key not in self.session.renamed_functions:
            return False
        if self.filter_commented.isChecked() and key not in self.session.comments:
            return False
        if self.filter_bookmarked.isChecked() and key not in self.session.bookmarks:
            return False
        if self.filter_suspicious.isChecked() and not (prof and prof.suspicious_api_usage):
            return False
        inbound_min = int(self.filter_inbound_spin.value())
        if inbound_min > 0:
            if not prof or inbound_min > int(prof.inbound_xrefs or 0):
                return False
        ref_q = self.filter_ref_string.text().strip().lower()
        if ref_q:
            if not prof or not any(ref_q in s.lower() for s in prof.referenced_strings):
                return False
        return True

    def filter_functions(self, _txt):
        if not hasattr(self, "_functions"):
            return
        self._refresh_function_list()

    # ----------------- Navigation handlers -----------------
    def on_func_selected(self, item):
        va = item.data(Qt.ItemDataRole.UserRole)
        va_hex = f"0x{int(va):08X}" if va is not None else item.text().split()[0]
        va = int(va_hex, 16)
        self._render_function_profile(va)
        try:
            asm = self.disasm.disasm_at(va, size=0x800)
            hx = self.disasm.hexdump_at(va, size=1024)
            self.asm_view.setPlainText(asm if asm else "<no disasm>")
            self.hex_view.setPlainText(hx if hx else "<no hex>")
            self._reannotate_disassembly_views()
            self.tabs.setCurrentWidget(self.asm_view)
            self._update_cfg_intel_for_function(va)
            self._update_data_flow_for_function(va)
            self.console(f"Disassembled at {va_hex}")
        except Exception as e:
            self.console(f"Disassembly error: {e}")

    def on_func_double_clicked(self, item):
        va = item.data(Qt.ItemDataRole.UserRole)
        va_hex = f"0x{int(va):08X}" if va is not None else item.text().split()[0]
        va = int(va_hex, 16)
        text = item.text().split()
        self._open_in_erevos_view(va, self._display_func_name(va, self._functions.get(va, text[-1])))

    def on_func_context_menu(self, pos):
        item = self.func_list.itemAt(pos)
        if not item:
            return
        text = item.text().split()
        va = item.data(Qt.ItemDataRole.UserRole)
        va_hex = f"0x{int(va):08X}" if va is not None else text[0]
        va = int(va_hex, 16)
        name = self._display_func_name(va, self._functions.get(va, f"sub_{va:08X}"))
        m = QMenu(self)
        a1 = m.addAction("Go to function (Erevos View)")
        a2 = m.addAction("Open in Disassembly (ASM)")
        a3 = m.addAction("Rename Function")
        a4 = m.addAction("Apply Suggested Name")
        a5 = m.addAction("Apply All High-Confidence Suggested Names")
        act = m.exec(self.func_list.mapToGlobal(pos))
        if act == a1:
            self._open_in_erevos_view(va, name)
        elif act == a2:
            self.on_func_selected(item)
        elif act == a3:
            self._rename_function(va)
        elif act == a4:
            self._apply_suggested_name(va)
        elif act == a5:
            self._apply_all_high_confidence_suggested_names()

    def _goto_va_from_cursor(self, edit: QTextEdit):
        cur = edit.textCursor()
        cur.select(QTextCursor.SelectionType.LineUnderCursor)
        line = cur.selectedText().strip()

        m = re.search(r"0x([0-9A-Fa-f]{6,16})", line)
        if not m:
            return
        va = int(m.group(0), 16)
        tokens = line.split()
        name = f"sub_{va:08X}"
        try:
            idx = tokens.index(m.group(0))
            if idx + 1 < len(tokens):
                if tokens[idx + 1] not in ("—", "--", "—,", "—."):
                    name = tokens[idx + 1]
        except ValueError:
            pass
        self._open_in_erevos_view(va, name)


    def _open_in_erevos_view(self, va: int, name: str):
        try:
            asm = self._disasm_function_text(va)
            self.erevos_view.set_function(name, va, asm)
            self.tabs.setCurrentWidget(self.erevos_view)
            if build_cfg:
                g = build_cfg(self.current_file, va)
                data = g.to_json() if hasattr(g, "to_json") else g
                if isinstance(data, dict):
                    # pass current disasm so CfgGraphView can fetch instructions to show
                    try:
                        self.cfg_graph.render_cfg(data, disasm=self.disasm)
                    except Exception:
                        # fallback: render without disasm
                        self.cfg_graph.render_cfg(data, disasm=None)
            self._update_cfg_intel_for_function(va)
            self._update_data_flow_for_function(va)
        except Exception as e:
            self.console(f"Erevos view error: {e}")

    # ----------------- Analyst workspace features -----------------
    def _display_func_name(self, va: int, fallback: str) -> str:
        return self.session.renamed_functions.get(f"0x{va:08X}", fallback)

    def _rebuild_xrefs(self):
        try:
            text = self.asm_view.toPlainText()
            strings_map = {}
            if extract_strings_with_locations and self.disasm:
                try:
                    hits = extract_strings_with_locations(self.disasm.pe, min_len=4, limit=5000)
                    strings_map = {int(h.va): h.text for h in hits}
                except Exception:
                    strings_map = {}
            imports = self.disasm.get_imports() if self.disasm else []
            self._xrefs = extract_structured_xrefs(text, functions=getattr(self, "_functions", {}), strings_by_addr=strings_map, imports=imports)
            self._xrefs_summary = summarize_xrefs(self._xrefs)
        except Exception as e:
            self._xrefs = []
            self._xrefs_summary = {"error": str(e)}

    def _rebuild_function_intelligence(self):
        try:
            disasm_text = self.asm_view.toPlainText()
            self._function_profiles = build_function_profiles(
                disasm_text=disasm_text,
                functions=getattr(self, "_functions", {}),
                xrefs=getattr(self, "_xrefs", []),
                comments=self.session.comments,
                labels=self.session.labels,
                bookmarks=self.session.bookmarks,
            )
            self._function_intel_summary = normalize_function_intel_summary(summarize_function_intelligence(
                self._function_profiles, self.session.renamed_functions
            ))
            self._behavior_summaries = generate_all_behavior_summaries(self._function_profiles)
            self.session.function_intel_summary = self._function_intel_summary
            self.session.behavior_summaries = self._behavior_summaries
        except Exception as e:
            self._function_profiles = {}
            self._function_intel_summary = {"error": str(e)}
            self._behavior_summaries = {}

    def _rebuild_call_graph(self):
        try:
            self._call_graph_model = build_call_graph_model(
                profiles=getattr(self, "_function_profiles", {}),
                xrefs=getattr(self, "_xrefs", []),
            )
            ep = self.disasm.get_entry_point() if self.disasm else None
            self._call_graph_summary = analyze_call_graph(self._call_graph_model, entry_point=ep)
            self.session.call_graph_summary = self._call_graph_summary
            self._refresh_call_graph_panel()
            self._rebuild_behavior_patterns()
            self._rebuild_threat_narrative()
        except Exception as e:
            self._call_graph_model = {}
            self._call_graph_summary = {"error": str(e)}
            self.call_graph_view.clear()
            self.call_graph_view.addItem(f"Call graph error: {e}")

    def _refresh_call_graph_panel(self):
        self.call_graph_view.clear()
        if not self._call_graph_summary:
            self.call_graph_view.addItem("No call graph summary available.")
            return
        for row in (self._call_graph_summary.get("top_hub_functions") or [])[:20]:
            mark = " [SUSP]" if row.get("suspicious") else ""
            self.call_graph_view.addItem(
                f"HUB {row.get('address')} in={row.get('inbound_degree',0)} out={row.get('outbound_degree',0)}{mark}"
            )
        for edge in (self._call_graph_model.get("edges") or [])[:80]:
            mark = " [SUSP]" if edge.get("suspicious_indicator") else ""
            self.call_graph_view.addItem(
                f"EDGE {edge.get('caller')} -> {edge.get('callee')} calls={edge.get('call_count',0)} conf={edge.get('confidence','?')}{mark}"
            )

    def _update_cfg_intel_for_function(self, va: int):
        try:
            asm = self._disasm_function_text(va)
            model = build_function_cfg_model(asm, function_start=va)
            analysis = analyze_function_cfg(model)
            self._cfg_intel_summary[f"0x{va:08X}"] = {
                "model": model,
                "analysis": analysis,
            }
            lines = [
                f"Function: 0x{va:08X}",
                f"Basic blocks: {analysis.get('basic_block_count', 0)}",
                f"Branches: {analysis.get('branch_count', 0)}",
                f"Branch density: {analysis.get('branch_density', 0)}",
                f"Unresolved edges: {analysis.get('unresolved_edge_count', 0)}",
                f"Loop/back-edge hints: {analysis.get('loop_back_edge_hints', [])}",
                f"Unreachable block hints: {analysis.get('unreachable_block_hints', [])}",
                f"Possible opaque predicate hints: {analysis.get('possible_opaque_predicate_hints', [])}",
                f"Suspicious CFG indicators: {analysis.get('suspicious_control_flow_indicators', [])}",
            ]
            self.cfg_intel_view.setPlainText("\n".join(lines))
        except Exception as e:
            self.cfg_intel_view.setPlainText(f"CFG intelligence error: {e}")

    def _rebuild_naming_intelligence(self):
        try:
            self._naming_suggestions = generate_all_name_suggestions(
                profiles=getattr(self, "_function_profiles", {}),
                behavior_summaries=getattr(self, "_behavior_summaries", {}),
                call_graph_summary=getattr(self, "_call_graph_summary", {}),
            )
            self.session.naming_suggestions = dict(self._naming_suggestions)
            self.session.applied_suggested_names = dict(self._applied_suggested_names)
        except Exception as e:
            self._naming_suggestions = {}
            self.console(f"Naming intelligence error: {e}")

    def _update_data_flow_for_function(self, va: int):
        try:
            asm = self._disasm_function_text(va)
            strings_map = {}
            for x in getattr(self, "_xrefs", []):
                if x.xref_type == "string" and isinstance(x.dst, int) and x.string_value:
                    strings_map[int(x.dst)] = x.string_value
            fx = [x for x in getattr(self, "_xrefs", []) if x.src_function == va or x.dst_function == va]
            self._data_flow_by_function[f"0x{va:08X}"] = analyze_function_data_flow(
                disasm_text=asm,
                xrefs=fx,
                strings_by_addr=strings_map,
            )
            self._api_semantics_by_function[f"0x{va:08X}"] = interpret_api_semantics(
                self._data_flow_by_function[f"0x{va:08X}"]
            )
            self._rebuild_behavior_patterns()
            self._rebuild_threat_narrative()
        except Exception as e:
            self._data_flow_by_function[f"0x{va:08X}"] = {"error": str(e)}
            self._api_semantics_by_function[f"0x{va:08X}"] = {"error": str(e)}
            self._behavior_patterns = {"error": str(e)}
            self._threat_narrative = {"error": str(e)}

    def _rebuild_behavior_patterns(self):
        try:
            self._behavior_patterns = detect_behavior_patterns(
                api_semantics_by_function=getattr(self, "_api_semantics_by_function", {}) or {},
                data_flow_by_function=getattr(self, "_data_flow_by_function", {}) or {},
                call_graph_model=getattr(self, "_call_graph_model", {}) or {},
                call_graph_summary=getattr(self, "_call_graph_summary", {}) or {},
            )
        except Exception as e:
            self._behavior_patterns = {"error": str(e)}

    def _rebuild_threat_narrative(self):
        try:
            hashes = {}
            if self.current_file:
                import hashlib
                p = Path(self.current_file)
                b = p.read_bytes() if p.exists() else b""
                hashes = {
                    "sha256": hashlib.sha256(b).hexdigest() if b else "",
                    "md5": hashlib.md5(b).hexdigest() if b else "",
                }
            meta = {
                "path": self.current_file or "",
                "entry_point": f"0x{int(self.disasm.get_entry_point()):08X}" if self.disasm else "",
                "hashes": hashes,
            }
            strings_rows = self.str_view.toPlainText().splitlines()[:3000]
            self._threat_narrative = build_threat_narrative(
                behavior_patterns=getattr(self, "_behavior_patterns", {}) or {},
                api_semantics=getattr(self, "_api_semantics_by_function", {}) or {},
                data_flow_insights=getattr(self, "_data_flow_by_function", {}) or {},
                function_intelligence=normalize_function_intel_summary(getattr(self, "_function_intel_summary", {}) or {}),
                call_graph_intelligence=getattr(self, "_call_graph_summary", {}) or {},
                cfg_intelligence=getattr(self, "_cfg_intel_summary", {}) or {},
                hashes_and_metadata=meta,
                extracted_strings=strings_rows,
            )
            self._render_threat_narrative()
        except Exception as e:
            self._threat_narrative = {"error": str(e)}
            self.threat_narrative_view.setPlainText(f"Threat narrative error: {e}")

    def _render_threat_narrative(self):
        n = self._threat_narrative or {}
        if not isinstance(n, dict) or not n:
            self.threat_narrative_view.setPlainText("No threat narrative available.")
            return
        if n.get("error"):
            self.threat_narrative_view.setPlainText(f"Threat narrative error: {n.get('error')}")
            return
        lines = [
            "[Threat Overview]",
            f"Summary: {(n.get('threat_overview') or {}).get('summary', '-')}",
            "Evidence:",
        ]
        lines.extend([f"  - {x}" for x in ((n.get("threat_overview") or {}).get("evidence") or [])[:8]])
        lines.extend(["", "[Capability Summary]"])
        for row in (n.get("capability_summary") or [])[:12]:
            lines.append(f"  - {row.get('capability')} (confidence={row.get('confidence')})")
            for ev in (row.get("evidence") or [])[:2]:
                lines.append(f"      evidence: {ev}")
        lines.extend(["", "[Execution Flow Summary]"])
        lines.extend([f"  - {x}" for x in (n.get("execution_flow_summary") or [])[:8]])
        lines.extend(["", "[Key Functions]"])
        for row in (n.get("key_functions") or [])[:10]:
            lines.append(f"  - {row.get('function')} | role={row.get('role')}")
            for ev in (row.get("evidence") or [])[:2]:
                lines.append(f"      evidence: {ev}")
            lines.append(f"      why: {row.get('why_it_matters')}")
        ioc = n.get("indicators_of_compromise") or {}
        lines.extend([
            "",
            "[Indicators of Compromise (IoC)]",
            f"URLs: {ioc.get('urls', [])[:8]}",
            f"IPs: {ioc.get('ips', [])[:8]}",
            f"File paths: {ioc.get('file_paths', [])[:8]}",
            f"Mutexes: {ioc.get('mutexes', [])[:8]}",
            f"Relevant API usage: {(ioc.get('relevant_api_usage', [])[:8])}",
            "",
            "[Risk Assessment]",
            f"Level: {(n.get('risk_assessment') or {}).get('level', '-')}",
            f"Reason: {(n.get('risk_assessment') or {}).get('reason', '-')}",
            "",
            "[Caveats]",
        ])
        lines.extend([f"  - {x}" for x in (n.get("caveats") or [])])
        self.threat_narrative_view.setPlainText("\n".join(lines))

    def _render_function_profile(self, va: int):
        prof = getattr(self, "_function_profiles", {}).get(va)
        if not prof:
            self.function_details_view.setPlainText(
                f"Function: 0x{va:08X}\nNo function intelligence profile available."
            )
            return
        d = prof.to_dict()
        lines = [
            f"Function: {d['start_hex']} -> {d['end_hex'] or 'EOF'}",
            f"Size estimate: {d['size_estimate']}",
            f"Instruction count: {d['instruction_count']}",
            f"Basic blocks (est): {d['basic_block_count']}",
            f"Inbound xrefs: {d['inbound_xrefs']}",
            f"Outbound xrefs: {d['outbound_xrefs']}",
            f"Calls made: {', '.join([f'0x{x:08X}' for x in d['calls_made']]) or '-'}",
            f"Referenced APIs: {', '.join(d['referenced_apis']) or '-'}",
            f"Suspicious APIs: {', '.join(d['suspicious_api_usage']) or '-'}",
            f"Referenced strings: {', '.join(d['referenced_strings'][:8]) or '-'}",
            f"Risk indicators: {', '.join(d['risk_indicators']) or '-'}",
            f"Comments: {', '.join(d['comments']) or '-'}",
            f"Labels: {', '.join(d['labels']) or '-'}",
            f"Bookmarked: {d['bookmarks']}",
            "",
            "[Stack/Calling Heuristics]",
            f"Prologue: {d['prologue_pattern'] or '-'}",
            f"Epilogue: {d['epilogue_pattern'] or '-'}",
            f"Frame size estimate: {d['stack_frame_size_estimate']}",
            f"Local offsets: {', '.join(d['local_offsets_estimate']) or '-'}",
            f"Argument offsets: {', '.join(d['argument_offsets_estimate']) or '-'}",
            f"Calling convention hint: {d['calling_convention_hint']}",
            "",
            d.get("heuristic_note", ""),
        ]
        behavior = (self._behavior_summaries or {}).get(f"0x{va:08X}") or {}
        if behavior:
            lines.extend([
                "",
                "[Behavioral Summary (Heuristic)]",
                f"Summary: {behavior.get('short_behavior_summary', '-')}",
                f"Confidence: {behavior.get('confidence', 'low')}",
                f"Possible capability tags: {', '.join(behavior.get('possible_capability_tags', [])) or '-'}",
                "Evidence:",
            ])
            lines.extend([f"  - {x}" for x in behavior.get("evidence_bullets", [])])
            lines.append("Caveats:")
            lines.extend([f"  - {x}" for x in behavior.get("caveats", [])])
        sugg = (self._naming_suggestions or {}).get(f"0x{va:08X}") or {}
        if sugg:
            lines.extend([
                "",
                "[Symbol & Naming Intelligence]",
                f"Suggested name: {sugg.get('suggested_name', '-')}",
                f"Confidence: {sugg.get('confidence', 'low')}",
                "Evidence:",
            ])
            lines.extend([f"  - {x}" for x in sugg.get("evidence_bullets", [])])
            lines.append("Caveats:")
            lines.extend([f"  - {x}" for x in sugg.get("caveats", [])])
        flow = (self._data_flow_by_function or {}).get(f"0x{va:08X}") or {}
        if flow:
            lines.extend([
                "",
                "[Data Flow Insights (Estimated)]",
                f"Heuristic note: {flow.get('heuristic_note', '-')}",
                f"API argument insights: {len(flow.get('api_argument_insights', []))}",
                f"String flows: {len(flow.get('string_flows', []))}",
            ])
            for row in (flow.get("api_argument_insights") or [])[:6]:
                lines.append(f"  - API {row.get('api')} @ {row.get('call_site')} ({row.get('confidence')}): estimated args={row.get('arguments')}")
            for row in (flow.get("string_flows") or [])[:6]:
                lines.append(f"  - String '{row.get('string')}' -> {row.get('api')} via {row.get('via_register')} @ {row.get('call_site')} [estimated]")
        sem = (self._api_semantics_by_function or {}).get(f"0x{va:08X}") or {}
        if sem:
            lines.extend([
                "",
                "[API Semantics Intelligence (Estimated)]",
                f"Note: {sem.get('heuristic_note', '-')}",
            ])
            for row in (sem.get("high_value_calls") or sem.get("api_semantics_calls") or [])[:8]:
                lines.append(
                    f"  - {row.get('api')} @ {row.get('call_site')}: tags={row.get('capability_tags')} | args={row.get('interpreted_arguments')} | evidence={row.get('evidence')}"
                )
        bp = (self._behavior_patterns or {}).get("patterns") or []
        rel = [r for r in bp if f"0x{va:08X}" in (r.get("involved_functions") or [])]
        if rel:
            lines.extend([
                "",
                "[Behavior Patterns (Estimated Candidates)]",
                f"Note: {(self._behavior_patterns or {}).get('heuristic_note', '-')}",
            ])
            for row in rel[:6]:
                lines.append(f"  - Pattern={row.get('pattern')} | confidence={row.get('confidence')} | scope={row.get('scope')}")
                for ev in (row.get("evidence_chain") or [])[:5]:
                    lines.append(f"      evidence: {ev}")
                for cv in (row.get("caveats") or [])[:2]:
                    lines.append(f"      caveat: {cv}")
        self.function_details_view.setPlainText("\n".join(lines))

    def _rename_function(self, va: int):
        old = self._display_func_name(va, self._functions.get(va, f"sub_{va:08X}"))
        new_name, ok = QInputDialog.getText(self, "Rename Function", "Function name:", text=old)
        if not ok:
            return
        new_name = new_name.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$", new_name):
            QMessageBox.warning(self, "Rename", "Invalid function name format.")
            return
        all_names = {self._display_func_name(v, n) for v, n in getattr(self, "_functions", {}).items() if v != va}
        if new_name in all_names:
            QMessageBox.warning(self, "Rename", "A function with this name already exists.")
            return
        key = f"0x{va:08X}"
        self.session.renamed_functions[key] = new_name
        self._rebuild_function_intelligence()
        self._rebuild_naming_intelligence()
        self._refresh_function_list()
        self._save_session_for_current_file()
        self.console(f"Renamed {key} -> {new_name}")

    def _apply_suggested_name(self, va: int):
        key = f"0x{va:08X}"
        row = (self._naming_suggestions or {}).get(key) or {}
        nm = row.get("suggested_name")
        if not nm:
            QMessageBox.information(self, "Suggested Name", f"No suggested name for {key}.")
            return
        if key in self.session.renamed_functions:
            ans = QMessageBox.question(
                self,
                "Overwrite analyst name?",
                f"{key} already has analyst name '{self.session.renamed_functions[key]}'. Overwrite with '{nm}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
        self.session.renamed_functions[key] = nm
        self._applied_suggested_names[key] = nm
        self._refresh_function_list()
        self._save_session_for_current_file()

    def _apply_all_high_confidence_suggested_names(self):
        suggestions = self._naming_suggestions or {}
        overwrite = False
        if any(k in self.session.renamed_functions for k in suggestions):
            ans = QMessageBox.question(
                self,
                "Overwrite analyst names?",
                "Some functions already have analyst names. Allow overwrite while applying high-confidence suggestions?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            overwrite = ans == QMessageBox.StandardButton.Yes
        apply_map = select_high_confidence_applications(
            suggestions=suggestions,
            analyst_renamed=self.session.renamed_functions,
            allow_overwrite=overwrite,
        )
        if not apply_map:
            QMessageBox.information(self, "Suggested Names", "No high-confidence names to apply.")
            return
        self.session.renamed_functions.update(apply_map)
        self._applied_suggested_names.update(apply_map)
        self._refresh_function_list()
        self._save_session_for_current_file()

    def _address_under_cursor(self, edit: QTextEdit) -> int | None:
        cur = edit.textCursor()
        cur.select(QTextCursor.SelectionType.LineUnderCursor)
        line = cur.selectedText()
        m = re.search(r"0x([0-9A-Fa-f]{6,16})", line)
        if not m:
            return None
        return int(m.group(0), 16)

    def on_asm_context_menu(self, pos):
        edit = self.sender()
        if not isinstance(edit, QTextEdit):
            edit = self.asm_view
        va = self._address_under_cursor(edit)
        m = QMenu(self)
        a_comment = m.addAction("Add/Edit Comment")
        a_label = m.addAction("Add/Edit Label")
        a_bookmark = m.addAction("Toggle Bookmark")
        a_xrefs_to = m.addAction("Show Xrefs to this address")
        a_xrefs_from = m.addAction("Show references from this function")
        act = m.exec(edit.mapToGlobal(pos))
        if va is None:
            return
        if act == a_comment:
            self._edit_comment(va)
        elif act == a_label:
            self._edit_label(va)
        elif act == a_bookmark:
            self._toggle_bookmark(va)
        elif act == a_xrefs_to:
            self._show_xrefs_to(va)
        elif act == a_xrefs_from:
            self._show_refs_from_current_function()

    def on_string_context_menu(self, pos):
        m = QMenu(self)
        a1 = m.addAction("Show String Xrefs")
        act = m.exec(self.str_view.mapToGlobal(pos))
        if act == a1:
            self._show_string_usage_from_cursor()

    def on_import_context_menu(self, pos):
        cur = self.imports_view.textCursor()
        cur.select(QTextCursor.SelectionType.LineUnderCursor)
        line = cur.selectedText().strip()
        m = QMenu(self)
        a1 = m.addAction("Show API references")
        act = m.exec(self.imports_view.mapToGlobal(pos))
        if act != a1 or not line:
            return
        api = line.split()[-1]
        rows = [x for x in getattr(self, "_xrefs", []) if x.api and api.lower() in x.api.lower()]
        self.xrefs_to_view.clear()
        for x in rows:
            self.xrefs_to_view.addItem(f"0x{x.src:08X} -> {x.api} [{x.xref_type}|{x.confidence}] {x.instruction}")
        if not rows:
            self.xrefs_to_view.addItem(f"No references found for {api}")
        self.tabs.setCurrentWidget(self.xrefs_to_view)

    def _show_string_usage_from_cursor(self):
        cur = self.str_view.textCursor()
        cur.select(QTextCursor.SelectionType.LineUnderCursor)
        s = cur.selectedText().strip()
        if not s:
            return
        rows = [x for x in getattr(self, "_xrefs", []) if x.string_value and s in x.string_value]
        self.xrefs_to_view.clear()
        for x in rows:
            dst = f"0x{x.dst:08X}" if x.dst is not None else "<unresolved>"
            self.xrefs_to_view.addItem(f"0x{x.src:08X} -> {dst} [string] {x.string_value}")
        if not rows:
            self.xrefs_to_view.addItem("No string references found (first-pass xref limitations).")
        self.tabs.setCurrentWidget(self.xrefs_to_view)

    def _edit_comment(self, va: int):
        key = f"0x{va:08X}"
        old = self.session.comments.get(key, "")
        txt, ok = QInputDialog.getText(self, "Comment", f"Comment for {key}:", text=old)
        if ok:
            if txt.strip():
                self.session.comments[key] = txt.strip()
            else:
                self.session.comments.pop(key, None)
            self._rebuild_function_intelligence()
            self._rebuild_naming_intelligence()
            self._refresh_function_list()
            self._save_session_for_current_file()
            self._reannotate_disassembly_views()

    def _edit_label(self, va: int):
        key = f"0x{va:08X}"
        old = self.session.labels.get(key, "")
        txt, ok = QInputDialog.getText(self, "Label", f"Label for {key}:", text=old)
        if ok:
            if txt.strip():
                self.session.labels[key] = txt.strip()
            else:
                self.session.labels.pop(key, None)
            self._rebuild_function_intelligence()
            self._rebuild_naming_intelligence()
            self._refresh_function_list()
            self._save_session_for_current_file()
            self._reannotate_disassembly_views()

    def _toggle_bookmark(self, va: int):
        key = f"0x{va:08X}"
        if key in self.session.bookmarks:
            self.session.bookmarks.remove(key)
        else:
            self.session.bookmarks.append(key)
        self._rebuild_function_intelligence()
        self._rebuild_naming_intelligence()
        self._refresh_function_list()
        self._save_session_for_current_file()
        self._refresh_bookmarks_panel()

    def _refresh_bookmarks_panel(self):
        self.bookmarks_view.clear()
        for key in sorted(set(self.session.bookmarks)):
            label = self.session.labels.get(key) or self.session.comments.get(key) or ""
            self.bookmarks_view.addItem(f"{key}  {label}")

    def on_bookmark_double_clicked(self, item):
        m = re.match(r"(0x[0-9A-Fa-f]+)", item.text().strip())
        if not m:
            return
        va = int(m.group(1), 16)
        self._open_in_erevos_view(va, self.session.labels.get(m.group(1), f"sub_{va:08X}"))

    def _reannotate_disassembly_views(self):
        # lightweight re-annotation of currently visible disassembly text
        self._annotate_editor(self.asm_view)
        self._annotate_editor(self.hex_view)

    def _annotate_editor(self, edit: QTextEdit):
        lines = edit.toPlainText().splitlines()
        out = []
        for ln in lines:
            m = re.match(r"0x([0-9A-Fa-f]{6,16}):", ln.strip())
            if m:
                key = "0x" + m.group(1).upper()
                ann = []
                if key in self.session.labels:
                    ann.append(f"label={self.session.labels[key]}")
                if key in self.session.comments:
                    ann.append(f"comment={self.session.comments[key]}")
                if key in self.session.bookmarks:
                    ann.append("bookmark")
                if ann and "; [" not in ln:
                    ln += "    ; [" + " | ".join(ann) + "]"
            out.append(ln)
        edit.setPlainText("\n".join(out))

    def _show_xrefs_to(self, va: int):
        self.xrefs_to_view.clear()
        rows = [x for x in getattr(self, "_xrefs", []) if x.dst == va or x.dst_function == va]
        for x in rows:
            dst = f"0x{x.dst:08X}" if x.dst is not None else "<unresolved>"
            src = f"0x{x.src:08X}"
            self.xrefs_to_view.addItem(f"{src} -> {dst} [{x.xref_type}|{x.confidence}] {x.instruction}")
        if not rows:
            self.xrefs_to_view.addItem(f"No xrefs to 0x{va:08X}. (Limitations apply for indirect flows)")
        self.tabs.setCurrentWidget(self.xrefs_to_view)

    def _show_refs_from_current_function(self):
        va = self._address_under_cursor(self.asm_view)
        src_func = None
        if va is not None:
            for fva in sorted(getattr(self, "_functions", {}).keys()):
                if fva <= va:
                    src_func = fva
                else:
                    break
        self.xrefs_from_view.clear()
        rows = [x for x in getattr(self, "_xrefs", []) if (src_func is not None and x.src_function == src_func)]
        for x in rows:
            dst = f"0x{x.dst:08X}" if x.dst is not None else "<unresolved>"
            src = f"0x{x.src:08X}"
            self.xrefs_from_view.addItem(f"{src} -> {dst} [{x.xref_type}|{x.confidence}] {x.instruction}")
        if not rows:
            self.xrefs_from_view.addItem("No outbound refs found for selected function.")
        self.tabs.setCurrentWidget(self.xrefs_from_view)

    def on_xref_item_double_clicked(self, item):
        m = re.search(r"->\\s+(0x[0-9A-Fa-f]+)", item.text())
        if not m:
            return
        va = int(m.group(1), 16)
        self._open_in_erevos_view(va, self.session.labels.get(m.group(1), f"sub_{va:08X}"))

    def on_call_graph_item_double_clicked(self, item):
        txt = item.text()
        m = re.findall(r"0x[0-9A-Fa-f]{6,16}", txt)
        if not m:
            return
        va = int(m[0], 16)
        self._open_in_erevos_view(va, self.session.labels.get(m[0], f"sub_{va:08X}"))

    def _save_session_for_current_file(self):
        if not self.current_file:
            return
        self.session.last_opened_file = self.current_file
        self.session.function_intel_summary = normalize_function_intel_summary(getattr(self, "_function_intel_summary", {}) or {})
        self.session.behavior_summaries = dict(getattr(self, "_behavior_summaries", {}) or {})
        self.session.call_graph_summary = dict(getattr(self, "_call_graph_summary", {}) or {})
        self.session.cfg_intel_summary = dict(getattr(self, "_cfg_intel_summary", {}) or {})
        self.session.naming_suggestions = dict(getattr(self, "_naming_suggestions", {}) or {})
        self.session.applied_suggested_names = dict(getattr(self, "_applied_suggested_names", {}) or {})
        self.session.data_flow_insights = dict(getattr(self, "_data_flow_by_function", {}) or {})
        self.session.api_semantics_insights = dict(getattr(self, "_api_semantics_by_function", {}) or {})
        self.session.behavior_patterns = dict(getattr(self, "_behavior_patterns", {}) or {})
        self.session.threat_narrative = normalize_threat_narrative(getattr(self, "_threat_narrative", {}) or {})
        p = self.session_path or SessionState.session_path_for_sample(self.current_file)
        self.session.save(p)

    def _load_session_for_current_file(self):
        if not self.current_file:
            return
        p = self.session_path or SessionState.session_path_for_sample(self.current_file)
        self.session = SessionState.load(p)
        self._function_intel_summary = normalize_function_intel_summary(self.session.function_intel_summary)
        self._behavior_summaries = dict(self.session.behavior_summaries or {})
        self._call_graph_summary = dict(self.session.call_graph_summary or {})
        self._cfg_intel_summary = dict(self.session.cfg_intel_summary or {})
        self._naming_suggestions = dict(self.session.naming_suggestions or {})
        self._applied_suggested_names = dict(self.session.applied_suggested_names or {})
        self._data_flow_by_function = dict(self.session.data_flow_insights or {})
        self._api_semantics_by_function = dict(self.session.api_semantics_insights or {})
        self._behavior_patterns = dict(self.session.behavior_patterns or {})
        self._threat_narrative = normalize_threat_narrative(self.session.threat_narrative)
        self._render_threat_narrative()

    def action_save_session(self):
        if not self.current_file:
            return
        self._save_session_for_current_file()
        QMessageBox.information(self, "Session", f"Session saved: {self.session_path}")

    def action_load_session(self):
        if not self.current_file:
            return
        self._load_session_for_current_file()
        self._rebuild_function_intelligence()
        self._rebuild_call_graph()
        self._rebuild_naming_intelligence()
        self._rebuild_threat_narrative()
        self._refresh_function_list()
        self._refresh_bookmarks_panel()
        self._reannotate_disassembly_views()
        QMessageBox.information(self, "Session", f"Session loaded: {self.session_path}")

    def action_global_search(self):
        q, ok = QInputDialog.getText(self, "Global Search", "Search across functions/strings/imports/addresses/comments:")
        if not ok or not q.strip():
            return
        ql = q.strip().lower()
        hits = []
        for va, name in getattr(self, "_functions", {}).items():
            dname = self._display_func_name(va, name)
            blob = f"0x{va:08X} {dname}".lower()
            if ql in blob:
                hits.append(f"FUNC 0x{va:08X} {dname}")
        for k, v in self.session.comments.items():
            if ql in (k.lower() + " " + v.lower()):
                hits.append(f"COMMENT {k} {v}")
        for txt in self.str_view.toPlainText().splitlines()[:5000]:
            if ql in txt.lower():
                hits.append(f"STRING {txt[:120]}")
                if len(hits) > 200:
                    break
        QMessageBox.information(self, "Global Search Results", "\n".join(hits[:200]) if hits else "No results.")

    # ----------------- Analyst workspace features -----------------
    def _display_func_name(self, va: int, fallback: str) -> str:
        return self.session.renamed_functions.get(f"0x{va:08X}", fallback)

    def _rebuild_xrefs(self):
        try:
            text = self.asm_view.toPlainText()
            strings_map = {}
            if extract_strings_with_locations and self.disasm:
                try:
                    hits = extract_strings_with_locations(self.disasm.pe, min_len=4, limit=5000)
                    strings_map = {int(h.va): h.text for h in hits}
                except Exception:
                    strings_map = {}
            imports = self.disasm.get_imports() if self.disasm else []
            self._xrefs = extract_structured_xrefs(text, functions=getattr(self, "_functions", {}), strings_by_addr=strings_map, imports=imports)
            self._xrefs_summary = summarize_xrefs(self._xrefs)
        except Exception as e:
            self._xrefs = []
            self._xrefs_summary = {"error": str(e)}

    def _rebuild_function_intelligence(self):
        try:
            disasm_text = self.asm_view.toPlainText()
            self._function_profiles = build_function_profiles(
                disasm_text=disasm_text,
                functions=getattr(self, "_functions", {}),
                xrefs=getattr(self, "_xrefs", []),
                comments=self.session.comments,
                labels=self.session.labels,
                bookmarks=self.session.bookmarks,
            )
            self._function_intel_summary = normalize_function_intel_summary(summarize_function_intelligence(
                self._function_profiles, self.session.renamed_functions
            ))
            self._behavior_summaries = generate_all_behavior_summaries(self._function_profiles)
            self.session.function_intel_summary = self._function_intel_summary
            self.session.behavior_summaries = self._behavior_summaries
        except Exception as e:
            self._function_profiles = {}
            self._function_intel_summary = {"error": str(e)}
            self._behavior_summaries = {}

    def _rebuild_call_graph(self):
        try:
            self._call_graph_model = build_call_graph_model(
                profiles=getattr(self, "_function_profiles", {}),
                xrefs=getattr(self, "_xrefs", []),
            )
            ep = self.disasm.get_entry_point() if self.disasm else None
            self._call_graph_summary = analyze_call_graph(self._call_graph_model, entry_point=ep)
            self.session.call_graph_summary = self._call_graph_summary
            self._refresh_call_graph_panel()
            self._rebuild_behavior_patterns()
            self._rebuild_threat_narrative()
        except Exception as e:
            self._call_graph_model = {}
            self._call_graph_summary = {"error": str(e)}
            self.call_graph_view.clear()
            self.call_graph_view.addItem(f"Call graph error: {e}")

    def _refresh_call_graph_panel(self):
        self.call_graph_view.clear()
        if not self._call_graph_summary:
            self.call_graph_view.addItem("No call graph summary available.")
            return
        for row in (self._call_graph_summary.get("top_hub_functions") or [])[:20]:
            mark = " [SUSP]" if row.get("suspicious") else ""
            self.call_graph_view.addItem(
                f"HUB {row.get('address')} in={row.get('inbound_degree',0)} out={row.get('outbound_degree',0)}{mark}"
            )
        for edge in (self._call_graph_model.get("edges") or [])[:80]:
            mark = " [SUSP]" if edge.get("suspicious_indicator") else ""
            self.call_graph_view.addItem(
                f"EDGE {edge.get('caller')} -> {edge.get('callee')} calls={edge.get('call_count',0)} conf={edge.get('confidence','?')}{mark}"
            )

    def _update_cfg_intel_for_function(self, va: int):
        try:
            asm = self._disasm_function_text(va)
            model = build_function_cfg_model(asm, function_start=va)
            analysis = analyze_function_cfg(model)
            self._cfg_intel_summary[f"0x{va:08X}"] = {
                "model": model,
                "analysis": analysis,
            }
            lines = [
                f"Function: 0x{va:08X}",
                f"Basic blocks: {analysis.get('basic_block_count', 0)}",
                f"Branches: {analysis.get('branch_count', 0)}",
                f"Branch density: {analysis.get('branch_density', 0)}",
                f"Unresolved edges: {analysis.get('unresolved_edge_count', 0)}",
                f"Loop/back-edge hints: {analysis.get('loop_back_edge_hints', [])}",
                f"Unreachable block hints: {analysis.get('unreachable_block_hints', [])}",
                f"Possible opaque predicate hints: {analysis.get('possible_opaque_predicate_hints', [])}",
                f"Suspicious CFG indicators: {analysis.get('suspicious_control_flow_indicators', [])}",
            ]
            self.cfg_intel_view.setPlainText("\n".join(lines))
        except Exception as e:
            self.cfg_intel_view.setPlainText(f"CFG intelligence error: {e}")

    def _rebuild_naming_intelligence(self):
        try:
            self._naming_suggestions = generate_all_name_suggestions(
                profiles=getattr(self, "_function_profiles", {}),
                behavior_summaries=getattr(self, "_behavior_summaries", {}),
                call_graph_summary=getattr(self, "_call_graph_summary", {}),
            )
            self.session.naming_suggestions = dict(self._naming_suggestions)
            self.session.applied_suggested_names = dict(self._applied_suggested_names)
        except Exception as e:
            self._naming_suggestions = {}
            self.console(f"Naming intelligence error: {e}")

    def _update_data_flow_for_function(self, va: int):
        try:
            asm = self._disasm_function_text(va)
            strings_map = {}
            for x in getattr(self, "_xrefs", []):
                if x.xref_type == "string" and isinstance(x.dst, int) and x.string_value:
                    strings_map[int(x.dst)] = x.string_value
            fx = [x for x in getattr(self, "_xrefs", []) if x.src_function == va or x.dst_function == va]
            self._data_flow_by_function[f"0x{va:08X}"] = analyze_function_data_flow(
                disasm_text=asm,
                xrefs=fx,
                strings_by_addr=strings_map,
            )
            self._api_semantics_by_function[f"0x{va:08X}"] = interpret_api_semantics(
                self._data_flow_by_function[f"0x{va:08X}"]
            )
            self._rebuild_behavior_patterns()
            self._rebuild_threat_narrative()
        except Exception as e:
            self._data_flow_by_function[f"0x{va:08X}"] = {"error": str(e)}
            self._api_semantics_by_function[f"0x{va:08X}"] = {"error": str(e)}
            self._behavior_patterns = {"error": str(e)}
            self._threat_narrative = {"error": str(e)}

    def _rebuild_behavior_patterns(self):
        try:
            self._behavior_patterns = detect_behavior_patterns(
                api_semantics_by_function=getattr(self, "_api_semantics_by_function", {}) or {},
                data_flow_by_function=getattr(self, "_data_flow_by_function", {}) or {},
                call_graph_model=getattr(self, "_call_graph_model", {}) or {},
                call_graph_summary=getattr(self, "_call_graph_summary", {}) or {},
            )
        except Exception as e:
            self._behavior_patterns = {"error": str(e)}

    def _rebuild_threat_narrative(self):
        try:
            hashes = {}
            if self.current_file:
                import hashlib
                p = Path(self.current_file)
                b = p.read_bytes() if p.exists() else b""
                hashes = {
                    "sha256": hashlib.sha256(b).hexdigest() if b else "",
                    "md5": hashlib.md5(b).hexdigest() if b else "",
                }
            meta = {
                "path": self.current_file or "",
                "entry_point": f"0x{int(self.disasm.get_entry_point()):08X}" if self.disasm else "",
                "hashes": hashes,
            }
            strings_rows = self.str_view.toPlainText().splitlines()[:3000]
            self._threat_narrative = build_threat_narrative(
                behavior_patterns=getattr(self, "_behavior_patterns", {}) or {},
                api_semantics=getattr(self, "_api_semantics_by_function", {}) or {},
                data_flow_insights=getattr(self, "_data_flow_by_function", {}) or {},
                function_intelligence=normalize_function_intel_summary(getattr(self, "_function_intel_summary", {}) or {}),
                call_graph_intelligence=getattr(self, "_call_graph_summary", {}) or {},
                cfg_intelligence=getattr(self, "_cfg_intel_summary", {}) or {},
                hashes_and_metadata=meta,
                extracted_strings=strings_rows,
            )
            self._render_threat_narrative()
        except Exception as e:
            self._threat_narrative = {"error": str(e)}
            self.threat_narrative_view.setPlainText(f"Threat narrative error: {e}")

    def _render_threat_narrative(self):
        n = self._threat_narrative or {}
        if not isinstance(n, dict) or not n:
            self.threat_narrative_view.setPlainText("No threat narrative available.")
            return
        if n.get("error"):
            self.threat_narrative_view.setPlainText(f"Threat narrative error: {n.get('error')}")
            return
        lines = [
            "[Threat Overview]",
            f"Summary: {(n.get('threat_overview') or {}).get('summary', '-')}",
            "Evidence:",
        ]
        lines.extend([f"  - {x}" for x in ((n.get("threat_overview") or {}).get("evidence") or [])[:8]])
        lines.extend(["", "[Capability Summary]"])
        for row in (n.get("capability_summary") or [])[:12]:
            lines.append(f"  - {row.get('capability')} (confidence={row.get('confidence')})")
            for ev in (row.get("evidence") or [])[:2]:
                lines.append(f"      evidence: {ev}")
        lines.extend(["", "[Execution Flow Summary]"])
        lines.extend([f"  - {x}" for x in (n.get("execution_flow_summary") or [])[:8]])
        lines.extend(["", "[Key Functions]"])
        for row in (n.get("key_functions") or [])[:10]:
            lines.append(f"  - {row.get('function')} | role={row.get('role')}")
            for ev in (row.get("evidence") or [])[:2]:
                lines.append(f"      evidence: {ev}")
            lines.append(f"      why: {row.get('why_it_matters')}")
        ioc = n.get("indicators_of_compromise") or {}
        lines.extend([
            "",
            "[Indicators of Compromise (IoC)]",
            f"URLs: {ioc.get('urls', [])[:8]}",
            f"IPs: {ioc.get('ips', [])[:8]}",
            f"File paths: {ioc.get('file_paths', [])[:8]}",
            f"Mutexes: {ioc.get('mutexes', [])[:8]}",
            f"Relevant API usage: {(ioc.get('relevant_api_usage', [])[:8])}",
            "",
            "[Risk Assessment]",
            f"Level: {(n.get('risk_assessment') or {}).get('level', '-')}",
            f"Reason: {(n.get('risk_assessment') or {}).get('reason', '-')}",
            "",
            "[Caveats]",
        ])
        lines.extend([f"  - {x}" for x in (n.get("caveats") or [])])
        self.threat_narrative_view.setPlainText("\n".join(lines))

    def _render_function_profile(self, va: int):
        prof = getattr(self, "_function_profiles", {}).get(va)
        if not prof:
            self.function_details_view.setPlainText(
                f"Function: 0x{va:08X}\nNo function intelligence profile available."
            )
            return
        d = prof.to_dict()
        lines = [
            f"Function: {d['start_hex']} -> {d['end_hex'] or 'EOF'}",
            f"Size estimate: {d['size_estimate']}",
            f"Instruction count: {d['instruction_count']}",
            f"Basic blocks (est): {d['basic_block_count']}",
            f"Inbound xrefs: {d['inbound_xrefs']}",
            f"Outbound xrefs: {d['outbound_xrefs']}",
            f"Calls made: {', '.join([f'0x{x:08X}' for x in d['calls_made']]) or '-'}",
            f"Referenced APIs: {', '.join(d['referenced_apis']) or '-'}",
            f"Suspicious APIs: {', '.join(d['suspicious_api_usage']) or '-'}",
            f"Referenced strings: {', '.join(d['referenced_strings'][:8]) or '-'}",
            f"Risk indicators: {', '.join(d['risk_indicators']) or '-'}",
            f"Comments: {', '.join(d['comments']) or '-'}",
            f"Labels: {', '.join(d['labels']) or '-'}",
            f"Bookmarked: {d['bookmarks']}",
            "",
            "[Stack/Calling Heuristics]",
            f"Prologue: {d['prologue_pattern'] or '-'}",
            f"Epilogue: {d['epilogue_pattern'] or '-'}",
            f"Frame size estimate: {d['stack_frame_size_estimate']}",
            f"Local offsets: {', '.join(d['local_offsets_estimate']) or '-'}",
            f"Argument offsets: {', '.join(d['argument_offsets_estimate']) or '-'}",
            f"Calling convention hint: {d['calling_convention_hint']}",
            "",
            d.get("heuristic_note", ""),
        ]
        behavior = (self._behavior_summaries or {}).get(f"0x{va:08X}") or {}
        if behavior:
            lines.extend([
                "",
                "[Behavioral Summary (Heuristic)]",
                f"Summary: {behavior.get('short_behavior_summary', '-')}",
                f"Confidence: {behavior.get('confidence', 'low')}",
                f"Possible capability tags: {', '.join(behavior.get('possible_capability_tags', [])) or '-'}",
                "Evidence:",
            ])
            lines.extend([f"  - {x}" for x in behavior.get("evidence_bullets", [])])
            lines.append("Caveats:")
            lines.extend([f"  - {x}" for x in behavior.get("caveats", [])])
        sugg = (self._naming_suggestions or {}).get(f"0x{va:08X}") or {}
        if sugg:
            lines.extend([
                "",
                "[Symbol & Naming Intelligence]",
                f"Suggested name: {sugg.get('suggested_name', '-')}",
                f"Confidence: {sugg.get('confidence', 'low')}",
                "Evidence:",
            ])
            lines.extend([f"  - {x}" for x in sugg.get("evidence_bullets", [])])
            lines.append("Caveats:")
            lines.extend([f"  - {x}" for x in sugg.get("caveats", [])])
        flow = (self._data_flow_by_function or {}).get(f"0x{va:08X}") or {}
        if flow:
            lines.extend([
                "",
                "[Data Flow Insights (Estimated)]",
                f"Heuristic note: {flow.get('heuristic_note', '-')}",
                f"API argument insights: {len(flow.get('api_argument_insights', []))}",
                f"String flows: {len(flow.get('string_flows', []))}",
            ])
            for row in (flow.get("api_argument_insights") or [])[:6]:
                lines.append(f"  - API {row.get('api')} @ {row.get('call_site')} ({row.get('confidence')}): estimated args={row.get('arguments')}")
            for row in (flow.get("string_flows") or [])[:6]:
                lines.append(f"  - String '{row.get('string')}' -> {row.get('api')} via {row.get('via_register')} @ {row.get('call_site')} [estimated]")
        sem = (self._api_semantics_by_function or {}).get(f"0x{va:08X}") or {}
        if sem:
            lines.extend([
                "",
                "[API Semantics Intelligence (Estimated)]",
                f"Note: {sem.get('heuristic_note', '-')}",
            ])
            for row in (sem.get("high_value_calls") or sem.get("api_semantics_calls") or [])[:8]:
                lines.append(
                    f"  - {row.get('api')} @ {row.get('call_site')}: tags={row.get('capability_tags')} | args={row.get('interpreted_arguments')} | evidence={row.get('evidence')}"
                )
        bp = (self._behavior_patterns or {}).get("patterns") or []
        rel = [r for r in bp if f"0x{va:08X}" in (r.get("involved_functions") or [])]
        if rel:
            lines.extend([
                "",
                "[Behavior Patterns (Estimated Candidates)]",
                f"Note: {(self._behavior_patterns or {}).get('heuristic_note', '-')}",
            ])
            for row in rel[:6]:
                lines.append(f"  - Pattern={row.get('pattern')} | confidence={row.get('confidence')} | scope={row.get('scope')}")
                for ev in (row.get("evidence_chain") or [])[:5]:
                    lines.append(f"      evidence: {ev}")
                for cv in (row.get("caveats") or [])[:2]:
                    lines.append(f"      caveat: {cv}")
        self.function_details_view.setPlainText("\n".join(lines))

    def _rename_function(self, va: int):
        old = self._display_func_name(va, self._functions.get(va, f"sub_{va:08X}"))
        new_name, ok = QInputDialog.getText(self, "Rename Function", "Function name:", text=old)
        if not ok:
            return
        new_name = new_name.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$", new_name):
            QMessageBox.warning(self, "Rename", "Invalid function name format.")
            return
        all_names = {self._display_func_name(v, n) for v, n in getattr(self, "_functions", {}).items() if v != va}
        if new_name in all_names:
            QMessageBox.warning(self, "Rename", "A function with this name already exists.")
            return
        key = f"0x{va:08X}"
        self.session.renamed_functions[key] = new_name
        self._rebuild_function_intelligence()
        self._rebuild_naming_intelligence()
        self._refresh_function_list()
        self._save_session_for_current_file()
        self.console(f"Renamed {key} -> {new_name}")

    def _apply_suggested_name(self, va: int):
        key = f"0x{va:08X}"
        row = (self._naming_suggestions or {}).get(key) or {}
        nm = row.get("suggested_name")
        if not nm:
            QMessageBox.information(self, "Suggested Name", f"No suggested name for {key}.")
            return
        if key in self.session.renamed_functions:
            ans = QMessageBox.question(
                self,
                "Overwrite analyst name?",
                f"{key} already has analyst name '{self.session.renamed_functions[key]}'. Overwrite with '{nm}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
        self.session.renamed_functions[key] = nm
        self._applied_suggested_names[key] = nm
        self._refresh_function_list()
        self._save_session_for_current_file()

    def _apply_all_high_confidence_suggested_names(self):
        suggestions = self._naming_suggestions or {}
        overwrite = False
        if any(k in self.session.renamed_functions for k in suggestions):
            ans = QMessageBox.question(
                self,
                "Overwrite analyst names?",
                "Some functions already have analyst names. Allow overwrite while applying high-confidence suggestions?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            overwrite = ans == QMessageBox.StandardButton.Yes
        apply_map = select_high_confidence_applications(
            suggestions=suggestions,
            analyst_renamed=self.session.renamed_functions,
            allow_overwrite=overwrite,
        )
        if not apply_map:
            QMessageBox.information(self, "Suggested Names", "No high-confidence names to apply.")
            return
        self.session.renamed_functions.update(apply_map)
        self._applied_suggested_names.update(apply_map)
        self._refresh_function_list()
        self._save_session_for_current_file()

    def _address_under_cursor(self, edit: QTextEdit) -> int | None:
        cur = edit.textCursor()
        cur.select(QTextCursor.SelectionType.LineUnderCursor)
        line = cur.selectedText()
        m = re.search(r"0x([0-9A-Fa-f]{6,16})", line)
        if not m:
            return None
        return int(m.group(0), 16)

    def on_asm_context_menu(self, pos):
        edit = self.sender()
        if not isinstance(edit, QTextEdit):
            edit = self.asm_view
        va = self._address_under_cursor(edit)
        m = QMenu(self)
        a_comment = m.addAction("Add/Edit Comment")
        a_label = m.addAction("Add/Edit Label")
        a_bookmark = m.addAction("Toggle Bookmark")
        a_xrefs_to = m.addAction("Show Xrefs to this address")
        a_xrefs_from = m.addAction("Show references from this function")
        act = m.exec(edit.mapToGlobal(pos))
        if va is None:
            return
        if act == a_comment:
            self._edit_comment(va)
        elif act == a_label:
            self._edit_label(va)
        elif act == a_bookmark:
            self._toggle_bookmark(va)
        elif act == a_xrefs_to:
            self._show_xrefs_to(va)
        elif act == a_xrefs_from:
            self._show_refs_from_current_function()

    def on_string_context_menu(self, pos):
        m = QMenu(self)
        a1 = m.addAction("Show String Xrefs")
        act = m.exec(self.str_view.mapToGlobal(pos))
        if act == a1:
            self._show_string_usage_from_cursor()

    def on_import_context_menu(self, pos):
        cur = self.imports_view.textCursor()
        cur.select(QTextCursor.SelectionType.LineUnderCursor)
        line = cur.selectedText().strip()
        m = QMenu(self)
        a1 = m.addAction("Show API references")
        act = m.exec(self.imports_view.mapToGlobal(pos))
        if act != a1 or not line:
            return
        api = line.split()[-1]
        rows = [x for x in getattr(self, "_xrefs", []) if x.api and api.lower() in x.api.lower()]
        self.xrefs_to_view.clear()
        for x in rows:
            self.xrefs_to_view.addItem(f"0x{x.src:08X} -> {x.api} [{x.xref_type}|{x.confidence}] {x.instruction}")
        if not rows:
            self.xrefs_to_view.addItem(f"No references found for {api}")
        self.tabs.setCurrentWidget(self.xrefs_to_view)

    def _show_string_usage_from_cursor(self):
        cur = self.str_view.textCursor()
        cur.select(QTextCursor.SelectionType.LineUnderCursor)
        s = cur.selectedText().strip()
        if not s:
            return
        rows = [x for x in getattr(self, "_xrefs", []) if x.string_value and s in x.string_value]
        self.xrefs_to_view.clear()
        for x in rows:
            dst = f"0x{x.dst:08X}" if x.dst is not None else "<unresolved>"
            self.xrefs_to_view.addItem(f"0x{x.src:08X} -> {dst} [string] {x.string_value}")
        if not rows:
            self.xrefs_to_view.addItem("No string references found (first-pass xref limitations).")
        self.tabs.setCurrentWidget(self.xrefs_to_view)

    def _edit_comment(self, va: int):
        key = f"0x{va:08X}"
        old = self.session.comments.get(key, "")
        txt, ok = QInputDialog.getText(self, "Comment", f"Comment for {key}:", text=old)
        if ok:
            if txt.strip():
                self.session.comments[key] = txt.strip()
            else:
                self.session.comments.pop(key, None)
            self._rebuild_function_intelligence()
            self._rebuild_naming_intelligence()
            self._refresh_function_list()
            self._save_session_for_current_file()
            self._reannotate_disassembly_views()

    def _edit_label(self, va: int):
        key = f"0x{va:08X}"
        old = self.session.labels.get(key, "")
        txt, ok = QInputDialog.getText(self, "Label", f"Label for {key}:", text=old)
        if ok:
            if txt.strip():
                self.session.labels[key] = txt.strip()
            else:
                self.session.labels.pop(key, None)
            self._rebuild_function_intelligence()
            self._rebuild_naming_intelligence()
            self._refresh_function_list()
            self._save_session_for_current_file()
            self._reannotate_disassembly_views()

    def _toggle_bookmark(self, va: int):
        key = f"0x{va:08X}"
        if key in self.session.bookmarks:
            self.session.bookmarks.remove(key)
        else:
            self.session.bookmarks.append(key)
        self._rebuild_function_intelligence()
        self._rebuild_naming_intelligence()
        self._refresh_function_list()
        self._save_session_for_current_file()
        self._refresh_bookmarks_panel()

    def _refresh_bookmarks_panel(self):
        self.bookmarks_view.clear()
        for key in sorted(set(self.session.bookmarks)):
            label = self.session.labels.get(key) or self.session.comments.get(key) or ""
            self.bookmarks_view.addItem(f"{key}  {label}")

    def on_bookmark_double_clicked(self, item):
        m = re.match(r"(0x[0-9A-Fa-f]+)", item.text().strip())
        if not m:
            return
        va = int(m.group(1), 16)
        self._open_in_erevos_view(va, self.session.labels.get(m.group(1), f"sub_{va:08X}"))

    def _reannotate_disassembly_views(self):
        # lightweight re-annotation of currently visible disassembly text
        self._annotate_editor(self.asm_view)
        self._annotate_editor(self.hex_view)

    def _annotate_editor(self, edit: QTextEdit):
        lines = edit.toPlainText().splitlines()
        out = []
        for ln in lines:
            m = re.match(r"0x([0-9A-Fa-f]{6,16}):", ln.strip())
            if m:
                key = "0x" + m.group(1).upper()
                ann = []
                if key in self.session.labels:
                    ann.append(f"label={self.session.labels[key]}")
                if key in self.session.comments:
                    ann.append(f"comment={self.session.comments[key]}")
                if key in self.session.bookmarks:
                    ann.append("bookmark")
                if ann and "; [" not in ln:
                    ln += "    ; [" + " | ".join(ann) + "]"
            out.append(ln)
        edit.setPlainText("\n".join(out))

    def _show_xrefs_to(self, va: int):
        self.xrefs_to_view.clear()
        rows = [x for x in getattr(self, "_xrefs", []) if x.dst == va or x.dst_function == va]
        for x in rows:
            dst = f"0x{x.dst:08X}" if x.dst is not None else "<unresolved>"
            src = f"0x{x.src:08X}"
            self.xrefs_to_view.addItem(f"{src} -> {dst} [{x.xref_type}|{x.confidence}] {x.instruction}")
        if not rows:
            self.xrefs_to_view.addItem(f"No xrefs to 0x{va:08X}. (Limitations apply for indirect flows)")
        self.tabs.setCurrentWidget(self.xrefs_to_view)

    def _show_refs_from_current_function(self):
        va = self._address_under_cursor(self.asm_view)
        src_func = None
        if va is not None:
            for fva in sorted(getattr(self, "_functions", {}).keys()):
                if fva <= va:
                    src_func = fva
                else:
                    break
        self.xrefs_from_view.clear()
        rows = [x for x in getattr(self, "_xrefs", []) if (src_func is not None and x.src_function == src_func)]
        for x in rows:
            dst = f"0x{x.dst:08X}" if x.dst is not None else "<unresolved>"
            src = f"0x{x.src:08X}"
            self.xrefs_from_view.addItem(f"{src} -> {dst} [{x.xref_type}|{x.confidence}] {x.instruction}")
        if not rows:
            self.xrefs_from_view.addItem("No outbound refs found for selected function.")
        self.tabs.setCurrentWidget(self.xrefs_from_view)

    def on_xref_item_double_clicked(self, item):
        m = re.search(r"->\\s+(0x[0-9A-Fa-f]+)", item.text())
        if not m:
            return
        va = int(m.group(1), 16)
        self._open_in_erevos_view(va, self.session.labels.get(m.group(1), f"sub_{va:08X}"))

    def on_call_graph_item_double_clicked(self, item):
        txt = item.text()
        m = re.findall(r"0x[0-9A-Fa-f]{6,16}", txt)
        if not m:
            return
        va = int(m[0], 16)
        self._open_in_erevos_view(va, self.session.labels.get(m[0], f"sub_{va:08X}"))

    def _save_session_for_current_file(self):
        if not self.current_file:
            return
        self.session.last_opened_file = self.current_file
        self.session.function_intel_summary = normalize_function_intel_summary(getattr(self, "_function_intel_summary", {}) or {})
        self.session.behavior_summaries = dict(getattr(self, "_behavior_summaries", {}) or {})
        self.session.call_graph_summary = dict(getattr(self, "_call_graph_summary", {}) or {})
        self.session.cfg_intel_summary = dict(getattr(self, "_cfg_intel_summary", {}) or {})
        self.session.naming_suggestions = dict(getattr(self, "_naming_suggestions", {}) or {})
        self.session.applied_suggested_names = dict(getattr(self, "_applied_suggested_names", {}) or {})
        self.session.data_flow_insights = dict(getattr(self, "_data_flow_by_function", {}) or {})
        self.session.api_semantics_insights = dict(getattr(self, "_api_semantics_by_function", {}) or {})
        self.session.behavior_patterns = dict(getattr(self, "_behavior_patterns", {}) or {})
        self.session.threat_narrative = normalize_threat_narrative(getattr(self, "_threat_narrative", {}) or {})
        p = self.session_path or SessionState.session_path_for_sample(self.current_file)
        self.session.save(p)

    def _load_session_for_current_file(self):
        if not self.current_file:
            return
        p = self.session_path or SessionState.session_path_for_sample(self.current_file)
        self.session = SessionState.load(p)
        self._function_intel_summary = normalize_function_intel_summary(self.session.function_intel_summary)
        self._behavior_summaries = dict(self.session.behavior_summaries or {})
        self._call_graph_summary = dict(self.session.call_graph_summary or {})
        self._cfg_intel_summary = dict(self.session.cfg_intel_summary or {})
        self._naming_suggestions = dict(self.session.naming_suggestions or {})
        self._applied_suggested_names = dict(self.session.applied_suggested_names or {})
        self._data_flow_by_function = dict(self.session.data_flow_insights or {})
        self._api_semantics_by_function = dict(self.session.api_semantics_insights or {})
        self._behavior_patterns = dict(self.session.behavior_patterns or {})
        self._threat_narrative = normalize_threat_narrative(self.session.threat_narrative)
        self._render_threat_narrative()

    def action_save_session(self):
        if not self.current_file:
            return
        self._save_session_for_current_file()
        QMessageBox.information(self, "Session", f"Session saved: {self.session_path}")

    def action_load_session(self):
        if not self.current_file:
            return
        self._load_session_for_current_file()
        self._rebuild_function_intelligence()
        self._rebuild_call_graph()
        self._rebuild_naming_intelligence()
        self._rebuild_threat_narrative()
        self._refresh_function_list()
        self._refresh_bookmarks_panel()
        self._reannotate_disassembly_views()
        QMessageBox.information(self, "Session", f"Session loaded: {self.session_path}")

    def action_global_search(self):
        q, ok = QInputDialog.getText(self, "Global Search", "Search across functions/strings/imports/addresses/comments:")
        if not ok or not q.strip():
            return
        ql = q.strip().lower()
        hits = []
        for va, name in getattr(self, "_functions", {}).items():
            dname = self._display_func_name(va, name)
            blob = f"0x{va:08X} {dname}".lower()
            if ql in blob:
                hits.append(f"FUNC 0x{va:08X} {dname}")
        for k, v in self.session.comments.items():
            if ql in (k.lower() + " " + v.lower()):
                hits.append(f"COMMENT {k} {v}")
        for txt in self.str_view.toPlainText().splitlines()[:5000]:
            if ql in txt.lower():
                hits.append(f"STRING {txt[:120]}")
                if len(hits) > 200:
                    break
        QMessageBox.information(self, "Global Search Results", "\n".join(hits[:200]) if hits else "No results.")


    # ----------------- Drag & Drop -----------------
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if path:
            self.load_pe(path)

    # ----------------- Console helper -----------------
    def console(self, msg):
        self.console_bar.appendPlainText(msg)
        print(msg)
