from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QMainWindow, QFileDialog,
    QListWidget, QTabWidget, QTextEdit, QLabel, QSplitter, QToolBar, QStatusBar,
    QLineEdit, QMessageBox, QMenuBar, QStyle, QPlainTextEdit,
    QGraphicsView, QGraphicsScene, QGraphicsTextItem, QMenu, QGraphicsProxyWidget, QFrame 
)
from PyQt6.QtGui import (
    QKeySequence, QFont, QAction, QColor, QTextCursor, QTextCharFormat,
    QPainter, QFontMetrics
)
from PyQt6.QtCore import Qt, QSize
from pathlib import Path
import traceback
import re
# Critical tab (risk/hot) adapter
from core.modules.risk import build_risk_views

from PyQt6.QtWidgets import QGraphicsView, QGraphicsScene, QGraphicsTextItem
from PyQt6.QtGui import QPainter, QPen, QBrush, QFont
from PyQt6.QtCore import Qt, QPointF

from PyQt6.QtGui import QPen, QBrush, QFont, QMouseEvent
from PyQt6.QtCore import Qt, QPointF, QRectF

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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Erevos - Static PE Disassembler")
        self.resize(1500, 950)
        self.disasm = None
        self.current_file = None

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        # Menu + Toolbar
        self._create_menu()
        self._create_toolbar()

        # Split layout: left (functions) and right (tabs)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)

        # Left panel
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(6, 6, 6, 6)
        left_layout.setSpacing(6)
        self.functions_label = QLabel("Functions")
        self.functions_label.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self.functions_label.setObjectName("FunctionsHeader")
        left_layout.addWidget(self.functions_label)
        self.func_list = QListWidget()
        self.func_list.setFont(QFont("Consolas", 10))
        self.func_list.itemClicked.connect(self.on_func_selected)
        self.func_list.itemDoubleClicked.connect(self.on_func_double_clicked)
        self.func_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.func_list.customContextMenuRequested.connect(self.on_func_context_menu)
        left_layout.addWidget(self.func_list)
        # search box
        search_box = QLineEdit()
        search_box.setPlaceholderText("Filter functions (address or name)...")
        search_box.textChanged.connect(self.filter_functions)
        left_layout.addWidget(search_box)
        splitter.addWidget(left_panel)
        splitter.setStretchFactor(0, 0)

        # Right panel - tabs
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(6, 6, 6, 6)
        right_layout.setSpacing(6)

        self.tabs = QTabWidget()
        # New: Erevos View (zoomable function box)
        self.erevos_view = FunctionBoxView()
        self.erevos_view.setObjectName("ErevosView")

        # ASM view (full .text disassembly)
        self.asm_view = QTextEdit()
        self.asm_view.setReadOnly(True)
        self.asm_view.setFont(QFont("Consolas", 10))
        self.asm_view.setObjectName("AsmView")
        if attach_highlighter:
            self.asm_highlighter = attach_highlighter(self.asm_view)

        self.hex_view = QTextEdit(); self.hex_view.setReadOnly(True); self.hex_view.setFont(QFont("Consolas", 10))
        self.str_view = QTextEdit(); self.str_view.setReadOnly(True); self.str_view.setFont(QFont("Consolas", 10))
        self.imports_view = QTextEdit(); self.imports_view.setReadOnly(True); self.imports_view.setFont(QFont("Consolas", 10))
        self.exports_view = QTextEdit(); self.exports_view.setReadOnly(True); self.exports_view.setFont(QFont("Consolas", 10))

        # Critical -> two sub-tabs (Risk + Hot)
        self.critical_tabs = QTabWidget()
        self.critical_risk = QTextEdit(); self.critical_risk.setReadOnly(True); self.critical_risk.setFont(QFont("Consolas", 10))
        self.critical_hot = QTextEdit(); self.critical_hot.setReadOnly(True); self.critical_hot.setFont(QFont("Consolas", 10))
        self.critical_tabs.addTab(self.critical_risk, "Risk (scores)")
        self.critical_tabs.addTab(self.critical_hot, "Hot (raw)")
        # Double-click to jump from risk/hot lines
        self.critical_risk.mouseDoubleClickEvent = lambda ev: (
            self._goto_va_from_cursor(self.critical_risk),
            QTextEdit.mouseDoubleClickEvent(self.critical_risk, ev)
        )
        self.critical_hot.mouseDoubleClickEvent = lambda ev: (
            self._goto_va_from_cursor(self.critical_hot),
            QTextEdit.mouseDoubleClickEvent(self.critical_hot, ev)
        )

        # Resources & CFG (text placeholder for now)
        self.resources_view = QTextEdit(); self.resources_view.setReadOnly(True); self.resources_view.setFont(QFont("Consolas", 10))
        self.cfg_graph = CfgGraphView()
        self.tabs.addTab(self.cfg_graph, "CFG")

        # Tab order
        self.tabs.addTab(self.erevos_view, "Erevos View")
        self.tabs.addTab(self.asm_view, "Disassembly (ASM)")
        self.tabs.addTab(self.hex_view, "Hex View")
        self.tabs.addTab(self.str_view, "Strings")
        self.tabs.addTab(self.imports_view, "Imports")
        self.tabs.addTab(self.exports_view, "Exports")
        self.tabs.addTab(self.critical_tabs, "Critical")
        self.tabs.addTab(self.resources_view, "Resources")
        self.tabs.addTab(self.cfg_graph, "CFG")

        right_layout.addWidget(self.tabs)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 1)

        # Console / output pane at bottom
        self.console_bar = QPlainTextEdit(); self.console_bar.setObjectName("Console")
        self.console_bar.setReadOnly(True)
        self.console_bar.setFixedHeight(150)
        self.console_bar.setFont(QFont("Consolas", 10))
        # Add splitter vertical stacking
        vsplit = QSplitter(Qt.Orientation.Vertical)
        top_widget = QWidget(); top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0); top_layout.addWidget(splitter)
        vsplit.addWidget(top_widget); vsplit.addWidget(self.console_bar)
        vsplit.setStretchFactor(0, 8); vsplit.setStretchFactor(1, 0)

        main.addWidget(vsplit)

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
        file_menu.addSeparator()
        exit_action = QAction("Exit", self); exit_action.setShortcut(QKeySequence.StandardKey.Quit); exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menubar.addMenu("&View")
        view_menu.addAction(QAction("Refresh", self, triggered=self.action_refresh))

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
            generate_report(self.current_file, top=30, max_strings=200, html_path=save_path)
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
            self.tabs.setCurrentWidget(self.critical_tabs)
            self.critical_tabs.setCurrentWidget(self.critical_risk)
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
            self._populate_critical()

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
        self.func_list.clear()
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
        for va, name in self._functions.items():
            self.func_list.addItem(f"0x{va:08X}    {name}")

    def filter_functions(self, txt):
        if not hasattr(self, "_functions"):
            return
        self.func_list.clear()
        q = txt.strip().lower()
        for va, name in self._functions.items():
            s = f"0x{va:08X} {name}".lower()
            if q in s:
                self.func_list.addItem(f"0x{va:08X}    {name}")

    # ----------------- Navigation handlers -----------------
    def on_func_selected(self, item):
        text = item.text().split()
        va_hex = text[0]
        va = int(va_hex, 16)
        try:
            asm = self.disasm.disasm_at(va, size=0x800)
            hx = self.disasm.hexdump_at(va, size=1024)
            self.asm_view.setPlainText(asm if asm else "<no disasm>")
            self.hex_view.setPlainText(hx if hx else "<no hex>")
            self.tabs.setCurrentWidget(self.asm_view)
            self.console(f"Disassembled at {va_hex}")
        except Exception as e:
            self.console(f"Disassembly error: {e}")

    def on_func_double_clicked(self, item):
        text = item.text().split()
        va_hex = text[0]
        va = int(va_hex, 16)
        self._open_in_erevos_view(va, text[-1])

    def on_func_context_menu(self, pos):
        item = self.func_list.itemAt(pos)
        if not item:
            return
        text = item.text().split()
        va_hex = text[0]
        va = int(va_hex, 16)
        name = text[-1]
        m = QMenu(self)
        a1 = m.addAction("Go to function (Erevos View)")
        a2 = m.addAction("Open in Disassembly (ASM)")
        act = m.exec(self.func_list.mapToGlobal(pos))
        if act == a1:
            self._open_in_erevos_view(va, name)
        elif act == a2:
            self.on_func_selected(item)

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
        except Exception as e:
            self.console(f"Erevos view error: {e}")


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
