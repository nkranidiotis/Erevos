from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QMainWindow, QFileDialog,
    QListWidget, QTabWidget, QTextEdit, QLabel, QSplitter, QToolBar, QStatusBar,
    QLineEdit, QMessageBox, QMenuBar, QStyle, QPlainTextEdit, QInputDialog,
    QDialog, QDialogButtonBox, QFormLayout,
    QListWidgetItem, QCheckBox, QSpinBox, QProgressDialog, QApplication,
    QGraphicsView, QGraphicsScene, QGraphicsTextItem, QMenu, QGraphicsProxyWidget, QFrame,
    QPushButton, QScrollArea, QGridLayout, QStackedWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QSizePolicy, QButtonGroup, QAbstractItemView,
)
from PyQt6.QtGui import (
    QKeySequence, QFont, QAction, QColor, QTextCursor, QTextCharFormat,
    QPainter, QFontMetrics, QPen, QBrush, QMouseEvent, QPainterPath, QPolygonF,
    QRadialGradient, QPixmap,
)
from PyQt6.QtCore import Qt, QSize, QPointF, QRectF, pyqtSignal
from pathlib import Path
import traceback
import re
import json
import math
import random
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



# ===== UI submodules (split out 2026-05) =====
from core.ui.styles import (
    NAVY_DEEP, NAVY, NAVY_LIGHT, NAVY_BORDER, APP_BG, WHITE, BG_LIGHT, BG_HOVER,
    CARD_BORDER, CARD_BORDER_MUTED,
    TEXT_PRIMARY, TEXT_BODY, TEXT_SECONDARY, TEXT_MUTED, TEXT_FAINT, TEXT_ON_NAVY,
    BLUE, BLUE_LIGHT, BLUE_DEEP, BLUE_SOFT,
    CYAN, PURPLE, GREEN, GREEN_SOFT, LIME, AMBER, ORANGE, RED, RED_SOFT,
    TAG_MALWARE_BG, TAG_MALWARE_FG, TAG_SUS_BG, TAG_SUS_FG, TAG_PACKED_BG, TAG_PACKED_FG,
    MONO, SANS, APP_QSS,
)
from core.ui.widgets import (
    hline, SkullLogo, Dot, Tag, Card, make_console_card,
    MiniMapWidget, RiskGauge, CallGraphWidget,
)
from core.ui.views import FunctionBoxView, CfgGraphView
from core.ui.topbar import TopBar, ViewRouter
from core.ui.dashboard import DashboardPage
from core.ui.loader import PELoaderThread


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Erevos - Static PE Disassembler")
        self.resize(1600, 980)
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

        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        self._create_menu()
        self._create_toolbar()
        # Hide the legacy header chrome — actions remain wired to keep shortcuts working
        try:
            self.menuBar().hide()
            for tb in self.findChildren(QToolBar):
                tb.hide()
        except Exception:
            pass

        self.top_bar = TopBar()
        self.top_bar.navChanged.connect(self._on_nav_changed)
        self.top_bar.report_btn.clicked.connect(self.action_export_html)
        root.addWidget(self.top_bar)

        utility = QWidget(); utility.setObjectName('PageRoot')
        util_layout = QHBoxLayout(utility); util_layout.setContentsMargins(22, 14, 22, 0); util_layout.setSpacing(12)
        util_label = QLabel('Workspace Search'); util_label.setObjectName('Kicker')
        util_layout.addWidget(util_label)
        self.tb_search = QLineEdit(); self.tb_search.setPlaceholderText('Search current visible view...'); self.tb_search.returnPressed.connect(self.toolbar_search); util_layout.addWidget(self.tb_search, 1)
        btn = QPushButton('Global Search'); btn.setObjectName('GhostBtn'); btn.clicked.connect(self.action_global_search); util_layout.addWidget(btn)
        open_btn = QPushButton('Open PE'); open_btn.setObjectName('PrimaryBtn'); open_btn.clicked.connect(self.action_open); util_layout.addWidget(open_btn)
        root.addWidget(utility)

        self.page_stack = QStackedWidget(); self.page_stack.setObjectName('PageRoot')
        root.addWidget(self.page_stack, 1)

        self.dashboard_page = DashboardPage(self)
        self.page_stack.addWidget(self.dashboard_page)

        # Page 1: Erevos View
        self.erevos_page = QWidget(); self.erevos_page.setObjectName('PageRoot')
        erevos_outer = QVBoxLayout(self.erevos_page); erevos_outer.setContentsMargins(22,18,22,18); erevos_outer.setSpacing(16)
        erevos_layout = QHBoxLayout(); erevos_layout.setSpacing(16); erevos_outer.addLayout(erevos_layout, 1)
        left_panel = Card('Functions')
        self.func_list = QListWidget(); self.func_list.setFont(QFont('Consolas', 10)); self.func_list.itemClicked.connect(self.on_func_selected); self.func_list.itemDoubleClicked.connect(self.on_func_double_clicked); self.func_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.func_list.customContextMenuRequested.connect(self.on_func_context_menu)
        self.func_search_box = QLineEdit(); self.func_search_box.setPlaceholderText('Filter functions (address or name)...'); self.func_search_box.textChanged.connect(self.filter_functions)
        self.filter_renamed = QCheckBox('Renamed'); self.filter_commented = QCheckBox('Commented'); self.filter_bookmarked = QCheckBox('Bookmarked'); self.filter_suspicious = QCheckBox('Suspicious API'); self.filter_inbound_spin = QSpinBox(); self.filter_inbound_spin.setPrefix('Inbound≥'); self.filter_inbound_spin.setRange(0,9999); self.filter_ref_string = QLineEdit(); self.filter_ref_string.setPlaceholderText('Referenced string contains...')
        for w in (self.filter_renamed, self.filter_commented, self.filter_bookmarked, self.filter_suspicious): w.stateChanged.connect(self.filter_functions)
        self.filter_inbound_spin.valueChanged.connect(self.filter_functions); self.filter_ref_string.textChanged.connect(self.filter_functions)
        left_panel.addWidget(self.func_search_box); left_panel.addWidget(self.func_list,1); left_panel.addWidget(self.filter_renamed); left_panel.addWidget(self.filter_commented); left_panel.addWidget(self.filter_bookmarked); left_panel.addWidget(self.filter_suspicious); left_panel.addWidget(self.filter_inbound_spin); left_panel.addWidget(self.filter_ref_string)
        left_wrap = QWidget(); left_wrap.setLayout(QVBoxLayout()); left_wrap.layout().setContentsMargins(0,0,0,0); left_wrap.layout().addWidget(left_panel); left_wrap.setFixedWidth(280)
        erevos_layout.addWidget(left_wrap)

        center_card = Card('Erevos View', 'Live backend wired to original app.py logic')
        self.erevos_center = QStackedWidget()
        self.erevos_view = FunctionBoxView(); self.erevos_view.setObjectName('ErevosView')
        self.asm_view = QTextEdit(); self.asm_view.setReadOnly(True); self.asm_view.setFont(QFont('Consolas', 10)); self.asm_view.setObjectName('AsmView');
        if attach_highlighter: self.asm_highlighter = attach_highlighter(self.asm_view)
        self.asm_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.asm_view.customContextMenuRequested.connect(self.on_asm_context_menu)
        self.erevos_center.addWidget(self.erevos_view); self.erevos_center.addWidget(self.asm_view)
        center_card.addWidget(self.erevos_center,1)
        erevos_layout.addWidget(center_card, 5)

        right_col = QWidget(); right_col.setFixedWidth(380); right_layout = QVBoxLayout(right_col); right_layout.setContentsMargins(0,0,0,0); right_layout.setSpacing(16)
        self.function_details_view = QTextEdit(); self.function_details_view.setObjectName('FunctionDetails'); self.function_details_view.setReadOnly(True); self.function_details_view.setFont(QFont('Consolas',10))
        self.function_card = Card('Function Intelligence'); self.function_card.addWidget(self.function_details_view,1); right_layout.addWidget(self.function_card,3)
        self.quick_intel = QTextEdit(); self.quick_intel.setReadOnly(True); self.quick_intel.setMaximumHeight(220); self.quick_intel.setObjectName('ThreatView')
        qi_card = Card('Threat Snapshot'); qi_card.addWidget(self.quick_intel,1); right_layout.addWidget(qi_card,2)
        erevos_layout.addWidget(right_col, 2)
        # Per-page console
        cwrap, _ = make_console_card(self, height=110)
        erevos_outer.addWidget(cwrap, 0)
        self.page_stack.addWidget(self.erevos_page)

        # Page 2: Analysis (Gemini-style redesign backed by real widgets/data)
        self.analysis_page = QWidget(); self.analysis_page.setObjectName('PageRoot')
        analysis_layout = QVBoxLayout(self.analysis_page); analysis_layout.setContentsMargins(22,18,22,18); analysis_layout.setSpacing(16)

        # Hidden legacy widgets retained as data sources / routers
        self.analysis_tabs = QTabWidget(); self.analysis_tabs.hide()
        self.resources_view = QTextEdit(); self.resources_view.setReadOnly(True); self.resources_view.setFont(QFont('Consolas',10))
        self.bookmarks_view = QListWidget(); self.bookmarks_view.setFont(QFont('Consolas',10)); self.bookmarks_view.itemDoubleClicked.connect(self.on_bookmark_double_clicked)
        self.xrefs_to_view = QListWidget(); self.xrefs_to_view.setFont(QFont('Consolas',10)); self.xrefs_to_view.itemDoubleClicked.connect(self.on_xref_item_double_clicked)
        self.xrefs_from_view = QListWidget(); self.xrefs_from_view.setFont(QFont('Consolas',10)); self.xrefs_from_view.itemDoubleClicked.connect(self.on_xref_item_double_clicked)
        self.call_graph_view = QListWidget(); self.call_graph_view.setFont(QFont('Consolas',10)); self.call_graph_view.itemDoubleClicked.connect(self.on_call_graph_item_double_clicked)
        self.threat_narrative_view = QTextEdit(); self.threat_narrative_view.setObjectName('ThreatView'); self.threat_narrative_view.setReadOnly(True); self.threat_narrative_view.setFont(QFont('Consolas',10))
        self.critical_tabs = QTabWidget(); self.critical_tabs.hide(); self.critical_risk = QTextEdit(); self.critical_risk.setReadOnly(True); self.critical_risk.setFont(QFont('Consolas',10)); self.critical_hot = QTextEdit(); self.critical_hot.setReadOnly(True); self.critical_hot.setFont(QFont('Consolas',10)); self.critical_tabs.addTab(self.critical_risk, 'Risk (scores)'); self.critical_tabs.addTab(self.critical_hot, 'Hot (raw)')
        self.critical_risk.mouseDoubleClickEvent = lambda ev: (self._goto_va_from_cursor(self.critical_risk), QTextEdit.mouseDoubleClickEvent(self.critical_risk, ev))
        self.critical_hot.mouseDoubleClickEvent = lambda ev: (self._goto_va_from_cursor(self.critical_hot), QTextEdit.mouseDoubleClickEvent(self.critical_hot, ev))
        for w, label in [(self.critical_tabs,'Critical'), (self.resources_view,'Resources'), (self.bookmarks_view,'Bookmarks'), (self.xrefs_to_view,'Xrefs To'), (self.xrefs_from_view,'Xrefs From'), (self.call_graph_view,'Call Graph'), (self.threat_narrative_view,'Threat Narrative')]:
            self.analysis_tabs.addTab(w, label)

        top = QHBoxLayout(); top.setSpacing(16); analysis_layout.addLayout(top, 1)

        left = QVBoxLayout(); left.setSpacing(16)
        right = QVBoxLayout(); right.setSpacing(16)
        top.addLayout(left, 6)
        top.addLayout(right, 6)

        # Disassembly card
        self.analysis_disasm_card = Card(parent=self, padding=(16,14,16,12))
        hdr = QHBoxLayout(); t = QLabel('DISASSEMBLY (ASM)'); t.setObjectName('CardTitle'); dash = QLabel('—'); dash.setStyleSheet(f'color:{TEXT_MUTED};'); self.analysis_disasm_name = QLabel('No function selected'); self.analysis_disasm_name.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:12px; font-weight:600;'); self.analysis_disasm_addr = QLabel(''); self.analysis_disasm_addr.setStyleSheet(f'color:{BLUE}; font-size:12px; font-weight:700; font-family:{MONO};'); hdr.addWidget(t); hdr.addWidget(dash); hdr.addWidget(self.analysis_disasm_name); hdr.addWidget(self.analysis_disasm_addr); hdr.addStretch(); self.analysis_disasm_card.addLayout(hdr); self.analysis_disasm_card.addWidget(hline())
        self.analysis_disasm_view = QTextEdit(); self.analysis_disasm_view.setObjectName('Disasm'); self.analysis_disasm_view.setReadOnly(True); self.analysis_disasm_view.setFont(QFont('Consolas',10)); self.analysis_disasm_card.addWidget(self.analysis_disasm_view, 1)
        left.addWidget(self.analysis_disasm_card, 6)

        # CFG preview card
        self.analysis_cfg_card = Card('CFG Graph', parent=self)
        self.analysis_cfg_subtitle = QLabel('— no function selected'); self.analysis_cfg_subtitle.setObjectName('CardSubtitle'); self.analysis_cfg_card.layout().insertWidget(0, self.analysis_cfg_subtitle)
        self.analysis_cfg_graph = CfgGraphView(); self.analysis_cfg_card.addWidget(self.analysis_cfg_graph, 1)
        left.addWidget(self.analysis_cfg_card, 4)

        # Function intelligence card
        self.analysis_intel_card = Card('Function Intelligence', parent=self)
        intel_top = QHBoxLayout(); intel_left = QVBoxLayout(); intel_left.setSpacing(2)
        self.analysis_intel_name = QLabel('No sample loaded'); self.analysis_intel_name.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:20px; font-weight:800;')
        self.analysis_intel_addr = QLabel(''); self.analysis_intel_addr.setStyleSheet(f'color:{TEXT_MUTED}; font-family:{MONO}; font-size:12px;')
        intel_left.addWidget(self.analysis_intel_name); intel_left.addWidget(self.analysis_intel_addr); intel_top.addLayout(intel_left)
        intel_right = QVBoxLayout(); intel_right.setSpacing(2); rk = QLabel('Risk Score'); rk.setStyleSheet(f'color:{TEXT_SECONDARY}; font-size:11.5px;'); intel_right.addWidget(rk)
        rkrow = QHBoxLayout(); self.analysis_risk_value = QLabel('0'); self.analysis_risk_value.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:28px; font-weight:800;'); small = QLabel('/ 100'); small.setStyleSheet(f'color:{TEXT_MUTED}; font-size:12px;'); rkrow.addWidget(self.analysis_risk_value); rkrow.addWidget(small); rkrow.addStretch(); intel_right.addLayout(rkrow); self.analysis_risk_badge = QLabel('No Data'); self.analysis_risk_badge.setStyleSheet(f'color:{TEXT_MUTED}; font-size:11px; font-weight:700;'); intel_right.addWidget(self.analysis_risk_badge); intel_top.addLayout(intel_right)
        self.analysis_risk_gauge = RiskGauge(value=0, label='', compact=True, size=130); self.analysis_risk_gauge.setMaximumHeight(100); self.analysis_risk_gauge.setMinimumWidth(120); intel_top.addWidget(self.analysis_risk_gauge)
        self.analysis_intel_card.addLayout(intel_top); self.analysis_intel_card.addWidget(hline())
        kk = QLabel('Key Indicators'); kk.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:12px; font-weight:700;'); self.analysis_intel_card.addWidget(kk)
        self.analysis_indicators_host = QWidget(); self.analysis_indicators_layout = QVBoxLayout(self.analysis_indicators_host); self.analysis_indicators_layout.setContentsMargins(0,0,0,0); self.analysis_indicators_layout.setSpacing(10); self.analysis_intel_card.addWidget(self.analysis_indicators_host)
        right.addWidget(self.analysis_intel_card)

        lower_right = QHBoxLayout(); lower_right.setSpacing(16); right.addLayout(lower_right)

        self.analysis_strings_card = Card('Strings Referenced', parent=self)
        self.analysis_string_rows = []
        for _ in range(5):
            row = QHBoxLayout(); a = QLabel(''); a.setStyleSheet(f'color:{BLUE}; font-family:{MONO}; font-size:11.5px;'); a.setFixedWidth(90); v = QLabel(''); v.setStyleSheet(f'color:{TEXT_BODY}; font-family:{MONO}; font-size:11.5px;'); v.setWordWrap(False); row.addWidget(a); row.addWidget(v,1); self.analysis_strings_card.addLayout(row); self.analysis_string_rows.append((a,v))
        self.analysis_strings_btn = QPushButton('VIEW ALL STRINGS'); self.analysis_strings_btn.setObjectName('PrimaryBtn'); self.analysis_strings_btn.setMinimumHeight(32); self.analysis_strings_btn.clicked.connect(lambda: self.tabs.setCurrentWidget(self.str_view)); self.analysis_strings_card.addSpacing(4); self.analysis_strings_card.addWidget(self.analysis_strings_btn)
        lower_right.addWidget(self.analysis_strings_card, 1)

        self.analysis_flow_card = Card('Data Flow', parent=self)
        self.analysis_flow_note = QLabel('Awaiting analysis'); self.analysis_flow_note.setStyleSheet(f'color:{TEXT_PRIMARY}; font-weight:700; font-size:12px;'); self.analysis_flow_card.addWidget(self.analysis_flow_note)
        self.analysis_flow_rows = []
        for color in [BLUE, PURPLE, AMBER, GREEN]:
            host = QWidget(); host_l = QVBoxLayout(host); host_l.setContentsMargins(0,0,0,0); host_l.setSpacing(0); self.analysis_flow_card.addWidget(host); self.analysis_flow_rows.append((host, host_l, color))
        lower_right.addWidget(self.analysis_flow_card, 1)

        # In-page console card for Analysis only
        self.analysis_console_wrap = QFrame(); self.analysis_console_wrap.setObjectName('Card'); self.analysis_console_wrap.setStyleSheet(f"QFrame#Card {{ background-color:#0B121F; border:1px solid #18243A; border-radius:6px; }}")
        acv = QVBoxLayout(self.analysis_console_wrap); acv.setContentsMargins(16,12,16,12); acv.setSpacing(6)
        ach = QHBoxLayout(); act = QLabel('CONSOLE LOG'); act.setStyleSheet('color:#D8DEE9; font-size:11px; font-weight:700; letter-spacing:1.4px;'); ach.addWidget(act); ach.addStretch(); acl = QPushButton('Clear Log'); acl.setStyleSheet(f"QPushButton {{ background: transparent; color:{TEXT_MUTED}; border:none; font-size:11px; }} QPushButton:hover {{ color:white; }}"); acl.clicked.connect(lambda: (self.console_bar.clear(), self.analysis_console.clear())); ach.addWidget(acl); acv.addLayout(ach)
        self.analysis_console = QTextEdit(); self.analysis_console.setObjectName('Console'); self.analysis_console.setReadOnly(True); self.analysis_console.setFixedHeight(110); acv.addWidget(self.analysis_console)
        # Analysis console pre-existed; ensure it participates in clear-all and global mirror
        if not hasattr(self, '_page_consoles'):
            self._page_consoles = []
        self._page_consoles.append(self.analysis_console)
        analysis_layout.addWidget(self.analysis_console_wrap, 0)

        self.page_stack.addWidget(self.analysis_page)

        # Page 3: Hex (redesigned 3-col: Sections|HexDump|Decoded+Bookmarks)
        self.hex_page = QWidget(); self.hex_page.setObjectName('PageRoot')
        hex_page_v = QVBoxLayout(self.hex_page); hex_page_v.setContentsMargins(22,18,22,18); hex_page_v.setSpacing(16)
        hex_outer = QHBoxLayout(); hex_outer.setSpacing(16); hex_page_v.addLayout(hex_outer, 1)

        # --- Build the four data widgets first (preserve names + behavior) ---
        self.hex_view = QTextEdit(); self.hex_view.setObjectName('HexView'); self.hex_view.setReadOnly(True); self.hex_view.setFont(QFont('Consolas',10))
        self.hex_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.hex_view.customContextMenuRequested.connect(self.on_asm_context_menu)
        self.hex_view.cursorPositionChanged.connect(self._on_hex_cursor_moved)
        self.str_view = QTextEdit(); self.str_view.setReadOnly(True); self.str_view.setFont(QFont('Consolas',10))
        self.str_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.str_view.customContextMenuRequested.connect(self.on_string_context_menu)
        self.str_view.mouseDoubleClickEvent = lambda ev: (self._show_string_usage_from_cursor(), QTextEdit.mouseDoubleClickEvent(self.str_view, ev))
        self.imports_view = QTextEdit(); self.imports_view.setReadOnly(True); self.imports_view.setFont(QFont('Consolas',10))
        self.imports_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.imports_view.customContextMenuRequested.connect(self.on_import_context_menu)
        self.exports_view = QTextEdit(); self.exports_view.setReadOnly(True); self.exports_view.setFont(QFont('Consolas',10))

        # QTabWidget kept alive for ViewRouter compat, tab bar hidden
        self.hex_tabs = QTabWidget(); self.hex_tabs.tabBar().hide()
        self.hex_tabs.setStyleSheet("QTabWidget::pane { border: none; background: transparent; padding: 0; }")
        for w, label in [(self.hex_view,'Hex View'), (self.str_view,'Strings'), (self.imports_view,'Imports'), (self.exports_view,'Exports')]:
            self.hex_tabs.addTab(w, label)

        # --- Left column: Sections + Hex Options ---
        hex_left = QVBoxLayout(); hex_left.setSpacing(16)

        self._hex_sections_card = Card('Sections')
        self._hex_sections_host = QWidget()
        self._hex_sections_layout = QVBoxLayout(self._hex_sections_host); self._hex_sections_layout.setContentsMargins(0,0,0,0); self._hex_sections_layout.setSpacing(2)
        self._hex_sections_card.addWidget(self._hex_sections_host); self._hex_sections_card.addStretch()
        hex_left.addWidget(self._hex_sections_card, 3)

        self._hex_options_card = Card('Hex Options')
        self._hex_opts = {'show_ascii': True, 'highlight_strings': False, 'highlight_apis': True, 'highlight_jumps': False}
        for key, label in [('show_ascii','Show ASCII'), ('highlight_strings','Highlight Strings'), ('highlight_apis','Highlight APIs'), ('highlight_jumps','Highlight Jumps')]:
            cb = QCheckBox(label); cb.setChecked(self._hex_opts[key])
            cb.stateChanged.connect(lambda state, k=key: (
                self._hex_opts.update({k: bool(state)}),
                self._render_hex_view(getattr(self, '_hex_current_va', 0), getattr(self, '_hex_current_size', 1024))
            ))
            self._hex_options_card.addWidget(cb)
        self._hex_options_card.addStretch()
        hex_left.addWidget(self._hex_options_card, 2)

        hex_left_wrap = QWidget(); hex_left_wrap.setFixedWidth(230); hex_left_wrap.setLayout(hex_left)
        hex_outer.addWidget(hex_left_wrap)

        # --- Center: Hex dump card with segmented control + hex_tabs ---
        hex_center_card = Card(parent=self, padding=(16,14,16,14))
        ch = QHBoxLayout()
        ct = QLabel('HEX DUMP'); ct.setObjectName('CardTitle')
        csep = QLabel('—'); csep.setStyleSheet(f'color:{TEXT_MUTED};')
        self._hex_subtitle = QLabel('No PE loaded'); self._hex_subtitle.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:12px; font-weight:600;')
        ch.addWidget(ct); ch.addWidget(csep); ch.addWidget(self._hex_subtitle); ch.addStretch()
        hex_center_card.addLayout(ch); hex_center_card.addWidget(hline())

        seg_row = QHBoxLayout(); seg_row.setSpacing(4)
        self._hex_seg_group = QButtonGroup(self); self._hex_seg_group.setExclusive(True)
        self._hex_seg_buttons = []
        for i, label in enumerate(['Hex View', 'Strings', 'Imports', 'Exports']):
            b = QPushButton(label); b.setObjectName('TabBtn'); b.setCheckable(True); b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(28); b.setMinimumWidth(86)
            if i == 0: b.setChecked(True)
            self._hex_seg_group.addButton(b, i); self._hex_seg_buttons.append(b)
            seg_row.addWidget(b)
        seg_row.addStretch()
        # Right-side info label inside the segmented control row
        self._hex_info_label = QLabel('')
        self._hex_info_label.setStyleSheet(f'color:{TEXT_MUTED}; font-family:{MONO}; font-size:11px;')
        seg_row.addWidget(self._hex_info_label)
        self._hex_seg_group.idClicked.connect(self.hex_tabs.setCurrentIndex)
        self.hex_tabs.currentChanged.connect(self._on_hex_tab_changed)
        hex_center_card.addLayout(seg_row)
        hex_center_card.addWidget(self.hex_tabs, 1)

        hex_outer.addWidget(hex_center_card, 5)

        # --- Right: Decoded View + Bookmarks ---
        hex_right = QVBoxLayout(); hex_right.setSpacing(16)

        self._hex_decoded_card = Card('Decoded View')
        self._hex_decoded_at = QLabel('No selection'); self._hex_decoded_at.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:13px; font-weight:700;')
        self._hex_decoded_card.addWidget(self._hex_decoded_at); self._hex_decoded_card.addWidget(hline())
        self._hex_decoded_type = QLabel('—'); self._hex_decoded_type.setObjectName('FieldValue')
        self._hex_decoded_target = QLabel('—'); self._hex_decoded_target.setStyleSheet(f'color:{BLUE}; font-family:{MONO}; font-size:12px; font-weight:600;')
        self._hex_decoded_symbol = QLabel('—'); self._hex_decoded_symbol.setStyleSheet(f'color:{BLUE}; font-size:12px; font-weight:600;')
        for lbl, vw in [('Type', self._hex_decoded_type), ('Target', self._hex_decoded_target), ('Symbol', self._hex_decoded_symbol)]:
            r = QHBoxLayout()
            l = QLabel(lbl); l.setObjectName('FieldLabel'); l.setFixedWidth(80)
            r.addWidget(l); r.addWidget(vw, 1)
            self._hex_decoded_card.addLayout(r)
        desc_lbl = QLabel('Description'); desc_lbl.setObjectName('FieldLabel'); self._hex_decoded_card.addWidget(desc_lbl)
        self._hex_decoded_desc = QLabel('Click in the hex view to decode the bytes at the cursor position.')
        self._hex_decoded_desc.setWordWrap(True); self._hex_decoded_desc.setStyleSheet(f'color:{TEXT_BODY}; font-size:12px;')
        self._hex_decoded_card.addWidget(self._hex_decoded_desc)
        self._hex_decoded_card.addSpacing(4)
        ref_btn = QPushButton('Go to Reference'); ref_btn.setObjectName('GhostBtn'); ref_btn.setMinimumHeight(30)
        ref_btn.clicked.connect(lambda: self.tabs.setCurrentWidget(self.imports_view))
        self._hex_decoded_card.addWidget(ref_btn)
        hex_right.addWidget(self._hex_decoded_card)

        self._hex_bookmarks_card = Card('Bookmarks')
        bk_hdr = QHBoxLayout(); bk_hdr.setSpacing(10)
        for col, w in [('NAME', 130), ('RVA', 104), ('TYPE', 56)]:
            l = QLabel(col); l.setStyleSheet(f'color:{TEXT_MUTED}; font-size:10px; font-weight:700; letter-spacing:0.8px;'); l.setFixedWidth(w)
            bk_hdr.addWidget(l)
        bk_hdr.addStretch()
        self._hex_bookmarks_card.addLayout(bk_hdr); self._hex_bookmarks_card.addWidget(hline())
        self._hex_bookmarks_host = QWidget()
        self._hex_bookmarks_layout = QVBoxLayout(self._hex_bookmarks_host); self._hex_bookmarks_layout.setContentsMargins(0,0,0,0); self._hex_bookmarks_layout.setSpacing(8)
        self._hex_bookmarks_card.addWidget(self._hex_bookmarks_host); self._hex_bookmarks_card.addStretch()
        self._hex_bookmarks_card.addSpacing(4)
        mb = QPushButton('MANAGE BOOKMARKS'); mb.setObjectName('PrimaryBtn'); mb.setMinimumHeight(32)
        mb.clicked.connect(lambda: self.tabs.setCurrentWidget(self.bookmarks_view))
        self._hex_bookmarks_card.addWidget(mb)
        hex_right.addWidget(self._hex_bookmarks_card); hex_right.addStretch()

        hex_right_wrap = QWidget(); hex_right_wrap.setFixedWidth(310); hex_right_wrap.setLayout(hex_right)
        hex_outer.addWidget(hex_right_wrap)

        # Per-page console
        cwrap, _ = make_console_card(self, height=110)
        hex_page_v.addWidget(cwrap, 0)

        self.page_stack.addWidget(self.hex_page)
        self._refresh_hex_sections(); self._refresh_hex_bookmarks()

        # Page 4: CFG (redesigned 3-col: Overview/Legend/Complexity | Graph | NodeInfo/MiniMap)
        self.cfg_page = QWidget(); self.cfg_page.setObjectName('PageRoot')
        cfg_page_layout = QVBoxLayout(self.cfg_page); cfg_page_layout.setContentsMargins(0,0,0,16); cfg_page_layout.setSpacing(0)

        # cfg_tabs preserved (ViewRouter target) but tab bar hidden
        self.cfg_tabs = QTabWidget(); self.cfg_tabs.tabBar().hide()
        self.cfg_tabs.setStyleSheet("QTabWidget::pane { border: none; background: transparent; padding: 0; }")

        # cfg_panel = the 3-column layout root
        self.cfg_panel = QWidget(); self.cfg_panel.setObjectName('PageRoot')
        cfg_outer = QHBoxLayout(self.cfg_panel); cfg_outer.setContentsMargins(22,18,22,22); cfg_outer.setSpacing(16)

        # cfg_graph and cfg_intel_view: same instances/behavior, just re-parented
        self.cfg_graph = CfgGraphView()
        self.cfg_intel_view = QTextEdit(); self.cfg_intel_view.setObjectName('CfgIntel'); self.cfg_intel_view.setReadOnly(True); self.cfg_intel_view.setFont(QFont('Consolas',10))
        self.cfg_intel_view.mouseDoubleClickEvent = lambda ev: (self._goto_va_from_cursor(self.cfg_intel_view), QTextEdit.mouseDoubleClickEvent(self.cfg_intel_view, ev))

        # --- Left column: Overview / Legend / Complexity ---
        cfg_left = QVBoxLayout(); cfg_left.setSpacing(16)

        self._cfg_overview_card = Card('CFG Overview')
        self._cfg_ov_function = QLabel('—'); self._cfg_ov_function.setObjectName('FieldValue')
        self._cfg_ov_entry    = QLabel('—'); self._cfg_ov_entry.setObjectName('FieldValueMono')
        self._cfg_ov_blocks   = QLabel('—'); self._cfg_ov_blocks.setObjectName('FieldValue')
        self._cfg_ov_edges    = QLabel('—'); self._cfg_ov_edges.setObjectName('FieldValue')
        self._cfg_ov_depth    = QLabel('—'); self._cfg_ov_depth.setObjectName('FieldValue')
        self._cfg_ov_exits    = QLabel('—'); self._cfg_ov_exits.setObjectName('FieldValue')
        for lbl, vw in [('Function', self._cfg_ov_function), ('Entry Address', self._cfg_ov_entry),
                        ('Blocks', self._cfg_ov_blocks), ('Edges', self._cfg_ov_edges),
                        ('Depth', self._cfg_ov_depth), ('Exits', self._cfg_ov_exits)]:
            row = QHBoxLayout()
            l = QLabel(lbl); l.setObjectName('FieldLabel'); l.setFixedWidth(108)
            row.addWidget(l); row.addWidget(vw, 1)
            self._cfg_overview_card.addLayout(row)
        cfg_left.addWidget(self._cfg_overview_card)

        self._cfg_legend_card = Card('Legend')
        for label, color, strong in [('Entry Block', BLUE_DEEP, True),
                                     ('Basic Block', '#B9C4D4', False),
                                     ('Exit Block',  '#FCA5A5', False),
                                     ('Suspicious API', AMBER, False)]:
            row = QHBoxLayout(); row.setSpacing(10)
            box = QLabel(); box.setFixedSize(18, 14)
            box.setStyleSheet(f"background-color:{color}; border-radius:3px; border:1px solid {'#94A3B8' if not strong else color};")
            lt = QLabel(label); lt.setStyleSheet(f"color:{TEXT_BODY}; font-size:12px;")
            row.addWidget(box); row.addWidget(lt, 1)
            self._cfg_legend_card.addLayout(row)
        cfg_left.addWidget(self._cfg_legend_card)

        self._cfg_complexity_card = Card('Complexity')
        self._cfg_cx_cyclo = QLabel('—'); self._cfg_cx_cyclo.setObjectName('FieldValue')
        self._cfg_cx_nest  = QLabel('—'); self._cfg_cx_nest.setObjectName('FieldValue')
        self._cfg_cx_loops = QLabel('—'); self._cfg_cx_loops.setObjectName('FieldValue')
        self._cfg_cx_dead  = QLabel('—'); self._cfg_cx_dead.setObjectName('FieldValue')
        for lbl, vw in [('Cyclomatic', self._cfg_cx_cyclo), ('Nesting Depth', self._cfg_cx_nest),
                        ('Loops', self._cfg_cx_loops), ('Dead Code', self._cfg_cx_dead)]:
            row = QHBoxLayout()
            l = QLabel(lbl); l.setObjectName('FieldLabel'); l.setFixedWidth(108)
            row.addWidget(l); row.addWidget(vw, 1)
            self._cfg_complexity_card.addLayout(row)
        self._cfg_complexity_card.addSpacing(6)
        self._cfg_cx_note = QLabel('Load a function in Erevos View to populate CFG complexity metrics.')
        self._cfg_cx_note.setWordWrap(True); self._cfg_cx_note.setStyleSheet(f'color:{TEXT_SECONDARY}; font-size:11.5px;')
        self._cfg_complexity_card.addWidget(self._cfg_cx_note); self._cfg_complexity_card.addStretch()
        cfg_left.addWidget(self._cfg_complexity_card, 1)

        cfg_left_wrap = QWidget(); cfg_left_wrap.setFixedWidth(250); cfg_left_wrap.setLayout(cfg_left)
        cfg_outer.addWidget(cfg_left_wrap)

        # --- Center: graph card with toolbar + cfg_intel_view at the bottom ---
        cfg_center_card = Card(parent=self, padding=(16,14,16,14))
        gh = QHBoxLayout()
        gtitle = QLabel('CFG'); gtitle.setObjectName('CardTitle')
        gsep = QLabel('—'); gsep.setStyleSheet(f'color:{TEXT_MUTED};')
        self._cfg_func_label = QLabel('No function selected'); self._cfg_func_label.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:12px; font-weight:600;')
        gh.addWidget(gtitle); gh.addWidget(gsep); gh.addWidget(self._cfg_func_label); gh.addStretch()
        for lbl, slot in [('Fit', self._cfg_action_fit),
                          ('−', lambda: self._cfg_action_zoom(1/1.15)),
                          ('100%', self._cfg_action_reset_zoom),
                          ('+', lambda: self._cfg_action_zoom(1.15)),
                          ('Export', self._cfg_action_export)]:
            b = QPushButton(lbl); b.setObjectName('GhostBtn'); b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(28); b.setFixedHeight(28); b.clicked.connect(slot)
            gh.addWidget(b)
        cfg_center_card.addLayout(gh); cfg_center_card.addWidget(hline())
        cfg_center_card.addWidget(self.cfg_graph, 1)

        intel_kicker = QLabel('CFG INTELLIGENCE'); intel_kicker.setObjectName('Kicker')
        cfg_center_card.addSpacing(6); cfg_center_card.addWidget(intel_kicker)
        self.cfg_intel_view.setMaximumHeight(140)
        cfg_center_card.addWidget(self.cfg_intel_view)

        cfg_outer.addWidget(cfg_center_card, 5)

        # --- Right: Node Info + Mini Map ---
        cfg_right = QVBoxLayout(); cfg_right.setSpacing(16)

        self._cfg_node_info_card = Card('Node Info')
        self._cfg_node_title = QLabel('—'); self._cfg_node_title.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:20px; font-weight:800;')
        self._cfg_node_addr  = QLabel('');  self._cfg_node_addr.setStyleSheet(f'color:{TEXT_MUTED}; font-family:{MONO}; font-size:11.5px;')
        self._cfg_node_info_card.addWidget(self._cfg_node_title); self._cfg_node_info_card.addWidget(self._cfg_node_addr)
        self._cfg_node_info_card.addWidget(hline())
        self._cfg_node_instr = QLabel('—'); self._cfg_node_instr.setObjectName('FieldValue')
        self._cfg_node_bytes = QLabel('—'); self._cfg_node_bytes.setObjectName('FieldValue')
        self._cfg_node_succ  = QLabel('—'); self._cfg_node_succ.setObjectName('FieldValue')
        self._cfg_node_pred  = QLabel('—'); self._cfg_node_pred.setObjectName('FieldValue')
        self._cfg_node_calls = QLabel('—'); self._cfg_node_calls.setObjectName('FieldValue')
        for lbl, vw in [('Instructions', self._cfg_node_instr), ('Bytes', self._cfg_node_bytes),
                        ('Successors', self._cfg_node_succ), ('Predecessors', self._cfg_node_pred),
                        ('Calls', self._cfg_node_calls)]:
            row = QHBoxLayout()
            l = QLabel(lbl); l.setObjectName('FieldLabel'); l.setFixedWidth(100)
            row.addWidget(l); row.addWidget(vw, 1)
            self._cfg_node_info_card.addLayout(row)
        prev_kicker = QLabel('Preview'); prev_kicker.setObjectName('Kicker')
        self._cfg_node_info_card.addSpacing(4); self._cfg_node_info_card.addWidget(prev_kicker)
        self._cfg_node_preview = QTextEdit(); self._cfg_node_preview.setObjectName('AsmView'); self._cfg_node_preview.setReadOnly(True)
        self._cfg_node_preview.setFont(QFont('Consolas', 9)); self._cfg_node_preview.setFixedHeight(110)
        self._cfg_node_info_card.addWidget(self._cfg_node_preview)
        self._cfg_open_in_erevos = QPushButton('OPEN IN EREVOS VIEW'); self._cfg_open_in_erevos.setObjectName('PrimaryBtn'); self._cfg_open_in_erevos.setMinimumHeight(32)
        self._cfg_open_in_erevos.clicked.connect(self._cfg_action_open_in_erevos)
        self._cfg_node_info_card.addWidget(self._cfg_open_in_erevos)
        cfg_right.addWidget(self._cfg_node_info_card)

        self._cfg_minimap_card = Card('Mini Map')
        self._cfg_minimap = MiniMapWidget()
        self._cfg_minimap.attach(self.cfg_graph)
        self.cfg_graph.blockClicked.connect(self._on_cfg_block_clicked)
        self._cfg_minimap_card.addWidget(self._cfg_minimap)
        mm_note = QLabel('Click to pan the main graph. Drag the graph to navigate.')
        mm_note.setStyleSheet(f'color:{TEXT_MUTED}; font-size:11px;'); mm_note.setWordWrap(True)
        self._cfg_minimap_card.addWidget(mm_note)
        cfg_right.addWidget(self._cfg_minimap_card); cfg_right.addStretch()

        cfg_right_wrap = QWidget(); cfg_right_wrap.setFixedWidth(310); cfg_right_wrap.setLayout(cfg_right)
        cfg_outer.addWidget(cfg_right_wrap)

        self.cfg_tabs.addTab(self.cfg_panel, 'CFG')
        cfg_page_layout.addWidget(self.cfg_tabs, 1)
        # Per-page console (with horizontal margins matching the panel above)
        cwrap, _ = make_console_card(self, height=110)
        cfg_console_holder = QWidget()
        ccl = QHBoxLayout(cfg_console_holder); ccl.setContentsMargins(22,0,22,0); ccl.setSpacing(0)
        ccl.addWidget(cwrap)
        cfg_page_layout.addWidget(cfg_console_holder, 0)
        self.page_stack.addWidget(self.cfg_page)

        self.console_bar = QPlainTextEdit(); self.console_bar.setObjectName('Console'); self.console_bar.setReadOnly(True); self.console_bar.setFixedHeight(150); self.console_bar.setFont(QFont('Consolas',10)); self.console_bar.hide(); root.addWidget(self.console_bar)
        self.status = QStatusBar(); self.setStatusBar(self.status)

        self.setStyleSheet(APP_QSS)
        try:
            qss = Path(__file__).parent.parent.joinpath('ui', 'styles.qss')
            if qss.exists():
                self.setStyleSheet(self.styleSheet() + '\n' + qss.read_text())
        except Exception:
            pass

        self.tabs = ViewRouter(self.page_stack, self)
        self._register_widget_mappings()

        if not PED_AVAILABLE:
            self.console(f"Warning: core.pedisasm not available. Import error: {PED_IMPORT_ERROR}")
        else:
            self.console('Erevos initialized. Ready.')
        self.setAcceptDrops(True)
        self._search = {'last': '', 'positions': [], 'index': -1}
        self.dashboard_page.refresh()

    def _register_widget_mappings(self):
        self.tabs.register(self.erevos_view, 1, lambda w: self.erevos_center.setCurrentWidget(self.erevos_view))
        self.tabs.register(self.asm_view, 1, lambda w: self.erevos_center.setCurrentWidget(self.asm_view))
        # Register Function Intelligence widgets so the Analysis-page buttons can route there
        self.tabs.register(self.function_details_view, 1, lambda w: None)
        self.tabs.register(self.quick_intel, 1, lambda w: None)
        for w in [self.critical_tabs, self.resources_view, self.bookmarks_view, self.xrefs_to_view, self.xrefs_from_view, self.call_graph_view, self.threat_narrative_view, self.analysis_page]:
            self.tabs.register(w, 2, lambda obj, ww=w: self.analysis_tabs.setCurrentWidget(ww) if hasattr(self, 'analysis_tabs') and ww in [self.critical_tabs, self.resources_view, self.bookmarks_view, self.xrefs_to_view, self.xrefs_from_view, self.call_graph_view, self.threat_narrative_view] else None)
        for w in [self.hex_view, self.str_view, self.imports_view, self.exports_view]:
            self.tabs.register(w, 3, lambda obj, ww=w: self.hex_tabs.setCurrentWidget(ww))
        self.tabs.register(self.cfg_panel, 4, lambda w: self.cfg_tabs.setCurrentWidget(self.cfg_panel))

    # ===== Hex page helpers =====
    def _on_hex_tab_changed(self, idx):
        try:
            if 0 <= idx < len(self._hex_seg_buttons):
                self._hex_seg_buttons[idx].setChecked(True)
            labels = ['.text', 'strings', 'imports (APIs)', 'exports']
            if hasattr(self, '_hex_subtitle'):
                if self.disasm and self.current_file:
                    self._hex_subtitle.setText(labels[idx] if 0 <= idx < len(labels) else '')
                else:
                    self._hex_subtitle.setText('No PE loaded')
            if hasattr(self, '_hex_info_label'):
                counts = {0: 'bytes', 1: 'strings', 2: 'imports', 3: 'exports'}
                try:
                    edits = [self.hex_view, self.str_view, self.imports_view, self.exports_view]
                    if 0 <= idx < len(edits):
                        n = len(edits[idx].toPlainText().splitlines())
                        self._hex_info_label.setText(f'{n:,} {counts.get(idx, "")}')
                    else:
                        self._hex_info_label.setText('')
                except Exception:
                    self._hex_info_label.setText('')
        except Exception:
            pass

    def _refresh_hex_sections(self):
        if not hasattr(self, '_hex_sections_layout'):
            return
        # Clear existing rows
        while self._hex_sections_layout.count():
            item = self._hex_sections_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        sections = []
        try:
            if self.disasm and getattr(self.disasm, 'pe', None):
                image_base = self.disasm.pe.OPTIONAL_HEADER.ImageBase
                for s in self.disasm.pe.sections:
                    name = s.Name.decode('utf-8', errors='ignore').rstrip('\x00') or '(unnamed)'
                    va_size = getattr(s, 'Misc_VirtualSize', 0) or 0
                    full_va = image_base + s.VirtualAddress
                    sections.append((name, va_size, full_va))
        except Exception:
            sections = []
        if not sections:
            ph = QLabel('No PE loaded'); ph.setStyleSheet(f'color:{TEXT_MUTED}; font-size:11.5px; padding:8px 4px;')
            self._hex_sections_layout.addWidget(ph)
            return
        active_idx = getattr(self, '_active_hex_section', 0)
        for i, (name, va_size, full_va) in enumerate(sections):
            active = (i == active_idx)
            row = QFrame()
            row.setCursor(Qt.CursorShape.PointingHandCursor)
            row.setStyleSheet(
                f"QFrame {{ background-color: {'#EFF6FF' if active else 'transparent'}; "
                f"border-radius:6px; "
                f"border-left:{'3px solid ' + BLUE if active else '3px solid transparent'}; }}"
            )
            row.mousePressEvent = lambda _e, va=full_va, sz=va_size, idx=i: self._jump_hex_to_section(va, sz, idx)
            h = QHBoxLayout(row); h.setContentsMargins(10, 6, 10, 6)
            n = QLabel(name)
            n.setStyleSheet(f"color:{BLUE_DEEP if active else TEXT_PRIMARY}; font-family:{MONO}; "
                            f"font-size:12px; font-weight:{'700' if active else '500'};")
            o = QLabel(f'0x{va_size:08X}'); o.setStyleSheet(f"color:{TEXT_MUTED}; font-family:{MONO}; font-size:11.5px;")
            h.addWidget(n); h.addStretch(); h.addWidget(o)
            self._hex_sections_layout.addWidget(row)

    def _refresh_hex_bookmarks(self):
        if not hasattr(self, '_hex_bookmarks_layout'):
            return
        while self._hex_bookmarks_layout.count():
            item = self._hex_bookmarks_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        rows = []
        try:
            if hasattr(self, 'bookmarks_view'):
                for i in range(min(self.bookmarks_view.count(), 6)):
                    txt = self.bookmarks_view.item(i).text()
                    parts = [p.strip() for p in txt.split('|')]
                    if len(parts) >= 2:
                        addr = parts[0]
                        name = parts[1] if len(parts) > 1 else '—'
                        typ  = parts[2] if len(parts) > 2 else 'Bookmark'
                        rows.append((name, addr, typ))
                    else:
                        rows.append((txt[:30], '—', 'Bookmark'))
        except Exception:
            rows = []
        if not rows:
            ph = QLabel('No bookmarks yet'); ph.setStyleSheet(f'color:{TEXT_MUTED}; font-size:11.5px;')
            self._hex_bookmarks_layout.addWidget(ph)
            return
        fm = QFontMetrics(QFont('Segoe UI', 9, QFont.Weight.DemiBold))
        for name, rva, typ in rows:
            host = QWidget()
            row = QHBoxLayout(host); row.setContentsMargins(0,0,0,0); row.setSpacing(10)
            elided = fm.elidedText(name, Qt.TextElideMode.ElideRight, 126)
            n = QLabel(elided); n.setToolTip(name)
            n.setStyleSheet(f'color:{TEXT_PRIMARY}; font-size:12px; font-weight:600;'); n.setFixedWidth(130)
            r = QLabel(rva); r.setStyleSheet(f'color:{BLUE}; font-family:{MONO}; font-size:11px;'); r.setFixedWidth(104)
            t = QLabel(typ); t.setStyleSheet(f'color:{TEXT_SECONDARY}; font-size:11px;'); t.setFixedWidth(56)
            row.addWidget(n); row.addWidget(r); row.addWidget(t); row.addStretch()
            self._hex_bookmarks_layout.addWidget(host)

    def _jump_hex_to_section(self, va: int, size: int, idx: int):
        self._active_hex_section = idx
        dump_size = min(max(size, 64), 0x4000)
        self._render_hex_view(va, dump_size)
        self.hex_tabs.setCurrentWidget(self.hex_view)
        self.page_stack.setCurrentIndex(3)
        self.top_bar.setIndex(3)
        self.console(f"Hex: section at 0x{va:08X} ({size} bytes)")
        self._refresh_hex_sections()

    def _render_hex_view(self, va: int, size: int):
        """Render hex dump for [va, va+size) into hex_view using current _hex_opts."""
        self._hex_current_va   = va
        self._hex_current_size = size
        if not self.disasm or not va:
            return
        try:
            html = self.disasm.hexdump_at_html(va, size, self._hex_opts)
            self.hex_view.setHtml(html)
        except Exception:
            try:
                self.hex_view.setPlainText(self.disasm.hexdump_at(va, size) or '<no hex>')
            except Exception:
                pass

    def _on_hex_cursor_moved(self):
        """Decode the instruction at the hex-view cursor line and populate the Decoded View card."""
        if not self.disasm or not getattr(self, '_hex_current_va', 0):
            return
        try:
            block_num = self.hex_view.textCursor().blockNumber()
            va = self._hex_current_va + block_num * 16
            info = self.disasm.decode_at(va)
            self._hex_decoded_at.setText(f'0x{va:08X}')
            self._hex_decoded_type.setText(info.get('type', '—'))
            self._hex_decoded_target.setText(info.get('target', '—'))
            self._hex_decoded_symbol.setText(info.get('symbol', '—'))
            self._hex_decoded_desc.setText(info.get('description', '—'))
        except Exception:
            pass

    # ===== CFG page helpers =====
    def _cfg_action_fit(self):
        try:
            scene = self.cfg_graph.scene()
            if scene and not scene.itemsBoundingRect().isEmpty():
                self.cfg_graph.fitInView(
                    scene.itemsBoundingRect().adjusted(-20, -20, 20, 20),
                    Qt.AspectRatioMode.KeepAspectRatio
                )
                self.cfg_graph._scale = 1.0
        except Exception:
            pass

    def _cfg_action_zoom(self, factor):
        try:
            cur = getattr(self.cfg_graph, '_scale', 1.0)
            new_scale = max(0.3, min(4.0, cur * factor))
            actual = new_scale / cur if cur else factor
            self.cfg_graph._scale = new_scale
            self.cfg_graph.scale(actual, actual)
        except Exception:
            pass

    def _cfg_action_reset_zoom(self):
        try:
            self.cfg_graph.resetTransform()
            self.cfg_graph._scale = 1.0
        except Exception:
            pass

    def _cfg_action_export(self):
        try:
            path, _ = QFileDialog.getSaveFileName(self, 'Export CFG', 'cfg.png', 'PNG Image (*.png)')
            if not path:
                return
            scene = self.cfg_graph.scene()
            if not scene:
                return
            rect = scene.itemsBoundingRect().adjusted(-20, -20, 20, 20)
            img = QPixmap(int(max(1, rect.width())), int(max(1, rect.height())))
            img.fill(Qt.GlobalColor.white)
            painter = QPainter(img)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            scene.render(painter, source=rect)
            painter.end()
            img.save(path)
            try: self.console(f"CFG exported to {path}")
            except Exception: pass
        except Exception as e:
            try: self.console(f"CFG export error: {e}")
            except Exception: pass

    def _goto_full_analysis(self):
        """Navigate to Erevos View page and route focus to the Function Intelligence panel."""
        try:
            self._on_nav_changed(1)
            if hasattr(self, 'function_details_view'):
                self.function_details_view.setFocus()
        except Exception:
            pass

    def _cfg_action_open_in_erevos(self):
        try:
            # Prefer the last clicked block VA, fall back to the current function
            va = getattr(self, '_cfg_selected_block_va', None) or getattr(self, '_current_function_va', None)
            if va is not None:
                self._on_nav_changed(1)
                if hasattr(self, '_open_in_erevos_view'):
                    self._open_in_erevos_view(va, 'CFG selection')
        except Exception:
            pass

    def _on_cfg_block_clicked(self, nid: int):
        cfg = getattr(self.cfg_graph, '_last_cfg', None)
        if not cfg:
            return
        nodes = cfg.get('nodes', []) or []
        edges = cfg.get('edges', []) or []
        node  = next((n for n in nodes if n.get('id') == nid), None)
        if not node:
            return

        start_str = node.get('start', '')
        end_str   = node.get('end', '')

        try:
            start_va  = int(start_str, 16)
            end_va    = int(end_str,   16)
            byte_count = max(0, end_va - start_va)
        except Exception:
            start_va = 0; byte_count = 0

        succs = [e['dst'] for e in edges if e.get('src') == nid]
        preds = [e['src'] for e in edges if e.get('dst') == nid]

        insn_lines  = []
        call_count  = 0
        try:
            if self.disasm and byte_count > 0:
                text = self.disasm.disasm_at(start_va, size=min(byte_count, 0x800))
                if text:
                    insn_lines = [l for l in text.splitlines() if l.strip()]
                    call_count = sum(1 for l in insn_lines if ' call ' in l.lower())
        except Exception:
            pass

        insn_count = len(insn_lines) if insn_lines else max(1, byte_count // 3)

        self._cfg_node_title.setText(f'BB {nid}')
        self._cfg_node_addr.setText(start_str)
        self._cfg_node_instr.setText(str(insn_count))
        self._cfg_node_bytes.setText(str(byte_count))
        self._cfg_node_succ.setText(str(len(succs)))
        self._cfg_node_pred.setText(str(len(preds)))
        self._cfg_node_calls.setText(str(call_count))
        self._cfg_node_preview.setPlainText('\n'.join(insn_lines[:14]))

        if start_va:
            self._cfg_selected_block_va = start_va

    def _refresh_cfg_overview_panel(self, va, model, analysis):
        try:
            if not hasattr(self, '_cfg_func_label'):
                return
            fn_name = '—'
            try:
                if hasattr(self, '_functions') and self._functions:
                    key = f'0x{va:08X}'
                    rec = self._functions.get(key) or self._functions.get(va)
                    if isinstance(rec, dict):
                        fn_name = rec.get('name') or fn_name
                    elif isinstance(rec, str):
                        fn_name = rec
            except Exception:
                pass
            self._cfg_func_label.setText(f'{fn_name}  @  0x{va:08X}' if fn_name != '—' else f'0x{va:08X}')
            self._cfg_ov_function.setText(fn_name)
            self._cfg_ov_entry.setText(f'0x{va:08X}')
            self._cfg_ov_blocks.setText(str(analysis.get('basic_block_count', 0) if analysis else 0))
            edges = (model or {}).get('edges', [])
            self._cfg_ov_edges.setText(str(len(edges)))
            self._cfg_ov_depth.setText('—')
            nodes = (model or {}).get('nodes', [])
            srcs = {e.get('src') for e in edges}
            exits = sum(1 for n in nodes if n.get('id') not in srcs)
            self._cfg_ov_exits.setText(str(exits))
            br = (analysis or {}).get('branch_count')
            self._cfg_cx_cyclo.setText(str(br + 1) if isinstance(br, int) else '—')
            self._cfg_cx_nest.setText('—')
            loops = (analysis or {}).get('loop_back_edge_hints') or []
            self._cfg_cx_loops.setText(str(len(loops)))
            unreach = (analysis or {}).get('unreachable_block_hints') or []
            self._cfg_cx_dead.setText(f'{len(unreach)} blocks')
            indicators = (analysis or {}).get('suspicious_control_flow_indicators') or []
            if indicators:
                self._cfg_cx_note.setText('Suspicious indicators: ' + ', '.join(indicators[:3]))
            else:
                self._cfg_cx_note.setText('Low to moderate complexity. No suspicious control-flow indicators detected.')
        except Exception:
            pass

    def _on_nav_changed(self, idx: int):
        self.page_stack.setCurrentIndex(idx)
        self.top_bar.setIndex(idx)

    def _refresh_dashboard(self):
        try:
            self.quick_intel.setPlainText(self.threat_narrative_view.toPlainText()[:1200] if self.threat_narrative_view.toPlainText().strip() else 'No threat narrative available yet.')
        except Exception:
            pass
        self.dashboard_page.refresh()

    def _analysis_risk_score_for_va(self, va: int) -> tuple[int, str]:
        prof = (getattr(self, '_function_profiles', {}) or {}).get(va)
        if not prof:
            return 0, 'No Data'
        try:
            score = 15
            score += min(30, len(getattr(prof, 'suspicious_api_usage', []) or []) * 10)
            score += min(20, len(getattr(prof, 'risk_indicators', []) or []) * 5)
            score += min(10, int(getattr(prof, 'inbound_xrefs', 0) or 0))
            score += min(10, len(getattr(prof, 'referenced_strings', []) or []))
            flow = (getattr(self, '_data_flow_by_function', {}) or {}).get(f'0x{va:08X}', {}) or {}
            score += min(15, len(flow.get('api_argument_insights', []) or []) * 2)
            score += min(10, len(flow.get('string_flows', []) or []) * 2)
            score = max(0, min(100, score))
        except Exception:
            score = 0
        if score >= 80:
            label = 'High Risk'
        elif score >= 50:
            label = 'Medium Risk'
        elif score > 0:
            label = 'Low Risk'
        else:
            label = 'No Data'
        return score, label

    def _set_analysis_indicators(self, indicators):
        while self.analysis_indicators_layout.count():
            item = self.analysis_indicators_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        if not indicators:
            indicators = ['No strong indicators available yet']
        for label in indicators[:4]:
            row = QHBoxLayout(); row.setSpacing(10); row.setContentsMargins(0,0,0,0)
            dot = Dot(color=BLUE, size=6); wrap = QVBoxLayout(); wrap.setContentsMargins(0,7,0,0); wrap.addWidget(dot); row.addLayout(wrap)
            lbl = QLabel(label); lbl.setObjectName('Bullet'); row.addWidget(lbl, 1)
            host = QWidget(); host.setLayout(row)
            self.analysis_indicators_layout.addWidget(host)
        self.analysis_indicators_layout.addStretch(1)

    def _refresh_analysis_page(self, va: int | None = None):
        try:
            if va is None:
                va = getattr(self, '_current_function_va', None)
            if va is None and getattr(self, '_functions', None):
                va = next(iter(self._functions.keys()))
            if va is None:
                self.analysis_disasm_name.setText('No function selected')
                self.analysis_disasm_addr.setText('')
                self.analysis_intel_name.setText('No sample loaded')
                self.analysis_intel_addr.setText('')
                self.analysis_risk_value.setText('0')
                self.analysis_risk_badge.setText('No Data')
                self.analysis_risk_badge.setStyleSheet(f'color:{TEXT_MUTED}; font-size:11px; font-weight:700;')
                self.analysis_risk_gauge.setValue(0)
                self.analysis_disasm_view.setPlainText(self.asm_view.toPlainText() if hasattr(self, 'asm_view') else '')
                self.analysis_cfg_subtitle.setText('— no function selected')
                self._set_analysis_indicators([])
                return
            self._current_function_va = va
            name = self._display_func_name(va, (getattr(self, '_functions', {}) or {}).get(va, f'sub_{va:08X}'))
            addr = f'0x{va:08X}'
            self.analysis_disasm_name.setText(f'{name} @')
            self.analysis_disasm_addr.setText(addr)
            self.analysis_intel_name.setText(name)
            self.analysis_intel_addr.setText(addr)
            self.analysis_cfg_subtitle.setText(f'— {name}')
            if hasattr(self, 'asm_view'):
                self.analysis_disasm_view.setPlainText(self.asm_view.toPlainText())
            score, badge = self._analysis_risk_score_for_va(va)
            self.analysis_risk_value.setText(str(score))
            self.analysis_risk_badge.setText(badge)
            badge_color = RED if score >= 80 else AMBER if score >= 50 else TEXT_MUTED
            self.analysis_risk_badge.setStyleSheet(f'color:{badge_color}; font-size:11px; font-weight:700;')
            self.analysis_risk_gauge.setValue(score)
            prof = (getattr(self, '_function_profiles', {}) or {}).get(va)
            indicators = []
            if prof:
                indicators.extend(getattr(prof, 'suspicious_api_usage', []) or [])
                indicators.extend(getattr(prof, 'risk_indicators', []) or [])
            sem = (getattr(self, '_api_semantics_by_function', {}) or {}).get(addr, {}) or {}
            for row in (sem.get('high_value_calls') or sem.get('api_semantics_calls') or [])[:2]:
                api = row.get('api')
                if api:
                    indicators.append(f'Uses {api}')
            cleaned = []
            for x in indicators:
                s = str(x).replace('_', ' ').strip()
                if s and s not in cleaned:
                    cleaned.append(s[:120])
            self._set_analysis_indicators(cleaned)
            strings = []
            if prof:
                strings.extend(getattr(prof, 'referenced_strings', []) or [])
            for x in getattr(self, '_xrefs', []) or []:
                if getattr(x, 'src_function', None) == va and getattr(x, 'string_value', None):
                    strings.append(x.string_value)
            seen=[]
            strings=[s for s in strings if not (s in seen or seen.append(s))]
            for idx, (a, v) in enumerate(self.analysis_string_rows):
                if idx < len(strings[:5]):
                    a.setText(f'#{idx+1}')
                    txt = strings[idx].replace('\n', ' ')
                    v.setText((txt[:42] + '…') if len(txt) > 43 else txt)
                else:
                    a.setText('')
                    v.setText('')
            flow = (getattr(self, '_data_flow_by_function', {}) or {}).get(addr, {}) or {}
            note = flow.get('heuristic_note', 'Awaiting analysis')
            self.analysis_flow_note.setText(note if note else 'Awaiting analysis')
            labels = [
                f"API Argument Insights: {len(flow.get('api_argument_insights', []) or [])}",
                f"Strings Flows: {len(flow.get('string_flows', []) or [])}",
                f"Memory Writes: {len(flow.get('memory_write_hints', []) or [])}",
                f"Network Endpoints: {len(flow.get('network_endpoint_hints', []) or [])}",
            ]
            for (host, host_l, color), label in zip(self.analysis_flow_rows, labels):
                while host_l.count():
                    item = host_l.takeAt(0)
                    w = item.widget()
                    if w:
                        w.deleteLater()
                row = QHBoxLayout(); row.setSpacing(10); row.setContentsMargins(0,0,0,0)
                dot = Dot(color=color, size=6); wrap = QVBoxLayout(); wrap.setContentsMargins(0,7,0,0); wrap.addWidget(dot); row.addLayout(wrap)
                lbl = QLabel(label); lbl.setObjectName('Bullet'); row.addWidget(lbl, 1)
                host_l.addLayout(row)
        except Exception as e:
            try:
                self.console(f'Analysis page refresh error: {e}')
            except Exception:
                pass

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

        # 1. Collect chain-of-custody fields before asking for a save path.
        meta = self._prompt_report_metadata()
        if meta is None:
            return  # user cancelled

        # 2. Then ask where to save.
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report",
            f"{Path(self.current_file).stem}_report.html",
            "HTML files (*.html)"
        )
        if not save_path:
            return

        # 3. Remember the analyst name across sessions for convenience.
        try:
            self.session.last_examiner = meta["examiner"]
        except Exception:
            pass

        try:
            generate_report(
                self.current_file,
                top=30,
                max_strings=200,
                html_path=save_path,
                case_id=meta["case_id"],
                examiner=meta["examiner"],
                analyst_notes=meta["notes"],
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

    def _prompt_report_metadata(self):
        """Show a dialog asking for examiner, case number, and notes.

        Returns a dict {'examiner', 'case_id', 'notes'} on accept, or None on cancel.
        Examiner is required; the rest are optional.
        """
        dlg = QDialog(self)
        dlg.setWindowTitle("Forensic Report - Case Information")
        dlg.setModal(True)
        dlg.setMinimumWidth(520)

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        hdr = QLabel("Fill in the chain-of-custody fields for this report.")
        hdr.setObjectName("Muted")
        hdr.setWordWrap(True)
        layout.addWidget(hdr)

        form = QFormLayout()
        form.setSpacing(10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        examiner_edit = QLineEdit()
        examiner_edit.setPlaceholderText("Required, e.g. Jane Doe")
        examiner_edit.setText(getattr(self.session, "last_examiner", "") or "")
        form.addRow("Examiner (Analyst):", examiner_edit)

        case_edit = QLineEdit()
        case_edit.setPlaceholderText("Optional, e.g. CASE-2026-0042")
        form.addRow("Case number:", case_edit)

        layout.addLayout(form)

        notes_label = QLabel("Notes:")
        notes_label.setObjectName("FieldLabel")
        layout.addWidget(notes_label)
        notes_edit = QPlainTextEdit()
        notes_edit.setPlaceholderText("Optional - context, hypothesis, tooling versions, etc.")
        notes_edit.setMinimumHeight(120)
        layout.addWidget(notes_edit)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        ok_btn = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok_btn.setText("Generate Report")
        layout.addWidget(buttons)

        # Enable OK only when examiner is filled
        def _refresh_ok():
            ok_btn.setEnabled(bool(examiner_edit.text().strip()))
        examiner_edit.textChanged.connect(_refresh_ok)
        _refresh_ok()

        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)

        examiner_edit.setFocus()

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None

        return {
            "examiner": examiner_edit.text().strip(),
            "case_id":  case_edit.text().strip(),
            "notes":    notes_edit.toPlainText().strip(),
        }

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

    # ----------------- Load / display PE (QThread-based) -----------------
    def load_pe(self, path):
        """Kick off a background PE load. UI is updated in `_on_pe_loaded`."""
        if getattr(self, "_loader_thread", None) is not None and self._loader_thread.isRunning():
            QMessageBox.information(self, "Load PE", "A load is already in progress.")
            return
        self.console(f"Loading: {path}")
        self._loader_path = path

        self._loader_prog = QProgressDialog("Loading PE…", "Cancel", 0, 100, self)
        self._loader_prog.setWindowTitle("Erevos — Loading")
        self._loader_prog.setWindowModality(Qt.WindowModality.WindowModal)
        self._loader_prog.setMinimumDuration(0)
        self._loader_prog.setAutoClose(True)
        self._loader_prog.setAutoReset(True)
        self._loader_prog.setValue(0)

        self._loader_thread = PELoaderThread(path, self.session)
        self._loader_thread.progress.connect(self._on_load_progress)
        self._loader_thread.log.connect(self.console)
        self._loader_thread.finished.connect(self._on_pe_loaded)
        self._loader_prog.canceled.connect(self._loader_thread.cancel)

        self._loader_thread.start()

    def _on_load_progress(self, pct: int, label: str):
        prog = getattr(self, "_loader_prog", None)
        if prog is not None:
            prog.setValue(int(pct))
            prog.setLabelText(label)

    def _on_pe_loaded(self, result: dict):
        path = getattr(self, "_loader_path", None)
        prog = getattr(self, "_loader_prog", None)
        try:
            if result.get("cancelled"):
                if prog: prog.cancel()
                self.console("Load cancelled.")
                return
            if "error" in result:
                if prog: prog.cancel()
                tb = result.get("traceback", "")
                self.console(f"Error loading file: {result['error']}\n{tb}")
                QMessageBox.critical(self, "Error", f"Failed to load PE: {result['error']}")
                return

            # ---- Apply results to UI ----
            self.disasm = result.get("disasm")
            self.current_file = path
            self.session_path = SessionState.session_path_for_sample(path)
            self._load_session_for_current_file()

            if self.disasm:
                self.status.showMessage(
                    f"Loaded: {Path(path).name} | Arch: {self.disasm.arch} | "
                    f"ImageBase: 0x{self.disasm.pe.OPTIONAL_HEADER.ImageBase:08X}",
                    8000,
                )

            self.imports_view.setPlainText(result.get("imports_text", ""))
            self.exports_view.setPlainText(result.get("exports_text", ""))
            self.str_view.setPlainText(result.get("strings_text", ""))

            # Use naming-applied functions if available, fall back to raw
            self._functions = result.get("functions_v2") or result.get("functions") or {}
            self._refresh_function_list()

            self.resources_view.setPlainText(result.get("resources_text", ""))

            asm_text = result.get("asm_text", "")
            self.asm_view.setPlainText(asm_text)
            self.analysis_disasm_view.setPlainText(asm_text)

            self._xrefs = result.get("xrefs", [])
            self._xrefs_summary = result.get("xrefs_summary", {})
            self._function_profiles = result.get("function_profiles", {})
            self._function_intel_summary = normalize_function_intel_summary(result.get("function_intel_summary", {}))
            self._behavior_summaries = result.get("behavior_summaries", {})
            self.session.function_intel_summary = self._function_intel_summary
            self.session.behavior_summaries = self._behavior_summaries

            self._call_graph_model = result.get("call_graph_model", {})
            self._call_graph_summary = result.get("call_graph_summary", {})
            self.session.call_graph_summary = self._call_graph_summary
            try: self._refresh_call_graph_panel()
            except Exception: pass

            self._naming_suggestions = result.get("naming_suggestions", {})
            self.session.naming_suggestions = dict(self._naming_suggestions)

            self.critical_risk.setPlainText(result.get("risk_text", ""))
            self.critical_hot.setPlainText(result.get("hot_text", ""))

            self._behavior_patterns = result.get("behavior_patterns", {})
            self._threat_narrative = result.get("threat_narrative", {})
            try: self._render_threat_narrative()
            except Exception: pass

            try: self._reannotate_disassembly_views()
            except Exception: pass
            try: self._refresh_bookmarks_panel()
            except Exception: pass
            try: self._refresh_dashboard()
            except Exception: pass
            try:
                self._refresh_hex_sections()
                self._refresh_hex_bookmarks()
            except Exception:
                pass

            # Auto-render entry-point CFG so Analysis/CFG pages aren't empty
            try:
                if self.disasm:
                    ep = self.disasm.get_entry_point()
                    if ep is not None:
                        self._update_cfg_intel_for_function(int(ep))
            except Exception:
                pass

            self.console(f"Loaded {path}. Found {len(self._functions)} function(s).")
            if prog: prog.setValue(100)
        except Exception as e:
            tb = traceback.format_exc()
            self.console(f"Apply load result error: {e}\n{tb}")
            QMessageBox.critical(self, "Error", f"Failed to apply load: {e}")
        finally:
            self._loader_thread = None
            self._loader_prog = None

    def _populate_full_disasm(self):
        try:
            sec = self.disasm.text_section
            if not sec:
                self.asm_view.setPlainText("<no .text section>")
                self.analysis_disasm_view.setPlainText("<no .text section>")
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
            self.analysis_disasm_view.setPlainText(self.asm_view.toPlainText())
            self._reannotate_disassembly_views()
        except Exception as e:
            self.asm_view.setPlainText(f"Full disassembly error: {e}")
            self.analysis_disasm_view.setPlainText(self.asm_view.toPlainText())

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
        self._current_function_va = va
        self._render_function_profile(va)
        try:
            asm = self.disasm.disasm_at(va, size=0x800)
            self.asm_view.setPlainText(asm if asm else "<no disasm>")
            self.analysis_disasm_view.setPlainText(self.asm_view.toPlainText())
            self._render_hex_view(va, 1024)
            self._reannotate_disassembly_views()
            self.tabs.setCurrentWidget(self.asm_view)
            self._render_function_cfgs(va)
            self._update_cfg_intel_for_function(va)
            self._update_data_flow_for_function(va)
            self._refresh_analysis_page(va)
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
        self._current_function_va = va
        try:
            asm = self._disasm_function_text(va)
            self.erevos_view.set_function(name, va, asm)
            self.tabs.setCurrentWidget(self.erevos_view)
            self._render_function_cfgs(va)
            self._update_cfg_intel_for_function(va)
            self._update_data_flow_for_function(va)
            self._refresh_analysis_page(va)
        except Exception as e:
            self.console(f"Erevos view error: {e}")

    def _render_function_cfgs(self, va: int):
        """Render the CFG for `va` into both the CFG page graph and the Analysis page mini-graph."""
        if not build_cfg or not self.current_file:
            return
        try:
            g = build_cfg(self.current_file, va)
            data = g.to_json() if hasattr(g, "to_json") else g
            if not isinstance(data, dict):
                return
            for view in (self.cfg_graph, getattr(self, 'analysis_cfg_graph', None)):
                if view is None:
                    continue
                try:
                    view.render_cfg(data, disasm=self.disasm)
                except Exception:
                    try: view.render_cfg(data, disasm=None)
                    except Exception: pass
        except Exception as e:
            self.console(f"CFG render error: {e}")

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
        self._current_function_va = va
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
            try:
                self._refresh_cfg_overview_panel(va, model, analysis)
            except Exception:
                pass
            try:
                self.analysis_cfg_graph.render_cfg(model, disasm=None)
            except Exception:
                pass
            self._refresh_analysis_page(va)
        except Exception as e:
            self.cfg_intel_view.setPlainText(f"CFG intelligence error: {e}")
            self._refresh_analysis_page(va)

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
        self._current_function_va = va
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
            self._refresh_analysis_page(getattr(self, '_current_function_va', None))
            return
        if n.get("error"):
            self.threat_narrative_view.setPlainText(f"Threat narrative error: {n.get('error')}")
            self._refresh_analysis_page(getattr(self, '_current_function_va', None))
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
        self._refresh_analysis_page(getattr(self, '_current_function_va', None))
        self._refresh_dashboard()

    def _render_function_profile(self, va: int):
        prof = getattr(self, "_function_profiles", {}).get(va)
        if not prof:
            self.function_details_view.setPlainText(
                f"Function: 0x{va:08X}\nNo function intelligence profile available."
            )
            self._refresh_analysis_page(va)
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
            "[Stack & Calling Convention]",
            f"Prologue: {d['prologue_pattern'] or '-'}",
            f"Epilogue: {d['epilogue_pattern'] or '-'}",
            f"Frame size: {d['stack_frame_size_estimate']}",
            f"Local offsets: {', '.join(d['local_offsets_estimate']) or '-'}",
            f"Argument offsets: {', '.join(d['argument_offsets_estimate']) or '-'}",
            f"Calling convention: {d['calling_convention_hint']}",
        ]
        behavior = (self._behavior_summaries or {}).get(f"0x{va:08X}") or {}
        if behavior:
            lines.extend([
                "",
                "[Behavioral Summary]",
                f"Summary: {behavior.get('short_behavior_summary', '-')}",
                f"Confidence: {behavior.get('confidence', 'low')}",
                f"Capability tags: {', '.join(behavior.get('possible_capability_tags', [])) or '-'}",
                "Evidence:",
            ])
            lines.extend([f"  - {x}" for x in behavior.get("evidence_bullets", [])])
            lines.append("Caveats:")
            lines.extend([f"  - {x}" for x in behavior.get("caveats", [])])
        sugg = (self._naming_suggestions or {}).get(f"0x{va:08X}") or {}
        if sugg:
            lines.extend([
                "",
                "[Symbol & Naming]",
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
                "[Data Flow]",
                f"API argument insights: {len(flow.get('api_argument_insights', []))}",
                f"String flows: {len(flow.get('string_flows', []))}",
            ])
            for row in (flow.get("api_argument_insights") or [])[:6]:
                lines.append(f"  - {row.get('api')} @ {row.get('call_site')} ({row.get('confidence')}): args={row.get('arguments')}")
            for row in (flow.get("string_flows") or [])[:6]:
                lines.append(f"  - String '{row.get('string')}' -> {row.get('api')} via {row.get('via_register')} @ {row.get('call_site')}")
        sem = (self._api_semantics_by_function or {}).get(f"0x{va:08X}") or {}
        if sem:
            lines.extend([
                "",
                "[API Semantics]",
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
                "[Behavior Patterns]",
            ])
            for row in rel[:6]:
                lines.append(f"  - Pattern={row.get('pattern')} | confidence={row.get('confidence')} | scope={row.get('scope')}")
                for ev in (row.get("evidence_chain") or [])[:5]:
                    lines.append(f"      evidence: {ev}")
                for cv in (row.get("caveats") or [])[:2]:
                    lines.append(f"      caveat: {cv}")
        self.function_details_view.setPlainText("\n".join(lines))
        try:
            self.quick_intel.setPlainText((self.threat_narrative_view.toPlainText() or '\n'.join(lines))[:1200])
        except Exception:
            pass
        self._refresh_analysis_page(va)

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
            self.xrefs_to_view.addItem("No string references found.")
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
        try:
            self._refresh_hex_bookmarks()
        except Exception:
            pass

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
            self.xrefs_to_view.addItem(f"No xrefs to 0x{va:08X}.")
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
        if self.console_bar.document().lineCount() > 2000:
            cur = self.console_bar.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.Start)
            cur.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor, 200)
            cur.removeSelectedText()
        for c in getattr(self, '_page_consoles', []) or []:
            try:
                c.append(msg)
                if c.document().lineCount() > 2000:
                    cur2 = c.textCursor()
                    cur2.movePosition(QTextCursor.MoveOperation.Start)
                    cur2.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor, 200)
                    cur2.removeSelectedText()
            except Exception:
                pass
        print(msg)