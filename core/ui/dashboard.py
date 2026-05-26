from pathlib import Path
from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTextEdit, QFrame,
)
from PyQt6.QtCore import Qt

from core.ui.styles import (
    TEXT_PRIMARY, TEXT_MUTED, TEXT_BODY, TEXT_SECONDARY,
    BLUE, BLUE_DEEP, MONO, RED, AMBER,
)
from core.ui.widgets import Card, RiskGauge, CallGraphWidget, make_console_card


class DashboardPage(QScrollArea):
    def __init__(self, owner, parent=None):
        super().__init__(parent)
        self.owner = owner
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        root = QWidget(); root.setObjectName('PageRoot'); self.setWidget(root)
        outer = QVBoxLayout(root); outer.setContentsMargins(22,18,22,22); outer.setSpacing(16)

        row1 = QGridLayout(); row1.setSpacing(16); outer.addLayout(row1)

        self.file_card = Card('File Information'); row1.addWidget(self.file_card, 0, 0)

        self.risk_card = Card('Risk Score')
        self.risk_gauge = RiskGauge(value=0, label='NO DATA', size=220)
        self.risk_card.addWidget(self.risk_gauge, 1)
        row1.addWidget(self.risk_card, 0, 1)

        self.class_card = Card('Classification')
        self.class_title = QLabel('No sample loaded')
        self.class_title.setStyleSheet(f'color:{TEXT_MUTED}; font-size:18px; font-weight:800;')
        self.class_card.addWidget(self.class_title)
        self.class_body = QLabel('Load a PE file to populate real analysis views.')
        self.class_body.setWordWrap(True); self.class_body.setObjectName('Body')
        self.class_card.addWidget(self.class_body, 1)
        row1.addWidget(self.class_card, 0, 2)

        self.quick_card = Card('Quick Actions')
        for label, cb in [
            ('Open PE', owner.action_open),
            ('Go to Erevos View', lambda: owner._on_nav_changed(1)),
            ('Open Analysis', lambda: owner._on_nav_changed(2)),
            ('Open Hex', lambda: owner._on_nav_changed(3)),
            ('Open CFG', lambda: owner._on_nav_changed(4)),
        ]:
            btn = QPushButton(label); btn.setObjectName('ActionBtn'); btn.clicked.connect(cb)
            self.quick_card.addWidget(btn)
        row1.addWidget(self.quick_card, 0, 3)

        self.metric_row = QHBoxLayout(); self.metric_row.setSpacing(16); outer.addLayout(self.metric_row)
        self.metric_cards = []
        for title in ['Functions', 'Strings', 'Imports (APIs)', 'Xrefs', 'Sections']:
            card = Card(parent=self, padding=(18,16,18,16))
            lbl = QLabel(title.upper()); lbl.setObjectName('MetricLabel')
            val = QLabel('0'); val.setObjectName('BigNumber')
            sub = QLabel('Awaiting sample'); sub.setObjectName('MetricSub')
            card.addWidget(lbl); card.addWidget(val); card.addWidget(sub)
            self.metric_row.addWidget(card)
            self.metric_cards.append((card, val, sub))

        row3 = QHBoxLayout(); row3.setSpacing(16); outer.addLayout(row3)

        self.graph_card = Card('Call Graph', 'Click to inspect, double-click to open')
        self.call_graph_widget = CallGraphWidget()
        self.call_graph_widget.nodeClicked.connect(self._on_callgraph_clicked)
        self.call_graph_widget.nodeDoubleClicked.connect(self._on_callgraph_dblclicked)
        self.graph_card.addWidget(self.call_graph_widget)
        row3.addWidget(self.graph_card, 3)

        right = QVBoxLayout(); right.setSpacing(16)
        self.behavior_card = Card('Behavior Patterns')
        self.behavior_text = QTextEdit(); self.behavior_text.setReadOnly(True); self.behavior_text.setMaximumHeight(220)
        right.addWidget(self.behavior_card); self.behavior_card.addWidget(self.behavior_text)
        self.threat_card = Card('Threat Narrative')
        self.threat_preview = QTextEdit(); self.threat_preview.setReadOnly(True); self.threat_preview.setMaximumHeight(220)
        self.threat_card.addWidget(self.threat_preview); right.addWidget(self.threat_card)
        side = QWidget(); side.setLayout(right); row3.addWidget(side, 2)

        cwrap, _ = make_console_card(owner, height=110)
        outer.addWidget(cwrap, 0)

    def refresh(self):
        owner = self.owner
        while self.file_card.layout().count() > 1:
            item = self.file_card.layout().takeAt(1)
            w = item.widget()
            if w: w.deleteLater()
            elif item.layout():
                while item.layout().count():
                    ci = item.layout().takeAt(0); cw = ci.widget()
                    if cw: cw.deleteLater()

        info = []
        if owner.current_file and owner.disasm:
            try:
                p = Path(owner.current_file)
                info = [
                    ('File Name', p.name, False),
                    ('File Size', f'{p.stat().st_size:,} bytes', False),
                    ('Architecture', str(getattr(owner.disasm, 'arch', '-')), False),
                    ('Image Base', f"0x{owner.disasm.pe.OPTIONAL_HEADER.ImageBase:08X}", True),
                    ('Entry Point', f"0x{owner.disasm.get_entry_point():08X}", True),
                ]
            except Exception:
                info = []
        if not info:
            info = [('Status', 'No sample loaded', False)]

        for lbl, val, mono in info:
            row = QHBoxLayout()
            l = QLabel(lbl); l.setObjectName('FieldLabel'); l.setFixedWidth(108)
            v = QLabel(val); v.setObjectName('FieldValueMono' if mono else 'FieldValue'); v.setWordWrap(True)
            row.addWidget(l); row.addWidget(v, 1)
            self.file_card.addLayout(row)

        funcs = len(getattr(owner, '_functions', {}) or {})
        strings = len(owner.str_view.toPlainText().splitlines()) if hasattr(owner, 'str_view') else 0
        imports = len(owner.imports_view.toPlainText().splitlines()) if hasattr(owner, 'imports_view') else 0
        xrefs = len(getattr(owner, '_xrefs', []) or [])
        sections = len(getattr(getattr(owner, 'disasm', None), 'pe', object()).sections) if getattr(owner, 'disasm', None) else 0
        for (_, val, sub), n, s in zip(self.metric_cards, [funcs, strings, imports, xrefs, sections], ['Discovered', 'Extracted', 'Imported', 'Structured refs', 'PE sections']):
            val.setText(f'{n:,}'); sub.setText(s)

        risk = 0; label = 'NO DATA'; class_text = 'No sample loaded'
        preview = 'Load a PE file to populate real analysis views.'
        if getattr(owner, '_threat_narrative', None):
            ra = (owner._threat_narrative or {}).get('risk_assessment') or {}
            lvl = str(ra.get('level', '')).lower()
            mapping = {'critical': 95, 'high': 85, 'medium': 60, 'low': 30}
            risk = mapping.get(lvl, 70 if owner.current_file else 0)
            label = (ra.get('level') or 'Analysis Ready')
            class_text = ra.get('level', 'Analysis Ready')
            preview = ra.get('reason') or preview
        elif owner.current_file:
            risk = 65; label = 'ANALYSIS'; class_text = 'Loaded'
            preview = 'Sample loaded. Open Erevos View or Analysis for detail.'

        self.risk_gauge.setValue(risk); self.risk_gauge.label = label; self.risk_gauge.update()
        self.class_title.setText(class_text); self.class_body.setText(preview)

        patterns = (getattr(owner, '_behavior_patterns', {}) or {}).get('patterns') or []
        if patterns:
            self.behavior_text.setPlainText('\n'.join(f"- {r.get('pattern')} | confidence={r.get('confidence')}" for r in patterns[:12]))
        else:
            self.behavior_text.setPlainText('No behavior pattern summary yet.')

        self.threat_preview.setPlainText(
            owner.threat_narrative_view.toPlainText()[:2000]
            if hasattr(owner, 'threat_narrative_view') else 'No narrative yet.'
        )

        # Live call graph
        try:
            model = getattr(owner, '_call_graph_model', None) or {}
            summary = getattr(owner, '_call_graph_summary', None) or {}
            ep = owner.disasm.get_entry_point() if owner.disasm else None
            if model.get('nodes'):
                self.call_graph_widget.set_call_graph(model, summary, entry_va=ep)
            else:
                self.call_graph_widget.clear_graph()
        except Exception:
            pass

    # ---- Call graph interactions ----
    def _on_callgraph_clicked(self, va: int):
        try:
            name = self.owner._functions.get(va) if getattr(self.owner, '_functions', None) else None
            label = name or f'sub_{va:08X}'
            self.owner.console(f'Call graph: 0x{va:08X}  {label}')
        except Exception:
            pass

    def _on_callgraph_dblclicked(self, va: int):
        try:
            name = self.owner._functions.get(va) if getattr(self.owner, '_functions', None) else None
            self.owner._open_in_erevos_view(va, name or f'sub_{va:08X}')
            self.owner._on_nav_changed(1)
        except Exception:
            pass
