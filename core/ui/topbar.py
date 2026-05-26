from PyQt6.QtWidgets import QFrame, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QButtonGroup
from PyQt6.QtCore import Qt, pyqtSignal

from core.ui.styles import (
    NAVY, NAVY_BORDER, NAVY_LIGHT, BLUE_LIGHT, TEXT_ON_NAVY, TEXT_MUTED,
    CARD_BORDER, WHITE, BG_HOVER,
)
from core.ui.widgets import SkullLogo


class TopBar(QFrame):
    navChanged = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('TopBar')
        self.setFixedHeight(68)
        outer = QHBoxLayout(self)
        outer.setContentsMargins(22, 10, 22, 10)
        outer.setSpacing(16)

        brand_box = QHBoxLayout(); brand_box.setSpacing(12)
        brand_box.addWidget(SkullLogo(36))
        brand_vbox = QVBoxLayout(); brand_vbox.setSpacing(0); brand_vbox.setContentsMargins(0,0,0,0)
        name = QLabel('EREVOS'); name.setObjectName('Brand')
        sub = QLabel('STATIC PE DISASSEMBLER'); sub.setObjectName('BrandSub')
        brand_vbox.addWidget(name); brand_vbox.addWidget(sub)
        brand_box.addLayout(brand_vbox)
        outer.addLayout(brand_box)
        outer.addSpacing(30)

        self.buttons = []; self.group = QButtonGroup(self); self.group.setExclusive(True)
        for i, nm in enumerate(['Dashboard', 'Erevos View', 'Analysis', 'Hex', 'CFG']):
            b = QPushButton(nm); b.setObjectName('NavBtn'); b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor); b.setMinimumWidth(110)
            if i == 0: b.setChecked(True)
            self.group.addButton(b, i); self.buttons.append(b); outer.addWidget(b)
        self.group.idClicked.connect(self.navChanged.emit)
        outer.addStretch()

        self.report_btn = QPushButton('⚑  GENERATE\nFORENSIC REPORT')
        self.report_btn.setObjectName('ReportBtn')
        self.report_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.report_btn.setMinimumHeight(44)
        self.report_btn.setMinimumWidth(170)
        outer.addWidget(self.report_btn)

    def setIndex(self, idx):
        if 0 <= idx < len(self.buttons):
            self.buttons[idx].setChecked(True)


class ViewRouter:
    def __init__(self, stack, window):
        self.stack = stack
        self.window = window
        self._map = {}

    def register(self, widget, page_idx, selector=None):
        self._map[id(widget)] = (page_idx, selector, widget)

    def setCurrentWidget(self, widget):
        info = self._map.get(id(widget))
        if not info: return
        page_idx, selector, obj = info
        self.stack.setCurrentIndex(page_idx)
        self.window.top_bar.setIndex(page_idx)
        if selector: selector(obj)

    def currentWidget(self):
        idx = self.stack.currentIndex()
        if idx == 1:
            return self.window.erevos_center.currentWidget()
        if idx == 2:
            return self.window.analysis_tabs.currentWidget()
        if idx == 3:
            return self.window.hex_tabs.currentWidget()
        if idx == 4:
            return self.window.cfg_tabs.currentWidget()
        return self.stack.currentWidget()
