# core/splash.py
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QPushButton, QWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QPixmap
from pathlib import Path


class SplashScreen(QDialog):
    finished = pyqtSignal()

    VERSION = "v0.1 preview"
    AUTHOR = "Nikolaos Kranidiotis"
    SITE = "https://osec.gr"
    CONTACT = "erevos@osec.gr"
    LOGO_PATH = Path("ui/logo.png")

    def __init__(self, parent=None):
        super().__init__(parent)

        # Window
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Dialog
            | Qt.WindowType.CustomizeWindowHint
        )
        self.setModal(True)
        self.setFixedSize(640, 420)

        # High-contrast dark theme
        self.setStyleSheet("""
            QDialog {
                background: #0f1115;
                border: 1px solid #2a2f3a;
            }
            QLabel#Title {
                color: #e9e9f1;
                font-family: Consolas, "SF Mono", monospace;
                font-size: 30px;
                font-weight: 800;
                letter-spacing: 1px;
            }
            QLabel#Meta, QLabel#Small {
                color: #cfd3dc;
                font-family: Consolas, "SF Mono", monospace;
                font-size: 12px;
            }
            QLabel#Link {
                color: #72d0ff;
                font-family: Consolas, "SF Mono", monospace;
                font-size: 12px;
            }
            QLabel#Badge {
                color: #0f1115;
                background: #b7a5ff;
                border: 0px;
                padding: 4px 10px;
                border-radius: 6px;
                font-family: Consolas, "SF Mono", monospace;
                font-size: 12px;
                font-weight: 700;
            }
            QLabel#Logo {
                border: 1px dashed #3a4152;
                background: #141821;
                color: #59627a;
            }
            QProgressBar {
                background: #141821;
                border: 1px solid #3a4152;
                height: 22px;
                color: #e9e9f1;            /* progress text */
                text-align: center;
                font-family: Consolas, "SF Mono", monospace;
                font-size: 12px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                                            stop:0 #7f6cff, stop:1 #c4baff);
            }
            QPushButton#Primary {
                border: 1px solid #7f6cff;
                background: #1a1f2b;
                color: #e9e9f1;
                padding: 10px 16px;
                border-radius: 10px;
                font-family: Consolas, "SF Mono", monospace;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton#Primary:hover { background: #222739; }
            QPushButton#Primary:disabled {
                border-color: #46506a;
                color: #8b94a7;
                background: #171b25;
            }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 22, 22, 22)
        root.setSpacing(12)

        # Title
        title = QLabel("EREVOS", self)
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(title)

        # Logo (centered, reserved space)
        logo = QLabel(self)
        logo.setObjectName("Logo")
        logo.setFixedHeight(130)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if self.LOGO_PATH.exists():
            pix = QPixmap(str(self.LOGO_PATH))
            if not pix.isNull():
                logo.setPixmap(pix.scaledToHeight(110, Qt.TransformationMode.SmoothTransformation))
                logo.setStyleSheet(logo.styleSheet() + "border: none;")
        else:
            logo.setText("logo.png")
        root.addWidget(logo, 0, Qt.AlignmentFlag.AlignHCenter)

        # Meta (version, author, links)
        meta = QVBoxLayout()
        ver = QLabel(self.VERSION, self); ver.setObjectName("Badge"); ver.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        author = QLabel(f"Author: {self.AUTHOR}", self); author.setObjectName("Meta"); author.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        site = QLabel(f'<a href="{self.SITE}">osec.gr</a>', self); site.setObjectName("Link"); site.setOpenExternalLinks(True); site.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        contact = QLabel(f'<a href="mailto:{self.CONTACT}">{self.CONTACT}</a>', self); contact.setObjectName("Link"); contact.setOpenExternalLinks(True); contact.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        meta.addWidget(ver)
        meta.addWidget(author)
        meta.addWidget(site)
        meta.addWidget(contact)

        meta_wrap = QWidget(self); meta_wrap.setLayout(meta)
        root.addWidget(meta_wrap)

        # Progress + status
        self.bar = QProgressBar(self)
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        root.addWidget(self.bar)

        self.status = QLabel("Initializing…", self)
        self.status.setObjectName("Small")
        self.status.setAlignment(Qt.AlignmentFlag.AlignLeft)
        root.addWidget(self.status)

        # Load button (below progress bar)
        self.load_btn = QPushButton("Load Erevos", self)
        self.load_btn.setObjectName("Primary")
        self.load_btn.setEnabled(False)
        self.load_btn.clicked.connect(self._emit_finished)
        root.addWidget(self.load_btn, 0, Qt.AlignmentFlag.AlignHCenter)

        # Smooth timed progress (you can replace with real signals later)
        self._steps = [
            (12, "Init UI…"),
            (30, "Loading disassembler core…"),
            (55, "Parsing modules (risk, cfg, resources)…"),
            (78, "High-DPI & styles…"),
            (95, "Finalizing…"),
            (100, "Ready. Click “Load Erevos”."),
        ]
        self._idx = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def start(self):
        self._timer.start(25)

    def _tick(self):
        v = self.bar.value()
        target = self._steps[self._idx][0]
        if v < target:
            self.bar.setValue(v + 1)
            self.bar.setFormat(f"{self.bar.value()}%")  # ensure visible text
            return

        # milestone reached
        self.status.setText(self._steps[self._idx][1])
        if self._idx + 1 < len(self._steps):
            self._idx += 1
        else:
            self._timer.stop()
            self.load_btn.setEnabled(True)
            self.load_btn.setDefault(True)
            self.load_btn.setFocus()

    def _emit_finished(self):
        self.finished.emit()
