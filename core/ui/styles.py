NAVY_DEEP    = "#0B1220"
NAVY         = "#101A2E"
NAVY_LIGHT   = "#16223C"
NAVY_BORDER  = "#1E2A44"
APP_BG       = "#F1F5F9"
WHITE        = "#FFFFFF"
BG_LIGHT     = "#F7FAFD"
BG_HOVER     = "#F1F5F9"
CARD_BORDER  = "#E4E9F2"
CARD_BORDER_MUTED = "#EEF1F6"
TEXT_PRIMARY   = "#0F172A"
TEXT_BODY      = "#1F2937"
TEXT_SECONDARY = "#64748B"
TEXT_MUTED     = "#94A3B8"
TEXT_FAINT     = "#B5BFCD"
TEXT_ON_NAVY   = "#D8DEE9"
BLUE        = "#2563EB"
BLUE_LIGHT  = "#3B82F6"
BLUE_DEEP   = "#1E3A8A"
BLUE_SOFT   = "#EFF6FF"
CYAN        = "#0891B2"
PURPLE      = "#7C3AED"
GREEN       = "#10B981"
GREEN_SOFT  = "#ECFDF5"
LIME        = "#84CC16"
AMBER       = "#F59E0B"
ORANGE      = "#F97316"
RED         = "#DC2626"
RED_SOFT    = "#FEF2F2"
TAG_MALWARE_BG  = "#FEE2E2"; TAG_MALWARE_FG  = "#991B1B"
TAG_SUS_BG      = "#FEF3C7"; TAG_SUS_FG      = "#92400E"
TAG_PACKED_BG   = "#E0E7FF"; TAG_PACKED_FG   = "#3730A3"
MONO = "Menlo, Consolas, 'DejaVu Sans Mono', 'Courier New', monospace"
SANS = "'Inter', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"

APP_QSS = f"""
* {{ font-family: {SANS}; color: {TEXT_PRIMARY}; }}
QMainWindow {{ background-color: {NAVY}; }}
QWidget#PageRoot {{ background-color: {APP_BG}; }}
QScrollArea, QScrollArea > QWidget > QWidget {{ background-color: {APP_BG}; border: none; }}
QFrame#TopBar {{ background-color: {NAVY}; border-bottom: 1px solid {NAVY_BORDER}; }}
QLabel#Brand {{ color: white; font-size: 20px; font-weight: 800; letter-spacing: 3px; }}
QLabel#BrandSub {{ color: {TEXT_MUTED}; font-size: 9px; letter-spacing: 2.4px; font-weight: 600; }}
QPushButton#NavBtn {{ color: {TEXT_ON_NAVY}; background: transparent; border: none; padding: 12px 20px 10px 20px; margin: 0px 2px; font-size: 13px; font-weight: 500; border-bottom: 2px solid transparent; }}
QPushButton#NavBtn:hover {{ color: white; }}
QPushButton#NavBtn:checked {{ color: white; font-weight: 600; border-bottom: 2px solid {BLUE_LIGHT}; }}
QPushButton#ReportBtn {{ background-color: {WHITE}; color: {NAVY}; border: 1px solid {CARD_BORDER}; border-radius: 4px; padding: 9px 18px; font-weight: 700; font-size: 10.5px; letter-spacing: 0.8px; }}
QPushButton#ReportBtn:hover {{ background-color: {BG_HOVER}; }}
QFrame#Card {{ background-color: {WHITE}; border: 1px solid {CARD_BORDER}; border-radius: 6px; }}
QFrame#SubCard {{ background-color: {BG_LIGHT}; border: 1px solid {CARD_BORDER_MUTED}; border-radius: 6px; }}
QLabel#CardTitle {{ color: {TEXT_PRIMARY}; font-size: 11px; font-weight: 800; letter-spacing: 1.4px; }}
QLabel#CardSubtitle {{ color: {TEXT_MUTED}; font-size: 10px; font-weight: 600; letter-spacing: 0.6px; }}
QLabel#Kicker {{ color: {TEXT_MUTED}; font-size: 10px; font-weight: 700; letter-spacing: 1.4px; }}
QLabel#FieldLabel {{ color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 500; }}
QLabel#FieldValue {{ color: {TEXT_PRIMARY}; font-size: 12.5px; font-weight: 600; }}
QLabel#FieldValueMono {{ color: {TEXT_PRIMARY}; font-size: 12px; font-weight: 600; font-family: {MONO}; }}
QLabel#BigNumber {{ color: {TEXT_PRIMARY}; font-size: 26px; font-weight: 800; }}
QLabel#MetricLabel {{ color: {TEXT_MUTED}; font-size: 10px; font-weight: 700; letter-spacing: 1.3px; }}
QLabel#MetricSub {{ color: {TEXT_MUTED}; font-size: 10.5px; font-weight: 500; }}
QLabel#Bullet {{ color: {TEXT_BODY}; font-size: 12.5px; }}
QLabel#Body {{ color: {TEXT_BODY}; font-size: 12.5px; }}
QLabel#Muted {{ color: {TEXT_SECONDARY}; font-size: 11.5px; }}
QPushButton#ActionBtn {{ background-color: {WHITE}; color: {TEXT_PRIMARY}; border: 1px solid {CARD_BORDER}; border-radius: 4px; padding: 9px 12px; font-size: 12px; font-weight: 600; text-align: left; }}
QPushButton#ActionBtn:hover {{ background-color: {BLUE_SOFT}; border-color: {BLUE_LIGHT}; color: {BLUE_DEEP}; }}
QPushButton#PrimaryBtn {{ background-color: {NAVY}; color: white; border: none; border-radius: 4px; padding: 9px 14px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
QPushButton#PrimaryBtn:hover {{ background-color: {NAVY_LIGHT}; }}
QPushButton#GhostBtn {{ background-color: {WHITE}; color: {TEXT_PRIMARY}; border: 1px solid {CARD_BORDER}; border-radius: 4px; padding: 7px 14px; font-size: 11px; font-weight: 600; }}
QPushButton#GhostBtn:hover {{ border-color: {BLUE_LIGHT}; color: {BLUE_DEEP}; }}
QPushButton#TabBtn {{ background: transparent; color: {TEXT_MUTED}; border: none; padding: 6px 8px; font-size: 10.5px; font-weight: 700; }}
QPushButton#TabBtn:checked {{ color: {TEXT_PRIMARY}; border-bottom: 2px solid {BLUE}; }}
QLineEdit {{ background-color: {WHITE}; color: {TEXT_PRIMARY}; border: 1px solid {CARD_BORDER}; border-radius: 4px; padding: 7px 10px; font-size: 12px; }}
QLineEdit:focus {{ border-color: {BLUE_LIGHT}; }}
QCheckBox {{ color: {TEXT_BODY}; font-size: 12px; spacing: 8px; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {TEXT_MUTED}; border-radius: 3px; background: white; }}
QCheckBox::indicator:checked {{ background: {BLUE}; border-color: {BLUE}; image: none; }}
QTableWidget, QListWidget, QTextEdit, QPlainTextEdit {{ background-color: {WHITE}; border: 1px solid {CARD_BORDER}; border-radius: 6px; font-size: 12px; color: {TEXT_BODY}; }}
QHeaderView::section {{ background-color: {WHITE}; color: {TEXT_MUTED}; border: none; border-bottom: 1px solid {CARD_BORDER_MUTED}; padding: 6px 4px; font-weight: 700; font-size: 10.5px; }}
QListWidget::item {{ padding: 8px 10px; border-bottom: 1px solid {CARD_BORDER_MUTED}; }}
QListWidget::item:selected {{ background-color: {NAVY}; color: {WHITE}; border-radius: 4px; }}
QPlainTextEdit#Console, QTextEdit#Console {{ background-color: #0B121F; color: #B7C5D9; border: none; font-family: {MONO}; font-size: 11.5px; padding: 8px 10px; }}
QTextEdit#AsmView, QTextEdit#HexView, QTextEdit#FunctionDetails, QTextEdit#ThreatView, QTextEdit#CfgIntel {{ font-family: {MONO}; }}
QTextEdit#HexView {{ background-color: {WHITE}; border: 1px solid {CARD_BORDER_MUTED}; border-radius: 6px; padding: 10px 14px; font-size: 12px; color: {TEXT_BODY}; selection-background-color: {BLUE_SOFT}; selection-color: {BLUE_DEEP}; }}
QStatusBar {{ background: {NAVY}; color: {TEXT_ON_NAVY}; border-top: 1px solid {NAVY_BORDER}; }}
QToolBar {{ background: {NAVY}; border: none; spacing: 6px; padding: 6px; }}
QMenuBar {{ background: {NAVY}; color: white; }}
QMenuBar::item:selected {{ background: {NAVY_LIGHT}; }}
QMenu {{ background: {WHITE}; color: {TEXT_PRIMARY}; border: 1px solid {CARD_BORDER}; }}
"""
