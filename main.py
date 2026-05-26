import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication

# Install diagnostics FIRST so any import error below is captured to the log.
from core.diagnostics import install as _install_diagnostics
_LOG = _install_diagnostics()
print(f"[startup] log file: {_LOG}")

from core.app import MainWindow
from core.splash import SplashScreen


def main():

    # DPI policy must be set before QApplication is created
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Erevos")
    app.setOrganizationName("Erevos")

    # 1) Show splash
    splash = SplashScreen()
    splash.show()
    splash.start()

    # 2) When splash finishes, show the main window
    def _launch():
        try:
            win = MainWindow()
            win.show()
        finally:
            splash.close()

    splash.finished.connect(_launch)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
