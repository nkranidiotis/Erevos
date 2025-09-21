import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication

from core.app import MainWindow
from core.splash import SplashScreen

def _excepthook(exc_type, exc_value, exc_traceback):
    import traceback
    traceback.print_exception(exc_type, exc_value, exc_traceback)

def main():
    sys.excepthook = _excepthook

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
