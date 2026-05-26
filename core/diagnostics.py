"""Crash logging + stdout/stderr capture.

When the app is built as a windowed PyInstaller EXE there is no console, so
`print()`, `sys.stderr.write()`, and uncaught exceptions all go to /dev/null.
This module redirects everything to a per-user log file and installs hooks for
both main-thread and worker-thread exceptions.

Log location:
    Windows: %LOCALAPPDATA%\\Erevos\\logs\\erevos.log
    Other:   ~/.erevos/logs/erevos.log

Crash dumps go to the same directory as `crash-YYYYmmdd-HHMMSS.log` so each
crash gets its own file you can attach to a bug report.
"""
from __future__ import annotations

import datetime as _dt
import faulthandler
import io
import os
import sys
import threading
import traceback
from pathlib import Path
from typing import Optional


_INSTALLED = False
_LOG_PATH: Optional[Path] = None
_CRASH_DIR: Optional[Path] = None
# faulthandler needs the file to stay open for the lifetime of the process;
# we hold a reference here so the GC doesn't close it.
_FAULT_FILE = None  # type: ignore[var-annotated]


def log_dir() -> Path:
    """Return the directory where Erevos writes its logs (creating it if needed)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        p = Path(base) / "Erevos" / "logs"
    else:
        p = Path.home() / ".erevos" / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _ts() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


class _TeeStream(io.TextIOBase):
    """File-like that writes to both an underlying stream (may be None) and a logfile."""

    def __init__(self, original, logfile_path: Path, tag: str):
        self._original = original
        self._path = logfile_path
        self._tag = tag

    def write(self, s):
        if not s:
            return 0
        try:
            if self._original is not None:
                try:
                    self._original.write(s)
                except Exception:
                    pass
            with open(self._path, "a", encoding="utf-8", errors="replace") as f:
                if s.strip():
                    f.write(s if s.endswith("\n") else s + "\n")
        except Exception:
            pass
        return len(s)

    def flush(self):
        try:
            if self._original is not None:
                self._original.flush()
        except Exception:
            pass


def _write_crash(prefix: str, exc_type, exc_value, exc_tb) -> Path:
    """Write a full traceback to a timestamped crash file. Return the path."""
    assert _CRASH_DIR is not None
    fname = f"crash-{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    path = _CRASH_DIR / fname
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Erevos crash report  {_ts()}\n")
            f.write(f"Origin: {prefix}\n")
            f.write(f"Platform: {sys.platform}\n")
            f.write(f"Python: {sys.version.splitlines()[0]}\n")
            f.write(f"Frozen: {bool(getattr(sys, 'frozen', False))}\n")
            f.write(f"MEIPASS: {getattr(sys, '_MEIPASS', '')}\n")
            f.write(f"Argv: {sys.argv!r}\n")
            f.write("-" * 60 + "\n")
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    except Exception:
        pass
    return path


def _show_crash_dialog(crash_path: Path, exc_type, exc_value):
    """Best-effort: pop up a QMessageBox so the user sees the error."""
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        if QApplication.instance() is None:
            return
        QMessageBox.critical(
            None,
            "Erevos crashed",
            f"An unhandled error occurred:\n\n"
            f"{exc_type.__name__}: {exc_value}\n\n"
            f"Full traceback was saved to:\n{crash_path}\n\n"
            f"Please attach this file when reporting the bug.",
        )
    except Exception:
        pass


def _excepthook(exc_type, exc_value, exc_tb):
    crash_path = _write_crash("main-thread", exc_type, exc_value, exc_tb)
    try:
        traceback.print_exception(exc_type, exc_value, exc_tb)
    except Exception:
        pass
    _show_crash_dialog(crash_path, exc_type, exc_value)


def _thread_excepthook(args):
    # args: threading.ExceptHookArgs(exc_type, exc_value, exc_traceback, thread)
    crash_path = _write_crash(
        f"thread:{getattr(args.thread, 'name', '?')}",
        args.exc_type, args.exc_value, args.exc_traceback,
    )
    try:
        traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback)
    except Exception:
        pass
    _show_crash_dialog(crash_path, args.exc_type, args.exc_value)


def install() -> Path:
    """Install crash logging and stdout/stderr capture. Idempotent.

    Returns the path to the main log file.
    """
    global _INSTALLED, _LOG_PATH, _CRASH_DIR, _FAULT_FILE
    if _INSTALLED:
        return _LOG_PATH  # type: ignore[return-value]

    d = log_dir()
    _CRASH_DIR = d
    _LOG_PATH = d / "erevos.log"

    # Header so we can tell sessions apart in the log
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n=== Erevos session start {_ts()} ===\n")
            f.write(f"argv={sys.argv!r}  frozen={bool(getattr(sys, 'frozen', False))}\n")
    except Exception:
        pass

    # Capture stdout / stderr -- in a windowed PyInstaller EXE both are None
    sys.stdout = _TeeStream(sys.stdout, _LOG_PATH, "stdout")
    sys.stderr = _TeeStream(sys.stderr, _LOG_PATH, "stderr")

    sys.excepthook = _excepthook
    # threading.excepthook covers everything created via threading.Thread, which
    # includes PyQt6's QThread when it runs Python code.
    try:
        threading.excepthook = _thread_excepthook
    except Exception:
        pass

    # faulthandler catches native crashes (SIGSEGV, access violations, etc.)
    # that bypass Python's normal exception machinery -- this is essential for
    # diagnosing crashes inside C extensions like Capstone.
    # The file must stay open for the process lifetime; faulthandler writes to
    # it synchronously from the signal handler.
    try:
        fault_path = d / "faulthandler.log"
        _FAULT_FILE = open(fault_path, "a", encoding="utf-8", buffering=1)
        _FAULT_FILE.write(f"\n=== faulthandler enabled {_ts()} pid={os.getpid()} ===\n")
        _FAULT_FILE.flush()
        faulthandler.enable(file=_FAULT_FILE, all_threads=True)
    except Exception as e:
        # Best-effort -- log to main file if we couldn't open the dedicated one
        try:
            with open(_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"WARN: could not enable faulthandler: {e}\n")
        except Exception:
            pass

    _INSTALLED = True
    return _LOG_PATH


def log_path() -> Optional[Path]:
    return _LOG_PATH
