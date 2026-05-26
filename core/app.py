"""Backward-compatible shim.

The Erevos GUI was split into the `core.ui` package in 2026-05.
This module re-exports `MainWindow` so that `from core.app import MainWindow`
(used by `main.py`) keeps working.
"""
from core.ui.main_window import MainWindow

__all__ = ["MainWindow"]
