"""Minimal plugin runtime for triage extensions.

Plugin function signature:
    def analyze(pe, file_bytes: bytes, current_result: dict) -> dict
"""

from __future__ import annotations

import importlib
from typing import Any, Dict, List


DEFAULT_PLUGINS = [
    # Example: "my_plugins.company_heuristics"
]


def run_plugins(pe: Any, file_bytes: bytes, current_result: Dict[str, Any], plugin_paths: List[str] | None = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path in (plugin_paths or DEFAULT_PLUGINS):
        try:
            mod = importlib.import_module(path)
            fn = getattr(mod, 'analyze', None)
            if callable(fn):
                rv = fn(pe, file_bytes, current_result)
                if isinstance(rv, dict):
                    out.append({'plugin': path, 'result': rv, 'error': None})
                else:
                    out.append({'plugin': path, 'result': None, 'error': 'plugin returned non-dict'})
            else:
                out.append({'plugin': path, 'result': None, 'error': 'analyze() not found'})
        except Exception as exc:
            out.append({'plugin': path, 'result': None, 'error': str(exc)})
    return out
