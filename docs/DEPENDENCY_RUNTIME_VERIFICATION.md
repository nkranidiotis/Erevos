# Erevos 2.0 Dependency & Runtime Verification

This document captures required runtime dependencies, degraded behavior when missing, and verification commands.

## Required dependencies

- `pefile` (PE parsing/report build path)
- `PyQt6` (GUI runtime)
- `capstone` (disassembly/xref-dependent paths)
- `jinja2` (HTML report rendering)
- `weasyprint` (PDF export)

The baseline dependency list is in `requirements.txt`.

## Degraded behavior when dependencies are missing

- Missing `pefile`
  - `core/modules/report.py::build_data()` raises a clear runtime error.
  - Effect: report generation from a PE path is unavailable.

- Missing `PyQt6`
  - GUI startup is unavailable (`core/app.py` cannot be imported/run).
  - Effect: UI features cannot be exercised.

- Missing `capstone`
  - Some xref/disassembly-dependent paths degrade depending on module usage.
  - Effect: reduced analysis fidelity in capstone-backed paths.

- Missing `jinja2`
  - `core/modules/report.py::render_html()` raises a clear runtime error.
  - Effect: no HTML report rendering.

- Missing `weasyprint`
  - `export_pdf_from_html()` returns an error string.
  - `generate_report(..., no_pdf_fail=True)` continues and records a note.
  - `generate_report(..., no_pdf_fail=False)` raises.

## Verification commands

### Compile verification

```bash
python -m compileall core tests
```

### Unit tests

```bash
python -m unittest discover -s tests
```

### CLI report generation

```bash
python core/modules/report.py <path_to_pe> --html /tmp/report.html --json /tmp/report.json
```

### PDF export behavior

Graceful mode (default):

```bash
python core/modules/report.py <path_to_pe> --html /tmp/report.html --json /tmp/report.json --pdf /tmp/report.pdf --no-pdf-fail
```

Hard-fail mode:

```bash
python core/modules/report.py <path_to_pe> --html /tmp/report.html --json /tmp/report.json --pdf /tmp/report.pdf --pdf-fail-hard
```

### Offscreen GUI smoke test

```bash
QT_QPA_PLATFORM=offscreen python - <<'PY'
from PyQt6.QtWidgets import QApplication
from core.app import MainWindow
app = QApplication([])
w = MainWindow()
print('tabs:', [w.tabs.tabText(i) for i in range(w.tabs.count())])
w.close()
app.quit()
PY
```

## Real-PE integration fixture policy

A real-PE integration test is only enabled when a safe fixture already exists in-repo under `tests/fixtures/`.
No external samples are downloaded and no suspicious binaries are added.
