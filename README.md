# Erevos

**Static PE Disassembler & Forensic Analysis Toolkit**

Erevos is a Python desktop application for static analysis of Windows PE
executables. It is built for investigators, reverse engineers, and malware
analysts who need to triage a sample, extract forensic artifacts, and produce
a chain-of-custody-ready report in minutes rather than hours.

It pairs a Capstone-powered disassembler with a layered intelligence pipeline
that goes well beyond raw bytes: function profiling, call-graph and CFG
analytics, data-flow insights, API semantics, behavior-pattern detection, a
threat narrative with extracted IoCs, and per-sample session persistence so
that analyst work (renames, comments, labels, bookmarks) survives across
runs.

---

## Highlights

### Five-page analyst workspace

- **Dashboard** — file metadata, risk gauge, classification, live call-graph
  preview (click to inspect, double-click to open), behavior patterns,
  threat-narrative snapshot, and key counters (functions, strings, imports,
  xrefs, sections).
- **Erevos View** — searchable function list with rich filters (renamed /
  commented / bookmarked / suspicious-API / inbound-xref count / referenced
  string), zoomable function box, full disassembly view, and a function
  intelligence panel with behavioral summary, suggested name, and risk
  indicators.
- **Analysis** — function-centric drill-in with disassembly, CFG mini-graph,
  risk gauge, key indicators, strings referenced by the function, and a
  data-flow summary (API argument insights, string flows, memory writes,
  network endpoints).
- **Hex** — three-column layout: PE section list (click to jump), hex dump
  with optional highlighting for strings / API IAT slots / jump targets, and
  a decoded-view card that interprets the bytes under the cursor (instruction
  type, target, resolved symbol, description).
- **CFG** — three-column layout: overview / legend / complexity metrics
  (cyclomatic, loops, dead-code blocks, suspicious indicators), interactive
  bezier-edge graph with arrowheads and BFS layout, and a node-info panel
  with per-block instruction preview, predecessors/successors, and call
  count. Includes a live minimap and PNG export.

### Intelligence pipeline

All of the following run automatically when a sample is loaded:

- **Function discovery** from exports, entry point, and prologue scanning.
- **Cross-references** — code, string, and API references with confidence
  labels.
- **Function intelligence** — instruction count, basic-block estimate,
  inbound/outbound xrefs, prologue/epilogue, calling-convention hint, stack
  frame size, referenced strings, suspicious-API usage, risk indicators.
- **Call-graph analysis** — hub detection, suspicious-edge marking, entry
  reachability.
- **CFG intelligence** — branch density, unresolved edges, loop / back-edge
  hints, unreachable-block hints, opaque-predicate candidates.
- **Naming intelligence** — high-confidence suggested function names you can
  apply individually or in bulk.
- **Data-flow** — per-function API argument insights, string flows
  (`"cmd.exe" -> CreateProcessA`), memory-write hints, network endpoints.
- **API semantics** — interpreted arguments and capability tags for
  high-value calls.
- **Behavior patterns** — multi-function pattern detection
  (persistence, injection, lateral movement, etc.) with evidence chains and
  confidence.
- **Threat narrative** — capability summary, execution-flow summary, key
  functions with rationale, and an IoC roll-up: URLs, IPs, file paths,
  mutexes, relevant API usage.

### Forensic reporting

Click **Generate Forensic Report** and Erevos asks for the chain-of-custody
fields before writing anything:

- **Examiner (Analyst)** — required.
- **Case number** — optional, free text.
- **Notes** — multi-line free-text block for context, hypothesis, tooling
  versions, etc.

The resulting HTML report embeds the full intelligence pipeline output along
with file hashes (SHA-256, MD5), entry point, section table, imports/exports,
strings, risk scoring, packer heuristics, and every analyst artifact (renames,
comments, labels, bookmarks). Disassembly is also exportable as plain `.txt`.

### Analyst-friendly UX

- Drag-and-drop a PE onto the window to load it.
- Background-threaded loader keeps the GUI responsive — twelve weighted
  phases with a Cancel button that actually aborts work.
- Per-page console with bounded scrollback.
- Right-click any address to add a comment, label, bookmark, or jump to
  xrefs.
- Per-sample session is saved automatically next to the sample's hash; all
  your work returns the next time you open the same binary.
- Crash log + auto-rotating diagnostic log at
  `%LOCALAPPDATA%\Erevos\logs\erevos.log` (and Python-level traceback in
  `crash-*.log` if anything ever goes sideways).

---

## Installation

Requires **Python 3.10 or newer** and a working PyQt6 stack.

```bash
git clone https://github.com/<your-org>/erevos.git
cd erevos
pip install -r requirements.txt
python main.py
```

Dependencies are pinned in `requirements.txt`:

- `pefile` — PE parsing
- `capstone` — disassembly engine
- `pyqt6` — GUI framework
- `graphviz`, `pydot` — CFG export plumbing
- `jinja2` — HTML report templating
- `weasyprint` — optional PDF report rendering

---

## Repository layout

```
erevos/
├── main.py                 entry point (splash -> MainWindow)
├── requirements.txt
├── core/
│   ├── app.py              backward-compat shim (re-exports MainWindow)
│   ├── pedisasm.py         Capstone + pefile backend
│   ├── splash.py           splash screen
│   ├── diagnostics.py      crash log + stdout/stderr capture
│   ├── templates/          HTML report templates
│   ├── ui/
│   │   ├── main_window.py  MainWindow + all 5 pages
│   │   ├── loader.py       PELoaderThread (QThread background loader)
│   │   ├── styles.py       theme constants + QSS
│   │   ├── widgets.py      Card / RiskGauge / CallGraphWidget / MiniMap / ...
│   │   ├── views.py        FunctionBoxView, CfgGraphView
│   │   ├── topbar.py       top navigation bar + view router
│   │   └── dashboard.py    Dashboard page
│   └── modules/            analysis modules (one file per intel layer)
├── ui/
│   ├── styles.qss
│   └── logo.png
├── tests/                  unit tests for the analysis modules
└── docs/
```

---

## Roadmap

- YARA / Sigma rule generation from extracted IoCs and behavior patterns.
- STIX 2.1 / MISP export of the IoC bundle.
- Batch / headless mode (`erevos-batch --input <dir> --output <dir>`) for
  bulk triage.
- Diff view across two samples for malware family tracking.
- Plugin SDK for custom analysis modules and signatures.
- Optional cloud sync for case files (opt-in).

---

## About

- **Author:** Nikolaos Kranidiotis
- **Website:** [osec.gr](https://osec.gr)
- **Contact:** erevos@osec.gr
- **Version:** 0.2

---

## License

Erevos is distributed for **forensic and research purposes only**. Any
malicious use is strictly prohibited. See `LICENSE` for the full terms.
