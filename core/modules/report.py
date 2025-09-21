# core/modules/report.py
"""
Erevos Module — report.py (standalone reporter)

Generates a self-contained HTML report and/or JSON snapshot for a PE file.

It aggregates data from other modules when available (best-effort):
  • resources.py   → manifest/version/string tables
  • risk.py        → function risk ranking (via score_table on a disasm)
  • packer.py      → packer/obfuscation score
  • xrefs.py       → strings with locations (for quick triage)

If a module is missing, the reporter degrades gracefully and notes it.

CLI usage:
  python report.py <path_to_pe> --html out.html --json out.json --top 30 --max-strings 200

Programmatic:
  from report import generate_report
  data, html = generate_report(pe_path, top=30, max_strings=200)

Dependencies: pefile (required). Optional: capstone + our modules.
"""
from __future__ import annotations
import os
import sys
import json
import datetime as _dt
from typing import Any, Dict, List, Optional

import pefile

# ---------- Try optional modules ----------
try:
    from .resources import summarize_resources  # type: ignore
except Exception:
    summarize_resources = None  # type: ignore

# Risk helpers that work with a disassembler
try:
    from .risk import score_table as risk_score_table  # returns parsed rows from build_risk_views
except Exception:
    risk_score_table = None  # type: ignore

try:
    from .packer import analyze_packer  # type: ignore
except Exception:
    analyze_packer = None  # type: ignore

try:
    from .xrefs import extract_strings_with_locations  # type: ignore
except Exception:
    extract_strings_with_locations = None  # type: ignore

# Disassembler core (for risk scoring)
try:
    # report.py lives in core/modules/, pedisasm.py is in core/
    from ..pedisasm import PEDisassembler  # type: ignore
except Exception:
    PEDisassembler = None  # type: ignore


# ---------- Helpers ----------
def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0]*256
    for b in data:
        freq[b]+=1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c/n
            ent -= p*math.log2(p)
    return round(ent, 3)


def _file_meta(pe: pefile.PE, path: str) -> Dict[str, Any]:
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    ts = fh.TimeDateStamp
    return {
        "path": os.path.abspath(path),
        "size": os.path.getsize(path),
        "image_base": f"0x{oh.ImageBase:08X}",
        "entry_point": f"0x{oh.ImageBase + oh.AddressOfEntryPoint:08X}",
        "machine": f"0x{fh.Machine:04X}",
        "timestamp": int(ts),
        "timestamp_iso": str(_dt.datetime.utcfromtimestamp(ts)) + "Z",
        "subsystem": getattr(oh, 'Subsystem', None),
        "dll_characteristics": getattr(oh, 'DllCharacteristics', None),
    }


def _sections(pe: pefile.PE) -> List[Dict[str, Any]]:
    out = []
    base = pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="ignore")
        raw = s.get_data() or b""
        out.append({
            "name": name,
            "va": f"0x{base + s.VirtualAddress:08X}",
            "raw_size": int(s.SizeOfRawData),
            "virtual_size": int(s.Misc_VirtualSize),
            "characteristics": int(s.Characteristics),
            "executable": bool(s.Characteristics & 0x20000000),
            "entropy": _entropy(raw),
        })
    return out


def _imports(pe: pefile.PE) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and pe.DIRECTORY_ENTRY_IMPORT:
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                dll = imp.dll.decode(errors='ignore') if getattr(imp, "dll", None) else '<unknown>'
                names: List[str] = []
                for f in imp.imports or []:
                    names.append((f.name.decode(errors='ignore') if f.name else f'ordinal_{f.ordinal}'))
                out[dll] = names
    except Exception:
        pass
    return out


def _exports(pe: pefile.PE) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    base = pe.OPTIONAL_HEADER.ImageBase
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
            for s in pe.DIRECTORY_ENTRY_EXPORT.symbols or []:
                addr = base + (s.address or 0)
                out.append({
                    "name": (s.name.decode(errors='ignore') if s.name else f"ordinal_{s.ordinal}"),
                    "va": f"0x{addr:08X}",
                })
    except Exception:
        pass
    return out


# ---------- Main API ----------
def build_data(pe_path: str, top: int = 30, max_strings: int = 200) -> Dict[str, Any]:
    # IMPORTANT: parse directories so imports/exports/resources exist
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        pe.parse_data_directories()
    except Exception:
        # continue anyway; some sections may remain empty
        pass

    data: Dict[str, Any] = {
        "meta": _file_meta(pe, pe_path),
        "sections": _sections(pe),
        "imports": _imports(pe),
        "exports": _exports(pe),
        "resources": None,
        "risk": None,
        "packer": None,
        "strings": None,
        "notes": [],
    }

    # Resources
    if summarize_resources:
        try:
            data["resources"] = summarize_resources(pe)
        except Exception as e:
            data["notes"].append(f"resources: {e}")
    else:
        data["notes"].append("resources module not available")

    # Risk scoring (consistent with app): needs a disassembler
    if PEDisassembler and risk_score_table:
        try:
            disasm = PEDisassembler(pe_path)
            rows = risk_score_table(disasm)  # [{'va': '0x...', 'name': ..., 'score': int, 'reason': str}]
            # keep only top N
            rows = sorted(rows, key=lambda r: (-int(r.get('score', 0)), r.get('va', '')))[:top]
            data["risk"] = rows
        except Exception as e:
            data["notes"].append(f"risk: {e}")
    else:
        data["notes"].append("risk module or disassembler not available")

    # Packer analysis
    if analyze_packer:
        try:
            data["packer"] = analyze_packer(pe_path)
        except Exception as e:
            data["notes"].append(f"packer: {e}")
    else:
        data["notes"].append("packer module not available")

    # Strings (locations)
    if extract_strings_with_locations:
        try:
            strings = extract_strings_with_locations(pe, min_len=4, limit=max_strings)
            data["strings"] = [{
                "text": s.text[:500],
                "va": f"0x{s.va:08X}",
                "rva": s.rva,
                "file_off": s.file_off,
                "encoding": s.encoding,
            } for s in strings]
        except Exception as e:
            data["notes"].append(f"xrefs/strings: {e}")
    else:
        data["notes"].append("xrefs module not available")

    return data


def render_html(data: Dict[str, Any], title: Optional[str] = None) -> str:
    title = title or (os.path.basename(data.get('meta',{}).get('path','')) or 'Erevos Report')
    # Minimal white/black forensic theme, collapsible sections.
    css = """
    body { background:#fff; color:#000; font-family:Consolas,monospace; margin:20px; }
    h1 { font-size:20px; margin:0 0 10px 0; }
    .meta { margin-bottom:14px; }
    .box { border:1px solid #000; padding:10px; margin:10px 0; background:#fbfbfb; }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(120px,1fr)); gap:6px; }
    .row { display:flex; gap:10px; align-items:center; }
    .key { font-weight:bold; }
    table { width:100%; border-collapse:collapse; }
    th, td { border:1px solid #000; padding:4px 6px; vertical-align:top; }
    th { background:#f0f0f0; }
    details { border:1px solid #000; padding:8px; margin:10px 0; background:#fff; }
    summary { cursor:pointer; font-weight:bold; }
    .badge { display:inline-block; border:1px solid #000; padding:2px 6px; margin-right:6px; }
    .score-high { background:#ffd9d9; }
    .score-med  { background:#fff0c2; }
    .score-low  { background:#e7ffe7; }
    .small { color:#444; font-size:12px; }
    """
    def esc(x: Any) -> str:
        from html import escape
        return escape(str(x))

    meta = data.get('meta', {})
    sections = data.get('sections', [])
    imports = data.get('imports', {})
    exports = data.get('exports', [])
    resources = data.get('resources', {}) or {}
    risk = data.get('risk', [])
    packer = data.get('packer', {}) or {}
    strings = data.get('strings', [])

    # Risk badge helper
    def rb(score: int) -> str:
        cls = 'score-low'
        if score >= 75: cls = 'score-high'
        elif score >= 40: cls = 'score-med'
        return f"<span class='badge {cls}'>▣ {score}</span>"

    # Build HTML parts
    html = [f"<html><head><meta charset='utf-8'><title>{esc(title)}</title><style>{css}</style></head><body>"]
    html.append(f"<h1>Erevos Report</h1>")
    html.append("<div class='meta box'>")
    html.append("<div class='grid'>")
    for k in ("path","size","image_base","entry_point","machine","timestamp_iso","subsystem","dll_characteristics"):
        html.append(f"<div><span class='key'>{esc(k)}:</span> {esc(meta.get(k,'-'))}</div>")
    html.append("</div></div>")

    # Sections
    html.append("<details open><summary>Sections</summary>")
    html.append("<div class='box'><table><tr><th>Name</th><th>VA</th><th>RawSize</th><th>VirtSize</th><th>Exec</th><th>Entropy</th></tr>")
    for s in sections:
        html.append(f"<tr><td>{esc(s['name'])}</td><td>{esc(s['va'])}</td><td>{s['raw_size']}</td><td>{s['virtual_size']}</td><td>{'Y' if s['executable'] else 'N'}</td><td>{s['entropy']}</td></tr>")
    html.append("</table></div></details>")

    # Imports
    html.append("<details open><summary>Imports</summary>")
    if imports:
        html.append("<div class='box'>")
        for dll, names in imports.items():
            html.append(f"<div class='row'><div class='key'>{esc(dll)}</div><div class='small'>({len(names)})</div></div>")
            html.append("<div class='small'>" + esc(", ".join(names[:200])) + (" …" if len(names)>200 else "") + "</div>")
        html.append("</div>")
    else:
        html.append("<div class='box small'>No imports.</div>")
    html.append("</details>")

    # Exports
    html.append("<details open><summary>Exports</summary>")
    if exports:
        html.append("<div class='box'><table><tr><th>VA</th><th>Name</th></tr>")
        for e in exports:
            html.append(f"<tr><td>{esc(e['va'])}</td><td>{esc(e['name'])}</td></tr>")
        html.append("</table></div>")
    else:
        html.append("<div class='box small'>No exports.</div>")
    html.append("</details>")

    # Resources (manifest summary + version)
    html.append("<details open><summary>Resources</summary>")
    if resources:
        man = resources.get('manifest') or []
        ver = resources.get('version_info') or {}
        if man:
            html.append("<div class='box'><div class='key'>Manifests:</div>")
            for m in man:
                summ = m.get('summary', {})
                html.append("<div class='small'>" + esc(summ) + "</div>")
            html.append("</div>")
        if ver:
            html.append("<div class='box'><div class='key'>Version Info:</div><div class='small'>" + esc(ver) + "</div></div>")
    else:
        html.append("<div class='box small'>No resource data (or module unavailable).</div>")
    html.append("</details>")

    # Risk (top functions)
    html.append("<details open><summary>Risk — Top Functions</summary>")
    if risk:
        html.append("<div class='box'><table><tr><th>Score</th><th>VA</th><th>Name</th><th>Reason</th></tr>")
        for r in risk:
            try:
                score = int(r.get('score', 0))
            except Exception:
                score = 0
            html.append(f"<tr><td>{rb(score)}</td><td>{esc(r.get('va',''))}</td><td>{esc(r.get('name',''))}</td><td>{esc(r.get('reason',''))}</td></tr>")
        html.append("</table></div>")
    else:
        html.append("<div class='box small'>Risk module unavailable or no findings.</div>")
    html.append("</details>")

    # Packer
    html.append("<details open><summary>Packer / Obfuscation</summary>")
    if packer:
        html.append("<div class='box'>")
        html.append(f"<div class='row'><div class='key'>Score:</div> <div>{packer.get('score','-')}</div></div>")
        if packer.get('reasons'):
            html.append("<div class='small'>Reasons: " + esc(", ".join(packer['reasons'])) + "</div>")
        if packer.get('hints'):
            html.append("<div class='small'>Hints: " + esc(", ".join(packer['hints'])) + "</div>")
        html.append("</div>")
    else:
        html.append("<div class='box small'>Packer module unavailable.</div>")
    html.append("</details>")

    # Strings (trimmed)
    html.append("<details><summary>Strings (sample)</summary>")
    if strings:
        html.append("<div class='box'><table><tr><th>VA</th><th>Encoding</th><th>Text</th></tr>")
        for s in strings[:200]:
            html.append(f"<tr><td>{esc(s['va'])}</td><td>{esc(s.get('encoding',''))}</td><td>{esc(s['text'])}</td></tr>")
        html.append("</table></div>")
    else:
        html.append("<div class='box small'>No strings (or module unavailable).</div>")
    html.append("</details>")

    # Notes
    notes = data.get('notes') or []
    if notes:
        html.append("<details><summary>Notes</summary><div class='box small'>" + esc(" | ".join(notes)) + "</div></details>")

    html.append("</body></html>")
    return "".join(html)


def generate_report(pe_path: str, top: int = 30, max_strings: int = 200, html_path: Optional[str] = None, json_path: Optional[str] = None):
    data = build_data(pe_path, top=top, max_strings=max_strings)
    html = render_html(data)
    if html_path:
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
    if json_path:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    return data, html


# ---------- CLI ----------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python report.py <path_to_pe> [--html out.html] [--json out.json] [--top 30] [--max-strings 200]')
        sys.exit(1)
    pe_path = sys.argv[1]
    html_out = None
    json_out = None
    top = 30
    max_strings = 200

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == '--html' and i+1 < len(args):
            html_out = args[i+1]; i += 2; continue
        if args[i] == '--json' and i+1 < len(args):
            json_out = args[i+1]; i += 2; continue
        if args[i] == '--top' and i+1 < len(args):
            top = int(args[i+1]); i += 2; continue
        if args[i] == '--max-strings' and i+1 < len(args):
            max_strings = int(args[i+1]); i += 2; continue
        i += 1

    data, html = generate_report(pe_path, top=top, max_strings=max_strings, html_path=html_out, json_path=json_out)
    print(json.dumps({
        'path': os.path.abspath(pe_path),
        'html': os.path.abspath(html_out) if html_out else None,
        'json': os.path.abspath(json_out) if json_out else None,
        'top': top,
        'max_strings': max_strings,
    }, indent=2))
