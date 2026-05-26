import os
import traceback
import hashlib
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal

try:
    from core.pedisasm import PEDisassembler
except Exception:
    PEDisassembler = None

try:
    from core.modules.xrefs_foundation import (
        extract_structured_xrefs, summarize_xrefs,
    )
except Exception:
    extract_structured_xrefs = summarize_xrefs = None

try:
    from core.modules.function_intel import (
        build_function_profiles, summarize_function_intelligence,
        generate_all_behavior_summaries,
    )
except Exception:
    build_function_profiles = summarize_function_intelligence = generate_all_behavior_summaries = None

try:
    from core.modules.call_graph_intel import build_call_graph_model, analyze_call_graph
except Exception:
    build_call_graph_model = analyze_call_graph = None

try:
    from core.modules.naming_intel import generate_all_name_suggestions
except Exception:
    generate_all_name_suggestions = None

try:
    from core.modules.behavior_patterns_intel import detect_behavior_patterns
except Exception:
    detect_behavior_patterns = None

try:
    from core.modules.threat_narrative_intel import build_threat_narrative
except Exception:
    build_threat_narrative = None

try:
    from core.modules.risk import build_risk_views
except Exception:
    build_risk_views = None

try:
    from core.modules.xrefs import extract_strings_with_locations
except Exception:
    extract_strings_with_locations = None

try:
    from core.modules.resources import summarize_resources
except Exception:
    summarize_resources = None

from core.modules.session_state import normalize_function_intel_summary, normalize_threat_narrative


class PELoaderThread(QThread):
    progress = pyqtSignal(int, str)   # percent 0-100, phase label
    log      = pyqtSignal(str)
    finished = pyqtSignal(dict)       # result dict (or {'error': ..., 'cancelled': True})

    def __init__(self, path: str, session, parent=None):
        super().__init__(parent)
        self._path = path
        self._session = session
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    # ------------------------------------------------------------------
    def run(self):
        result = {}
        current_phase = "init"
        try:
            def step(pct, label):
                nonlocal current_phase
                current_phase = label
                if self._cancelled:
                    return True
                self.progress.emit(pct, label)
                self.log.emit(label)
                # Mirror to log file so we know which phase the crash hit.
                print(f"[loader] {pct:3d}% {label}")
                return False

            # ---- Phase 0: Parse PE ----
            if step(0, "Parsing PE headers"): self._emit_cancel(); return
            disasm = PEDisassembler(self._path)
            result['disasm'] = disasm

            # ---- Phase 1: Imports / exports ----
            if step(8, "Reading imports / exports"): self._emit_cancel(); return
            result['imports_text'] = "\n".join(disasm.get_imports())
            result['exports_text'] = "\n".join(disasm.get_exports())

            # ---- Phase 2: Strings ----
            if step(17, "Extracting strings"): self._emit_cancel(); return
            result['strings_text'] = "\n".join(disasm.get_strings()[:5000])

            # ---- Phase 3: Functions ----
            if step(25, "Discovering functions"): self._emit_cancel(); return
            result['functions'] = _compute_functions(disasm)

            # ---- Phase 4: Resources ----
            if step(33, "Reading resources"): self._emit_cancel(); return
            result['resources_text'] = _compute_resources_text(disasm)

            # ---- Phase 5: Disassemble .text ----
            if step(42, "Disassembling .text"): self._emit_cancel(); return
            result['asm_text'] = _compute_full_disasm(disasm, result.get('functions') or {})

            # ---- Phase 6: XRefs ----
            if step(50, "Building xrefs"): self._emit_cancel(); return
            xrefs, xrefs_summary = _compute_xrefs(disasm, result['asm_text'], result['functions'])
            result['xrefs'] = xrefs
            result['xrefs_summary'] = xrefs_summary

            # ---- Phase 7: Function intelligence ----
            if step(58, "Function intelligence"): self._emit_cancel(); return
            fp, fi_summary, beh_summaries = _compute_function_intel(
                result['asm_text'], result['functions'], xrefs, self._session
            )
            result['function_profiles']      = fp
            result['function_intel_summary'] = fi_summary
            result['behavior_summaries']     = beh_summaries

            # ---- Phase 8: Call graph ----
            if step(67, "Call graph"): self._emit_cancel(); return
            cg_model, cg_summary = _compute_call_graph(fp, xrefs, disasm)
            result['call_graph_model']   = cg_model
            result['call_graph_summary'] = cg_summary

            # ---- Phase 9: Naming intelligence ----
            if step(75, "Naming intelligence"): self._emit_cancel(); return
            naming = _compute_naming(fp, beh_summaries, cg_summary)
            result['naming_suggestions'] = naming

            # Second-pass functions with suggested names applied
            result['functions_v2'] = _apply_naming_pass(result['functions'], naming, self._session)

            # ---- Phase 10: Critical ranking ----
            if step(83, "Critical-function ranking"): self._emit_cancel(); return
            result['risk_text'], result['hot_text'] = _compute_critical(disasm)

            # ---- Phase 11: Behavior patterns + threat narrative ----
            if step(92, "Threat analysis"): self._emit_cancel(); return
            bp = _compute_behavior_patterns(cg_model, cg_summary)
            result['behavior_patterns'] = bp
            result['threat_narrative']  = _compute_threat_narrative(
                disasm, self._path, result['strings_text'], fi_summary,
                cg_summary, bp,
            )

            self.progress.emit(100, "Done")
            self.finished.emit(result)

        except BaseException as e:
            tb = traceback.format_exc()
            # Write to log file so the user can see what blew up in a windowed build.
            print(f"[loader] CRASH during phase '{current_phase}': {type(e).__name__}: {e}")
            print(tb)
            self.finished.emit({
                'error': f"{type(e).__name__}: {e}",
                'phase': current_phase,
                'traceback': tb,
            })

    def _emit_cancel(self):
        self.finished.emit({'cancelled': True})


# ------------------------------------------------------------------
# Pure-computation helpers (no UI dependencies)
# ------------------------------------------------------------------

def _compute_functions(disasm):
    funcs = {}
    try:
        base = disasm.pe.OPTIONAL_HEADER.ImageBase
        ep = disasm.get_entry_point()
        funcs[ep] = "entry_point"
        if hasattr(disasm.pe, "DIRECTORY_ENTRY_EXPORT") and disasm.pe.DIRECTORY_ENTRY_EXPORT:
            for s in disasm.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                va = base + (s.address or 0)
                name = s.name.decode(errors="ignore") if s.name else f"ordinal_{s.ordinal}"
                funcs[va] = name
        if disasm.text_section:
            data = disasm.text_section.get_data() or b""
            tva = base + disasm.text_section.VirtualAddress
            for i in range(max(0, len(data) - 6)):
                if data[i:i + 3] in (b"\x55\x8B\xEC", b"\x55\x48"):
                    va = tva + i
                    funcs.setdefault(va, f"sub_{va:08X}")
    except Exception:
        pass
    return dict(sorted(funcs.items()))


def _compute_full_disasm(disasm, functions=None):
    """Disassemble all known FUNCTIONS into one big text buffer.

    Hard lessons learned:
      - byte-scanning .text in 8KB chunks fed Capstone arbitrary non-code
        bytes (padding, jump tables, data) -> hard process kill, no traceback.
      - per-function disassembly with size capped at the next-function delta
        ALSO crashes when the function discovery heuristic is sparse (e.g.,
        ChromeSetup) and the cap allows a 0x2000 read that overruns far past
        the actual function end into padding/data.

    This implementation:
      - uses a dedicated hardened Capstone instance: detail=False,
        skipdata=True (non-code bytes become `.byte` instead of stopping),
      - caps each function's disasm at 0x200 bytes (512), which covers the
        vast majority of real functions and bounds the damage radius,
      - early-terminates each function at the first int3 padding run
        (3+ consecutive int3 is the standard MSVC alignment pad),
      - uses disasm_lite() which returns tuples instead of full instruction
        objects (orders of magnitude less allocation, far less GC pressure).

    Escape hatch: set EREVOS_SKIP_FULL_DISASM=1 to skip this phase entirely.
    """
    if os.environ.get("EREVOS_SKIP_FULL_DISASM"):
        print("[disasm] EREVOS_SKIP_FULL_DISASM set -- skipping full .text disasm")
        return ""
    try:
        import capstone as _cs
        sec = disasm.text_section
        if not sec:
            return "<no .text section>"
        if not functions:
            print("[disasm] no functions discovered -- nothing to disassemble")
            return ""

        # Pre-read the entire .text into memory once so we can slice per-function
        # without touching pefile or Capstone's internal seek state.
        base = disasm.pe.OPTIONAL_HEADER.ImageBase
        text_va = base + sec.VirtualAddress
        text_data = sec.get_data() or b""
        text_end = text_va + len(text_data)

        def _slice(va, size):
            if va < text_va or va >= text_end:
                return b""
            off = va - text_va
            return text_data[off:off + size]

        # Hardened Capstone instance dedicated to bulk decoding.
        mode = _cs.CS_MODE_64 if getattr(disasm, "arch", "x64") == "x64" else _cs.CS_MODE_32
        md = _cs.Cs(_cs.CS_ARCH_X86, mode)
        md.detail = False
        md.skipdata = True

        addrs = sorted(functions.keys())
        total = len(addrs)
        # Hard per-function size cap -- 512 bytes covers ~95% of real functions
        # and stops us from running off the end of any single function into
        # padding/data, which is what was triggering the native crash.
        SIZE_CAP = 0x200
        print(f"[disasm] disassembling {total} known functions  arch={getattr(disasm, 'arch', '?')}  cap=0x{SIZE_CAP:x}")

        out = []
        truncated = False
        for idx, va in enumerate(addrs):
            # Smaller of (next function delta, hard cap, distance to .text end).
            if idx + 1 < total:
                delta = addrs[idx + 1] - va
            else:
                delta = text_end - va
            size = max(0x10, min(SIZE_CAP, delta if delta > 0 else SIZE_CAP))

            if idx % 64 == 0:
                print(f"[disasm] func {idx:4d}/{total} va=0x{va:08x} size=0x{size:x} insns={len(out)}")

            chunk = _slice(va, size)
            if not chunk:
                continue

            try:
                lines = []
                int3_streak = 0
                for addr, _sz, mnem, op_str in md.disasm_lite(chunk, va):
                    # Stop at start of int3 padding -- standard MSVC alignment.
                    # 3+ consecutive int3 means we've left the function body.
                    if mnem == "int3":
                        int3_streak += 1
                        if int3_streak >= 3:
                            break
                    else:
                        int3_streak = 0
                    lines.append(f"0x{addr:08X}: {mnem} {op_str}")
                if lines:
                    out.append(f"; --- 0x{va:08X}  {functions.get(va, '')} ---")
                    out.extend(lines)
            except Exception as e:
                print(f"[disasm] func 0x{va:08X} skipped: {type(e).__name__}: {e}")
                out.append(f"; <disasm error at 0x{va:08X}: {e}>")

            if len(out) > 200000:
                out.append("; <truncated>")
                truncated = True
                break

        print(f"[disasm] done  total_lines={len(out)}  truncated={truncated}")
        return "\n".join(out)
    except Exception as e:
        print(f"[disasm] FATAL: {type(e).__name__}: {e}")
        return f"Full disassembly error: {e}"


def _compute_resources_text(disasm):
    if not summarize_resources:
        return "resources module not available"
    try:
        res = summarize_resources(disasm.pe)
        lines = []

        mans = res.get("manifest") or []
        if mans:
            lines.append("[Manifest summary]")
            for m in mans:
                summ = m.get("summary", {}) or {}
                if summ.get("dpiAware"):
                    lines.append(f"  dpiAware: {', '.join(summ['dpiAware'])}")
                if "requestedExecutionLevel" in summ:
                    lvl = summ["requestedExecutionLevel"]
                    desc = summ.get("requestedExecutionLevelDesc") or ""
                    lines.append(f"  requestedExecutionLevel: {lvl}" + (f"  ({desc})" if desc else ""))
                if "uiAccess" in summ:
                    lines.append(f"  uiAccess: {summ['uiAccess']}")
                compat_names = summ.get("compat_names") or []
                compat_guids = summ.get("compat") or []
                if compat_names:
                    lines.append(f"  supportedOS: {', '.join(compat_names)}")
                if compat_guids and not compat_names:
                    lines.append(f"  supportedOS GUIDs: {', '.join(compat_guids)}")
            lines.append("")

        vi = res.get("version_info") or {}
        if vi:
            lines.append("[Version info]")
            for key in ("FileVersion", "ProductVersion", "CompanyName", "FileDescription",
                        "ProductName", "OriginalFilename", "LegalCopyright"):
                if key in vi and vi[key]:
                    lines.append(f"  {key}: {vi[key]}")
            lines.append("")

        stabs = res.get("string_tables") or []
        if stabs:
            lines.append("[String tables]")
            for i, t in enumerate(stabs[:2], start=1):
                entries = t.get("entries", {}) or {}
                lines.append(f"  Table {i} (lang={t.get('lang')}, sublang={t.get('sublang')}):")
                shown = 0
                for k, v in entries.items():
                    if shown >= 6:
                        lines.append("    …"); break
                    vv = v.replace("\r", " ").replace("\n", " ")
                    if len(vv) > 120: vv = vv[:120] + "…"
                    lines.append(f"    [{k:02d}] {vv}"); shown += 1
            lines.append("")

        return "\n".join(lines) if lines else "No resource summaries available."
    except Exception as e:
        return f"Resources error: {e}"


def _compute_xrefs(disasm, asm_text, functions):
    try:
        strings_map = {}
        if extract_strings_with_locations and disasm:
            try:
                hits = extract_strings_with_locations(disasm.pe, min_len=4, limit=5000)
                strings_map = {int(h.va): h.text for h in hits}
            except Exception:
                strings_map = {}
        imports = disasm.get_imports() if disasm else []
        xrefs = extract_structured_xrefs(asm_text, functions=functions, strings_by_addr=strings_map, imports=imports)
        xrefs_summary = summarize_xrefs(xrefs)
        return xrefs, xrefs_summary
    except Exception as e:
        return [], {"error": str(e)}


def _compute_function_intel(asm_text, functions, xrefs, session):
    try:
        fp = build_function_profiles(
            disasm_text=asm_text,
            functions=functions,
            xrefs=xrefs,
            comments=session.comments,
            labels=session.labels,
            bookmarks=session.bookmarks,
        )
        fi_summary = normalize_function_intel_summary(
            summarize_function_intelligence(fp, session.renamed_functions)
        )
        beh_summaries = generate_all_behavior_summaries(fp)
        return fp, fi_summary, beh_summaries
    except Exception as e:
        return {}, {"error": str(e)}, {}


def _compute_call_graph(fp, xrefs, disasm):
    try:
        cg_model = build_call_graph_model(profiles=fp, xrefs=xrefs)
        ep = disasm.get_entry_point() if disasm else None
        cg_summary = analyze_call_graph(cg_model, entry_point=ep)
        return cg_model, cg_summary
    except Exception as e:
        return {}, {"error": str(e)}


def _compute_naming(fp, beh_summaries, cg_summary):
    try:
        return generate_all_name_suggestions(
            profiles=fp,
            behavior_summaries=beh_summaries,
            call_graph_summary=cg_summary,
        )
    except Exception:
        return {}


def _apply_naming_pass(functions, naming, session):
    result = dict(functions)
    try:
        for key, sugg in (naming or {}).items():
            try:
                va = int(key, 16)
                if va in result and key not in session.renamed_functions:
                    nm = sugg.get("suggested_name")
                    if nm and sugg.get("confidence") in ("high", "very_high"):
                        result[va] = nm
            except Exception:
                pass
    except Exception:
        pass
    return dict(sorted(result.items()))


def _compute_critical(disasm):
    if not build_risk_views:
        return "— risk module unavailable —", "— risk module unavailable —"
    try:
        return build_risk_views(disasm)
    except Exception as e:
        return f"Risk error: {e}", f"Hot error: {e}"


def _compute_behavior_patterns(cg_model, cg_summary):
    if not detect_behavior_patterns:
        return {}
    try:
        return detect_behavior_patterns(
            api_semantics_by_function={},
            data_flow_by_function={},
            call_graph_model=cg_model or {},
            call_graph_summary=cg_summary or {},
        )
    except Exception as e:
        return {"error": str(e)}


def _compute_threat_narrative(disasm, path, strings_text, fi_summary, cg_summary, behavior_patterns):
    if not build_threat_narrative:
        return {}
    try:
        hashes = {}
        p = Path(path)
        b = p.read_bytes() if p.exists() else b""
        if b:
            hashes = {
                "sha256": hashlib.sha256(b).hexdigest(),
                "md5":    hashlib.md5(b).hexdigest(),
            }
        ep_str = f"0x{int(disasm.get_entry_point()):08X}" if disasm else ""
        meta = {"path": path, "entry_point": ep_str, "hashes": hashes}
        strings_rows = strings_text.splitlines()[:3000]
        return build_threat_narrative(
            behavior_patterns=behavior_patterns or {},
            api_semantics={},
            data_flow_insights={},
            function_intelligence=normalize_function_intel_summary(fi_summary or {}),
            call_graph_intelligence=cg_summary or {},
            cfg_intelligence={},
            hashes_and_metadata=meta,
            extracted_strings=strings_rows,
        )
    except Exception as e:
        return {"error": str(e)}
