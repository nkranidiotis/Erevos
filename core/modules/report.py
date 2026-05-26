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
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import pefile
except Exception:
    pefile = None  # type: ignore

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

try:
    from .triage import analyze_triage  # type: ignore
except Exception:
    analyze_triage = None  # type: ignore

try:
    from .xrefs_foundation import extract_structured_xrefs, summarize_xrefs  # type: ignore
except Exception:
    extract_structured_xrefs = summarize_xrefs = None  # type: ignore

try:
    from .function_intel import (
        build_function_profiles,
        summarize_function_intelligence,
        generate_all_behavior_summaries,
    )  # type: ignore
except Exception:
    build_function_profiles = summarize_function_intelligence = generate_all_behavior_summaries = None  # type: ignore
try:
    from .session_state import normalize_function_intel_summary, normalize_behavior_summaries  # type: ignore
except Exception:
    def normalize_function_intel_summary(value):  # type: ignore
        if isinstance(value, dict):
            return value
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    return item
        return {}
    def normalize_behavior_summaries(value):  # type: ignore
        if isinstance(value, dict):
            return value
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    return item
        return {}
    def normalize_call_graph_summary(value):  # type: ignore
        if isinstance(value, dict):
            return value
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    return item
        return {}
    def normalize_cfg_intel_summary(value):  # type: ignore
        if isinstance(value, dict):
            return value
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    return item
        return {}
    def normalize_naming_suggestions(value):  # type: ignore
        if isinstance(value, dict):
            return value
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    return item
        return {}
else:
    from .session_state import normalize_call_graph_summary, normalize_cfg_intel_summary, normalize_naming_suggestions  # type: ignore

try:
    from .call_graph_intel import build_call_graph_model, analyze_call_graph  # type: ignore
except Exception:
    build_call_graph_model = analyze_call_graph = None  # type: ignore
try:
    from .cfg_intel import build_function_cfg_model, analyze_function_cfg  # type: ignore
except Exception:
    build_function_cfg_model = analyze_function_cfg = None  # type: ignore
try:
    from .naming_intel import generate_all_name_suggestions  # type: ignore
except Exception:
    generate_all_name_suggestions = None  # type: ignore
try:
    from .data_flow_intel import analyze_function_data_flow  # type: ignore
except Exception:
    analyze_function_data_flow = None  # type: ignore
try:
    from .api_semantics_intel import interpret_api_semantics  # type: ignore
except Exception:
    interpret_api_semantics = None  # type: ignore
try:
    from .behavior_patterns_intel import detect_behavior_patterns  # type: ignore
except Exception:
    detect_behavior_patterns = None  # type: ignore
try:
    from .threat_narrative_intel import build_threat_narrative  # type: ignore
except Exception:
    build_threat_narrative = None  # type: ignore

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
def build_data(
    pe_path: str,
    top: int = 30,
    max_strings: int = 200,
    case_id: str = "",
    examiner: str = "",
    analyst_notes: str = "",
    analyst_artifacts: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if pefile is None:
        raise RuntimeError("pefile dependency is required for build_data(). Install with: pip install pefile")
    # IMPORTANT: parse directories so imports/exports/resources exist
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        pe.parse_data_directories()
    except Exception:
        # continue anyway; some sections may remain empty
        pass

    data: Dict[str, Any] = {
        "schema_version": "erevos.report.v2",
        "case": {
            "case_id": case_id,
            "examiner": examiner,
            "analyst_notes": analyst_notes,
            "generated_utc": _dt.datetime.utcnow().isoformat() + "Z",
        },
        "analyst_artifacts": analyst_artifacts or {},
        "meta": _file_meta(pe, pe_path),
        "sections": _sections(pe),
        "imports": _imports(pe),
        "exports": _exports(pe),
        "resources": None,
        "risk": None,
        "packer": None,
        "strings": None,
        "triage": None,
        "xrefs_summary": None,
        "function_intelligence_summary": None,
        "behavior_summaries": None,
        "call_graph_summary": None,
        "cfg_intel_summary": None,
        "naming_suggestions": None,
        "data_flow_insights": None,
        "api_semantics_insights": None,
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

    # Explainable triage scoring
    if analyze_triage:
        try:
            data["triage"] = analyze_triage(pe_path)
        except Exception as e:
            data["notes"].append(f"triage: {e}")
    else:
        data["notes"].append("triage module not available")

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

    # Xrefs summary (best-effort, first-pass textual model)
    if PEDisassembler and extract_structured_xrefs and summarize_xrefs:
        try:
            d = PEDisassembler(pe_path)
            sec = d.text_section
            if sec:
                base = d.pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
                code = sec.get_data() or b""
                lines = []
                for ins in d.md.disasm(code[: min(len(code), 0x20000)], base):
                    lines.append(f"0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}")
                xrefs = extract_structured_xrefs("\n".join(lines))
                data["xrefs_summary"] = summarize_xrefs(xrefs)
                if build_function_profiles and summarize_function_intelligence:
                    functions: Dict[int, str] = {}
                    ep = d.get_entry_point()
                    functions[ep] = "entry_point"
                    for row in data.get("risk") or []:
                        try:
                            va = int(str(row.get("va")), 16)
                            functions[va] = str(row.get("name") or f"sub_{va:08X}")
                        except Exception:
                            continue
                    if not functions:
                        for x in xrefs:
                            if getattr(x, "src_function", None):
                                functions[int(x.src_function)] = f"sub_{int(x.src_function):08X}"
                            if getattr(x, "dst_function", None):
                                functions[int(x.dst_function)] = f"sub_{int(x.dst_function):08X}"
                    profiles = build_function_profiles(
                        disasm_text="\n".join(lines),
                        functions=functions,
                        xrefs=xrefs,
                        comments=((analyst_artifacts or {}).get("comments") or {}),
                        labels=((analyst_artifacts or {}).get("labels") or {}),
                        bookmarks=((analyst_artifacts or {}).get("bookmarks") or []),
                    )
                    data["function_intelligence_summary"] = normalize_function_intel_summary(summarize_function_intelligence(
                        profiles, ((analyst_artifacts or {}).get("renamed_functions") or {})
                    ))
                    if generate_all_behavior_summaries:
                        data["behavior_summaries"] = generate_all_behavior_summaries(profiles)
                    call_graph = {}
                    if build_call_graph_model and analyze_call_graph:
                        call_graph = build_call_graph_model(profiles=profiles, xrefs=xrefs)
                        data["call_graph_summary"] = analyze_call_graph(call_graph, entry_point=d.get_entry_point())
                    if build_function_cfg_model and analyze_function_cfg:
                        cfg_rows = {}
                        for va in list(functions.keys())[:60]:
                            ftxt = d.disasm_at(va, size=0x1200) or ""
                            m = build_function_cfg_model(ftxt, function_start=va)
                            a = analyze_function_cfg(m)
                            cfg_rows[f"0x{va:08X}"] = {"analysis": a}
                        data["cfg_intel_summary"] = cfg_rows
                    if generate_all_name_suggestions:
                        data["naming_suggestions"] = generate_all_name_suggestions(
                            profiles=profiles,
                            behavior_summaries=data.get("behavior_summaries") or {},
                            call_graph_summary=data.get("call_graph_summary") or {},
                        )
                    if analyze_function_data_flow:
                        dfi = {}
                        api_sem = {}
                        for va in list(functions.keys())[:60]:
                            ftxt = d.disasm_at(va, size=0x1200) or ""
                            fx = [x for x in xrefs if x.src_function == va or x.dst_function == va]
                            strings_map = {int(x.dst): x.string_value for x in xrefs if x.xref_type == "string" and isinstance(x.dst, int) and x.string_value}
                            dfi[f"0x{va:08X}"] = analyze_function_data_flow(ftxt, fx, strings_by_addr=strings_map)
                            if interpret_api_semantics:
                                api_sem[f"0x{va:08X}"] = interpret_api_semantics(dfi[f"0x{va:08X}"])
                        data["data_flow_insights"] = dfi
                        if api_sem:
                            data["api_semantics_insights"] = api_sem
                        if detect_behavior_patterns and api_sem:
                            data["behavior_patterns"] = detect_behavior_patterns(
                                api_semantics_by_function=api_sem,
                                data_flow_by_function=dfi,
                                call_graph_model=call_graph,
                                call_graph_summary=data.get("call_graph_summary") or {},
                            )
                        if build_threat_narrative:
                            data["threat_narrative"] = build_threat_narrative(
                                behavior_patterns=data.get("behavior_patterns") or {},
                                api_semantics=data.get("api_semantics_insights") or {},
                                data_flow_insights=data.get("data_flow_insights") or {},
                                function_intelligence=data.get("function_intelligence_summary") or {},
                                call_graph_intelligence=data.get("call_graph_summary") or {},
                                cfg_intelligence=data.get("cfg_intel_summary") or {},
                                hashes_and_metadata={
                                    "path": data.get("meta", {}).get("path"),
                                    "entry_point": data.get("meta", {}).get("entry_point"),
                                    "hashes": ((data.get("triage") or {}).get("hashes") or {}),
                                },
                                extracted_strings=data.get("strings") or [],
                            )
        except Exception as e:
            data["notes"].append(f"xrefs_summary: {e}")
    else:
        data["notes"].append("xrefs foundation not available")
    if not data.get("function_intelligence_summary") and analyst_artifacts:
        data["function_intelligence_summary"] = normalize_function_intel_summary(
            analyst_artifacts.get("function_intelligence_summary")
        )
    if not data.get("behavior_summaries") and analyst_artifacts:
        data["behavior_summaries"] = normalize_behavior_summaries(
            analyst_artifacts.get("behavior_summaries")
        )
    if not data.get("call_graph_summary") and analyst_artifacts:
        data["call_graph_summary"] = normalize_call_graph_summary(
            analyst_artifacts.get("call_graph_summary")
        )
    if not data.get("cfg_intel_summary") and analyst_artifacts:
        data["cfg_intel_summary"] = normalize_cfg_intel_summary(
            analyst_artifacts.get("cfg_intel_summary")
        )
    if not data.get("naming_suggestions") and analyst_artifacts:
        data["naming_suggestions"] = normalize_naming_suggestions(
            analyst_artifacts.get("naming_suggestions")
        )
    if not data.get("data_flow_insights") and analyst_artifacts:
        data["data_flow_insights"] = (analyst_artifacts.get("data_flow_insights") or {})
    if not data.get("api_semantics_insights") and analyst_artifacts:
        data["api_semantics_insights"] = (analyst_artifacts.get("api_semantics_insights") or {})
    if not data.get("behavior_patterns") and analyst_artifacts:
        data["behavior_patterns"] = (analyst_artifacts.get("behavior_patterns") or {})
    if not data.get("threat_narrative") and analyst_artifacts:
        data["threat_narrative"] = (analyst_artifacts.get("threat_narrative") or {})
    if not data.get("threat_narrative") and build_threat_narrative:
        data["threat_narrative"] = build_threat_narrative(
            behavior_patterns=data.get("behavior_patterns") or {},
            api_semantics=data.get("api_semantics_insights") or {},
            data_flow_insights=data.get("data_flow_insights") or {},
            function_intelligence=data.get("function_intelligence_summary") or {},
            call_graph_intelligence=data.get("call_graph_summary") or {},
            cfg_intelligence=data.get("cfg_intel_summary") or {},
            hashes_and_metadata={
                "path": data.get("meta", {}).get("path"),
                "entry_point": data.get("meta", {}).get("entry_point"),
                "hashes": ((data.get("triage") or {}).get("hashes") or {}),
            },
            extracted_strings=data.get("strings") or [],
        )

    return data


def _safe_logo_data_uri(logo_path: Optional[str] = None) -> str:
    import base64
    root = Path(__file__).resolve().parents[2]
    candidates: List[Path] = []
    if logo_path:
        p = Path(logo_path)
        candidates.append(p if p.is_absolute() else (Path.cwd() / p))
        candidates.append(root / p)
    candidates.extend([root / "logo.png", root / "ui" / "logo.png"])
    for c in candidates:
        try:
            with open(c, "rb") as f:
                b = f.read()
            if b:
                return "data:image/png;base64," + base64.b64encode(b).decode("ascii")
        except Exception:
            continue
    return ""


def _resolve_template_path(template_path: str) -> Path:
    p = Path(template_path)
    if p.is_absolute() and p.exists():
        return p
    cwd_p = Path.cwd() / p
    if cwd_p.exists():
        return cwd_p
    repo_p = Path(__file__).resolve().parents[2] / p
    if repo_p.exists():
        return repo_p
    # final fallback to bundled default
    return Path(__file__).resolve().parents[1] / "templates" / "report_v2.html"


def _select_top_behavior_summaries(function_intel_summary: Dict[str, Any], behavior_summaries: Dict[str, Any], limit: int = 12) -> List[Dict[str, Any]]:
    if not isinstance(behavior_summaries, dict):
        return []
    ranked = []
    risky = {r.get("start") for r in (function_intel_summary.get("top_risky_functions") or []) if isinstance(r, dict)}
    suspicious = {r.get("start") for r in (function_intel_summary.get("functions_with_suspicious_apis") or []) if isinstance(r, dict)}
    interesting = {r.get("start") for r in (function_intel_summary.get("functions_with_interesting_strings") or []) if isinstance(r, dict)}
    commented = {r.get("start") for r in (function_intel_summary.get("commented_or_bookmarked_functions") or []) if isinstance(r, dict)}

    for addr, row in behavior_summaries.items():
        if not isinstance(row, dict):
            continue
        score = 0
        score += 3 if addr in risky else 0
        score += 2 if addr in suspicious else 0
        score += 1 if addr in interesting else 0
        score += 1 if addr in commented else 0
        score += len(row.get("possible_capability_tags") or [])
        if row.get("confidence") == "high":
            score += 2
        elif row.get("confidence") == "medium":
            score += 1
        if row.get("evidence_bullets"):
            score += 1
        ranked.append((score, addr, row))
    ranked.sort(key=lambda t: (-t[0], t[1]))
    return [r for _, _, r in ranked[:limit] if r.get("evidence_bullets")]


def _build_view_model(data: Dict[str, Any], title: Optional[str] = None, logo_path: Optional[str] = None) -> Dict[str, Any]:
    meta = data.get("meta", {}) or {}
    triage = data.get("triage") or {}
    sections = data.get("sections") or []
    risk = data.get("risk") or []
    packer = data.get("packer") or {}
    function_intel_summary = normalize_function_intel_summary(
        data.get("function_intelligence_summary") or ((data.get("analyst_artifacts") or {}).get("function_intelligence_summary"))
    )
    behavior_summaries = normalize_behavior_summaries(
        data.get("behavior_summaries") or ((data.get("analyst_artifacts") or {}).get("behavior_summaries"))
    )
    call_graph_summary = normalize_call_graph_summary(
        data.get("call_graph_summary") or ((data.get("analyst_artifacts") or {}).get("call_graph_summary"))
    )
    cfg_intel_summary = normalize_cfg_intel_summary(
        data.get("cfg_intel_summary") or ((data.get("analyst_artifacts") or {}).get("cfg_intel_summary"))
    )
    naming_suggestions = normalize_naming_suggestions(
        data.get("naming_suggestions") or ((data.get("analyst_artifacts") or {}).get("naming_suggestions"))
    )
    data_flow_insights = data.get("data_flow_insights") or ((data.get("analyst_artifacts") or {}).get("data_flow_insights") or {})
    api_semantics_insights = data.get("api_semantics_insights") or ((data.get("analyst_artifacts") or {}).get("api_semantics_insights") or {})
    behavior_patterns = data.get("behavior_patterns") or ((data.get("analyst_artifacts") or {}).get("behavior_patterns") or {})
    threat_narrative = data.get("threat_narrative") or ((data.get("analyst_artifacts") or {}).get("threat_narrative") or {})
    naming_high = [v for _, v in sorted((naming_suggestions or {}).items()) if isinstance(v, dict) and v.get("confidence") == "high"][:40]
    data_flow_high = []
    for addr, row in (data_flow_insights or {}).items():
        if not isinstance(row, dict):
            continue
        for finding in (row.get("high_confidence_findings") or []):
            if isinstance(finding, dict):
                x = dict(finding)
                x["address"] = addr
                data_flow_high.append(x)
    data_flow_high = data_flow_high[:60]
    api_semantics_high = []
    for addr, row in (api_semantics_insights or {}).items():
        if not isinstance(row, dict):
            continue
        for call in (row.get("high_value_calls") or []):
            if isinstance(call, dict):
                x = dict(call)
                x["address"] = addr
                api_semantics_high.append(x)
    api_semantics_high = api_semantics_high[:60]
    behavior_patterns_high = []
    for row in ((behavior_patterns or {}).get("high_confidence_patterns") or []):
        if isinstance(row, dict):
            behavior_patterns_high.append(row)
    behavior_patterns_high = behavior_patterns_high[:30]
    cfg_high_value = []
    for addr, row in (cfg_intel_summary or {}).items():
        if not isinstance(row, dict):
            continue
        a = row.get("analysis") or {}
        if not isinstance(a, dict):
            continue
        if a.get("abnormal_high_branch_density") or a.get("possible_opaque_predicate_hints") or a.get("loop_back_edge_hints") or a.get("unreachable_block_hints") or int(a.get("unresolved_edge_count", 0)) > 0:
            cfg_high_value.append({"address": addr, "analysis": a})
    cfg_high_value = cfg_high_value[:30]
    top_behavior_rows = _select_top_behavior_summaries(function_intel_summary, behavior_summaries)

    arch = "x64" if str(meta.get("machine", "")).lower() in {"0x8664", "34404"} else "x86/other"
    high_entropy_count = sum(1 for s in sections if float(s.get("entropy", 0)) >= 7.2)

    risk_top = sorted((r for r in risk if isinstance(r, dict)), key=lambda r: int(r.get("score", 0)), reverse=True)[:10]
    for r in risk_top:
        sc = int(r.get("score", 0))
        r["badge_class"] = "danger" if sc >= 70 else ("warn" if sc >= 40 else "ok")

    packer_score = int(packer.get("score", 0) or 0)
    packer_label = "High" if packer_score >= 60 else ("Medium" if packer_score >= 30 else "Low")

    imports = data.get("imports") or {}
    import_rows = [{"dll": dll, "apis": names} for dll, names in imports.items()]

    oep_preview = []
    try:
        oep_preview = (((triage.get("stats") or {}).get("oep") or {}).get("oep_disasm_preview") or [])
    except Exception:
        oep_preview = []

    triage_stats = (triage.get("stats") or {}) if isinstance(triage, dict) else {}
    triage_hashes = (triage.get("hashes") or {}) if isinstance(triage, dict) else {}
    triage_evidence = (triage.get("evidence") or []) if isinstance(triage, dict) else []
    triage_present = bool(isinstance(triage, dict) and (triage.get("score") is not None or triage.get("findings")))
    triage_score = int(triage.get("score", 0) or 0) if isinstance(triage, dict) else 0
    if triage_score >= 85:
        severity_label = "Critical"
    elif triage_score >= 70:
        severity_label = "High"
    elif triage_score >= 40:
        severity_label = "Medium"
    else:
        severity_label = "Low"

    findings = triage.get("findings") or []
    rule_hits = triage.get("rule_hits") or []
    capabilities = triage.get("capability_tags") or []
    evidence_lines = [f"{e.get('rule','-')}: {e.get('details','-')}" for e in triage_evidence if isinstance(e, dict)]

    finding_rows = []
    for f in findings:
        fs = str(f).lower()
        matched = [ln for ln in evidence_lines if any(tok in ln.lower() for tok in fs.split()[:4])]
        if not matched:
            matched = evidence_lines[:3]
        finding_rows.append({"finding": f, "evidence": matched or ["No direct evidence line available."]})

    executive_summary = []
    if triage_present:
        executive_summary.append(f"Overall triage severity assessed as {severity_label} (score {triage_score}/100).")
        if capabilities:
            executive_summary.append(f"Capability tags present: {', '.join(capabilities[:8])}.")
        if rule_hits:
            executive_summary.append(f"Rule engine generated {len(rule_hits)} hit(s), each shown with supporting data.")
        if not capabilities and not rule_hits:
            executive_summary.append("No high-confidence capability tags or rule hits were produced by static triage.")
    else:
        executive_summary.append("No triage payload was available; this report is based on legacy PE/static sections only.")

    analyst_interpretation = []
    if triage_present:
        if triage_hashes.get("imphash"):
            analyst_interpretation.append("Import hash was generated, enabling sample family correlation in external datasets.")
        if ((triage_stats.get("tls") or {}).get("count") or 0) > 0:
            analyst_interpretation.append("TLS callbacks are present; this can alter pre-entry-point execution flow.")
        if ((triage_stats.get("overlay") or {}).get("overlay_size") or 0) > 0:
            analyst_interpretation.append("Overlay data exists; appended payload/container should be manually reviewed.")
        if (triage_stats.get("header_anomalies") or []):
            analyst_interpretation.append("Header anomalies were detected; malformed metadata may indicate evasive packing or corruption.")
        if not analyst_interpretation:
            analyst_interpretation.append("Static evidence did not reveal strong structural anomalies beyond baseline metadata.")

    conclusions = []
    recommendations = []
    if triage_present:
        conclusions.append(f"Static triage result: {severity_label} confidence bucket based on current evidence set.")
        conclusions.append("Findings are evidence-linked and should be interpreted as static indicators, not proof of runtime behavior.")
        recommendations.append("Correlate imphash/rich hash/fuzzy hash with threat-intel repositories and prior casework.")
        recommendations.append("Perform dynamic analysis/sandbox execution before asserting operational malware capabilities.")
        if triage_score >= 70:
            recommendations.append("Prioritize this sample for expedited reverse-engineering and containment triage.")
    else:
        conclusions.append("No triage payload available; conclusions are limited to structural PE metadata.")
        recommendations.append("Run full triage module to enrich report with evidence-linked findings.")

    return {
        "title": title or "Erevos Static Analysis Report",
        "logo_data_uri": _safe_logo_data_uri(logo_path),
        "schema_version": data.get("schema_version", "erevos.report.v2"),
        "case": data.get("case", {}) or {},
        "analyst_artifacts": data.get("analyst_artifacts", {}) or {},
        "meta": meta,
        "sections": sections,
        "imports": imports,
        "import_rows": import_rows,
        "exports": data.get("exports") or [],
        "resources": data.get("resources") or {},
        "risk": risk,
        "risk_top": risk_top,
        "packer": packer,
        "strings": data.get("strings") or [],
        "notes": data.get("notes") or [],
        "triage": triage,
        "xrefs_summary": data.get("xrefs_summary") or {},
        "function_intelligence_summary": function_intel_summary,
        "behavior_summaries_top": top_behavior_rows,
        "call_graph_summary": call_graph_summary,
        "cfg_intel_high_value": cfg_high_value,
        "naming_suggestions_high": naming_high,
        "data_flow_insights_high": data_flow_high,
        "api_semantics_high": api_semantics_high,
        "behavior_patterns_high": behavior_patterns_high,
        "threat_narrative": threat_narrative,
        "triage_present": triage_present,
        "triage_v2": {
            "score": triage.get("score"),
            "severity_label": severity_label,
            "verdict": triage.get("verdict"),
            "capability_tags": triage.get("capability_tags") or [],
            "rule_hits": triage.get("rule_hits") or [],
            "plugins": triage.get("plugins") or [],
            "hashes": {
                "imphash": triage_hashes.get("imphash", ""),
                "rich_hash": triage_hashes.get("rich_hash", ""),
                "fuzzy_hash": triage_hashes.get("fuzzy_hash", ""),
            },
            "entropy_heatmap": triage_stats.get("entropy_heatmap") or [],
            "import_clusters": ((triage_stats.get("imports") or {}).get("clusters") or {}),
            "api_combinations": ((triage_stats.get("imports") or {}).get("api_combinations") or []),
            "oep": triage_stats.get("oep") or {},
            "tls": triage_stats.get("tls") or {},
            "overlay": triage_stats.get("overlay") or {},
            "header_anomalies": triage_stats.get("header_anomalies") or [],
            "resource_entropy": ((triage_stats.get("sections") or {}).get("resource_entropy") or []),
            "config_artifacts": ((triage_stats.get("artifacts") or {}).get("artifacts") or []),
            "evidence": triage_evidence,
            "findings": triage.get("findings") or [],
            "finding_rows": finding_rows,
        },
        "executive_summary": executive_summary,
        "analyst_interpretation": analyst_interpretation,
        "conclusions": conclusions,
        "recommendations": recommendations,
        "summary": {
            "risk_score": triage.get("score", packer_score),
            "risk_verdict": triage.get("verdict", "unknown"),
            "packer_score": packer_score,
            "packer_label": packer_label,
            "architecture": arch,
            "section_count": len(sections),
            "import_dll_count": len(imports),
            "high_entropy_sections": high_entropy_count,
            "string_count": len(data.get("strings") or []),
        },
        "oep_preview": oep_preview,
    }


def render_html(
    data: Dict[str, Any],
    title: Optional[str] = None,
    template_path: str = "core/templates/report_v2.html",
    logo_path: Optional[str] = None,
) -> str:
    """Render report using Jinja2 template.

    Jinja2 is chosen because it cleanly separates presentation from data and is
    robust for complex forensic report layouts.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except Exception as exc:
        raise RuntimeError("Jinja2 is required for report rendering. Install jinja2.") from exc

    vm = _build_view_model(data, title=title, logo_path=logo_path)
    tpath = _resolve_template_path(template_path)
    env = Environment(
        loader=FileSystemLoader(str(tpath.parent)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(tpath.name)
    return template.render(**vm)


def export_pdf_from_html(html_text: str, pdf_path: str, base_url: Optional[str] = None) -> Optional[str]:
    """Export PDF from rendered HTML using WeasyPrint.

    WeasyPrint is selected because it has strong CSS paged-media support and
    does not require an external browser process.
    Returns None on success or an error string.
    """
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:
        return "PDF export unavailable: missing dependency 'weasyprint'. Install with: pip install weasyprint"

    try:
        HTML(string=html_text, base_url=base_url or os.getcwd()).write_pdf(pdf_path)
        return None
    except Exception as exc:
        return f"PDF export failed: {exc}"


def generate_report(
    pe_path: str,
    top: int = 30,
    max_strings: int = 200,
    html_path: Optional[str] = None,
    json_path: Optional[str] = None,
    pdf_path: Optional[str] = None,
    case_id: str = "",
    examiner: str = "",
    analyst_notes: str = "",
    analyst_artifacts: Optional[Dict[str, Any]] = None,
    template_path: str = "core/templates/report_v2.html",
    logo_path: Optional[str] = None,
    no_pdf_fail: bool = True,
):
    data = build_data(
        pe_path,
        top=top,
        max_strings=max_strings,
        case_id=case_id,
        examiner=examiner,
        analyst_notes=analyst_notes,
        analyst_artifacts=analyst_artifacts,
    )
    html = render_html(data, template_path=template_path, logo_path=logo_path)
    if html_path:
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
    if json_path:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    if pdf_path:
        err = export_pdf_from_html(html, pdf_path, base_url=os.getcwd())
        if err:
            data.setdefault("notes", []).append(err)
            if not no_pdf_fail:
                raise RuntimeError(err)
    return data, html


# ---------- CLI ----------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python report.py <path_to_pe> [--html out.html] [--json out.json] [--pdf out.pdf] [--top 30] [--max-strings 200] [--case-id ID] [--examiner NAME] [--analyst-notes TEXT] [--logo path.png] [--template path.html] [--no-pdf-fail]')
        sys.exit(1)
    pe_path = sys.argv[1]
    html_out = None
    json_out = None
    pdf_out = None
    top = 30
    max_strings = 200
    case_id = ""
    examiner = ""
    analyst_notes = ""
    logo_path = None
    template_path = "core/templates/report_v2.html"
    no_pdf_fail = True

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == '--html' and i+1 < len(args):
            html_out = args[i+1]; i += 2; continue
        if args[i] == '--json' and i+1 < len(args):
            json_out = args[i+1]; i += 2; continue
        if args[i] == '--pdf' and i+1 < len(args):
            pdf_out = args[i+1]; i += 2; continue
        if args[i] == '--top' and i+1 < len(args):
            top = int(args[i+1]); i += 2; continue
        if args[i] == '--max-strings' and i+1 < len(args):
            max_strings = int(args[i+1]); i += 2; continue
        if args[i] == '--case-id' and i+1 < len(args):
            case_id = args[i+1]; i += 2; continue
        if args[i] == '--examiner' and i+1 < len(args):
            examiner = args[i+1]; i += 2; continue
        if args[i] == '--analyst-notes' and i+1 < len(args):
            analyst_notes = args[i+1]; i += 2; continue
        if args[i] == '--logo' and i+1 < len(args):
            logo_path = args[i+1]; i += 2; continue
        if args[i] == '--template' and i+1 < len(args):
            template_path = args[i+1]; i += 2; continue
        if args[i] == '--no-pdf-fail':
            no_pdf_fail = True; i += 1; continue
        if args[i] == '--pdf-fail-hard':
            no_pdf_fail = False; i += 1; continue
        i += 1

    data, html = generate_report(
        pe_path,
        top=top,
        max_strings=max_strings,
        html_path=html_out,
        json_path=json_out,
        pdf_path=pdf_out,
        case_id=case_id,
        examiner=examiner,
        analyst_notes=analyst_notes,
        logo_path=logo_path,
        template_path=template_path,
        no_pdf_fail=no_pdf_fail,
    )
    print(json.dumps({
        'path': os.path.abspath(pe_path),
        'html': os.path.abspath(html_out) if html_out else None,
        'json': os.path.abspath(json_out) if json_out else None,
        'pdf': os.path.abspath(pdf_out) if pdf_out else None,
        'top': top,
        'max_strings': max_strings,
        'notes': data.get('notes', []),
    }, indent=2))
