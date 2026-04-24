from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import pefile

try:
    import capstone
except Exception:
    capstone = None

try:
    import pydeep  # type: ignore
except Exception:
    pydeep = None

from .plugins_runtime import run_plugins
from .rules_engine import evaluate_rules

SCHEMA_VERSION = "2.0.0"

SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".aspack", ".vmp0", ".vmp1", ".themida", ".packed", ".adata", ".petite"
}

CAPABILITY_APIS = {
    "process_injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext"},
    "defense_evasion": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"},
    "persistence": {"RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW", "ShellExecuteW"},
    "command_execution": {"WinExec", "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW"},
    "network_beaconing": {"InternetOpenA", "InternetOpenW", "WinHttpOpen", "connect", "send", "recv"},
}

DIRECTORY_NAMES = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE",
    "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
]

RX_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
RX_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
RX_URL = re.compile(rb"https?://[^\s\"'<>]+", re.I)
RX_IP = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RX_MUTEX = re.compile(rb"Global\\[A-Za-z0-9_\-]{4,}|Local\\[A-Za-z0-9_\-]{4,}")
RX_C2_HINT = re.compile(rb"/gate\.php|/panel|/api/v\d+|botnet|beacon", re.I)
RX_POWERSHELL = re.compile(rb"powershell(?:\.exe)?|\b-enc\b|\bencodedcommand\b", re.I)


@dataclass
class Evidence:
    rule: str
    details: str


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _compute_hashes(path: str) -> Dict[str, str]:
    hs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hs.values():
                h.update(chunk)
    out = {k: v.hexdigest() for k, v in hs.items()}
    out["fuzzy_hash"] = pydeep.hash_file(path) if pydeep else "unavailable:install_pydeep"
    return out


def _safe_pe_load(pe_path: str) -> Tuple[Optional[pefile.PE], Optional[str]]:
    try:
        pe = pefile.PE(pe_path, fast_load=False)
        pe.parse_data_directories()
        return pe, None
    except Exception as exc:
        return None, str(exc)


def _directory_summary(pe: pefile.PE) -> List[Dict[str, Any]]:
    out = []
    dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])
    for idx, dd in enumerate(dirs[:16]):
        out.append({
            "index": idx,
            "name": DIRECTORY_NAMES[idx],
            "virtual_address": int(getattr(dd, "VirtualAddress", 0)),
            "size": int(getattr(dd, "Size", 0)),
            "present": bool(getattr(dd, "VirtualAddress", 0) and getattr(dd, "Size", 0)),
        })
    return out


def _entropy_heatmap(file_bytes: bytes, window: int = 512) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for off in range(0, len(file_bytes), window):
        chunk = file_bytes[off:off + window]
        out.append({"offset": off, "size": len(chunk), "entropy": _entropy(chunk)})
        if len(out) >= 4096:
            break
    return out


def _section_analysis(pe: pefile.PE, evidence: List[Evidence]) -> Dict[str, Any]:
    high = []
    suspicious = []
    rwx = []
    malformed = []
    res_entropy = []

    sz_image = int(getattr(pe.OPTIONAL_HEADER, "SizeOfImage", 0) or 0)
    sec_align = int(getattr(pe.OPTIONAL_HEADER, "SectionAlignment", 0) or 0)

    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="ignore")
        raw = s.get_data() or b""
        ent = _entropy(raw)
        if ent >= 7.2:
            high.append({"name": name, "entropy": ent})
        if name.lower() in SUSPICIOUS_SECTION_NAMES:
            suspicious.append(name)
        if (s.Characteristics & 0x20000000) and (s.Characteristics & 0x80000000):
            rwx.append(name)
        if s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) > sz_image + 0x100000:
            malformed.append(f"{name}: section exceeds expected image span")
        if sec_align and (s.VirtualAddress % sec_align != 0):
            malformed.append(f"{name}: VA misaligned")
        if name.lower().startswith(".rsrc"):
            res_entropy.append({"name": name, "entropy": ent})

    if suspicious:
        evidence.append(Evidence("suspicious_sections", ", ".join(suspicious)))
    if rwx:
        evidence.append(Evidence("rwx_sections", ", ".join(rwx)))
    if malformed:
        evidence.append(Evidence("malformed_section_headers", malformed[0]))

    return {
        "high_entropy_sections": high,
        "suspicious_sections": suspicious,
        "rwx_sections": rwx,
        "malformed_headers": malformed,
        "resource_entropy": res_entropy,
        "high_entropy_sections_count": len(high),
    }


def _oep_analysis(pe: pefile.PE, file_bytes: bytes, evidence: List[Evidence]) -> Dict[str, Any]:
    ep_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    ep_va = image_base + ep_rva
    ep_off = None
    ep_bytes = b""
    try:
        ep_off = pe.get_offset_from_rva(ep_rva)
        ep_bytes = file_bytes[ep_off:ep_off + 96] if ep_off is not None else b""
    except Exception:
        pass

    disasm_preview: List[str] = []
    if capstone and ep_bytes:
        try:
            mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            for i, ins in enumerate(md.disasm(ep_bytes, ep_va)):
                disasm_preview.append(f"0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}".strip())
                if i >= 14:
                    break
        except Exception:
            pass

    ep_section = None
    for s in pe.sections:
        if s.VirtualAddress <= ep_rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            ep_section = s.Name.rstrip(b"\x00").decode(errors="ignore")
            break

    if ep_section and ep_section.lower() not in {".text", "text"}:
        evidence.append(Evidence("entrypoint_section", f"entrypoint in {ep_section}"))

    return {
        "entrypoint_rva": ep_rva,
        "entrypoint_va": ep_va,
        "entrypoint_file_offset": ep_off,
        "entrypoint_section": ep_section,
        "entrypoint_bytes_hex": ep_bytes[:24].hex(),
        "oep_disasm_preview": disasm_preview,
    }


def _imports_and_capabilities(pe: pefile.PE, evidence: List[Evidence]) -> Dict[str, Any]:
    imports_by_dll: Dict[str, List[str]] = {}
    flat: List[str] = []
    for imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = imp.dll.decode(errors="ignore") if getattr(imp, "dll", None) else "<unknown>"
        names = []
        for f in imp.imports or []:
            n = f.name.decode(errors="ignore") if getattr(f, "name", None) else None
            if n:
                names.append(n)
                flat.append(n)
        imports_by_dll[dll] = names

    clusters = {
        "network": [n for n in flat if n.lower().startswith(("internet", "winhttp", "wsa", "socket", "connect", "send", "recv"))],
        "registry": [n for n in flat if n.lower().startswith("reg")],
        "process": [n for n in flat if "process" in n.lower() or "thread" in n.lower()],
        "crypto": [n for n in flat if n.lower().startswith(("crypt", "bcrypt"))],
    }

    capabilities: Dict[str, List[str]] = {}
    for cap, api_set in CAPABILITY_APIS.items():
        hits = sorted(set(n for n in flat if n in api_set))
        if hits:
            capabilities[cap] = hits
            evidence.append(Evidence(f"api_{cap}", ", ".join(hits[:8])))

    combos = []
    if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.issubset(set(flat)):
        combos.append("remote_thread_injection_combo")
    if {"CreateProcessW", "WriteProcessMemory", "SetThreadContext"}.issubset(set(flat)):
        combos.append("process_hollowing_like_combo")
    if combos:
        evidence.append(Evidence("suspicious_api_combinations", ", ".join(combos)))

    return {
        "imports_total": len(flat),
        "imports_by_dll": imports_by_dll,
        "clusters": {k: sorted(set(v)) for k, v in clusters.items() if v},
        "capabilities": capabilities,
        "api_combinations": combos,
        "flat": flat,
    }


def _tls_callbacks(pe: pefile.PE, evidence: List[Evidence]) -> Dict[str, Any]:
    callbacks: List[int] = []
    try:
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls and getattr(tls, "struct", None):
            addr = int(getattr(tls.struct, "AddressOfCallBacks", 0) or 0)
            image_base = int(pe.OPTIONAL_HEADER.ImageBase)
            if addr:
                rva = addr - image_base
                off = pe.get_offset_from_rva(rva)
                for _ in range(16):
                    if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
                        raw = pe.__data__[off:off + 8]
                        if len(raw) < 8:
                            break
                        v = int.from_bytes(raw, "little")
                        off += 8
                    else:
                        raw = pe.__data__[off:off + 4]
                        if len(raw) < 4:
                            break
                        v = int.from_bytes(raw, "little")
                        off += 4
                    if v == 0:
                        break
                    callbacks.append(v)
    except Exception:
        pass
    if callbacks:
        evidence.append(Evidence("tls_callbacks", f"count={len(callbacks)}"))
    return {"callbacks": [hex(v) for v in callbacks], "count": len(callbacks)}


def _overlay(pe: pefile.PE, file_path: str, evidence: List[Evidence]) -> Dict[str, Any]:
    size = os.path.getsize(file_path)
    last_end = max((s.PointerToRawData + s.SizeOfRawData) for s in pe.sections) if pe.sections else 0
    overlay_size = max(0, size - last_end)
    overlay = b""
    classification = "none"
    if overlay_size:
        with open(file_path, "rb") as f:
            f.seek(last_end)
            overlay = f.read(min(overlay_size, 4096))
        if overlay.startswith(b"MZ"):
            classification = "embedded_pe_candidate"
        elif overlay.startswith(b"PK\x03\x04"):
            classification = "zip_blob"
        elif b"<?xml" in overlay[:256]:
            classification = "xml_blob"
        else:
            classification = "opaque_blob"
        evidence.append(Evidence("overlay", f"size={overlay_size} class={classification}"))
    return {
        "overlay_size": overlay_size,
        "overlay_ratio": round(overlay_size / max(1, size), 4),
        "classification": classification,
        "preview_hex": overlay[:64].hex(),
    }


def _extract_strings_and_artifacts(file_bytes: bytes, evidence: List[Evidence]) -> Dict[str, Any]:
    hits: List[Tuple[int, bytes, str]] = []
    for m in RX_ASCII.finditer(file_bytes):
        hits.append((m.start(), m.group(), "ascii"))
        if len(hits) > 12000:
            break
    for m in RX_UTF16.finditer(file_bytes):
        hits.append((m.start(), m.group(), "utf16le"))
        if len(hits) > 12000:
            break

    def count(rx: re.Pattern[bytes]) -> int:
        return sum(1 for _, raw, _ in hits if rx.search(raw))

    signals = {
        "urls": count(RX_URL),
        "ips": count(RX_IP),
        "mutex": count(RX_MUTEX),
        "c2_hints": count(RX_C2_HINT),
        "powershell": count(RX_POWERSHELL),
    }
    signals = {k: v for k, v in signals.items() if v}

    config_artifacts = []
    for off, raw, enc in hits:
        if RX_URL.search(raw) or RX_MUTEX.search(raw) or RX_C2_HINT.search(raw):
            txt = raw.decode("utf-16le" if enc == "utf16le" else "ascii", errors="ignore")
            config_artifacts.append({"offset": off, "encoding": enc, "value": txt[:240]})
            if len(config_artifacts) >= 30:
                break

    if signals:
        evidence.append(Evidence("suspicious_artifacts", str(signals)))

    return {"signals": signals, "artifacts": config_artifacts}


def _header_anomalies(pe: pefile.PE, evidence: List[Evidence]) -> List[str]:
    out = []
    try:
        if pe.DOS_HEADER.e_magic != 0x5A4D:
            out.append("invalid_mz_signature")
        if pe.NT_HEADERS.Signature != 0x4550:
            out.append("invalid_pe_signature")
        if pe.FILE_HEADER.NumberOfSections <= 0 or pe.FILE_HEADER.NumberOfSections > 96:
            out.append("abnormal_number_of_sections")
        if pe.OPTIONAL_HEADER.SizeOfHeaders <= 0:
            out.append("invalid_size_of_headers")
        if pe.OPTIONAL_HEADER.FileAlignment and pe.OPTIONAL_HEADER.SectionAlignment:
            if pe.OPTIONAL_HEADER.SectionAlignment < pe.OPTIONAL_HEADER.FileAlignment:
                out.append("section_alignment_smaller_than_file_alignment")
    except Exception as exc:
        out.append(f"header_parse_exception:{exc}")

    if out:
        evidence.append(Evidence("header_anomalies", ", ".join(out[:4])))
    return out


def _cert_dotnet_rich(pe: pefile.PE, evidence: List[Evidence]) -> Dict[str, Any]:
    dirs = _directory_summary(pe)
    sec = dirs[4] if len(dirs) > 4 else {"present": False, "virtual_address": 0, "size": 0}
    com = dirs[14] if len(dirs) > 14 else {"present": False, "virtual_address": 0, "size": 0}

    rich_hash = None
    try:
        rich_hash = pe.get_rich_header_hash()
    except Exception:
        rich_hash = "unavailable"

    cert = {"present": sec.get("present"), "file_offset": sec.get("virtual_address"), "size": sec.get("size")}
    dotnet = {"is_dotnet": com.get("present"), "cli_header_rva": com.get("virtual_address"), "cli_header_size": com.get("size")}
    if cert["present"]:
        evidence.append(Evidence("certificate_table", f"size={cert['size']}"))
    if dotnet["is_dotnet"]:
        evidence.append(Evidence("dotnet_cli_header", f"rva={dotnet['cli_header_rva']}"))
    return {"certificate": cert, "dotnet": dotnet, "rich_hash": rich_hash}


def _build_default_rules() -> List[Dict[str, Any]]:
    return [
        {
            "name": "packed_entropy_sparse_imports",
            "all": [["stats.sections.high_entropy_sections_count", ">=", 1], ["stats.imports.imports_total", "<", 10]],
            "severity": "high",
            "tag": "packed_binary_suspected",
            "message": "High entropy sections with sparse imports",
        },
        {
            "name": "injection_combo",
            "all": [["stats.imports.api_combinations", "contains", "remote_thread_injection_combo"]],
            "severity": "high",
            "tag": "process_injection_suspected",
            "message": "Classic remote thread injection API combination observed",
        },
    ]


def _score(stats: Dict[str, Any]) -> int:
    score = 0
    score += min(20, stats["sections"]["high_entropy_sections_count"] * 8)
    score += 12 if stats["sections"]["rwx_sections"] else 0
    score += 10 if stats["overlay"]["overlay_ratio"] > 0.02 else 0
    score += min(24, len(stats["imports"]["capabilities"]) * 6)
    score += 10 if stats["imports"]["api_combinations"] else 0
    score += min(12, len(stats["artifacts"]["signals"]) * 3)
    score += 8 if stats["tls"]["count"] else 0
    score += 8 if stats["header_anomalies"] else 0
    return min(score, 100)


def analyze_triage(pe_path: str, custom_rules: Optional[List[Dict[str, Any]]] = None, plugin_paths: Optional[List[str]] = None) -> Dict[str, Any]:
    hashes = _compute_hashes(pe_path)
    file_bytes = open(pe_path, "rb").read()

    pe, err = _safe_pe_load(pe_path)
    if pe is None:
        return {
            "schema_version": SCHEMA_VERSION,
            "file": pe_path,
            "hashes": hashes,
            "score": 100,
            "verdict": "high",
            "findings": ["PE parsing failed; sample may be malformed or hostile"],
            "evidence": [{"rule": "pe_parse_error", "details": err or "unknown"}],
            "stats": {"parse_error": err or "unknown"},
        }

    evidence: List[Evidence] = []
    try:
        hashes["imphash"] = pe.get_imphash()
    except Exception:
        hashes["imphash"] = ""

    directories = _directory_summary(pe)
    sections = _section_analysis(pe, evidence)
    oep = _oep_analysis(pe, file_bytes, evidence)
    imports = _imports_and_capabilities(pe, evidence)
    tls = _tls_callbacks(pe, evidence)
    overlay = _overlay(pe, pe_path, evidence)
    artifacts = _extract_strings_and_artifacts(file_bytes, evidence)
    header_anomalies = _header_anomalies(pe, evidence)
    certdot = _cert_dotnet_rich(pe, evidence)
    heatmap = _entropy_heatmap(file_bytes)

    stats = {
        "directories": directories,
        "sections": sections,
        "oep": oep,
        "imports": imports,
        "tls": tls,
        "overlay": overlay,
        "artifacts": artifacts,
        "header_anomalies": header_anomalies,
        "certificate": certdot["certificate"],
        "dotnet": certdot["dotnet"],
        "entropy_heatmap": heatmap,
    }

    rule_hits = evaluate_rules({"stats": stats}, custom_rules or _build_default_rules())
    for r in rule_hits:
        evidence.append(Evidence("rule_engine", f"{r['name']}:{r.get('message', '')}"))

    partial_result = {
        "schema_version": SCHEMA_VERSION,
        "file": pe_path,
        "hashes": {**hashes, "rich_hash": certdot["rich_hash"]},
        "capabilities": imports["capabilities"],
        "capability_tags": sorted(set(imports["capabilities"].keys() + [r["tag"] for r in rule_hits])),
        "rule_hits": rule_hits,
        "stats": stats,
    }
    plugin_results = run_plugins(pe, file_bytes, partial_result, plugin_paths=plugin_paths)

    score = _score(stats)
    if rule_hits:
        score = min(100, score + min(12, len(rule_hits) * 4))

    verdict = "low" if score < 40 else "medium" if score < 70 else "high"
    findings = [f"{c.replace('_', ' ')} capability suspected" for c in imports["capabilities"].keys()]
    findings += [r.get("message", r["name"]) for r in rule_hits]
    if overlay["classification"] == "embedded_pe_candidate":
        findings.append("embedded payload candidate in overlay")

    return {
        "schema_version": SCHEMA_VERSION,
        "file": pe_path,
        "hashes": {**hashes, "rich_hash": certdot["rich_hash"]},
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "capabilities": imports["capabilities"],
        "capability_tags": sorted(set(imports["capabilities"].keys() + [r["tag"] for r in rule_hits])),
        "rule_hits": rule_hits,
        "plugins": plugin_results,
        "evidence": [asdict(e) for e in evidence],
        "stats": stats,
        "warnings": [
            "Static signals are heuristic and can be evaded by packed or staged loaders.",
            "Treat malformed header anomalies as potential anti-analysis artifacts.",
        ],
    }
