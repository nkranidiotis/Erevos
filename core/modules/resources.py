# core/modules/resources.py
"""
Erevos Module — resources.py (standalone)

Purpose
  • Parse PE resources (manifest, version info, string tables) with pefile
  • Provide structured access + convenience helpers (pretty manifest summary)

Dependencies: pefile (stdlib: re, json, xml.etree)
CLI:  python resources.py <path_to_pe> [--limit 4] [--dump-manifest]
Outputs JSON to stdout (summary) and optionally prints full manifest XML.
"""
from __future__ import annotations
import sys
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any
import xml.etree.ElementTree as ET

import pefile

# Resource type IDs (subset)
RT_CURSOR = 1
RT_BITMAP = 2
RT_ICON = 3
RT_MENU = 4
RT_DIALOG = 5
RT_STRING = 6
RT_FONTDIR = 7
RT_FONT = 8
RT_ACCELERATOR = 9
RT_RCDATA = 10
RT_MESSAGETABLE = 11
RT_GROUP_CURSOR = 12
RT_GROUP_ICON = 14
RT_VERSION = 16
RT_DLGINCLUDE = 17
RT_MANIFEST = 24


@dataclass
class ResourceEntry:
    type_id: Optional[int]
    type_name: Optional[str]
    name_id: Optional[int]
    name_str: Optional[str]
    lang_id: Optional[int]
    sublang_id: Optional[int]
    rva: int
    va: int
    size: int


# -------------------- helpers --------------------
def _safe_decode(raw: bytes) -> Tuple[str, str]:
    """Try decodings: utf-8, utf-16le, utf-16, ascii. Return (text, encoding)."""
    for enc in ("utf-8", "utf-16le", "utf-16", "ascii"):
        try:
            return raw.decode(enc), enc
        except Exception:
            continue
    return raw.decode("latin-1", errors="ignore"), "latin-1"


def _resource_type_name(entry) -> Tuple[Optional[int], Optional[str]]:
    if getattr(entry, "id", None) is not None:
        return entry.id, None
    if getattr(entry, "name", None) is not None:
        return None, str(entry.name)
    return None, None


def _walk_resources(pe: pefile.PE) -> List[ResourceEntry]:
    out: List[ResourceEntry] = []
    base = pe.OPTIONAL_HEADER.ImageBase
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") or not pe.DIRECTORY_ENTRY_RESOURCE:
        return out
    try:
        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_id, type_name = _resource_type_name(type_entry)
            name_dir = getattr(type_entry, "directory", None)
            for name_entry in (name_dir.entries if name_dir else []) or []:
                name_id = getattr(name_entry, "id", None)
                name_str = str(getattr(name_entry, "name", "")) if getattr(name_entry, "name", None) else None
                lang_dir = getattr(name_entry, "directory", None)
                for lang_entry in (lang_dir.entries if lang_dir else []) or []:
                    data = lang_entry.data.struct
                    rva = data.OffsetToData
                    size = data.Size
                    va = base + rva
                    lang_id = getattr(lang_entry.data, "lang", None)
                    sublang_id = getattr(lang_entry.data, "sublang", None)
                    out.append(ResourceEntry(type_id, type_name, name_id, name_str, lang_id, sublang_id, rva, va, size))
    except Exception:
        pass
    return out


# -------------------- public API --------------------
def list_resources(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Return all resource leaf nodes with metadata."""
    return [asdict(r) for r in _walk_resources(pe)]


def extract_raw_resource(pe: pefile.PE, rva: int, size: int) -> bytes:
    mm = pe.get_memory_mapped_image()
    return mm[rva:rva+size]


def extract_manifests(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Return list of manifests: {lang, sublang, encoding, xml, summary}."""
    results: List[Dict[str, Any]] = []
    for r in _walk_resources(pe):
        if (r.type_id == RT_MANIFEST) or (r.type_name and 'manifest' in r.type_name.lower()):
            raw = extract_raw_resource(pe, r.rva, r.size)
            txt, enc = _safe_decode(raw)
            summary = _summarize_manifest_xml(txt)
            results.append({
                "lang": r.lang_id, "sublang": r.sublang_id,
                "encoding": enc, "xml": txt, "summary": summary,
            })
    return results


# --- Friendly lookups for manifest ---
GUID2OS = {
    "{e2011457-1546-43c5-a5fe-008deee3d3f0}": "Windows Vista",
    "{35138b9a-5d96-4fbd-8e2d-a2440225f93a}": "Windows 7",
    "{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}": "Windows 8",
    "{1f676c76-80e1-4239-95bb-83d0f6d0da78}": "Windows 8.1",
    "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}": "Windows 10",
    "{a4dcaa52-0da6-4e3f-b2fd-1fe97111f2a4}": "Windows 11",  # seen in newer manifests
}
LEVEL_DESC = {
    "asInvoker": "Does not request elevation (runs at caller level)",
    "highestAvailable": "Requests highest available integrity (prompts if possible)",
    "requireAdministrator": "Always prompts for admin (requires elevation)",
}


def _summarize_manifest_xml(xml_txt: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        root = ET.fromstring(xml_txt)
    except Exception:
        return out

    # Strip namespaces for tag matching
    def _local(tag: str) -> str:
        return tag.split('}', 1)[-1] if '}' in tag else tag

    dpiAware_vals: List[str] = []
    requested_level: Optional[str] = None
    ui_access: Optional[str] = None
    compat_ids: List[str] = []

    for elem in root.iter():
        tag = _local(elem.tag or "")
        text = (elem.text or "").strip()
        t = tag.lower()
        if t == "dpiaware" and text:
            dpiAware_vals.append(text)
        elif t == "requestedexecutionlevel":
            level = elem.attrib.get("level") or text
            if level:
                requested_level = level
            ui = elem.attrib.get("uiAccess")
            if ui is not None:
                ui_access = ui
        elif t == "supportedos":
            ident = elem.attrib.get("Id") or elem.attrib.get("id") or text
            if ident:
                compat_ids.append(ident)

    if dpiAware_vals:
        out["dpiAware"] = dpiAware_vals
    if requested_level:
        out["requestedExecutionLevel"] = requested_level
        out["requestedExecutionLevelDesc"] = LEVEL_DESC.get(requested_level, "Unknown / custom")
    if ui_access is not None:
        out["uiAccess"] = ui_access

    if compat_ids:
        out["compat"] = compat_ids
        # Also provide friendly names when possible
        names = []
        for gid in compat_ids:
            names.append(GUID2OS.get(gid, gid))
        out["compat_names"] = names
    return out


def _split_ver(ms: int, ls: int) -> str:
    """Convert FileVersionMS/LS into 'A.B.C.D'."""
    hi = lambda x: (x >> 16) & 0xFFFF
    lo = lambda x: x & 0xFFFF
    return f"{hi(ms)}.{lo(ms)}.{hi(ls)}.{lo(ls)}"


def extract_version_info(pe: pefile.PE) -> Dict[str, Any]:
    """Parse VS_VERSIONINFO (RT_VERSION). Returns flattened dict and pretty versions."""
    info: Dict[str, Any] = {}
    try:
        if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
            ffi = pe.VS_FIXEDFILEINFO[0]
            info['FileVersionMS'] = ffi.FileVersionMS
            info['FileVersionLS'] = ffi.FileVersionLS
            info['ProductVersionMS'] = ffi.ProductVersionMS
            info['ProductVersionLS'] = ffi.ProductVersionLS
            # Pretty strings
            try:
                info['FileVersion'] = _split_ver(ffi.FileVersionMS, ffi.FileVersionLS)
                info['ProductVersion'] = _split_ver(ffi.ProductVersionMS, ffi.ProductVersionLS)
            except Exception:
                pass

        if hasattr(pe, 'FileInfo') and pe.FileInfo:
            for entry in pe.FileInfo:
                if getattr(entry, "Key", b"") == b'StringFileInfo':
                    for st in getattr(entry, "StringTable", []) or []:
                        for k, v in getattr(st, "entries", {}).items():
                            try:
                                info[k.decode()] = v.decode(errors='ignore')
                            except Exception:
                                info[str(k)] = str(v)
    except Exception:
        pass
    return info


def extract_string_tables(pe: pefile.PE, limit_tables: Optional[int] = None) -> List[Dict[str, Any]]:
    """Extract RT_STRING blocks (ID 6). Returns list of tables with entries."""
    tables: List[Dict[str, Any]] = []
    count = 0
    for r in _walk_resources(pe):
        if r.type_id == RT_STRING or (r.type_name and 'string' in r.type_name.lower()):
            raw = extract_raw_resource(pe, r.rva, r.size)
            # RT_STRING packs 16 strings per block; each string is length-prefixed UTF-16LE
            try:
                entries: Dict[int, str] = {}
                view = memoryview(raw)
                off = 0
                for idx in range(16):
                    if off + 2 > len(view):
                        break
                    ulen = int.from_bytes(view[off:off+2], 'little')
                    off += 2
                    if ulen == 0:
                        continue
                    nbytes = ulen * 2
                    if off + nbytes > len(view):
                        break
                    s = bytes(view[off:off+nbytes]).decode('utf-16le', errors='ignore')
                    off += nbytes
                    entries[idx] = s
                tables.append({
                    'lang': r.lang_id,
                    'sublang': r.sublang_id,
                    'entries': entries,
                })
                count += 1
                if limit_tables and count >= limit_tables:
                    break
            except Exception:
                continue
    return tables


def summarize_resources(pe: pefile.PE, limit_tables: int = 3) -> Dict[str, Any]:
    """High-level summary for UI/reporting."""
    return {
        'resources': list_resources(pe),
        'manifest': extract_manifests(pe),
        'version_info': extract_version_info(pe),
        'string_tables': extract_string_tables(pe, limit_tables=limit_tables),
    }


# -------------------- CLI --------------------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python resources.py <pe_path> [--limit 3] [--dump-manifest]')
        sys.exit(1)
    pe_path = sys.argv[1]
    limit = 3
    dump_manifest = False
    for i, arg in enumerate(sys.argv[2:], start=2):
        if arg == '--limit' and i + 1 < len(sys.argv):
            limit = int(sys.argv[i+1])
        if arg == '--dump-manifest':
            dump_manifest = True

    pe = pefile.PE(pe_path, fast_load=True)
    s = summarize_resources(pe, limit_tables=limit)
    print(json.dumps(s, indent=2, ensure_ascii=False))

    if dump_manifest and s.get('manifest'):
        print('\n--- MANIFEST XML ---')
        for m in s['manifest']:
            print(m.get('xml','')[:20000])
            print('\n--------------------')
