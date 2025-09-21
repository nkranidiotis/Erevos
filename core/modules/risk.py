# core/modules/risk.py
from __future__ import annotations
import re
from collections import defaultdict
from typing import Dict, List, Tuple, Iterable, Optional

# ---------------- Configuration ----------------

# Category weights (roughly scaled so totals cap ~100)
WEIGHTS_CAT = {
    "api_injection": 28,
    "api_persistence": 18,
    "api_network": 16,
    "api_evasion": 12,
    "api_loading": 10,
    "str_urls": 12,
    "str_shells": 10,
    "str_registry": 8,
    "str_appdata": 6,
    "entry": 8,          # small nudge; optional
}

# API catalog by category  (names are case-sensitive matches from import names)
CAT_APIS: Dict[str, List[str]] = {
    "api_injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
        "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "QueueUserAPC", "SetThreadContext", "RtlMoveMemory", "MapViewOfFile",
        "NtUnmapViewOfSection",
    ],
    "api_persistence": [
        "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyA", "RegCreateKeyW", "CreateServiceA", "CreateServiceW",
        "ChangeServiceConfigA", "ChangeServiceConfigW", "StartServiceA", "StartServiceW",
        "ShellExecuteA", "ShellExecuteW", "IShellLinkA", "IShellLinkW", "CoCreateInstance",
    ],
    "api_network": [
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
        "URLDownloadToFileA", "URLDownloadToFileW", "WSAStartup", "WSASocketA",
        "WSASocketW", "connect", "send", "recv",
    ],
    "api_evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "GetTickCount", "GetLocalTime",
    ],
    "api_loading": [
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll",
    ],
}

# Build a fast name->category map
API_TO_CATEGORY: Dict[str, str] = {}
for cat, names in CAT_APIS.items():
    for n in names:
        API_TO_CATEGORY[n] = cat

# Suspicious string patterns (ASCII; your disassembler already normalizes)
RX_URLS      = re.compile(r"https?://[^\s'\"<>]+", re.I)
RX_SHELLS    = re.compile(r"(?:\b|/)(?:cmd\.exe|powershell(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?)\b", re.I)
RX_REGISTRY  = re.compile(r"\b(?:HKLM|HKCU)\\|\\Software\\", re.I)
RX_APPDATA   = re.compile(r"\\Users\\[^\\]+\\AppData\\", re.I)

# ---------------- Normalization helpers ----------------

def _to_va_int(x) -> Optional[int]:
    """Best-effort convert VA-like value to int, or return None."""
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except Exception:
            return None
    return None

def _normalize_func_map(raw) -> Dict[int, str]:
    """Coerce function map keys to ints and drop anything unparseable."""
    out: Dict[int, str] = {}
    for k, v in (raw or {}).items():
        va = _to_va_int(k)
        if va is not None:
            out[va] = v
    return out

# ---------------- Helpers ----------------

def _owning_function(func_map: Dict[int, str], va: int) -> Optional[int]:
    """Return function start VA that owns 'va' (<= va < next_start)."""
    if not func_map:
        return None
    addrs = sorted(func_map.keys())
    lo, hi, ans = 0, len(addrs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if addrs[mid] <= va:
            ans = addrs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return ans

def _truncate(s: str, n: int = 90) -> str:
    return s if len(s) <= n else s[:n] + "…"

def _gather_strings(disasm) -> List[str]:
    try:
        arr = disasm.get_strings() or []
    except Exception:
        arr = []
    out: List[str] = []
    for s in arr:
        if isinstance(s, bytes):
            try:
                out.append(s.decode("utf-8", "ignore"))
            except Exception:
                out.append(repr(s))
        else:
            out.append(str(s))
    return out

def _strings_hits(strings: Iterable[str]) -> List[Tuple[str, str]]:
    """
    Return list of (tag, text) where tag in {'urls','shells','registry','appdata'}.
    """
    out: List[Tuple[str, str]] = []
    for s in strings:
        if RX_URLS.search(s):
            m = RX_URLS.search(s)
            out.append(("urls", m.group(0) if m else s))
        if RX_SHELLS.search(s):
            out.append(("shells", _truncate(s, 80)))
        if RX_REGISTRY.search(s):
            out.append(("registry", _truncate(s, 80)))
        if RX_APPDATA.search(s):
            out.append(("appdata", _truncate(s, 80)))
    return out

# ---------------- Core scoring & views ----------------

def build_risk_views(disasm) -> Tuple[str, str]:
    """
    Build Critical tab contents from an existing PEDisassembler-like object.

    Returns:
        risk_txt (str): Ranked, only functions with score>0.
        hot_txt  (str): Raw artifacts (urls/registry/shells/appdata + api summaries).
    disasm must provide:
        - image_base (int)
        - entrypoint (int | str | optional)
        - imports: List[(dll, name, thunk_va (int|str))]
        - find_functions() -> Dict[int|str, str]
        - get_strings() -> List[str|bytes]
        - optional: xrefs_to(addr:int) -> List[int|str]
    """
    # Normalize function map keys → int
    try:
        func_map = _normalize_func_map(disasm.find_functions())
    except Exception:
        func_map = {}

    # Normalize imports (thunk_va → int or None)
    imports: List[Tuple[str, str, Optional[int]]] = []
    try:
        for dll, name, th in (disasm.imports or []):
            imports.append((dll, name, _to_va_int(th)))
    except Exception:
        imports = []

    # Normalize entrypoint
    entry: Optional[int] = _to_va_int(getattr(disasm, "entrypoint", None))

    strings = _gather_strings(disasm)
    xrefs = getattr(disasm, "xrefs_to", None)
    has_xrefs = callable(xrefs)

    # --- API attribution to functions ---
    func_scores: Dict[int, int] = defaultdict(int)
    func_reasons: Dict[int, List[str]] = defaultdict(list)

    for dll, name, thunk_va in imports:
        cat = API_TO_CATEGORY.get(name)
        if not cat:
            continue
        w = WEIGHTS_CAT.get(cat, 0)
        owners: List[int] = []
        if has_xrefs and isinstance(thunk_va, int):
            try:
                for ref in xrefs(thunk_va) or []:
                    ref_i = _to_va_int(ref)
                    if ref_i is None:
                        continue
                    owner = _owning_function(func_map, ref_i)
                    if owner is not None:
                        owners.append(owner)
            except Exception:
                owners = []
        if not owners and isinstance(entry, int):
            owners = [entry]
        for fva in owners:
            func_scores[fva] += w
            func_reasons[fva].append(f"api:{name}")

    # --- Suspicious strings attribution ---
    str_hits = _strings_hits(strings)  # (tag, text)
    for tag, text in str_hits:
        cat_key = {
            "urls": "str_urls",
            "shells": "str_shells",
            "registry": "str_registry",
            "appdata": "str_appdata",
        }.get(tag)
        if not cat_key:
            continue
        w = WEIGHTS_CAT.get(cat_key, 0)
        target_f = entry if isinstance(entry, int) else (next(iter(func_map.keys())) if func_map else None)
        if target_f is None:
            continue
        func_scores[target_f] += w
        func_reasons[target_f].append(f"{tag}:{_truncate(text, 80)}")

    # Optional: small nudge to entrypoint
    if isinstance(entry, int):
        func_scores[entry] += WEIGHTS_CAT.get("entry", 0)
        if WEIGHTS_CAT.get("entry", 0):
            func_reasons[entry].append("entry")

    # --- Build Risk (scores) view (hide zeros) ---
    ranked: List[Tuple[int, int, str, str]] = []  # (score, va, name, reasons)
    for va, name in func_map.items():
        sc = func_scores.get(va, 0)
        if sc <= 0:
            continue
        reasons = func_reasons.get(va, [])
        apis = [r[4:] for r in reasons if r.startswith("api:")]
        tags = [r for r in reasons if not r.startswith("api:")]
        api_part = f"apis: {', '.join(sorted(set(apis))[:6])}" if apis else ""
        tag_part = ", ".join(tags[:3])
        why = " | ".join(p for p in (api_part, tag_part) if p) or "—"
        ranked.append((sc, va, name, why))

    ranked.sort(key=lambda t: (-t[0], t[1]))

    risk_lines: List[str] = []
    for sc, va, name, why in ranked:
        risk_lines.append(f"▣ {sc:3d}  0x{va:08X}  {name}  —  {why}")

    risk_txt = "\n".join(risk_lines) if risk_lines else "— no risks scored —"

    # --- Build Hot (raw) view (concrete artifacts with snippets) ---
    hot_lines: List[str] = []

    # API hot summary per function
    for sc, va, name, _ in ranked:
        apis = [r[4:] for r in func_reasons.get(va, []) if r.startswith("api:")]
        if apis:
            uniq = sorted(set(apis))
            short = ", ".join(uniq[:8]) + (" , …" if len(uniq) > 8 else "")
            hot_lines.append(f"▣  0x{va:08X}  {name}  —  apis: {short}")

    # String hot: attach to a concrete, clickable VA
    shown_va = entry if isinstance(entry, int) else (next(iter(func_map.keys())) if func_map else 0)
    owner_name = func_map.get(shown_va, f"sub_{shown_va:08X}") if shown_va else "sub_00000000"
    for tag, text in str_hits:
        hot_lines.append(f"▣  0x{shown_va:08X}  {owner_name}  —  {tag}: {_truncate(text, 120)}")

    hot_txt = "\n".join(hot_lines) if hot_lines else "— no hot artifacts —"

    return risk_txt, hot_txt


# Convenience: structured table if you ever want JSON/export
def score_table(disasm) -> List[Dict[str, object]]:
    """Return structured rows for export/reporting."""
    risk_txt, _ = build_risk_views(disasm)
    rows: List[Dict[str, object]] = []
    for line in risk_txt.splitlines():
        if not line.startswith("▣"):
            continue
        try:
            parts = line.split()
            score = int(parts[1])
            va_hex = parts[2]
            name = parts[3]
            reason = line.split("—", 1)[1].strip() if "—" in line else ""
            rows.append({"va": va_hex, "name": name, "score": score, "reason": reason})
        except Exception:
            pass
    return rows
