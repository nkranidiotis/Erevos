from __future__ import annotations

from typing import Any, Dict, List

API_SEMANTICS_DB: Dict[str, Dict[str, Any]] = {
    "VirtualAlloc": {
        "category": "memory",
        "arg_names": ["lpAddress", "dwSize", "flAllocationType", "flProtect"],
        "capability_tags": ["memory_allocation"],
    },
    "VirtualProtect": {
        "category": "memory",
        "arg_names": ["lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"],
        "capability_tags": ["memory_allocation"],
    },
    "WriteProcessMemory": {
        "category": "process",
        "arg_names": ["hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesWritten"],
        "capability_tags": ["process_injection_candidate"],
    },
    "CreateRemoteThread": {"category": "process", "arg_names": [], "capability_tags": ["process_injection_candidate"]},
    "OpenProcess": {"category": "process", "arg_names": ["dwDesiredAccess", "bInheritHandle", "dwProcessId"], "capability_tags": ["process_injection_candidate"]},
    "LoadLibraryA": {"category": "loader", "arg_names": ["lpLibFileName"], "capability_tags": []},
    "LoadLibraryW": {"category": "loader", "arg_names": ["lpLibFileName"], "capability_tags": []},
    "GetProcAddress": {"category": "loader", "arg_names": ["hModule", "lpProcName"], "capability_tags": []},
    "RegSetValueExA": {"category": "registry", "arg_names": ["hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData"], "capability_tags": ["persistence_registry_candidate"]},
    "RegSetValueExW": {"category": "registry", "arg_names": ["hKey", "lpValueName", "Reserved", "dwType", "lpData", "cbData"], "capability_tags": ["persistence_registry_candidate"]},
    "CreateServiceA": {"category": "service", "arg_names": [], "capability_tags": ["service_persistence_candidate"]},
    "CreateServiceW": {"category": "service", "arg_names": [], "capability_tags": ["service_persistence_candidate"]},
    "WinHttpOpen": {"category": "network", "arg_names": [], "capability_tags": ["network_communication_candidate"]},
    "WinHttpConnect": {"category": "network", "arg_names": [], "capability_tags": ["network_communication_candidate"]},
    "InternetOpenUrlA": {"category": "network", "arg_names": [], "capability_tags": ["network_communication_candidate"]},
    "InternetOpenUrlW": {"category": "network", "arg_names": [], "capability_tags": ["network_communication_candidate"]},
    "CreateFileA": {"category": "file", "arg_names": ["lpFileName"], "capability_tags": ["file_write_candidate"]},
    "CreateFileW": {"category": "file", "arg_names": ["lpFileName"], "capability_tags": ["file_write_candidate"]},
    "WriteFile": {"category": "file", "arg_names": ["hFile", "lpBuffer", "nNumberOfBytesToWrite"], "capability_tags": ["file_write_candidate"]},
    "ShellExecuteA": {"category": "execution", "arg_names": [], "capability_tags": []},
    "ShellExecuteW": {"category": "execution", "arg_names": [], "capability_tags": []},
    "IsDebuggerPresent": {"category": "anti_debug", "arg_names": [], "capability_tags": ["anti_debugging_candidate"]},
    "CheckRemoteDebuggerPresent": {"category": "anti_debug", "arg_names": ["hProcess", "pbDebuggerPresent"], "capability_tags": ["anti_debugging_candidate"]},
}

_EXEC_PROTECT = {"0x40", "64", "0x80", "128", "0x20", "32"}  # PAGE_EXECUTE* approximations


def _api_key(api_name: str) -> str:
    if not api_name:
        return ""
    if "!" in api_name:
        api_name = api_name.split("!")[-1]
    return api_name


def interpret_api_semantics(data_flow: Dict[str, Any]) -> Dict[str, Any]:
    rows = []
    high_value = []
    for call in (data_flow or {}).get("api_argument_insights", []):
        api = call.get("api") or ""
        k = _api_key(api)
        meta = API_SEMANTICS_DB.get(k)
        if not meta:
            continue
        args = call.get("arguments") or []
        arg_notes = []
        caps = list(meta.get("capability_tags") or [])

        for idx, arg in enumerate(args):
            nm = (meta.get("arg_names") or [])[idx] if idx < len(meta.get("arg_names") or []) else f"arg{idx}"
            val = str(arg.get("value") or "unknown")
            note = f"{nm}={val} (estimated)"
            if k in {"VirtualAlloc", "VirtualProtect"} and nm.lower() in {"flprotect", "flnewprotect"}:
                if val.lower() in _EXEC_PROTECT:
                    note += " -> suggests executable memory protection indicator"
                    if "executable_memory" not in caps:
                        caps.append("executable_memory")
            if k in {"WinHttpOpen", "WinHttpConnect", "InternetOpenUrlA", "InternetOpenUrlW"} and ("http" in val.lower() or "www" in val.lower()):
                note += " -> URL/network string indicator"
            if k in {"CreateFileA", "CreateFileW", "WriteFile"} and (":" in val or "\\" in val or "/" in val):
                note += " -> file path/string indicator"
            if k in {"RegSetValueExA", "RegSetValueExW"} and ("run" in val.lower() or "software" in val.lower()):
                note += " -> registry persistence path/value indicator"
            arg_notes.append(note)

        evidence = f"API {api} observed at {call.get('call_site')} with estimated argument state from local data flow."
        row = {
            "api": api,
            "call_site": call.get("call_site"),
            "category": meta.get("category"),
            "interpreted_arguments": arg_notes,
            "capability_tags": sorted(set(caps)),
            "evidence": evidence,
            "confidence": "high" if call.get("confidence") == "high" and arg_notes else "medium",
            "estimated": True,
        }
        rows.append(row)

        if row["confidence"] == "high" and (row["capability_tags"] or any("indicator" in n for n in arg_notes)):
            high_value.append(row)

    return {
        "api_semantics_calls": rows,
        "high_value_calls": high_value,
        "heuristic_note": "Semantics are static indicators based on estimated argument values; runtime behavior is not asserted.",
    }
