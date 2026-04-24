from __future__ import annotations

from typing import Any, Dict, List

from .function_intel import FunctionProfile


def _sanitize_token(s: str) -> str:
    out = "".join(ch.lower() if ch.isalnum() else "_" for ch in s)
    while "__" in out:
        out = out.replace("__", "_")
    return out.strip("_")[:48] or "function"


def generate_function_name_suggestion(
    profile: FunctionProfile,
    behavior_summary: Dict[str, Any] | None = None,
    entry_reachable: bool = False,
) -> Dict[str, Any]:
    evidence: List[str] = []
    caveats = [
        "Heuristic naming suggestion from static evidence only.",
        "Use analyst validation before adopting as canonical symbol.",
    ]

    base = "function_candidate"
    confidence_score = 0

    apis = [a.lower() for a in (profile.referenced_apis or [])]
    strings = [s.lower() for s in (profile.referenced_strings or [])]
    behavior = (behavior_summary or {}).get("short_behavior_summary", "").lower()

    if any("winhttp" in a or "internet" in a or "ws2_" in a or "socket" in a for a in apis):
        base = "possible_network_init"
        evidence.append("Network-related API references observed.")
        confidence_score += 2
    elif any("reg" in a for a in apis):
        base = "possible_registry_persistence"
        evidence.append("Registry-related API references observed.")
        confidence_score += 2
    elif any("virtualalloc" in a or "writeprocessmemory" in a or "createremotethread" in a for a in apis):
        base = "possible_injection_candidate"
        evidence.append("Sensitive memory/thread APIs observed.")
        confidence_score += 2
    elif any("decode" in s or "decrypt" in s or "xor" in s for s in strings):
        base = "string_decoder_candidate"
        evidence.append("String artifacts suggest decoding/deobfuscation intent.")
        confidence_score += 1
    elif behavior:
        if "string" in behavior:
            base = "string_processing_candidate"
            confidence_score += 1
            evidence.append("Behavior summary suggests notable string handling.")
        elif "sensitive api" in behavior:
            base = "possible_sensitive_api_handler"
            confidence_score += 1
            evidence.append("Behavior summary indicates sensitive API mediation.")

    if profile.labels:
        base = f"possible_{_sanitize_token(profile.labels[0])}"
        evidence.append("Analyst label hints role.")
        confidence_score += 1
    if profile.comments:
        evidence.append("Analyst comments present for this function.")
        confidence_score += 1
    if profile.suspicious_api_usage:
        evidence.append("Suspicious API usage present.")
        confidence_score += 1
    if entry_reachable:
        evidence.append("Function appears entry-point reachable in call graph.")
        confidence_score += 1

    suggested_name = f"{base}_{profile.start:08x}"
    confidence = "high" if confidence_score >= 4 else ("medium" if confidence_score >= 2 else "low")
    if confidence == "low":
        caveats.append("Low confidence due to limited direct role evidence.")

    if not evidence:
        evidence = ["No strong evidence for semantic naming; generic candidate generated."]

    return {
        "address": f"0x{profile.start:08X}",
        "suggested_name": suggested_name,
        "confidence": confidence,
        "evidence_bullets": evidence,
        "caveats": caveats,
    }


def generate_all_name_suggestions(
    profiles: Dict[int, FunctionProfile],
    behavior_summaries: Dict[str, Dict[str, Any]] | None = None,
    call_graph_summary: Dict[str, Any] | None = None,
) -> Dict[str, Dict[str, Any]]:
    reachable = set((call_graph_summary or {}).get("entry_reachable_functions") or [])
    out: Dict[str, Dict[str, Any]] = {}
    for va, p in sorted((profiles or {}).items()):
        addr = f"0x{va:08X}"
        out[addr] = generate_function_name_suggestion(
            p,
            behavior_summary=(behavior_summaries or {}).get(addr),
            entry_reachable=addr in reachable,
        )
    return out


def select_high_confidence_applications(
    suggestions: Dict[str, Dict[str, Any]],
    analyst_renamed: Dict[str, str],
    allow_overwrite: bool = False,
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for addr, row in (suggestions or {}).items():
        if not isinstance(row, dict):
            continue
        if row.get("confidence") != "high":
            continue
        if not allow_overwrite and addr in (analyst_renamed or {}):
            continue
        nm = row.get("suggested_name")
        if isinstance(nm, str) and nm:
            out[addr] = nm
    return out
