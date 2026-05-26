from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from .xrefs_foundation import XrefRecord

_INS_RX = re.compile(r"^0x([0-9A-Fa-f]{6,16}):\s+([a-z][a-z0-9]*)\s*(.*)$")
_LOCAL_RX = re.compile(r"\[(?:e?bp|r?bp)\s*([-+]\s*0x[0-9A-Fa-f]+)\]", re.I)
_ARG_RX = re.compile(r"\[(?:e?bp|r?bp)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\]", re.I)

SUSPICIOUS_API_TOKENS = (
    "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "WinHttp", "InternetOpen", "RegSetValue", "CreateService", "IsDebuggerPresent",
)


@dataclass
class FunctionProfile:
    start: int
    end: Optional[int]
    size_estimate: Optional[int]
    instruction_count: int
    basic_block_count: int
    calls_made: List[int]
    inbound_xrefs: int
    outbound_xrefs: int
    referenced_strings: List[str]
    referenced_apis: List[str]
    suspicious_api_usage: List[str]
    risk_indicators: List[str]
    comments: List[str]
    labels: List[str]
    bookmarks: bool
    prologue_pattern: Optional[str]
    epilogue_pattern: Optional[str]
    stack_frame_size_estimate: Optional[int]
    local_offsets_estimate: List[str]
    argument_offsets_estimate: List[str]
    calling_convention_hint: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["start_hex"] = f"0x{self.start:08X}"
        d["end_hex"] = f"0x{self.end:08X}" if self.end is not None else None
        d["heuristic_note"] = "Fields with _estimate/_hint are conservative heuristics."
        return d


def _split_function_lines(disasm_text: str, start: int, end: Optional[int]) -> List[str]:
    out = []
    for line in disasm_text.splitlines():
        m = _INS_RX.match(line.strip())
        if not m:
            continue
        va = int(m.group(1), 16)
        if va < start:
            continue
        if end is not None and va >= end:
            continue
        out.append(line)
    return out


def _stack_heuristics(lines: List[str]) -> Dict[str, Any]:
    prologue = None
    epilogue = None
    frame_size = None
    locals_off = set()
    args_off = set()
    calling_hint = "unknown"

    if lines:
        first = lines[0].lower()
        if "push rbp" in first or "push ebp" in first:
            prologue = "frame_pointer_push"
        for ln in lines[:6]:
            l = ln.lower()
            if "sub rsp," in l or "sub esp," in l:
                m = re.search(r"sub\s+r?[es]sp,\s*(0x[0-9a-f]+|\d+)", l)
                if m:
                    frame_size = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
            if "mov rbp, rsp" in l or "mov ebp, esp" in l:
                prologue = (prologue + "+set_fp") if prologue else "set_frame_pointer"

    for ln in lines:
        l = ln.lower()
        if "ret" in l:
            epilogue = "ret"
        m1 = _LOCAL_RX.search(l)
        if m1:
            locals_off.add(m1.group(1).replace(" ", ""))
        m2 = _ARG_RX.search(l)
        if m2:
            args_off.add(m2.group(1))

    if prologue and any(a in args_off for a in ("8", "0x8", "0x10")):
        calling_hint = "likely_stdcall_or_cdecl_x86"
    if any("rcx" in ln.lower() or "rdx" in ln.lower() for ln in lines[:8]):
        calling_hint = "likely_win64_fastcall"

    return {
        "prologue": prologue,
        "epilogue": epilogue,
        "frame_size": frame_size,
        "locals": sorted(locals_off),
        "args": sorted(args_off),
        "calling": calling_hint,
    }


def build_function_profiles(
    disasm_text: str,
    functions: Dict[int, str],
    xrefs: List[XrefRecord],
    comments: Dict[str, str],
    labels: Dict[str, str],
    bookmarks: List[str],
) -> Dict[int, FunctionProfile]:
    starts = sorted(functions.keys())
    profiles: Dict[int, FunctionProfile] = {}

    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else None
        lines = _split_function_lines(disasm_text, start, end)
        ins_count = len(lines)
        bb_count = 1 + sum(1 for ln in lines if re.search(r"\b(j\w+|ret)\b", ln.lower()))

        fx = [x for x in xrefs if x.src_function == start or x.dst_function == start]
        inbound = [x for x in fx if x.dst_function == start or x.dst == start]
        outbound = [x for x in fx if x.src_function == start]

        calls = sorted({x.dst for x in outbound if x.xref_type == "call" and isinstance(x.dst, int)})
        refs_strings = sorted({x.string_value for x in outbound if x.xref_type == "string" and x.string_value})
        refs_apis = sorted({x.api for x in outbound if x.xref_type == "import" and x.api})
        suspicious_apis = sorted([a for a in refs_apis if any(tok.lower() in a.lower() for tok in SUSPICIOUS_API_TOKENS)])

        risk_notes = []
        if suspicious_apis:
            risk_notes.append("suspicious_api_usage")
        if len(inbound) > 20:
            risk_notes.append("high_inbound_xref_density")
        if any(x.confidence == "low" and x.xref_type == "call" for x in outbound):
            risk_notes.append("unresolved_indirect_call")

        key = f"0x{start:08X}"
        stack = _stack_heuristics(lines)

        profiles[start] = FunctionProfile(
            start=start,
            end=end,
            size_estimate=(end - start) if end else None,
            instruction_count=ins_count,
            basic_block_count=bb_count,
            calls_made=calls,
            inbound_xrefs=len(inbound),
            outbound_xrefs=len(outbound),
            referenced_strings=refs_strings,
            referenced_apis=refs_apis,
            suspicious_api_usage=suspicious_apis,
            risk_indicators=risk_notes,
            comments=[comments[key]] if key in comments else [],
            labels=[labels[key]] if key in labels else [],
            bookmarks=(key in bookmarks),
            prologue_pattern=stack["prologue"],
            epilogue_pattern=stack["epilogue"],
            stack_frame_size_estimate=stack["frame_size"],
            local_offsets_estimate=stack["locals"],
            argument_offsets_estimate=stack["args"],
            calling_convention_hint=stack["calling"],
        )

    return profiles


def summarize_function_intelligence(profiles: Dict[int, FunctionProfile], renamed: Dict[str, str]) -> Dict[str, Any]:
    vals = list(profiles.values())
    risky = sorted(vals, key=lambda p: (len(p.risk_indicators), len(p.suspicious_api_usage), p.inbound_xrefs), reverse=True)[:20]
    with_susp_apis = [p for p in vals if p.suspicious_api_usage][:20]
    with_strings = [p for p in vals if p.referenced_strings][:20]
    renamed_rows = [{"address": k, "name": v} for k, v in sorted((renamed or {}).items())]
    commented = [p for p in vals if p.comments or p.bookmarks][:30]

    return {
        "top_risky_functions": [
            {
                "start": f"0x{p.start:08X}",
                "risk_indicators": p.risk_indicators,
                "suspicious_api_usage": p.suspicious_api_usage,
                "inbound_xrefs": p.inbound_xrefs,
            }
            for p in risky
        ],
        "functions_with_suspicious_apis": [{"start": f"0x{p.start:08X}", "apis": p.suspicious_api_usage} for p in with_susp_apis],
        "functions_with_interesting_strings": [{"start": f"0x{p.start:08X}", "strings": p.referenced_strings[:5]} for p in with_strings],
        "analyst_renamed_functions": renamed_rows,
        "commented_or_bookmarked_functions": [{"start": f"0x{p.start:08X}", "comments": p.comments, "bookmarked": p.bookmarks} for p in commented],
    }


def generate_function_behavior_summary(profile: FunctionProfile) -> Dict[str, Any]:
    """Heuristic behavioral summary based only on static evidence in FunctionProfile."""
    evidence: List[str] = []
    tags: List[str] = []

    if profile.suspicious_api_usage:
        evidence.append(f"Suspicious API references: {', '.join(profile.suspicious_api_usage[:6])}.")
        tags.append("suspicious_api_usage")
    elif profile.referenced_apis:
        evidence.append(f"Referenced APIs: {', '.join(profile.referenced_apis[:6])}.")

    if profile.referenced_strings:
        evidence.append(f"Referenced strings include: {', '.join(profile.referenced_strings[:3])}.")
        if any("http" in s.lower() or "://" in s.lower() for s in profile.referenced_strings):
            tags.append("possible_network_config")

    if profile.calls_made:
        evidence.append(f"Direct call targets observed: {', '.join([f'0x{x:08X}' for x in profile.calls_made[:6]])}.")

    if profile.inbound_xrefs > 0 or profile.outbound_xrefs > 0:
        evidence.append(
            f"Xref density: inbound={profile.inbound_xrefs}, outbound={profile.outbound_xrefs}."
        )

    if profile.prologue_pattern or profile.calling_convention_hint != "unknown":
        evidence.append(
            f"Stack/calling heuristic: prologue={profile.prologue_pattern or '-'}, calling={profile.calling_convention_hint}."
        )

    if profile.comments:
        evidence.append(f"Analyst comments present: {', '.join(profile.comments[:2])}.")
        tags.append("analyst_flagged")
    if profile.labels:
        evidence.append(f"Analyst labels present: {', '.join(profile.labels[:2])}.")
    if profile.bookmarks:
        evidence.append("Function is bookmarked by analyst.")
        tags.append("analyst_bookmark")
    if profile.risk_indicators:
        evidence.append(f"Risk indicators: {', '.join(profile.risk_indicators[:4])}.")

    if profile.suspicious_api_usage:
        short = "Function likely performs sensitive API-mediated operations (static heuristic)."
    elif profile.referenced_strings:
        short = "Function appears to process notable string data (static heuristic)."
    elif profile.calls_made:
        short = "Function appears to orchestrate calls to other routines (static heuristic)."
    else:
        short = "Behavior unclear from current static evidence."

    score = 0
    score += 2 if profile.suspicious_api_usage else 0
    score += 1 if profile.referenced_apis else 0
    score += 1 if profile.referenced_strings else 0
    score += 1 if profile.risk_indicators else 0
    score += 1 if profile.comments or profile.bookmarks else 0
    confidence = "high" if score >= 4 else ("medium" if score >= 2 else "low")

    if not evidence:
        evidence = ["No strong static evidence extracted for this function."]

    caveats = [
        "Heuristic behavioral summary derived from static disassembly/xref evidence only.",
        "Not a decompiler output; does not prove runtime execution path or intent.",
    ]
    if confidence == "low":
        caveats.append("Low confidence due to limited observable evidence.")

    return {
        "function_address": f"0x{profile.start:08X}",
        "short_behavior_summary": short,
        "evidence_bullets": evidence,
        "confidence": confidence,
        "possible_capability_tags": sorted(set(tags)),
        "caveats": caveats,
    }


def generate_all_behavior_summaries(profiles: Dict[int, FunctionProfile]) -> Dict[str, Dict[str, Any]]:
    return {
        f"0x{va:08X}": generate_function_behavior_summary(profile)
        for va, profile in sorted((profiles or {}).items())
    }
