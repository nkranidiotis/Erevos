from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Iterable, Any


_LINE_RX = re.compile(r"^0x([0-9A-Fa-f]{6,16}):\s+([a-z][a-z0-9]*)\s*(.*)$")
_ADDR_RX = re.compile(r"0x([0-9A-Fa-f]{6,16})")
_IMPORT_HINT_RX = re.compile(r"([A-Za-z0-9_]+)!([A-Za-z0-9_@?$]+)")
_COND_JMPS = {
    "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle", "jna", "jne", "jno", "jnp", "jns",
    "jo", "jp", "jpe", "jpo", "js", "jz", "jnz"
}


@dataclass(frozen=True)
class XrefRecord:
    src: int
    dst: Optional[int]
    xref_type: str  # call|jump|conditional_jump|data|string|import
    src_function: Optional[int]
    dst_function: Optional[int]
    instruction: str
    confidence: str  # high|medium|low
    api: Optional[str] = None
    string_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _find_owner_function(functions: Dict[int, str], addr: int) -> Optional[int]:
    if not functions:
        return None
    starts = sorted(functions.keys())
    owner = None
    for s in starts:
        if s <= addr:
            owner = s
        else:
            break
    return owner


def extract_structured_xrefs(
    disasm_text: str,
    functions: Optional[Dict[int, str]] = None,
    strings_by_addr: Optional[Dict[int, str]] = None,
    imports: Optional[Iterable[str]] = None,
) -> List[XrefRecord]:
    """Extract structured xrefs from textual disassembly.

    Limitations:
    - Resolves only immediate/printed addresses and explicit import hints.
    - Indirect calls/jumps without explicit targets are marked unresolved (dst=None, low confidence).
    """
    functions = functions or {}
    strings_by_addr = strings_by_addr or {}
    imports_set = set(imports or [])

    out: List[XrefRecord] = []

    for line in disasm_text.splitlines():
        m = _LINE_RX.match(line.strip())
        if not m:
            continue
        src = int(m.group(1), 16)
        mnemonic = m.group(2).lower()
        op = m.group(3).strip()

        src_func = _find_owner_function(functions, src)

        def add(dst: Optional[int], typ: str, conf: str, api: Optional[str] = None, s_val: Optional[str] = None):
            dst_func = _find_owner_function(functions, dst) if isinstance(dst, int) else None
            out.append(
                XrefRecord(
                    src=src,
                    dst=dst,
                    xref_type=typ,
                    src_function=src_func,
                    dst_function=dst_func,
                    instruction=f"{mnemonic} {op}".strip(),
                    confidence=conf,
                    api=api,
                    string_value=s_val,
                )
            )

        # control-flow xrefs
        if mnemonic == "call":
            a = _ADDR_RX.search(op)
            if a:
                dst = int(a.group(1), 16)
                add(dst, "call", "high")
            else:
                imp = _IMPORT_HINT_RX.search(op)
                if imp:
                    api = f"{imp.group(1)}!{imp.group(2)}"
                    add(None, "import", "medium", api=api)
                else:
                    # check plain symbol-ish import names
                    tok = op.split()[-1] if op else ""
                    if tok in imports_set:
                        add(None, "import", "medium", api=tok)
                    else:
                        add(None, "call", "low")
            continue

        if mnemonic == "jmp":
            a = _ADDR_RX.search(op)
            if a:
                add(int(a.group(1), 16), "jump", "high")
            else:
                add(None, "jump", "low")
            continue

        if mnemonic in _COND_JMPS:
            a = _ADDR_RX.search(op)
            if a:
                add(int(a.group(1), 16), "conditional_jump", "high")
            else:
                add(None, "conditional_jump", "low")
            continue

        # data/string refs via explicit addresses in operands
        if mnemonic in {"mov", "lea", "push", "cmp", "test"}:
            for am in _ADDR_RX.finditer(op):
                dst = int(am.group(1), 16)
                if dst in strings_by_addr:
                    add(dst, "string", "medium", s_val=strings_by_addr[dst])
                else:
                    add(dst, "data", "low")

        # import hints present outside call mnemonic (e.g., mov rax, KERNEL32!CreateFileW)
        imp2 = _IMPORT_HINT_RX.search(op)
        if imp2:
            add(None, "import", "medium", api=f"{imp2.group(1)}!{imp2.group(2)}")

    return out


def summarize_xrefs(xrefs: List[XrefRecord]) -> Dict[str, Any]:
    top_called: Dict[int, int] = {}
    suspicious_api_refs: Dict[str, int] = {}
    strings_with_refs: Dict[str, int] = {}
    unresolved_indirect_calls = 0

    for x in xrefs:
        if x.xref_type == "call" and isinstance(x.dst, int):
            top_called[x.dst] = top_called.get(x.dst, 0) + 1
        if x.xref_type == "import" and x.api:
            suspicious_api_refs[x.api] = suspicious_api_refs.get(x.api, 0) + 1
        if x.xref_type == "string" and x.string_value:
            strings_with_refs[x.string_value] = strings_with_refs.get(x.string_value, 0) + 1
        if x.xref_type == "call" and x.dst is None:
            unresolved_indirect_calls += 1

    top_called_sorted = sorted(top_called.items(), key=lambda kv: kv[1], reverse=True)[:20]
    api_sorted = sorted(suspicious_api_refs.items(), key=lambda kv: kv[1], reverse=True)[:30]
    str_sorted = sorted(strings_with_refs.items(), key=lambda kv: kv[1], reverse=True)[:30]

    return {
        "top_called_functions": [{"dst": f"0x{dst:08X}", "count": c} for dst, c in top_called_sorted],
        "suspicious_api_references": [{"api": api, "count": c} for api, c in api_sorted],
        "strings_with_references": [{"string": s, "count": c} for s, c in str_sorted],
        "unresolved_indirect_calls": unresolved_indirect_calls,
        "limitations": "First-pass textual xref extraction; indirect control-flow may be unresolved.",
    }


def build_code_xrefs_from_text(disasm_text: str) -> Dict[int, List[int]]:
    xrefs = extract_structured_xrefs(disasm_text)
    out: Dict[int, List[int]] = {}
    for x in xrefs:
        if x.dst is not None and x.xref_type in {"call", "jump", "conditional_jump"}:
            out.setdefault(x.dst, []).append(x.src)
    return out


def find_refs_from_function(disasm_text: str) -> List[int]:
    xrefs = extract_structured_xrefs(disasm_text)
    return [x.dst for x in xrefs if x.dst is not None and x.xref_type in {"call", "jump", "conditional_jump"}]
