from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .xrefs_foundation import XrefRecord

_INS_RX = re.compile(r"^0x([0-9A-Fa-f]{6,16}):\s+([a-z][a-z0-9]*)\s*(.*)$")
_ADDR_RX = re.compile(r"0x([0-9A-Fa-f]{6,16})")
_IMM_RX = re.compile(r"\b(0x[0-9A-Fa-f]+|\d+)\b")
_X64_ARG_REGS = ("rcx", "rdx", "r8", "r9")


def _split_ops(op_str: str) -> List[str]:
    return [x.strip() for x in op_str.split(",") if x.strip()]


def analyze_function_data_flow(
    disasm_text: str,
    xrefs: List[XrefRecord],
    strings_by_addr: Optional[Dict[int, str]] = None,
) -> Dict[str, Any]:
    strings_by_addr = strings_by_addr or {}
    reg_state: Dict[str, Dict[str, Any]] = {}
    register_flow: List[Dict[str, Any]] = []
    argument_uses: Dict[str, List[str]] = {"rcx": [], "rdx": [], "r8": [], "r9": [], "stack_args": []}
    api_insights: List[Dict[str, Any]] = []
    string_flows: List[Dict[str, Any]] = []

    xref_by_src = {x.src: x for x in (xrefs or []) if x.xref_type in {"import", "call", "string"}}

    for line in (disasm_text or "").splitlines():
        m = _INS_RX.match(line.strip())
        if not m:
            continue
        va = int(m.group(1), 16)
        mnem = m.group(2).lower()
        op = m.group(3).strip()
        ops = _split_ops(op)
        effects = []

        if mnem in {"mov", "lea"} and len(ops) >= 2:
            dst, src = ops[0].lower(), ops[1].lower()
            if re.match(r"^[re]?[abcds][xiph]$|^r\d+$|^r..$", dst):
                val: Dict[str, Any] = {"estimated": True, "source_instruction": f"0x{va:08X}"}
                a = _ADDR_RX.search(src)
                if a:
                    addr = int(a.group(1), 16)
                    val.update({"type": "address", "value": f"0x{addr:08X}"})
                    if addr in strings_by_addr:
                        val.update({"type": "string_address", "string": strings_by_addr[addr]})
                elif src in reg_state:
                    val = dict(reg_state[src])
                    val["estimated"] = True
                else:
                    imm = _IMM_RX.search(src)
                    if imm:
                        val.update({"type": "constant", "value": imm.group(1)})
                    else:
                        val.update({"type": "unknown", "value": src})
                reg_state[dst] = val
                effects.append(f"{dst} <= {val.get('type')}:{val.get('value', val.get('string', '?'))}")

        if "[rbp+" in op.lower() or "[ebp+" in op.lower():
            argument_uses["stack_args"].append(f"0x{va:08X}: {line.strip()}")

        for r in _X64_ARG_REGS:
            if re.search(rf"\b{r}\b", op.lower()):
                argument_uses[r].append(f"0x{va:08X}: {line.strip()}")

        if mnem == "call":
            xr = xref_by_src.get(va)
            api = xr.api if xr and xr.api else None
            if api:
                args = []
                for r in _X64_ARG_REGS:
                    st = reg_state.get(r)
                    if not st:
                        continue
                    args.append({"register": r, "estimated": True, "value_type": st.get("type", "unknown"), "value": st.get("value") or st.get("string")})
                    if st.get("type") == "string_address":
                        string_flows.append({
                            "string": st.get("string"),
                            "via_register": r,
                            "api": api,
                            "call_site": f"0x{va:08X}",
                            "estimated": True,
                        })
                api_insights.append({
                    "call_site": f"0x{va:08X}",
                    "api": api,
                    "arguments": args,
                    "confidence": "high" if args else "low",
                    "evidence": f"Register state observed immediately before API call at 0x{va:08X}.",
                })

        if effects:
            register_flow.append({"address": f"0x{va:08X}", "instruction": line.strip(), "effects": effects})

    high_value = []
    for row in api_insights:
        if row.get("confidence") == "high":
            high_value.append({
                "type": "api_argument_insight",
                "api": row.get("api"),
                "call_site": row.get("call_site"),
                "evidence": row.get("evidence"),
                "estimated": True,
            })
    for row in string_flows:
        high_value.append({
            "type": "string_flow",
            "string": row.get("string"),
            "api": row.get("api"),
            "call_site": row.get("call_site"),
            "estimated": True,
        })

    return {
        "register_flow": register_flow,
        "arguments": argument_uses,
        "api_argument_insights": api_insights,
        "string_flows": string_flows,
        "high_confidence_findings": high_value,
        "heuristic_note": "All inferred values are estimated from static local data flow and may be incomplete.",
    }
