from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

_INS_RX = re.compile(r"^0x([0-9A-Fa-f]{6,16}):\s+([a-z][a-z0-9]*)\s*(.*)$")
_ADDR_RX = re.compile(r"0x([0-9A-Fa-f]{6,16})")
_COND_JMPS = {
    "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle", "jna", "jne", "jno", "jnp", "jns",
    "jo", "jp", "jpe", "jpo", "js", "jz", "jnz"
}


def _parse_instructions(disasm_text: str) -> List[Tuple[int, str, str, str]]:
    ins = []
    for line in (disasm_text or "").splitlines():
        m = _INS_RX.match(line.strip())
        if not m:
            continue
        va = int(m.group(1), 16)
        mnem = m.group(2).lower()
        op = m.group(3).strip()
        ins.append((va, mnem, op, line.strip()))
    return ins


def build_function_cfg_model(disasm_text: str, function_start: Optional[int] = None) -> Dict[str, Any]:
    ins = _parse_instructions(disasm_text)
    if not ins:
        return {"function_start": f"0x{(function_start or 0):08X}", "basic_blocks": [], "edges": []}

    addr_to_idx = {va: i for i, (va, _, _, _) in enumerate(ins)}
    leaders = {ins[0][0]}

    for i, (va, mnem, op, _) in enumerate(ins):
        tgt_match = _ADDR_RX.search(op)
        tgt = int(tgt_match.group(1), 16) if tgt_match else None
        next_va = ins[i + 1][0] if i + 1 < len(ins) else None

        if mnem == "jmp":
            if tgt in addr_to_idx:
                leaders.add(tgt)
            if next_va is not None:
                leaders.add(next_va)
        elif mnem in _COND_JMPS:
            if tgt in addr_to_idx:
                leaders.add(tgt)
            if next_va is not None:
                leaders.add(next_va)
        elif mnem.startswith("ret") and next_va is not None:
            leaders.add(next_va)

    leaders_sorted = sorted(leaders)
    blocks = []
    leader_set = set(leaders_sorted)
    i = 0
    while i < len(ins):
        start = ins[i][0]
        if start not in leader_set:
            i += 1
            continue
        j = i
        while j + 1 < len(ins) and ins[j + 1][0] not in leader_set:
            j += 1
        block_ins = ins[i:j + 1]
        blocks.append(
            {
                "id": len(blocks),
                "start": f"0x{block_ins[0][0]:08X}",
                "end": f"0x{block_ins[-1][0]:08X}",
                "instructions": [ln for _, _, _, ln in block_ins],
                "incoming_edges": [],
                "outgoing_edges": [],
                "suspicious": False,
            }
        )
        i = j + 1

    block_by_start = {int(b["start"], 16): b for b in blocks}
    block_index_order = [int(b["start"], 16) for b in blocks]

    edges = []
    for idx, b in enumerate(blocks):
        last = b["instructions"][-1]
        m = _INS_RX.match(last)
        if not m:
            continue
        src = int(b["start"], 16)
        mnem = m.group(2).lower()
        op = m.group(3).strip()
        tgt_match = _ADDR_RX.search(op)
        tgt = int(tgt_match.group(1), 16) if tgt_match else None
        next_start = block_index_order[idx + 1] if idx + 1 < len(block_index_order) else None

        def add_edge(dst: Optional[int], edge_type: str):
            row = {
                "src": f"0x{src:08X}",
                "dst": f"0x{dst:08X}" if isinstance(dst, int) else "<unresolved>",
                "edge_type": edge_type,
                "suspicious": edge_type == "unresolved",
            }
            edges.append(row)
            b["outgoing_edges"].append(row)
            if isinstance(dst, int) and dst in block_by_start:
                block_by_start[dst]["incoming_edges"].append(row)
            elif edge_type == "unresolved":
                b["suspicious"] = True

        if mnem.startswith("ret"):
            add_edge(None, "return")
        elif mnem == "jmp":
            if isinstance(tgt, int) and tgt in block_by_start:
                add_edge(tgt, "unconditional_jump")
            else:
                add_edge(None, "unresolved")
        elif mnem in _COND_JMPS:
            if isinstance(tgt, int) and tgt in block_by_start:
                add_edge(tgt, "conditional_true")
            else:
                add_edge(None, "unresolved")
            if isinstance(next_start, int):
                add_edge(next_start, "conditional_false")
            else:
                add_edge(None, "unresolved")
        else:
            if isinstance(next_start, int):
                add_edge(next_start, "fallthrough")

    return {
        "function_start": f"0x{(function_start or ins[0][0]):08X}",
        "basic_blocks": blocks,
        "edges": edges,
    }


def analyze_function_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    blocks = cfg.get("basic_blocks") or []
    edges = cfg.get("edges") or []
    if not blocks:
        return {
            "basic_block_count": 0,
            "branch_count": 0,
            "loop_back_edge_hints": [],
            "unreachable_block_hints": [],
            "suspicious_control_flow_indicators": [],
            "possible_opaque_predicate_hints": [],
            "abnormal_high_branch_density": False,
            "unresolved_edge_count": 0,
        }

    branch_count = sum(1 for e in edges if e.get("edge_type") in {"conditional_true", "conditional_false", "unconditional_jump"})
    unresolved = [e for e in edges if e.get("edge_type") == "unresolved"]

    back_edges = []
    for e in edges:
        src = e.get("src")
        dst = e.get("dst")
        if isinstance(src, str) and isinstance(dst, str) and dst.startswith("0x") and src.startswith("0x"):
            if int(dst, 16) <= int(src, 16):
                back_edges.append(e)

    addr_blocks = {b["start"]: b for b in blocks}
    reachable = set()
    entry = blocks[0]["start"]
    dq = deque([entry])
    reachable.add(entry)
    out_adj = defaultdict(list)
    for e in edges:
        if isinstance(e.get("dst"), str) and e["dst"].startswith("0x"):
            out_adj[e["src"]].append(e["dst"])
    while dq:
        cur = dq.popleft()
        for nxt in out_adj.get(cur, []):
            if nxt in addr_blocks and nxt not in reachable:
                reachable.add(nxt)
                dq.append(nxt)

    unreachable = [b["start"] for b in blocks if b["start"] not in reachable]

    opaque_hints = []
    grouped = defaultdict(list)
    for e in edges:
        if e.get("edge_type") in {"conditional_true", "conditional_false"}:
            grouped[e["src"]].append(e)
    for src, rows in grouped.items():
        dsts = {r.get("dst") for r in rows}
        if len(rows) >= 2 and len(dsts) == 1:
            opaque_hints.append({"block": src, "reason": "both conditional branches converge to same destination (possible opaque predicate)"})

    density = branch_count / max(1, len(blocks))
    high_density = density >= 1.2

    indicators = []
    if unresolved:
        indicators.append("unresolved_edges_present")
    if back_edges:
        indicators.append("loop_back_edges_present")
    if high_density:
        indicators.append("abnormal_high_branch_density")
    if unreachable:
        indicators.append("unreachable_blocks_present")

    return {
        "basic_block_count": len(blocks),
        "branch_count": branch_count,
        "loop_back_edge_hints": [{"src": e["src"], "dst": e["dst"]} for e in back_edges[:20]],
        "unreachable_block_hints": unreachable[:20],
        "suspicious_control_flow_indicators": indicators,
        "possible_opaque_predicate_hints": opaque_hints[:20],
        "abnormal_high_branch_density": high_density,
        "branch_density": round(density, 3),
        "unresolved_edge_count": len(unresolved),
    }
