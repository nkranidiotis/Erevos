"""
Erevos Module 5 — cfg.py (standalone)

Builds a *per‑function* Control Flow Graph (CFG) for x86/x64 PE binaries.
Pure Python using capstone + pefile. No graph libs required.

What it does
  • Disassembles from a given function start VA
  • Detects basic blocks (leaders, terminators)
  • Resolves branch targets (IMM + RIP‑relative)
  • Builds edges (conditional, fall‑through, jmp)
  • Computes metrics: instruction count, blocks, edges, cyclomatic complexity
  • Optionally emits Graphviz DOT string

CLI
    python cfg.py <path_to_pe> --start 0x401000 [--max-ins 4000] [--dot]

Programmatic
    from cfg import build_cfg
    g = build_cfg(pe_path, start_va)

Output structure
    {
      "function_start": "0x...",
      "nodes": [{"id": 0, "start": "0x...", "end": "0x..."}, ...],
      "edges": [{"src": 0, "dst": 1, "type": "fall|cond_true|cond_false|jmp"}, ...],
      "metrics": {"insns": N, "blocks": B, "edges": E, "cyclomatic": C}
    }
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional, Iterable, Set
import sys
import json

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import *

# ----------------- helpers: PE / disasm -----------------

def _get_text_section(pe: pefile.PE):
    for s in pe.sections:
        if s.Name.rstrip(b"\x00").decode(errors="ignore") == ".text":
            return s
    for s in pe.sections:
        if s.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            return s
    return None


def _make_md(pe: pefile.PE) -> Cs:
    if pe.FILE_HEADER.Machine == 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def _rip_target(ins) -> Optional[int]:
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
            return ins.address + ins.size + op.value.mem.disp
    return None

# ----------------- basic block detection -----------------
@dataclass
class Block:
    id: int
    start: int
    end: int  # end is *last instruction address + size*


def _is_term_uncond(ins) -> bool:
    return ins.id in (X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ, X86_INS_JMP, X86_INS_IRET, X86_INS_IRETD, X86_INS_IRETQ, X86_INS_HLT)


def _is_cond_jump(ins) -> bool:
    return ins.group(X86_GRP_JUMP) and ins.id != X86_INS_JMP


def _branch_target(ins, md_mode) -> Optional[int]:
    # Direct immediates
    for op in ins.operands:
        if op.type == X86_OP_IMM:
            return op.value.imm
        if md_mode == CS_MODE_64 and op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
            return ins.address + ins.size + op.value.mem.disp
    return None


@dataclass
class CFG:
    start_va: int
    nodes: List[Block]
    edges: List[Tuple[int,int,str]]  # (src_id, dst_id, type)
    insn_count: int

    def to_json(self) -> Dict:
        return {
            "function_start": f"0x{self.start_va:08X}",
            "nodes": [{"id": b.id, "start": f"0x{b.start:08X}", "end": f"0x{b.end:08X}"} for b in self.nodes],
            "edges": [{"src": s, "dst": d, "type": t} for (s,d,t) in self.edges],
            "metrics": {
                "insns": self.insn_count,
                "blocks": len(self.nodes),
                "edges": len(self.edges),
                "cyclomatic": max(1, len(self.edges) - len(self.nodes) + 1),
            }
        }

    def to_dot(self) -> str:
        lines = ["digraph CFG {"]
        for b in self.nodes:
            label = f"{b.id}\\n0x{b.start:08X}-0x{b.end:08X}"
            lines.append(f"  n{b.id} [shape=box,label=\"{label}\"];")
        for s,d,t in self.edges:
            color = {
                'fall':'black', 'jmp':'blue', 'cond_true':'green', 'cond_false':'red'
            }.get(t,'black')
            lines.append(f"  n{s} -> n{d} [color={color},label=\"{t}\"];")
        lines.append("}")
        return "\n".join(lines)


# ----------------- core CFG builder -----------------

def build_cfg(pe_path: str, start_va: int, max_instructions: int = 4000) -> CFG:
    pe = pefile.PE(pe_path, fast_load=True)
    text = _get_text_section(pe)
    if not text:
        return CFG(start_va, [], [], 0)
    base = pe.OPTIONAL_HEADER.ImageBase
    text_start = base + text.VirtualAddress
    code = text.get_data() or b""
    text_end = text_start + len(code)

    md = _make_md(pe)

    # Single pass disasm from function start, bounded by .text and max_ins
    # Collect instructions and discover leaders
    leaders: Set[int] = set([start_va])
    insns: Dict[int, object] = {}
    order: List[int] = []  # addresses in disassembly order

    # naive linear traversal with queue of pending addresses to visit
    work: List[int] = [start_va]
    visited: Set[int] = set()

    def in_text(addr: int) -> bool:
        return text_start <= addr < text_end

    # decode from an address until a terminator; branch targets added to work
    while work and len(order) < max_instructions:
        cur = work.pop(0)
        if cur in visited or not in_text(cur):
            continue
        visited.add(cur)

        # compute local offset in code
        off = cur - text_start
        if off < 0 or off >= len(code):
            continue

        # disasm forward until term or out-of-range
        for ins in md.disasm(code[off:], cur):
            addr = ins.address
            if addr in insns:  # already decoded this instruction
                break
            insns[addr] = ins
            order.append(addr)
            if len(order) >= max_instructions:
                break

            if _is_cond_jump(ins):
                tgt = _branch_target(ins, md.mode)
                if tgt and in_text(tgt):
                    leaders.add(tgt)
                    work.append(tgt)
                # fall-through leader is next instruction
                leaders.add(addr + ins.size)
                work.append(addr + ins.size)
                break  # end of block

            elif _is_term_uncond(ins):
                if ins.id == X86_INS_JMP:
                    tgt = _branch_target(ins, md.mode)
                    if tgt and in_text(tgt):
                        leaders.add(tgt)
                        work.append(tgt)
                break  # block ends

            else:
                # regular instruction; if RET, handled above; CALL does not end block
                pass
        # loop continues for next work item

    # If nothing decoded, return empty graph
    if not order:
        return CFG(start_va, [], [], 0)

    # Build basic blocks from leaders and instruction stream
    leaders = set(a for a in leaders if a in insns)  # keep only decoded
    sorted_addrs = sorted(insns.keys())

    # mark block starts
    block_starts = sorted(leaders)
    # ensure we start at function start and cover trailing bytes
    if start_va not in block_starts and start_va in insns:
        block_starts.insert(0, start_va)

    # build blocks by slicing until next leader or terminator
    blocks: List[Block] = []
    addr_to_block: Dict[int, int] = {}

    i = 0
    while i < len(sorted_addrs):
        a = sorted_addrs[i]
        if a not in leaders and not blocks:
            # skip prelude if decoding started earlier
            i += 1
            continue
        # start a new block at 'a' if it's a leader or start of function
        if a in leaders:
            bstart = a
            j = i
            # advance until next leader or terminator
            while j < len(sorted_addrs):
                cur_addr = sorted_addrs[j]
                ins = insns[cur_addr]
                j += 1
                if _is_cond_jump(ins) or _is_term_uncond(ins) or (j < len(sorted_addrs) and sorted_addrs[j] in leaders):
                    bend = cur_addr + ins.size
                    break
            else:
                bend = sorted_addrs[-1] + insns[sorted_addrs[-1]].size
            bid = len(blocks)
            blocks.append(Block(bid, bstart, bend))
            # map addresses in [bstart, bend) to this block id
            k = i
            while k < len(sorted_addrs) and sorted_addrs[k] < bend:
                addr_to_block[sorted_addrs[k]] = bid
                k += 1
            i = j
        else:
            i += 1

    # Build edges
    edges: List[Tuple[int,int,str]] = []
    for b in blocks:
        # last instruction in block
        last_addr = max(a for a in addr_to_block if b.start <= a < b.end)
        ins = insns[last_addr]
        if _is_cond_jump(ins):
            tgt = _branch_target(ins, md.mode)
            if tgt in addr_to_block:
                edges.append((b.id, addr_to_block[tgt], 'cond_true'))
            # fall-through
            fall = last_addr + ins.size
            if fall in addr_to_block:
                edges.append((b.id, addr_to_block[fall], 'cond_false'))
        elif ins.id == X86_INS_JMP:
            tgt = _branch_target(ins, md.mode)
            if tgt in addr_to_block:
                edges.append((b.id, addr_to_block[tgt], 'jmp'))
        elif not _is_term_uncond(ins):
            # fall-through to next sequential block if contiguous
            fall = last_addr + ins.size
            if fall in addr_to_block:
                edges.append((b.id, addr_to_block[fall], 'fall'))

    # Deduplicate edges
    seen = set()
    dedup_edges: List[Tuple[int,int,str]] = []
    for e in edges:
        if e not in seen:
            dedup_edges.append(e)
            seen.add(e)

    return CFG(start_va, blocks, dedup_edges, insn_count=len(insns))


# ----------------- CLI -----------------
if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[1] in ('-h','--help'):
        print('Usage: python cfg.py <path_to_pe> --start 0xADDRESS [--max-ins 4000] [--dot]')
        sys.exit(1)
    pe_path = sys.argv[1]
    start_va = None
    max_ins = 4000
    want_dot = False
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == '--start' and i+1 < len(args):
            sv = args[i+1]
            start_va = int(sv, 16) if sv.lower().startswith('0x') else int(sv)
            i += 2
            continue
        if args[i] == '--max-ins' and i+1 < len(args):
            max_ins = int(args[i+1]); i += 2; continue
        if args[i] == '--dot':
            want_dot = True; i += 1; continue
        i += 1

    if start_va is None:
        print('Error: --start 0xADDRESS is required')
        sys.exit(1)

    g = build_cfg(pe_path, start_va, max_instructions=max_ins)
    out = g.to_json()
    print(json.dumps(out, indent=2))
    if want_dot:
        print('\n/* DOT */')
        print(g.to_dot())
