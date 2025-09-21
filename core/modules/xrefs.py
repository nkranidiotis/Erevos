"""
Erevos Module 1 — strings ↔ code cross-references (standalone)

Pure-Python helper functions to:
  - extract ASCII & UTF-16LE strings *with locations* (file offset, RVA, VA)
  - find code references (xrefs) to a given data VA in .text
    • handles immediates (push/mov) and RIP-relative addressing on x64

Dependencies: pefile, capstone
Usage (CLI): python xrefs.py <path_to_pe> --min-len 4 --limit 50
Outputs JSON summary to stdout.
"""
from __future__ import annotations
import re
import sys
import json
from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Iterable, Optional

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import *  # for operand types/regs


# ---------------------------- Data models ----------------------------
@dataclass
class StringHit:
    text: str
    file_off: int
    rva: int
    va: int
    encoding: str  # 'ascii' or 'utf16le'

@dataclass
class XrefHit:
    instr_va: int
    mnemonic: str
    op_str: str


# ---------------------------- Utilities ----------------------------
def _section_for_file_off(pe: pefile.PE, off: int) -> Optional[pefile.SectionStructure]:
    for sec in pe.sections:
        start = sec.PointerToRawData
        size = sec.SizeOfRawData
        if start <= off < start + size:
            return sec
    return None


def _iter_ascii_hits(data: bytes, min_len: int) -> Iterable[Tuple[int, bytes]]:
    pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
    for m in pattern.finditer(data):
        yield m.start(), m.group()


def _iter_utf16le_hits(data: bytes, min_len: int) -> Iterable[Tuple[int, bytes]]:
    # Printable chars separated by 0x00 bytes
    pattern = re.compile((rb"(?:[\x20-\x7E]\x00){%d,}" % min_len))
    for m in pattern.finditer(data):
        yield m.start(), m.group()


def extract_strings_with_locations(pe: pefile.PE, min_len: int = 4, limit: Optional[int] = None) -> List[StringHit]:
    """Extract ASCII & UTF-16LE strings *with* file offset, RVA, VA.
    `limit` caps results for speed (None = no cap).
    """
    data = pe.__data__
    base = pe.OPTIONAL_HEADER.ImageBase
    out: List[StringHit] = []

    def push_hit(raw_off: int, raw_bytes: bytes, enc: str):
        sec = _section_for_file_off(pe, raw_off)
        if not sec:
            return
        rva = sec.VirtualAddress + (raw_off - sec.PointerToRawData)
        va = base + rva
        try:
            txt = raw_bytes.decode("utf-16le" if enc == "utf16le" else "ascii", errors="ignore")
        except Exception:
            return
        out.append(StringHit(txt, raw_off, rva, va, enc))

    for off, b in _iter_ascii_hits(data, min_len):
        push_hit(off, b, "ascii")
        if limit and len(out) >= limit:
            break

    if not limit or len(out) < limit:
        for off, b in _iter_utf16le_hits(data, min_len):
            push_hit(off, b, "utf16le")
            if limit and len(out) >= limit:
                break

    return out


# ---------------------------- Disassembly helpers ----------------------------
@dataclass
class _DisasmCtx:
    md: Cs
    text_bytes: bytes
    text_va: int


def _make_disasm_ctx(pe: pefile.PE) -> Optional[_DisasmCtx]:
    # Find .text (or first executable) and set up capstone
    text_sec = None
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="ignore")
        if name == ".text":
            text_sec = s
            break
    if text_sec is None:
        for s in pe.sections:
            if s.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                text_sec = s
                break
    if text_sec is None:
        return None

    base = pe.OPTIONAL_HEADER.ImageBase
    text_va = base + text_sec.VirtualAddress
    text_bytes = text_sec.get_data() or b""

    arch = pe.FILE_HEADER.Machine
    if arch == 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return _DisasmCtx(md=md, text_bytes=text_bytes, text_va=text_va)


# ---------------------------- Xref engine ----------------------------
def find_data_xrefs_to_va(pe: pefile.PE, target_va: int) -> List[XrefHit]:
    """Return instructions in .text that reference target_va.
    Handles:
      - immediate operands equal to target_va (push/mov/cmp/etc.)
      - RIP-relative memory operands (x64): target = ins.address + ins.size + disp
    """
    ctx = _make_disasm_ctx(pe)
    if ctx is None:
        return []

    hits: List[XrefHit] = []
    md, text_bytes, text_va = ctx.md, ctx.text_bytes, ctx.text_va

    for ins in md.disasm(text_bytes, text_va):
        try:
            # 1) Direct immediates
            for op in ins.operands:
                if op.type == X86_OP_IMM and op.value.imm == target_va:
                    hits.append(XrefHit(ins.address, ins.mnemonic, ins.op_str))
                    raise StopIteration  # found in this ins; skip further checks

            # 2) RIP-relative memory operands (x64)
            if md.mode == CS_MODE_64:
                for op in ins.operands:
                    if op.type == X86_OP_MEM and op.value.mem.base == X86_REG_RIP:
                        disp = op.value.mem.disp
                        # Effective address calculation for RIP-relative: next_ip + disp
                        ea = ins.address + ins.size + disp
                        if ea == target_va:
                            hits.append(XrefHit(ins.address, ins.mnemonic, ins.op_str))
                            raise StopIteration
        except StopIteration:
            pass
        except Exception:
            # Be permissive; continue
            pass

    # Deduplicate
    seen = set()
    uniq: List[XrefHit] = []
    for h in hits:
        k = (h.instr_va, h.mnemonic, h.op_str)
        if k not in seen:
            uniq.append(h)
            seen.add(k)
    return uniq


# ---------------------------- CLI ----------------------------
def _summarize(pe_path: str, min_len: int = 4, limit: int = 200) -> Dict:
    pe = pefile.PE(pe_path, fast_load=True)
    strings = extract_strings_with_locations(pe, min_len=min_len, limit=limit)

    # For demo: compute xrefs for the first N strings that are inside a mapped section
    demo_count = min(10, len(strings))
    demo = []
    for sh in strings[:demo_count]:
        xrefs = find_data_xrefs_to_va(pe, sh.va)
        demo.append({
            "string": sh.text[:200],
            "va": f"0x{sh.va:08X}",
            "encoding": sh.encoding,
            "xrefs": [
                {"at": f"0x{xh.instr_va:08X}", "ins": f"{xh.mnemonic} {xh.op_str}"}
                for xh in xrefs
            ]
        })

    return {
        "file": pe_path,
        "image_base": f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}",
        "strings_total": len(strings),
        "demo_first_strings_with_xrefs": demo,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python xrefs.py <pe_path> [--min-len 4] [--limit 200]")
        sys.exit(1)
    path = sys.argv[1]
    min_len = 4
    limit = 200
    for i, arg in enumerate(sys.argv[2:], start=2):
        if arg == "--min-len" and i + 1 < len(sys.argv):
            min_len = int(sys.argv[i + 1])
        if arg == "--limit" and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])
    result = _summarize(path, min_len=min_len, limit=limit)
    print(json.dumps(result, indent=2, ensure_ascii=False))
