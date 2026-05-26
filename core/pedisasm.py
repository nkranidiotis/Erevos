import pefile
import capstone
import string
import math

# Optional modules
try:
    from core.modules import resources, risk, packer, xrefs, cfg
except ImportError:
    resources = risk = packer = xrefs = cfg = None

try:
    from capstone.x86_const import X86_OP_IMM, X86_OP_REG, X86_OP_MEM
except ImportError:
    X86_OP_IMM = X86_OP_REG = X86_OP_MEM = None

# Opcode first-bytes that are almost certainly jump instructions
_JUMP_FIRST_BYTES = frozenset([
    *range(0x70, 0x80),   # Jcc short (JO..JG)
    0xE2, 0xE3,           # LOOP / JCXZ
    0xEB,                 # JMP rel8
    0xE9,                 # JMP rel32
])


def extract_printable_strings(data, min_len=4):
    """Extract printable ASCII and UTF-16LE strings from binary data."""
    results = []

    # ASCII
    acc = ""
    for b in data:
        ch = chr(b)
        if ch in string.printable and ch not in "\t\n\r\x0b\x0c":
            acc += ch
            continue
        if len(acc) >= min_len:
            results.append(acc)
        acc = ""
    if len(acc) >= min_len:
        results.append(acc)

    # UTF-16LE
    try:
        text = data.decode("utf-16le", errors="ignore")
        acc = ""
        for ch in text:
            if ch in string.printable and ch not in "\t\n\r\x0b\x0c":
                acc += ch
                continue
            if len(acc) >= min_len:
                results.append(acc)
            acc = ""
        if len(acc) >= min_len:
            results.append(acc)
    except Exception:
        pass

    return list(set(results))


def bytes_to_hex(data, base_addr=0):
    """Return formatted hex + ASCII dump for display."""
    out_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out_lines.append(f"{base_addr+i:08X}  {hex_part:<47}  {ascii_part}")
    return "\n".join(out_lines)


def _string_byte_offsets(data: bytes) -> set:
    """Return set of byte offsets that lie inside printable-ASCII runs of ≥4 chars."""
    marked = set()
    start = -1
    run = 0
    for i, b in enumerate(data):
        if chr(b) in string.printable and chr(b) not in '\t\n\r\x0b\x0c':
            if start < 0:
                start = i
            run += 1
        else:
            if run >= 4:
                marked.update(range(start, start + run))
            start = -1; run = 0
    if run >= 4:
        marked.update(range(start, start + run))
    return marked


def _jump_byte_offsets(data: bytes) -> set:
    """Heuristic: return offsets whose leading byte looks like a jump opcode."""
    marked = set()
    for i, b in enumerate(data):
        if b in _JUMP_FIRST_BYTES:
            marked.add(i)
        elif b == 0x0F and i + 1 < len(data) and 0x80 <= data[i + 1] <= 0x8F:
            marked.add(i); marked.add(i + 1)
    return marked


def bytes_to_hex_html(
    data: bytes,
    base_addr: int = 0,
    *,
    show_ascii: bool = True,
    str_offs: set = None,
    api_offs: set = None,
    jmp_offs: set = None,
) -> str:
    """Return an HTML hex dump with optional per-byte highlighting.

    Colour scheme (also shown in the legend on the Hex page):
      green  (#DCFCE7) – printable-string bytes
      amber  (#FEF9C3) – IAT/import pointer bytes
      blue   (#DBEAFE) – jump-opcode bytes
    """
    STR_BG  = '#DCFCE7'
    API_BG  = '#FEF9C3'
    JMP_BG  = '#DBEAFE'
    ADDR_FG = '#6B7280'
    ASC_FG  = '#9CA3AF'

    def _bg(off: int):
        if api_offs and off in api_offs: return API_BG
        if jmp_offs and off in jmp_offs: return JMP_BG
        if str_offs and off in str_offs: return STR_BG
        return None

    lines_html = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        line_parts = [f'<span style="color:{ADDR_FG};">{base_addr + i:08X}</span>  ']

        hex_tokens = []
        asc_tokens = []
        for j, b in enumerate(chunk):
            bg = _bg(i + j)
            hx = f'{b:02X}'
            if bg:
                hex_tokens.append(f'<span style="background-color:{bg};">{hx}</span>')
            else:
                hex_tokens.append(hx)
            if j < len(chunk) - 1:
                hex_tokens.append(' ')

            if show_ascii:
                if 32 <= b < 127:
                    ch = chr(b).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                else:
                    ch = '.'
                if bg:
                    asc_tokens.append(f'<span style="color:{ASC_FG};background-color:{bg};">{ch}</span>')
                else:
                    asc_tokens.append(f'<span style="color:{ASC_FG};">{ch}</span>')

        # Pad hex field to 47 chars for short final lines
        if len(chunk) < 16:
            hex_tokens.append(' ' * (48 - 3 * len(chunk)))

        line_parts.append(''.join(hex_tokens))
        if show_ascii:
            line_parts.append('  ')
            line_parts.append(''.join(asc_tokens))
        lines_html.append(''.join(line_parts))

    body = '\n'.join(lines_html)
    return (
        '<html><body style="font-family:Consolas,monospace; font-size:10pt; '
        'color:#0F172A; background:#FFFFFF;">'
        f'<pre style="margin:0; padding:0;">{body}</pre>'
        '</body></html>'
    )


def calc_entropy(data):
    """Calculate Shannon entropy of given data."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for f in freq:
        if f:
            p = f / len(data)
            entropy -= p * math.log2(p)
    return entropy


class PEDisassembler:
    def __init__(self, path):
        self.path = path
        self.pe = pefile.PE(path, fast_load=False)
        self.arch = self._detect_arch()
        self.md = capstone.Cs(capstone.CS_ARCH_X86,
                              capstone.CS_MODE_64 if self.arch == "x64" else capstone.CS_MODE_32)
        self.md.detail = True
        self.text_section = self._get_text_section()

    def _detect_arch(self):
        if self.pe.FILE_HEADER.Machine == 0x8664:
            return "x64"
        if self.pe.FILE_HEADER.Machine == 0x14c:
            return "x86"
        return "unknown"

    def _get_text_section(self):
        for s in self.pe.sections:
            if s.Name.strip(b"\x00").decode(errors="ignore") == ".text":
                return s
        return None

    def get_entry_point(self):
        return self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_imports(self):
        results = []
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return results
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            for imp in entry.imports:
                if imp.name:
                    results.append(f"{dll}!{imp.name.decode(errors='ignore')}")
        return results

    def get_exports(self):
        results = []
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return results
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode(errors="ignore") if exp.name else f"ord{exp.ordinal}"
            results.append(name)
        return results

    def get_strings(self, min_len=4):
        data = self.pe.get_memory_mapped_image()
        return extract_printable_strings(data, min_len)

    def find_functions(self):
        """Heuristic function discovery: exports + prologues + entrypoint."""
        funcs = {}

        # Exports
        for e in self.get_exports():
            funcs[e] = 0

        # Entry point
        funcs["entry"] = self.get_entry_point()

        # Simple prologue scan
        if self.text_section:
            data = self.text_section.get_data()
            va = self.pe.OPTIONAL_HEADER.ImageBase + self.text_section.VirtualAddress
            for i in range(len(data)-2):
                if data[i] == 0x55 and data[i+1] == 0x8B and data[i+2] == 0xEC:
                    funcs[f"sub_{va+i:08X}"] = va+i

        return funcs

    def disasm_at(self, va, size=0x200):
        """Disassemble at VA, up to size bytes."""
        file_offset = self.pe.get_offset_from_rva(va - self.pe.OPTIONAL_HEADER.ImageBase)
        self.pe.__data__.seek(file_offset)
        data = self.pe.__data__.read(size)
        lines = []
        for ins in self.md.disasm(data, va):
            lines.append(f"0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}")
        return "\n".join(lines)

    def hexdump_at(self, va, size=0x100):
        file_offset = self.pe.get_offset_from_rva(va - self.pe.OPTIONAL_HEADER.ImageBase)
        self.pe.__data__.seek(file_offset)
        data = self.pe.__data__.read(size)
        return bytes_to_hex(data, va)

    def _build_import_map(self) -> dict:
        """Lazily build a VA→'dll!symbol' map from the IAT."""
        if not hasattr(self, '_import_map'):
            m = {}
            try:
                if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        dll = entry.dll.decode(errors='ignore')
                        for imp in entry.imports:
                            addr = getattr(imp, 'address', None)
                            if imp.name and addr:
                                m[addr] = f"{dll}!{imp.name.decode(errors='ignore')}"
            except Exception:
                pass
            self._import_map = m
        return self._import_map

    def _iat_byte_offsets(self, base_va: int, size: int) -> set:
        """Return set of byte offsets (relative to base_va) occupied by IAT pointer slots."""
        ptr_sz = 8 if self.arch == 'x64' else 4
        offs = set()
        for iat_va in self._build_import_map():
            off = iat_va - base_va
            if 0 <= off < size:
                offs.update(range(off, off + ptr_sz))
        return offs

    def decode_at(self, va: int) -> dict:
        """Disassemble one instruction at VA and return a decoded info dict.

        Keys: type, target, symbol, description, bytes
        """
        result = {'type': '—', 'target': '—', 'symbol': '—', 'description': '—', 'bytes': '—'}
        try:
            rva = va - self.pe.OPTIONAL_HEADER.ImageBase
            file_offset = self.pe.get_offset_from_rva(rva)
            self.pe.__data__.seek(file_offset)
            raw = self.pe.__data__.read(16)
            result['bytes'] = ' '.join(f'{b:02X}' for b in raw[:4]) + '…'

            insns = list(self.md.disasm(raw, va))
            if not insns:
                result['type'] = 'Data'
                result['description'] = 'No instruction decoded — may be a data region.'
                return result

            ins = insns[0]
            result['bytes'] = ' '.join(f'{b:02X}' for b in ins.bytes)
            mnem = ins.mnemonic.lower()

            if mnem == 'call':
                result['type'] = 'Call'
            elif mnem in ('ret', 'retn', 'retf'):
                result['type'] = 'Return'
            elif mnem == 'jmp':
                result['type'] = 'Jump'
            elif mnem and mnem[0] == 'j':
                result['type'] = 'Branch'
            elif mnem in ('mov', 'movsx', 'movzx', 'movd', 'movq', 'movsxd'):
                result['type'] = 'Data Move'
            elif mnem == 'lea':
                result['type'] = 'LEA'
            elif mnem in ('push', 'pop', 'pushad', 'popad', 'pushfd', 'popfd'):
                result['type'] = 'Stack'
            elif mnem in ('add', 'sub', 'mul', 'imul', 'div', 'idiv', 'inc', 'dec', 'neg'):
                result['type'] = 'Arithmetic'
            elif mnem in ('and', 'or', 'xor', 'not', 'shl', 'shr', 'sar', 'rol', 'ror'):
                result['type'] = 'Bitwise'
            elif mnem in ('cmp', 'test'):
                result['type'] = 'Comparison'
            elif mnem in ('int', 'syscall', 'sysenter'):
                result['type'] = 'System Call'
            elif mnem == 'nop':
                result['type'] = 'NOP'
            else:
                result['type'] = ins.mnemonic.upper()

            # Extract branch / call target
            if X86_OP_IMM is not None:
                try:
                    for op in ins.operands:
                        if op.type == X86_OP_IMM:
                            tgt = op.imm
                            result['target'] = f'0x{tgt:08X}'
                            sym = self._build_import_map().get(tgt)
                            if sym:
                                result['symbol'] = sym
                            break
                        if op.type == X86_OP_MEM:
                            disp = op.mem.disp
                            if disp and op.mem.base == 0 and op.mem.index == 0:
                                result['target'] = f'[0x{disp:08X}]'
                                sym = self._build_import_map().get(disp)
                                if sym:
                                    result['symbol'] = sym
                            break
                except Exception:
                    pass

            t   = result['type']
            tgt = result['target']
            sym = result['symbol']
            suf = f' ({sym})' if sym != '—' else ''
            if   t == 'Call':       result['description'] = f'Call to {tgt}{suf}'
            elif t == 'Return':     result['description'] = 'Return from current procedure'
            elif t == 'Jump':       result['description'] = f'Unconditional jump → {tgt}'
            elif t == 'Branch':     result['description'] = f'Conditional branch ({ins.mnemonic}) → {tgt}'
            elif t == 'Data Move':  result['description'] = f'Move: {ins.op_str}'
            elif t == 'LEA':        result['description'] = f'Load effective address: {ins.op_str}'
            elif t == 'Stack':      result['description'] = f'{"Push" if "push" in mnem else "Pop"}: {ins.op_str}'
            elif t == 'Arithmetic': result['description'] = f'{ins.mnemonic.upper()} {ins.op_str}'
            elif t == 'Bitwise':    result['description'] = f'{ins.mnemonic.upper()} {ins.op_str}'
            elif t == 'Comparison': result['description'] = f'Compare: {ins.op_str}'
            elif t == 'System Call':result['description'] = 'System call / software interrupt'
            elif t == 'NOP':        result['description'] = 'No operation — padding or alignment'
            else:                   result['description'] = f'{ins.mnemonic} {ins.op_str}'

        except Exception as e:
            result['description'] = f'Could not decode: {e}'
        return result

    def hexdump_at_html(self, va: int, size: int = 0x100, opts: dict = None) -> str:
        """HTML hex dump of size bytes starting at VA, with highlighting per opts dict."""
        if opts is None:
            opts = {}
        file_offset = self.pe.get_offset_from_rva(va - self.pe.OPTIONAL_HEADER.ImageBase)
        self.pe.__data__.seek(file_offset)
        data = self.pe.__data__.read(size)

        str_offs = _string_byte_offsets(data)   if opts.get('highlight_strings') else None
        api_offs = self._iat_byte_offsets(va, size) if opts.get('highlight_apis')    else None
        jmp_offs = _jump_byte_offsets(data)     if opts.get('highlight_jumps')   else None

        return bytes_to_hex_html(
            data, va,
            show_ascii=opts.get('show_ascii', True),
            str_offs=str_offs,
            api_offs=api_offs,
            jmp_offs=jmp_offs,
        )

    # --- Integration with optional modules ---
    def analyze_resources(self):
        if resources:
            return resources.summarize_resources(self.pe)
        return {}

    def analyze_risk(self):
        if risk:
            return risk.analyze_file(self.path)
        return {}

    def analyze_packer(self):
        if packer:
            return packer.analyze_file(self.path)
        return {}

    def analyze_xrefs(self):
        if xrefs:
            return xrefs.analyze_file(self.path)
        return {}

    def analyze_cfg(self, va=None):
        if cfg and va:
            return cfg.build_cfg(self.path, va)
        return {}
