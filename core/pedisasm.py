import pefile
import capstone
import string
import math

# Optional modules
try:
    from core.modules import resources, risk, packer, xrefs, cfg
except ImportError:
    resources = risk = packer = xrefs = cfg = None


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
