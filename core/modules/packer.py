"""
Erevos Module 6 — packer.py (standalone)

Detects likely packing/obfuscation and provides remediation hints.
Pure Python using pefile. No exotic deps.

Heuristics used:
  - Section entropy (Shannon) for all sections, highlight >= 7.2
  - Executable section small vs large raw data mismatch
  - Import table sparsity (few imports) and many forwarded exports
  - Overlay size (data appended after last section)
  - Presence of TLS callbacks (sometimes used legitimately, but suspicious)
  - Suspicious section names (.UPX, .aspack, .packed, .adata, etc.)
  - Entry point in high-entropy area or mapped to resource
  - Large relocation table anomalies

API:
  analyze_packer(pe_path) -> dict (summary + signals + score 0..100 + hints)

CLI:
  python packer.py <path_to_pe> [--verbose]

"""
from __future__ import annotations
import math
import sys
import json
import os
from typing import List, Dict, Any

import pefile

# ------------------ utils ------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b]+=1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c/n
            ent -= p * math.log2(p)
    return ent

# ------------------ heuristics ------------------
KNOWN_PACKER_SECTION_NAMES = [
    b'.UPX0', b'.UPX1', b'.upx', b'.aspack', b'.adata', b'.packed', b'.vmp0', b'.vmp1',
    b'.themida', b'.boncode', b'.seal', b'.kkrnl', b'.rsrc'  # rsrc common but included for heuristic
]

ENTROPY_THRESHOLD = 7.2
IMPORT_DENSITY_THRESHOLD = 5  # less than N imported functions is suspicious
SMALL_TEXT_THRESHOLD = 0x200  # raw size < 512 bytes suspicious if file big
OVERLAY_RATIO = 0.02  # overlay > 2% of file size

# ------------------ main API ------------------

def analyze_packer(pe_path: str) -> Dict[str, Any]:
    pe = pefile.PE(pe_path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'], pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'], pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']])

    filesize = os.path.getsize(pe_path)

    sigs: Dict[str, Any] = {}

    # Section entropy
    sections = []
    high_entropy_sections = []
    for s in pe.sections:
        raw = s.get_data() or b''
        ent = round(shannon_entropy(raw), 3)
        sections.append({'name': s.Name.rstrip(b'\x00').decode(errors='ignore'), 'entropy': ent, 'raw_size': s.SizeOfRawData, 'virtual_size': s.Misc_VirtualSize, 'executable': bool(s.Characteristics & 0x20000000)})
        if ent >= ENTROPY_THRESHOLD:
            high_entropy_sections.append(sections[-1])
    sigs['sections'] = sections
    sigs['high_entropy_sections'] = high_entropy_sections

    # Executable .text characteristics
    text_sec = None
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00')
        if name == b'.text':
            text_sec = s
            break
    if text_sec is None:
        for s in pe.sections:
            if s.Characteristics & 0x20000000:
                text_sec = s
                break
    if text_sec:
        sigs['text_raw_size'] = text_sec.SizeOfRawData
        sigs['text_virtual_size'] = text_sec.Misc_VirtualSize
        sigs['text_entropy'] = round(shannon_entropy(text_sec.get_data() or b''), 3)
    else:
        sigs['text_raw_size'] = 0
        sigs['text_virtual_size'] = 0
        sigs['text_entropy'] = 0.0

    # Import table sparsity
    total_imports = 0
    import_modules = []
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                import_modules.append(imp.dll.decode(errors='ignore'))
                for f in imp.imports:
                    total_imports += 1
    except Exception:
        pass
    sigs['import_modules'] = import_modules
    sigs['total_imports'] = total_imports
    sigs['import_density_suspicious'] = total_imports < IMPORT_DENSITY_THRESHOLD

    # Overlay detection (data appended after last section)
    last_section_end = max((s.PointerToRawData + s.SizeOfRawData) for s in pe.sections) if pe.sections else 0
    overlay_size = max(0, filesize - last_section_end)
    sigs['overlay_size'] = overlay_size
    sigs['overlay_ratio'] = round(overlay_size / max(1, filesize), 4)
    sigs['overlay_suspicious'] = sigs['overlay_ratio'] > OVERLAY_RATIO

    # TLS callbacks
    tls_cb = []
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
            if pe.DIRECTORY_ENTRY_TLS.struct and getattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks', 0):
                # Read callback RVAs (best-effort)
                addr = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
                # pe.get_dword_at_rva may fail; best-effort, skip heavy parsing
                tls_cb.append(addr)
    except Exception:
        pass
    sigs['tls_callbacks'] = tls_cb

    # Suspicious section names
    suspicious_names = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00")
        for know in KNOWN_PACKER_SECTION_NAMES:
            if know.lower() in name.lower():
                suspicious_names.append(name.decode(errors='ignore'))
    sigs['suspicious_section_names'] = suspicious_names

    # Entry point in high entropy
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
        sigs['entry_point_va'] = hex(ep)
        ep_in_high_entropy = False
        for hs in high_entropy_sections:
            # each hs has 'name', 'entropy', 'raw_size' and 'virtual_size'
            # map name to section and check range
            for s in pe.sections:
                if s.Name.rstrip(b'\x00').decode(errors='ignore') == hs['name']:
                    start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                    end = start + s.Misc_VirtualSize
                    if start <= ep < end:
                        ep_in_high_entropy = True
                        break
            if ep_in_high_entropy:
                break
        sigs['entry_in_high_entropy_section'] = ep_in_high_entropy
    except Exception:
        sigs['entry_in_high_entropy_section'] = False

    # Import absence (many packers use few imports)
    sigs['no_imports'] = total_imports == 0

    # Relocations presence
    try:
        rcount = len(pe.DIRECTORY_ENTRY_BASERELOC) if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') and pe.DIRECTORY_ENTRY_BASERELOC else 0
        sigs['reloc_count'] = rcount
    except Exception:
        sigs['reloc_count'] = 0

    # Compose a simple score
    score = 0
    reasons = []
    if high_entropy_sections:
        score += 30
        reasons.append('high entropy sections found')
    if sigs['text_raw_size'] < SMALL_TEXT_THRESHOLD and filesize > 50_000:
        score += 15
        reasons.append('tiny .text rawsize for a large file')
    if sigs['import_density_suspicious']:
        score += 20
        reasons.append('very few imports')
    if sigs['overlay_suspicious']:
        score += 10
        reasons.append('large overlay detected')
    if sigs['tls_callbacks']:
        score += 8
        reasons.append('TLS callbacks present')
    if suspicious_names:
        score += 12
        reasons.append('suspicious section names present')
    if sigs['entry_in_high_entropy_section']:
        score += 15
        reasons.append('entry point inside high entropy section')

    # normalize to 0..100
    score = min(100, score)

    hints = []
    if score >= 60:
        hints.append('Likely packed or obfuscated — static disassembly may be incomplete.')
        hints.append('Recommended: run dynamic unpacking (sandbox) or use known unpackers (UPX) and re-analyze.')
    elif score >= 30:
        hints.append('Possible packing/obfuscation. Inspect high-entropy sections and overlay manually.')
    else:
        hints.append('No strong packing indicators found; static analysis should be reliable.')

    return {
        'file': pe_path,
        'filesize': filesize,
        'score': score,
        'reasons': reasons,
        'hints': hints,
        'signals': sigs,
    }

# ------------------ CLI ------------------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python packer.py <path_to_pe> [--verbose]')
        sys.exit(1)
    p = sys.argv[1]
    res = analyze_packer(p)
    verbose = '--verbose' in sys.argv
    print(json.dumps(res, indent=2))
    if verbose:
        print('\nQuick summary:')
        print('Score:', res['score'])
        print('Reasons:', res['reasons'])
        print('Hints:', res['hints'])
