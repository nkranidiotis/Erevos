"""
Erevos Module 4 — asm_highlighter.py (standalone)

Qt syntax highlighter for x86/x64 assembly displayed in a QTextEdit/QPlainTextEdit.
Highlights:
  • addresses, mnemonics, registers, immediates, hex numbers
  • comments (semicolon and Capstone-style) & quoted strings
  • CALL/JMP emphasized; NOP sleds dimmed

Usage:
    from PyQt6.QtWidgets import QTextEdit
    from asm_highlighter import AsmHighlighter

    editor = QTextEdit()
    highlighter = AsmHighlighter(editor.document())

Notes:
  - Colors chosen to remain readable on your light theme; tweak in THEME below.
  - Stateless: safe to reuse. Works with either QTextEdit or QPlainTextEdit.
"""
from __future__ import annotations
import re
from typing import List, Pattern

from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import Qt

# ----------------------- Theme -----------------------
class THEME:
    addr      = QColor(80, 80, 80)        # gray
    mnemonic  = QColor(0, 70, 160)        # blue-ish
    reg       = QColor(0, 120, 120)       # teal
    number    = QColor(140, 0, 160)       # purple
    comment   = QColor(120, 120, 120)     # dim gray
    string    = QColor(160, 80, 0)        # brown-ish
    calljmp   = QColor(200, 0, 0)         # red accent
    nopdim    = QColor(150, 150, 150)     # dimmer gray

    bold = QFont.Weight.DemiBold

# ----------------------- Highlighter -----------------------
class AsmHighlighter(QSyntaxHighlighter):
    def __init__(self, parent_doc):
        super().__init__(parent_doc)
        self._build_rules()

    # Build regex patterns and formats
    def _build_rules(self):
        self.rules: List[tuple[Pattern[str], QTextCharFormat]] = []

        def fmt(color: QColor, bold: bool=False, italic: bool=False):
            f = QTextCharFormat()
            f.setForeground(color)
            if bold:
                f.setFontWeight(THEME.bold)
            if italic:
                f.setFontItalic(True)
            return f

        # Addresses like: 0x00401234: or 00401234
        addr_pat = re.compile(r"\b(?:0x)?[0-9A-Fa-f]{6,16}:?")
        self.rules.append((addr_pat, fmt(THEME.addr)))

        # Mnemonics (common x86/x64); bold special flow mnemonics below
        mnems = (
            "mov|lea|xor|add|sub|mul|imul|div|idiv|and|or|not|neg|sar|sal|shr|shl|rol|ror|test|cmp|xchg|push|pop|ret|nop|call|jmp|jz|jnz|je|jne|ja|jae|jb|jbe|jg|jge|jl|jle|jo|jno|js|jns|jcxz|jecxz|jrcxz|cmov[a-z]+|set[a-z]+|bt|bts|btr|btc|movzx|movsx|cdq|cwd|cqo|syscall|int|hlt"
        )
        mnem_pat = re.compile(rf"\b(?:{mnems})\b", re.IGNORECASE)
        self.rules.append((mnem_pat, fmt(THEME.mnemonic)))

        # CALL/JMP emphasized
        calljmp_pat = re.compile(r"\b(?:call|jmp|jz|jnz|je|jne|ja|jae|jb|jbe|jg|jge|jl|jle)\b", re.IGNORECASE)
        self.rules.append((calljmp_pat, fmt(THEME.calljmp, bold=True)))

        # Registers (32/64-bit + flags)
        regs = (
            "r[0-9]{1,2}|e?[abcd]x|e?[sd]i|e?[sb]p|r[a-z]{2}|[abcd][hl]|rflags|eflags|flags|cr[0-8]|xmm[0-9]+|ymm[0-9]+|zmm[0-9]+"
        )
        reg_pat = re.compile(rf"\b(?:{regs})\b", re.IGNORECASE)
        self.rules.append((reg_pat, fmt(THEME.reg)))

        # Hex numbers & immediates
        hex_pat = re.compile(r"\b(?:(?:0x)?[0-9A-Fa-f]{2,}|[0-9]+h)\b")
        self.rules.append((hex_pat, fmt(THEME.number)))

        # Strings (single or double quoted)
        str_pat = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
        self.rules.append((str_pat, fmt(THEME.string)))

        # Comments start with ';' (also allow Capstone style '\t; ...')
        self.comment_pat = re.compile(r";.*$")
        self.comment_fmt = fmt(THEME.comment, italic=True)

        # NOP sled dim (sequence of at least 3 'nop' instructions)
        self.nopline_pat = re.compile(r"^(?:\s*nop\b.*){3,}$", re.IGNORECASE)
        self.nopline_fmt = fmt(THEME.nopdim)

    # Apply rules per block (line)
    def highlightBlock(self, text: str) -> None:
        # Full-line NOP dimming first
        if self.nopline_pat.search(text):
            self.setFormat(0, len(text), self.nopline_fmt)
            return

        # Comments: apply once to end-of-line
        m = self.comment_pat.search(text)
        comment_from = m.start() if m else -1
        if comment_from >= 0:
            self.setFormat(comment_from, len(text) - comment_from, self.comment_fmt)
            text_to_match = text[:comment_from]
        else:
            text_to_match = text

        # Regex rules
        for pat, f in self.rules:
            for m in pat.finditer(text_to_match):
                self.setFormat(m.start(), m.end() - m.start(), f)

        # Small polish: make addresses bold-ish (already colored)
        # (We could re-run address pattern here to add weight; skip for speed.)

# ----------------------- Convenience -----------------------
def attach_highlighter(widget) -> AsmHighlighter:
    """Attach to a QTextEdit/QPlainTextEdit and return the highlighter instance."""
    return AsmHighlighter(widget.document())
