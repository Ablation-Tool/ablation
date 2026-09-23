"""
window_analyzer.py -- LLM-native bulk disassembly window for stripped ELF RE.

Motivation: per-instruction disassembly calls fragment LLM context across dozens of
round trips. This module dumps a configurable-size window (default 1536 bytes) centered
on any target VA, resolves PLT call targets and .rodata strings inline, and marks
function start heuristics (endbr64, CET stub patterns). One call = one annotated
chunk the LLM can pattern-match in a single pass.

Core workflow:
    wa = WindowAnalyzer.from_path('/path/to/binary')
    lines = wa.dump(va=0x41366, window=1536)
    # lines is a list of annotated instruction strings

    # Or dump to formatted text block:
    text = wa.dump_text(va=0x41366, window=1536)

Annotation format per instruction line:
    0x41366: call 0x3000          ; PLT -> target_func
    0x41371: lea  rdi, [rip+0x...]  ; "==diff==> %s:%d loading cli context fail"
    0x41290: endbr64               ; [FUNC_START]

The module reuses XRefGraph's PLT and string resolution when available.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import capstone

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

_RIP_RE = re.compile(r'\[rip [+-] (0x[0-9a-f]+)\]')
_ENDBR64 = bytes([0xf3, 0x0f, 0x1e, 0xfa])


def _parse_rip_target(insn_addr: int, insn_size: int, op_str: str) -> Optional[int]:
    m = _RIP_RE.search(op_str)
    if not m:
        return None
    disp = int(m.group(1), 16)
    if '-' in op_str and '[rip -' in op_str:
        disp = -disp
    return insn_addr + insn_size + disp


class WindowAnalyzer:
    """
    Bulk window disassembler with inline PLT + string annotation.

    Attributes:
        plt      -- va -> symbol name for PLT stubs
        strings  -- va -> string content for .rodata references
    """

    def __init__(self, data: bytes, base_va: int = 0, path: str = ""):
        self.data = data
        self.base_va = base_va
        self.path = path
        self.plt: Dict[int, str] = {}
        self.strings: Dict[int, str] = {}
        self._text_start: int = 0
        self._text_end: int = 0
        self._md: Optional[capstone.Cs] = None
        if _LIEF_OK and data:
            self._load_lief()

    @classmethod
    def from_path(cls, path: str) -> "WindowAnalyzer":
        data = Path(path).read_bytes()
        inst = cls(data, path=path)
        return inst

    def _load_lief(self) -> None:
        try:
            binary = lief.parse(self.data)
        except Exception:
            return
        if not binary:
            return
        if not isinstance(binary, lief.ELF.Binary):
            return

        self.base_va = binary.imagebase

        # Locate .text bounds
        text_sec = binary.get_section(".text")
        if text_sec:
            self._text_start = text_sec.virtual_address
            self._text_end = text_sec.virtual_address + text_sec.size

        # Build PLT map via .rela.plt -> .plt.sec stubs
        self._build_plt(binary)

        # Build .rodata string map
        self._build_strings(binary)

    def _build_plt(self, binary) -> None:
        # Map: GOT VA -> symbol name from .rela.plt
        got_to_sym: Dict[int, str] = {}
        try:
            rela_plt = binary.get_section(".rela.plt")
            if rela_plt:
                rela_data = bytes(rela_plt.content)
                rela_va = rela_plt.virtual_address
                for off in range(0, len(rela_data), 24):
                    if off + 24 > len(rela_data):
                        break
                    r_offset, r_info = struct.unpack_from("<QQ", rela_data, off)
                    sym_idx = r_info >> 32
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        got_to_sym[r_offset] = sym.name
                    except (IndexError, Exception):
                        pass
        except Exception:
            pass

        # Walk .plt.sec: each entry = endbr64 (4) + jmp [rip+disp] (6) or similar
        for sec_name in (".plt.sec", ".plt", ".plt.got"):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            for off in range(0, len(sec_data), 16):
                stub_va = sec_va + off
                chunk = sec_data[off:off + 16]
                if len(chunk) < 6:
                    break
                # CET stub: f3 0f 1e fa ff 25 xx xx xx xx
                start = 0
                if chunk[:4] == _ENDBR64:
                    start = 4
                if len(chunk) < start + 6:
                    continue
                if chunk[start:start + 2] == b'\xff\x25':  # jmp [rip+disp]
                    disp = struct.unpack_from("<i", chunk, start + 2)[0]
                    got_va = stub_va + start + 6 + disp
                    if got_va in got_to_sym:
                        self.plt[stub_va] = got_to_sym[got_va]
                elif chunk[start:start + 2] == b'\xff\xa3':  # jmp [rbx+disp] unlikely
                    pass

    def _build_strings(self, binary) -> None:
        for sec_name in (".rodata", ".data.rel.ro", ".data"):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            i = 0
            while i < len(sec_data):
                start = i
                while i < len(sec_data) and 0x20 <= sec_data[i] < 0x7f:
                    i += 1
                if i - start >= 4:
                    s = sec_data[start:i].decode("ascii", errors="replace")
                    self.strings[sec_va + start] = s
                else:
                    i = start + 1

    def _cs(self) -> capstone.Cs:
        if self._md is None:
            self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self._md.detail = False
        return self._md

    def _va_to_offset(self, va: int) -> int:
        if not _LIEF_OK or not self.base_va:
            return va
        if not hasattr(self, '_sections'):
            try:
                binary = lief.parse(self.data)
                self._sections = list(binary.sections) if binary else []
            except Exception:
                self._sections = []
        for sec in getattr(self, '_sections', []):
            s_va = sec.virtual_address
            s_off = sec.offset
            s_sz = sec.size
            if s_va <= va < s_va + s_sz:
                return s_off + (va - s_va)
        return va - self.base_va

    def dump(
        self,
        va: int,
        window: int = 1536,
        align_back: int = 0,
    ) -> List[str]:
        """
        Disassemble [va - align_back, va - align_back + window) and return
        annotated instruction strings.

        Args:
            va         -- center/start VA to disassemble from
            window     -- bytes to disassemble (default 1536 = 1.5KB)
            align_back -- bytes before va to include (default 0)
        """
        start_va = va - align_back
        offset = self._va_to_offset(start_va)
        chunk = self.data[offset:offset + window]
        if not chunk:
            return [f"; no data at va=0x{start_va:x} offset=0x{offset:x}"]

        lines: List[str] = []
        md = self._cs()
        for insn in md.disasm(chunk, start_va):
            mnemonic = insn.mnemonic
            op_str = insn.op_str
            addr = insn.address
            line = f"0x{addr:x}: {mnemonic:<8} {op_str}"
            annotations: List[str] = []

            # Mark function starts
            if bytes(insn.bytes[:4]) == _ENDBR64:
                annotations.append("[FUNC_START]")

            # Annotate calls with PLT symbol name
            if mnemonic == "call":
                try:
                    target = int(op_str, 16)
                    if target in self.plt:
                        annotations.append(f"PLT -> {self.plt[target]}")
                    elif target in self.strings:
                        annotations.append(f"-> {self.strings[target]!r}")
                except ValueError:
                    pass

            # Annotate RIP-relative LEA/MOV with string content
            if mnemonic in ("lea", "mov") and "[rip" in op_str:
                target = _parse_rip_target(addr, insn.size, op_str)
                if target is not None and target in self.strings:
                    s = self.strings[target]
                    snippet = s[:64] + "..." if len(s) > 64 else s
                    annotations.append(f'"{snippet}"')

            if annotations:
                line += "  ; " + " | ".join(annotations)
            lines.append(line)

        return lines

    def dump_text(
        self,
        va: int,
        window: int = 1536,
        align_back: int = 0,
        header: bool = True,
    ) -> str:
        """Return dump as a single formatted string block."""
        lines = self.dump(va, window=window, align_back=align_back)
        if header:
            tag = f"window: {window}B @ 0x{va:x} (back={align_back})"
            sep = "-" * len(tag)
            return "\n".join([sep, tag, sep] + lines)
        return "\n".join(lines)

    def find_func_starts(self, va: int, window: int = 1536, align_back: int = 0) -> List[int]:
        """Return VAs of all endbr64 instructions in the window (function start candidates)."""
        starts = []
        for line in self.dump(va, window=window, align_back=align_back):
            if "[FUNC_START]" in line:
                try:
                    addr_str = line.split(":")[0]
                    starts.append(int(addr_str, 16))
                except ValueError:
                    pass
        return starts

    def calls_in_window(self, va: int, window: int = 1536, align_back: int = 0) -> List[Tuple[int, int, str]]:
        """
        Return (call_site_va, target_va, label) for all call instructions in the window.
        label is the PLT symbol name if known, else ''.
        """
        calls = []
        for line in self.dump(va, window=window, align_back=align_back):
            if ": call" not in line:
                continue
            parts = line.split(":")
            try:
                site_va = int(parts[0], 16)
                rest = ":".join(parts[1:])
                op_part = rest.split(";")[0].strip()
                target_str = op_part.replace("call", "").strip()
                target_va = int(target_str, 16)
                label = ""
                if "PLT ->" in line:
                    label = line.split("PLT ->")[1].split("|")[0].strip().rstrip('"')
                calls.append((site_va, target_va, label))
            except (ValueError, IndexError):
                pass
        return calls
