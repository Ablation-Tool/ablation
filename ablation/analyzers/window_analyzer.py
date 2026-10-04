"""
window_analyzer.py: LLM-native bulk disassembly window for stripped ELF RE.

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


def _elf_arch(data: bytes) -> str:
    """Return arch string from ELF e_machine, respecting EI_DATA byte order."""
    if len(data) < 20:
        return 'x86_64'
    if data[:4] != b'\x7fELF':
        return 'x86_64'
    ei_data = data[5]  # ELFDATA2LSB=1, ELFDATA2MSB=2
    bo = '>' if ei_data == 2 else '<'
    e_machine = struct.unpack_from(bo + 'H', data, 18)[0]
    if e_machine == 183:   # EM_AARCH64
        return 'arm64'
    if e_machine == 40:    # EM_ARM
        return 'arm32'
    if e_machine == 3:     # EM_386
        return 'x86_32'
    if e_machine == 20:    # EM_PPC
        return 'ppc32'
    if e_machine == 21:    # EM_PPC64
        return 'ppc64'
    return 'x86_64'


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
        plt     : va -> symbol name for PLT stubs
        strings : va -> string content for .rodata references
    """

    def __init__(self, data: bytes, base_va: int = 0, path: str = ""):
        self.data = data
        self.base_va = base_va
        self.path = path
        self.arch: str = _elf_arch(data)
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
        if self.arch in ('ppc32', 'ppc64'):
            self._build_plt_ppc32_bss(binary)
            return
        # Map: GOT VA -> symbol name from .rela.plt (ELF64) or .rel.plt (ELF32)
        got_to_sym: Dict[int, str] = {}
        try:
            rela_plt = binary.get_section(".rela.plt")
            if rela_plt:
                rela_data = bytes(rela_plt.content)
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

        # ELF32: .rel.plt uses 8-byte records (no addend): r_offset(4), r_info(4)
        if self.arch == 'x86_32' and not got_to_sym:
            try:
                rel_plt = binary.get_section(".rel.plt")
                if rel_plt:
                    rel_data = bytes(rel_plt.content)
                    for off in range(0, len(rel_data), 8):
                        if off + 8 > len(rel_data):
                            break
                        r_offset, r_info = struct.unpack_from("<II", rel_data, off)
                        sym_idx = r_info >> 8
                        try:
                            sym = binary.dynamic_symbols[sym_idx]
                            got_to_sym[r_offset] = sym.name
                        except (IndexError, Exception):
                            pass
            except Exception:
                pass

        if self.arch == 'arm64':
            self._build_plt_arm64(binary, got_to_sym)
            return

        if self.arch == 'x86_32':
            self._build_plt_x86_32(binary, got_to_sym)
            return

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

    def _build_plt_x86_32(self, binary, got_to_sym: Dict[int, str]) -> None:
        # i386 PLT: each stub is 16 bytes, first stub is PLT[0] trampoline (skip it).
        # Stub n: ff 25 <abs_got_va 4 bytes> (JMP [abs_addr]) or push + jmp pattern.
        for sec_name in (".plt",):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            # PLT[0] is the lazy-bind trampoline (16 bytes); skip it
            for off in range(16, len(sec_data), 16):
                stub_va = sec_va + off
                chunk = sec_data[off:off + 16]
                if len(chunk) < 6:
                    break
                # JMP [abs_addr]: ff 25 xx xx xx xx
                if chunk[:2] == b'\xff\x25':
                    got_va = struct.unpack_from("<I", chunk, 2)[0]
                    if got_va in got_to_sym:
                        self.plt[stub_va] = got_to_sym[got_va]

    def _build_plt_arm64(self, binary, got_to_sym: Dict[int, str]) -> None:
        # ARM64 PLT stub: adrp x16, page / ldr x17, [x16, #off] / br x17 (12 bytes, padded to 16)
        # GOT VA = ADRP page result + LDR immediate offset
        try:
            plt_sec = binary.get_section(".plt")
        except Exception:
            plt_sec = None
        if not plt_sec:
            return

        sec_data = bytes(plt_sec.content)
        sec_va = plt_sec.virtual_address
        # PLT[0] is the lazy-binding trampoline; skip it
        for i in range(1, len(sec_data) // 16):
            off = i * 16
            stub_va = sec_va + off
            if off + 16 > len(sec_data):
                break
            w0, w1, w2, w3 = struct.unpack_from("<IIII", sec_data, off)
            # ARM64 PLT stub: ADRP x16 / LDR x17, [x16, #imm] / ADD x16, x16, #imm / BR x17
            # ADRP x16: (w & 0x9f00001f) == 0x90000010
            if (w0 & 0x9f00001f) != 0x90000010:
                continue
            # LDR x17, [x16, #imm12]: 64-bit unsigned-offset, Rn=x16, Rt=x17
            if (w1 & 0xFFC003FF) != 0xF9400211:
                continue
            # BR x17 is the 4th instruction (w3)
            if w3 != 0xD61F0220:
                continue
            # Decode ADRP imm: sign-extend 21-bit (immhi:immlo) << 12
            immlo = (w0 >> 29) & 0x3
            immhi = (w0 >> 5) & 0x7ffff
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            adrp_page = (stub_va & ~0xfff) + (imm21 << 12)
            # Decode LDR imm12 (scaled by 8 for 64-bit loads)
            ldr_imm12 = (w1 >> 10) & 0xfff
            got_slot_va = adrp_page + ldr_imm12 * 8
            if got_slot_va in got_to_sym:
                self.plt[stub_va] = got_to_sym[got_slot_va]

    def _build_plt_ppc32_bss(self, binary) -> None:
        """BSS PLT for PPC32/PPC64 SYSV ABI.

        Stubs are written at load time by glibc, not stored in the ELF file.
        Recover stub_va → symbol by correlating .rela.plt entry order with BL
        targets in .text that land in the .plt VA range.  Stub size is always
        8 bytes (2 words) for the glibc SYSV PPC32 BSS PLT; resolver_size is
        inferred as (first_observed_consecutive_stub_va - plt_va).  The algorithm
        is correct when stub index 0 is called from .text (the common case in
        firmware with many imports).
        """
        bo = '>' if (len(self.data) > 5 and self.data[5] == 2) else '<'

        # 1. Build index → sym_name from .rela.plt (Elf32_Rela: r_offset, r_info, r_addend)
        index_to_sym: List[str] = []
        try:
            rela_plt = binary.get_section('.rela.plt')
            if rela_plt is None:
                return
            rela_data = bytes(rela_plt.content)
            dyn_syms = list(binary.dynamic_symbols)
            for off in range(0, len(rela_data), 12):
                if off + 12 > len(rela_data):
                    break
                _, r_info, _ = struct.unpack_from(bo + 'III', rela_data, off)
                sym_idx = r_info >> 8
                try:
                    sym = dyn_syms[sym_idx] if sym_idx < len(dyn_syms) else None
                    index_to_sym.append(sym.name if sym and sym.name else '')
                except Exception:
                    index_to_sym.append('')
        except Exception:
            return
        if not index_to_sym:
            return

        # 2. Get .plt section VA (BSS — no file content)
        try:
            plt_sec = binary.get_section('.plt')
        except Exception:
            return
        if plt_sec is None:
            return
        plt_va = plt_sec.virtual_address
        stub_size = 8
        plt_est_end = plt_va + 512 + len(index_to_sym) * stub_size

        # 3. Scan .text for BL targets in [plt_va, plt_est_end)
        try:
            text_sec = binary.get_section('.text')
        except Exception:
            return
        if text_sec is None:
            return
        text_data = bytes(text_sec.content)
        if not text_data:
            return
        text_va = text_sec.virtual_address
        bl_targets: set = set()
        for i in range(0, len(text_data) - 3, 4):
            w = struct.unpack_from(bo + 'I', text_data, i)[0]
            if (w & 0xFC000003) != 0x48000001:  # BL (opcode 18, AA=0, LK=1)
                continue
            li = (w >> 2) & 0xFFFFFF
            if li >= 0x800000:
                li -= 0x1000000
            target_va = text_va + i + li * 4
            if plt_va <= target_va < plt_est_end:
                bl_targets.add(target_va)
        if not bl_targets:
            return

        # 4. Find first stub VA: smallest BL target T where T+stub_size is also observed.
        #    That T is stub index 0 (assuming it is called from .text).
        sorted_t = sorted(bl_targets)
        target_set = set(sorted_t)
        first_stub_va = None
        for t in sorted_t:
            if (t + stub_size) in target_set:
                first_stub_va = t
                break
        if first_stub_va is None:
            return  # no consecutive stub pair observed; cannot determine index 0

        # 5. Map each rela.plt index to its stub VA
        resolver_size = first_stub_va - plt_va
        for idx, sym_name in enumerate(index_to_sym):
            if sym_name:
                self.plt[plt_va + resolver_size + idx * stub_size] = sym_name

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
            if self.arch == 'arm32':
                self._md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            elif self.arch == 'arm64':
                self._md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            elif self.arch == 'x86_32':
                self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif self.arch in ('ppc32', 'ppc64'):
                ppc_mode = capstone.CS_MODE_32 if self.arch == 'ppc32' else capstone.CS_MODE_64
                self._md = capstone.Cs(capstone.CS_ARCH_PPC, ppc_mode | capstone.CS_MODE_BIG_ENDIAN)
            else:
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
            va        : center/start VA to disassemble from
            window    : bytes to disassemble (default 1536 = 1.5KB)
            align_back: bytes before va to include (default 0)
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

            # Mark function starts (x86_64: endbr64 probe; arm32/arm64: push/stp prologue)
            if self.arch == 'x86_64' and bytes(insn.bytes[:4]) == _ENDBR64:
                annotations.append("[FUNC_START]")
            elif self.arch in ('arm32', 'arm64') and mnemonic in ('push', 'stp', 'stmdb', 'stmfd'):
                if 'lr' in op_str.lower() or 'x29' in op_str.lower():
                    annotations.append("[FUNC_START?]")

            # Annotate calls with PLT symbol name
            call_mnems = {'call'} if self.arch == 'x86_64' else {'bl', 'blx', 'blr'}
            if mnemonic.lower().split('.')[0] in call_mnems:
                try:
                    target = int(op_str.strip().lstrip('#'), 16)
                    if target in self.plt:
                        annotations.append(f"PLT -> {self.plt[target]}")
                    elif target in self.strings:
                        annotations.append(f"-> {self.strings[target]!r}")
                except ValueError:
                    pass

            # Annotate RIP-relative LEA/MOV with string content (x86_64 only)
            if self.arch == 'x86_64' and mnemonic in ("lea", "mov") and "[rip" in op_str:
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
        """Return VAs of function start candidates in the window."""
        starts = []
        for line in self.dump(va, window=window, align_back=align_back):
            if "[FUNC_START" in line:
                try:
                    addr_str = line.split(":")[0]
                    starts.append(int(addr_str, 16))
                except ValueError:
                    pass
        return starts

    def calls_in_window(self, va: int, window: int = 1536, align_back: int = 0) -> List[Tuple[int, int, str]]:
        """
        Return (call_site_va, target_va, label) for all call/bl instructions in the window.
        label is the PLT symbol name if known, else ''.
        """
        call_marker = ': call' if self.arch == 'x86_64' else ': bl'
        calls = []
        for line in self.dump(va, window=window, align_back=align_back):
            if call_marker not in line:
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
