"""
xref_graph.py: Multi-arch ELF cross-reference graph: strings, call graph, callers.

Closes the primary capability gap vs. Ghidra: knowing what strings a function
references and who calls it. Both dramatically improve BERT embedding quality.

Supported architectures: x86_64, arm64, arm32 (including Thumb).

Key outputs per function VA:
  strings_at(va) : printable strings the function references
  callees(va)    : VAs this function calls directly
  callers(va)    : VAs that call this function
  plt_name(va)   : imported symbol name if va is a PLT entry

Usage:
    xg = XRefGraph.from_path('/path/to/binary')
    xg.build()

    # Enrich a describe_function call:
    enriched = xg.enrich_desc(func_va, base_desc, name='func_0x1234')

    # Standalone lookups:
    print(xg.strings_at(0x12345))
    print(xg.callers(0x12345))
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
import lief
import numpy as np

_RIP_RE = re.compile(r'\[rip [+-] (0x[0-9a-f]+)\]')


def _elf_arch(data: bytes) -> str:
    """Detect architecture from ELF e_machine field."""
    if len(data) < 20 or data[:4] != b'\x7fELF':
        return 'x86_64'
    e_machine = struct.unpack_from('<H', data, 18)[0]
    if e_machine == 183:
        return 'arm64'
    if e_machine == 40:
        return 'arm32'
    return 'x86_64'


def _parse_rip_target(insn_addr: int, insn_size: int, op_str: str) -> Optional[int]:
    """Resolve RIP-relative address from capstone op_str."""
    m = _RIP_RE.search(op_str)
    if not m:
        return None
    disp = int(m.group(1), 16)
    if '-' in op_str and '[rip -' in op_str:
        disp = -disp
    return insn_addr + insn_size + disp


class XRefGraph:
    def __init__(self, data: bytes, path: str = ""):
        self.data = data
        self.path = path
        self._arch: str = _elf_arch(data)
        self._binary: Optional[lief.ELF.Binary] = None

        # va -> imported name (PLT entries)
        self._plt: Dict[int, str] = {}

        # va -> string content (.rodata strings reachable by RIP-relative addressing)
        self._strings: Dict[int, str] = {}
        self._rodata_start = 0
        self._rodata_end = 0

        # Call graph edges
        self._callees: Dict[int, Set[int]] = {}   # func_va -> callee VAs (may be PLT or internal)
        self._callers: Dict[int, Set[int]] = {}   # func_va -> caller VAs

        # String refs: func_va -> set of referenced string values
        self._str_refs: Dict[int, Set[str]] = {}

        # Function start VAs (populated during build)
        self._func_starts: Set[int] = set()

    # ── construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> "XRefGraph":
        data = open(path, "rb").read()
        xg = cls(data, path)
        xg._binary = lief.parse(path)
        return xg

    @classmethod
    def from_data(cls, data: bytes, path: str = "") -> "XRefGraph":
        xg = cls(data, path)
        if path:
            try:
                xg._binary = lief.parse(path)
            except Exception:
                pass
        return xg

    # ── public API ────────────────────────────────────────────────────────────

    def strings_at(self, func_va: int) -> List[str]:
        return sorted(self._str_refs.get(func_va, set()))

    def callees(self, func_va: int) -> Set[int]:
        return self._callees.get(func_va, set())

    def callers(self, func_va: int) -> Set[int]:
        return self._callers.get(func_va, set())

    def plt_name(self, va: int) -> Optional[str]:
        return self._plt.get(va)

    def resolve_call(self, target_va: int) -> str:
        """Return human-readable name for a call target (PLT name or hex address)."""
        name = self._plt.get(target_va)
        if name:
            return name
        return f"0x{target_va:x}"

    def callee_names(self, func_va: int) -> List[str]:
        """Return callee names (PLT name or hex) for a function."""
        return [self.resolve_call(va) for va in sorted(self.callees(func_va))]

    def caller_names(self, func_va: int) -> List[str]:
        """Return caller function VAs as hex strings."""
        return [f"0x{va:x}" for va in sorted(self.callers(func_va))]

    def enrich_desc(self, func_va: int, base_desc: str, name: str = "") -> str:
        """
        Append xref context (callers + strings) to a describe_function output.

        Input:  'func_0x1234 | role: FUNC | calls: malloc | asm: ...'
        Output: same but with '| callers: 0x5678 | strings: "buffer", "error"' inserted
        """
        additions = []

        callers = self.caller_names(func_va)
        if callers:
            additions.append("callers: " + ", ".join(callers[:6]))

        strs = self.strings_at(func_va)
        if strs:
            quoted = [f'"{s}"' for s in strs[:8]]
            additions.append("strings: " + ", ".join(quoted))

        if not additions:
            return base_desc

        # Insert before 'asm:' part to keep that at the end
        if "| asm:" in base_desc:
            idx = base_desc.index("| asm:")
            return base_desc[:idx] + " | " + " | ".join(additions) + " | " + base_desc[idx:]
        return base_desc + " | " + " | ".join(additions)

    # ── build pipeline ────────────────────────────────────────────────────────

    def build(self, func_starts: Optional[Set[int]] = None) -> "XRefGraph":
        """
        Full build: extract PLT, extract strings, trace calls + string refs.

        func_starts: optional set of known function start VAs to focus on.
        If None, .eh_frame + prologue heuristic are used (union).
        """
        self._extract_plt()
        self._extract_strings()

        # Merge caller-supplied starts with .eh_frame FDE starts
        merged = set(func_starts or [])
        eh_starts = self._extract_func_starts_from_eh_frame()
        merged.update(eh_starts)

        self._build_call_graph(merged if merged else None)

        # Second pass: all call targets are function entries by definition.
        # Augment _func_starts with discovered callees: catches leaf functions
        # and non-standard prologues missed by the prologue heuristic.
        self._augment_func_starts_from_callees()
        return self

    def _augment_func_starts_from_callees(self) -> None:
        """
        Add all discovered callee VAs to _func_starts.

        A call target is a function entry point by definition. The prologue
        heuristic (push rbp; mov rbp,rsp) misses:
          - Leaf functions (no frame setup)
          - Functions with non-standard prologues (PIE, PIC, LTO-compiled)
          - Functions entered only via tail-call jump
        Call targets discovered during the flat scan are authoritative.
        """
        new_starts: Set[int] = set()
        plt_vas: Set[int] = set(self._plt.keys())
        for callee_set in self._callees.values():
            for callee_va in callee_set:
                if callee_va not in self._func_starts and callee_va not in plt_vas:
                    new_starts.add(callee_va)
        self._func_starts.update(new_starts)

    def _extract_func_starts_from_eh_frame(self) -> Set[int]:
        """
        Parse .eh_frame section via pyelftools FDE records.

        Each FDE covers one function; its initial_location is the function's
        start VA. Present in stripped binaries (gcc default).
        Returns empty set if section absent or pyelftools unavailable.
        """
        if not self.path:
            return set()
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.dwarf.callframe import FDE
            with open(self.path, "rb") as fh:
                elf = ELFFile(fh)
                if not elf.has_dwarf_info():
                    return set()
                di = elf.get_dwarf_info()
                if not di.has_EH_CFI():
                    return set()
                return {
                    e["initial_location"]
                    for e in di.EH_CFI_entries()
                    if isinstance(e, FDE) and e["initial_location"] > 0
                }
        except Exception:
            return set()

    def _extract_plt(self):
        """Extract PLT va -> symbol name from ELF dynamic relocations."""
        if self._binary is None:
            return
        if self._arch == 'arm32':
            self._extract_plt_arm32()
            return
        if self._arch == 'arm64':
            self._extract_plt_arm64()
            return
        try:
            # LIEF 1.x API
            for sym in self._binary.imported_functions:
                if hasattr(sym, 'value') and sym.value:
                    self._plt[sym.value] = sym.name
        except Exception:
            pass
        # Fallback: dynamic relocations JUMP_SLOT type
        try:
            for rel in self._binary.relocations:
                if not rel.has_symbol:
                    continue
                rtype = str(rel.type) if hasattr(rel, 'type') else ''
                if 'JUMP_SLOT' in rtype or 'GLOB_DAT' in rtype:
                    self._plt[rel.address] = rel.symbol.name
        except Exception:
            pass
        # PLT section disassembly: .plt.sec is the critical one for modern x86-64.
        md_plt = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md_plt.detail = False

        def _scan_plt_section(sect_name: str, skip_first: bool = False):
            try:
                sect = self._binary.get_section(sect_name)
                if not sect:
                    return
                plt_data = bytes(sect.content)
                plt_base = sect.virtual_address
                entry_size = 16
                start_idx = 1 if skip_first else 0
                for entry_idx in range(start_idx, len(plt_data) // entry_size):
                    offset = entry_idx * entry_size
                    entry_va = plt_base + offset
                    chunk = plt_data[offset: offset + entry_size]
                    for insn in md_plt.disasm(chunk, entry_va):
                        if insn.mnemonic in ('jmp', 'jmpq', 'bnd jmp'):
                            got_va = _parse_rip_target(insn.address, insn.size, insn.op_str)
                            if got_va and got_va in self._plt:
                                self._plt[entry_va] = self._plt[got_va]
                            break
                        if insn.mnemonic == 'endbr64':
                            continue
                        if insn.mnemonic not in ('endbr64', 'nop'):
                            break
            except Exception:
                pass

        _scan_plt_section('.plt', skip_first=True)
        _scan_plt_section('.plt.sec', skip_first=False)
        _scan_plt_section('.plt.got', skip_first=False)

    def _extract_plt_arm32(self):
        """ARM32 PLT: .rel.plt (8-byte REL entries), stubs at PLT_VA + 20 + n*12."""
        sym_names: List[str] = []
        try:
            rel_plt = self._binary.get_section('.rel.plt')
            if rel_plt:
                rel_data = bytes(rel_plt.content)
                for off in range(0, len(rel_data) - 7, 8):
                    r_offset, r_info = struct.unpack_from('<II', rel_data, off)
                    sym_idx = r_info >> 8
                    try:
                        sym = self._binary.dynamic_symbols[sym_idx]
                        sym_names.append(sym.name or '')
                    except Exception:
                        sym_names.append('')
        except Exception:
            pass
        if sym_names:
            plt_sec = self._binary.get_section('.plt')
            if plt_sec:
                plt_va = int(plt_sec.virtual_address)
                for i, name in enumerate(sym_names):
                    if name:
                        self._plt[plt_va + 20 + i * 12] = name
                return
        try:
            for rel in self._binary.relocations:
                if rel.has_symbol:
                    rtype = str(getattr(rel, 'type', ''))
                    if 'JUMP_SLOT' in rtype and rel.symbol.name:
                        self._plt[rel.address] = rel.symbol.name
        except Exception:
            pass

    def _extract_plt_arm64(self):
        """
        ARM64 PLT: two-pass.
        Pass 1: LIEF relocations (JUMP_SLOT) -> GOT VA -> symbol name.
        Pass 2: Disassemble .plt stubs (ADRP/LDR/ADD/BR, 16 bytes each, skip
                32-byte resolver at index 0) -> PLT stub VA -> GOT VA -> name.
        Callers use BL <plt_stub_va>, so stub VAs must be in self._plt.
        """
        # Pass 1: GOT VA -> name from dynamic relocations
        got_to_name: Dict[int, str] = {}
        try:
            for rel in self._binary.relocations:
                if not rel.has_symbol:
                    continue
                rtype = str(getattr(rel, 'type', ''))
                if 'JUMP_SLOT' in rtype and rel.symbol.name:
                    got_to_name[rel.address] = rel.symbol.name
        except Exception:
            pass
        # Also via imported_functions if available
        try:
            for sym in self._binary.imported_functions:
                if hasattr(sym, 'value') and sym.value and sym.name:
                    got_to_name[sym.value] = sym.name
        except Exception:
            pass

        self._plt.update(got_to_name)

        # Pass 2: disassemble .plt stubs to map stub VA -> GOT VA -> name
        arm64_arch = getattr(capstone, 'CS_ARCH_AARCH64', None) or getattr(capstone, 'CS_ARCH_ARM64', None)
        if arm64_arch is None:
            return
        try:
            plt_sec = self._binary.get_section('.plt')
            if not plt_sec:
                return
            plt_data = bytes(plt_sec.content)
            plt_base = int(plt_sec.virtual_address)
            # First 32 bytes = resolver stub; real entries start at offset 32, 16 bytes each
            RESOLVER_SIZE = 32
            STUB_SIZE = 16
            md = capstone.Cs(arm64_arch, capstone.CS_MODE_ARM)
            md.detail = False
            offset = RESOLVER_SIZE
            while offset + STUB_SIZE <= len(plt_data):
                stub_va = plt_base + offset
                chunk = plt_data[offset: offset + STUB_SIZE]
                insns = list(md.disasm(chunk, stub_va))
                # Expect: ADRP x16, page; LDR/NOP; ADD x16, x16, #off; BR x17
                # Extract page from ADRP and offset from ADD to reconstruct GOT VA
                page = None
                got_off = None
                for insn in insns:
                    mn = insn.mnemonic.lower()
                    op = insn.op_str
                    if mn == 'adrp' and 'x16' in op:
                        parts = op.split(',')
                        if len(parts) >= 2:
                            try:
                                page = int(parts[-1].strip().lstrip('#'), 16)
                            except ValueError:
                                pass
                    elif mn == 'add' and 'x16' in op:
                        parts = op.split(',')
                        if len(parts) >= 3:
                            try:
                                got_off = int(parts[-1].strip().lstrip('#'), 16)
                            except ValueError:
                                pass
                if page is not None and got_off is not None:
                    got_va = page + got_off
                    name = got_to_name.get(got_va)
                    if name:
                        self._plt[stub_va] = name
                offset += STUB_SIZE
        except Exception:
            pass

    def _extract_strings(self, min_len: int = 4):
        """Extract null-terminated ASCII strings from .rodata section."""
        rodata = None
        if self._binary is not None:
            try:
                rodata = self._binary.get_section('.rodata')
            except Exception:
                pass

        if rodata is None:
            return

        base = rodata.virtual_address
        content = bytes(rodata.content)
        self._rodata_start = base
        self._rodata_end = base + len(content)

        i = 0
        current: List[int] = []
        current_start = 0
        while i < len(content):
            b = content[i]
            if 0x20 <= b <= 0x7e:
                if not current:
                    current_start = i
                current.append(b)
            elif b == 0 and len(current) >= min_len:
                s = bytes(current).decode('ascii', errors='replace').strip()
                if s and len(s) >= min_len:
                    self._strings[base + current_start] = s
                current = []
            else:
                current = []
            i += 1

    def _build_call_graph(self, func_starts: Optional[Set[int]] = None):
        """
        Flat-scan disassembly: attribute every call and string-load to its
        containing function via binary search. Arch-aware for x86-64, ARM32, ARM64.
        """
        if self._arch == 'arm32':
            self._build_call_graph_arm32(func_starts)
        elif self._arch == 'arm64':
            self._build_call_graph_arm64(func_starts)
        else:
            self._build_call_graph_x86(func_starts)

    def _build_call_graph_x86(self, func_starts: Optional[Set[int]] = None):
        import bisect

        text_sections = []
        if self._binary is not None:
            try:
                for sect in self._binary.sections:
                    name = sect.name
                    if name in ('.text', '.plt.sec'):
                        text_sections.append(
                            (sect.virtual_address, int(sect.offset), int(sect.size))
                        )
            except Exception:
                pass

        if not text_sections and len(self.data) > 0:
            text_sections = [(0, 0, len(self.data))]

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = False

        all_func_starts = set(func_starts or [])

        for vaddr, offset, size in text_sections:
            chunk = self.data[offset: offset + size]
            if not chunk:
                continue
            if not func_starts:
                for i in range(len(chunk) - 4):
                    # push rbp; mov rbp/rsp (classic prologue)
                    if chunk[i] == 0x55 and chunk[i + 1:i + 3] == b'\x48\x89':
                        all_func_starts.add(vaddr + i)
                    # endbr64 / endbr32 (CET IBT marker, emitted by gcc -fcf-protection)
                    elif chunk[i:i + 4] in (b'\xf3\x0f\x1e\xfa', b'\xf3\x0f\x1e\xfb'):
                        all_func_starts.add(vaddr + i)

        self._func_starts = all_func_starts
        sorted_starts = sorted(all_func_starts)

        if not sorted_starts:
            return

        for vaddr, offset, size in text_sections:
            chunk = self.data[offset: offset + size]
            if not chunk:
                continue

            for insn in md.disasm(chunk, vaddr):
                mnem = insn.mnemonic
                op = insn.op_str
                ia = insn.address

                idx = bisect.bisect_right(sorted_starts, ia) - 1
                if idx < 0:
                    continue
                fva = sorted_starts[idx]
                if ia - fva > 8192:
                    continue

                if mnem in ('call', 'callq') and op.startswith('0x'):
                    try:
                        target = int(op, 16)
                        self._callees.setdefault(fva, set()).add(target)
                    except ValueError:
                        pass

                elif mnem in ('lea', 'mov') and '[rip' in op:
                    target = _parse_rip_target(ia, insn.size, op)
                    if target and self._rodata_start <= target < self._rodata_end:
                        s = self._strings.get(target)
                        if s:
                            self._str_refs.setdefault(fva, set()).add(s)

        for caller_va, callee_set in self._callees.items():
            for callee in callee_set:
                self._callers.setdefault(callee, set()).add(caller_va)

    def _build_call_graph_arm32(self, func_starts: Optional[Set[int]] = None):
        """ARM32/Thumb flat scan using capstone ARM disassembler."""
        import bisect
        from capstone import arm as C_ARM

        text_sec = None
        text_va = 0
        text_off = 0
        text_size = 0
        if self._binary is not None:
            try:
                sec = self._binary.get_section('.text')
                if sec:
                    text_sec = sec
                    text_va = int(sec.virtual_address)
                    text_off = int(sec.offset)
                    text_size = int(sec.size)
            except Exception:
                pass

        if text_size == 0:
            return

        chunk = self.data[text_off: text_off + text_size]

        # Collect func starts: prefer caller-supplied; fall back to PUSH {lr} heuristic
        all_func_starts = set(func_starts or [])
        if not func_starts:
            # ARM PUSH {regs, lr}: byte[3]==0xE9, byte[2]==0x2D, byte[1] bit6 set (LR)
            for i in range(0, len(chunk) - 3, 4):
                if chunk[i + 3] == 0xE9 and chunk[i + 2] == 0x2D and (chunk[i + 1] & 0x40):
                    all_func_starts.add(text_va + i)

        self._func_starts = all_func_starts
        sorted_starts = sorted(all_func_starts)
        if not sorted_starts:
            return

        # Build a thumb_funcs set from eh_frame or symbol LSB (best-effort)
        thumb_funcs: Set[int] = set()
        if self._binary is not None:
            try:
                for sym in self._binary.dynamic_symbols:
                    if sym.name and sym.value and str(getattr(sym, 'type', '')).endswith('FUNC'):
                        if sym.value & 1:
                            thumb_funcs.add(sym.value & ~1)
            except Exception:
                pass

        # Flat scan: iterate each function range with the correct capstone mode
        for i, fva in enumerate(sorted_starts):
            end = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else text_va + text_size
            func_size = min(end - fva, 8192)
            if func_size <= 0:
                continue
            off = fva - text_va
            if off < 0 or off + func_size > len(chunk):
                continue
            fn_chunk = chunk[off: off + func_size]
            is_thumb = fva in thumb_funcs
            mode = capstone.CS_MODE_THUMB if is_thumb else capstone.CS_MODE_ARM
            md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
            md.detail = True
            md.skipdata = True

            for insn in md.disasm(fn_chunk, fva):
                mn = insn.mnemonic.lower()

                # Calls: BL / BLX with immediate target
                if mn in ('bl', 'blx'):
                    try:
                        ops = insn.operands
                        for op in ops:
                            if op.type == C_ARM.ARM_OP_IMM:
                                self._callees.setdefault(fva, set()).add(op.imm)
                    except Exception:
                        pass

                # String refs: LDR Rd, [PC, #off] -> pool -> .rodata pointer
                elif mn == 'ldr':
                    try:
                        ops = insn.operands
                        if len(ops) >= 2 and ops[1].type == C_ARM.ARM_OP_MEM:
                            if insn.reg_name(ops[1].mem.base).lower() == 'pc':
                                disp = ops[1].mem.disp
                                if is_thumb and insn.size == 2:
                                    pool_va = ((insn.address + 4) & ~3) + disp
                                elif is_thumb:
                                    pool_va = insn.address + 4 + disp
                                else:
                                    pool_va = insn.address + 8 + disp
                                pool_off = pool_va - text_va
                                ptr = None
                                if 0 <= pool_off <= len(chunk) - 4:
                                    ptr = struct.unpack_from('<I', chunk, pool_off)[0]
                                if ptr is not None and self._rodata_start <= ptr < self._rodata_end:
                                    s = self._strings.get(ptr)
                                    if s:
                                        self._str_refs.setdefault(fva, set()).add(s)
                    except Exception:
                        pass

        for caller_va, callee_set in self._callees.items():
            for callee in callee_set:
                self._callers.setdefault(callee, set()).add(caller_va)

    def _build_call_graph_arm64(self, func_starts: Optional[Set[int]] = None):
        """ARM64 flat scan: BL (direct call) + ADRP+ADD/LDR string refs."""
        import bisect

        # Determine capstone ARM64 arch constant (CS_ARCH_AARCH64 in capstone 6+, CS_ARCH_ARM64 in 5.x)
        arm64_arch = getattr(capstone, 'CS_ARCH_AARCH64', None) or getattr(capstone, 'CS_ARCH_ARM64', None)
        if arm64_arch is None:
            return

        text_sections = []
        if self._binary is not None:
            try:
                for sect in self._binary.sections:
                    if sect.name == '.text':
                        text_sections.append(
                            (int(sect.virtual_address), int(sect.offset), int(sect.size))
                        )
            except Exception:
                pass
        if not text_sections:
            return

        md = capstone.Cs(arm64_arch, capstone.CS_MODE_ARM)
        md.detail = True
        md.skipdata = True

        # Use caller-supplied or eh_frame func starts; fall back to STP x29,x30 prologue heuristic
        all_func_starts = set(func_starts or [])
        if not all_func_starts:
            for vaddr, offset, size in text_sections:
                chunk = self.data[offset: offset + size]
                # stp x29, x30, [sp, #-N]!  encoding: fd 7b ?? a9 (pre-index, negative offset)
                for i in range(0, len(chunk) - 3, 4):
                    if chunk[i] == 0xfd and chunk[i + 1] == 0x7b and chunk[i + 3] == 0xa9:
                        all_func_starts.add(vaddr + i)

        if not all_func_starts:
            return

        self._func_starts.update(all_func_starts)
        sorted_starts = sorted(self._func_starts)

        # Capstone ARM64 operand type constants
        try:
            from capstone import arm64 as C_A64
            OP_IMM = C_A64.ARM64_OP_IMM
            OP_REG = C_A64.ARM64_OP_REG
            OP_MEM = C_A64.ARM64_OP_MEM
        except ImportError:
            try:
                from capstone import aarch64 as C_A64
                OP_IMM = C_A64.AARCH64_OP_IMM
                OP_REG = C_A64.AARCH64_OP_REG
                OP_MEM = C_A64.AARCH64_OP_MEM
            except ImportError:
                OP_IMM, OP_REG, OP_MEM = 2, 1, 3

        for vaddr, offset, size in text_sections:
            chunk = self.data[offset: offset + size]
            if not chunk:
                continue

            # adrp state: reg_id -> (page_va, insn_va) for ADRP+ADD/LDR string resolution
            adrp_state: Dict[int, Tuple[int, int]] = {}

            for insn in md.disasm(chunk, vaddr):
                ia = insn.address
                mn = insn.mnemonic.lower()

                idx = bisect.bisect_right(sorted_starts, ia) - 1
                if idx < 0:
                    continue
                fva = sorted_starts[idx]
                if ia - fva > 16384:
                    continue

                try:
                    ops = insn.operands
                except Exception:
                    ops = []

                # BL <imm>: direct call with immediate target
                if mn == 'bl' and ops:
                    for op in ops:
                        if op.type == OP_IMM:
                            self._callees.setdefault(fva, set()).add(op.imm)
                            break

                # ADRP Xn, page: record page base per dest register
                elif mn == 'adrp' and len(ops) >= 2:
                    try:
                        dest_reg = ops[0].reg
                        page_va = ops[1].imm
                        adrp_state[dest_reg] = (page_va, ia)
                    except Exception:
                        pass

                # ADD Xd, Xn, #imm or LDR Xd, [Xn, #imm]: resolve ADRP+offset -> string ref
                elif mn in ('add', 'ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw') and len(ops) >= 2:
                    try:
                        if mn == 'add' and len(ops) >= 3:
                            base_reg = ops[1].reg if ops[1].type == OP_REG else None
                            imm_off = ops[2].imm if ops[2].type == OP_IMM else None
                        elif ops[1].type == OP_MEM:
                            base_reg = ops[1].mem.base
                            imm_off = ops[1].mem.disp
                        else:
                            base_reg, imm_off = None, None

                        if base_reg is not None and imm_off is not None and base_reg in adrp_state:
                            page_va, adrp_ia = adrp_state[base_reg]
                            if ia - adrp_ia <= 12:  # within 3 instructions
                                target = page_va + imm_off
                                if self._rodata_start <= target < self._rodata_end:
                                    s = self._strings.get(target)
                                    if s:
                                        self._str_refs.setdefault(fva, set()).add(s)
                    except Exception:
                        pass

        for caller_va, callee_set in self._callees.items():
            for callee in callee_set:
                self._callers.setdefault(callee, set()).add(caller_va)

    # ── stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        funcs_with_strings = sum(1 for v in self._str_refs.values() if v)
        funcs_with_callers = sum(1 for v in self._callers.values() if v)
        return {
            "functions": len(self._func_starts),
            "plt_entries": len(self._plt),
            "strings": len(self._strings),
            "call_edges": sum(len(v) for v in self._callees.values()),
            "funcs_with_string_refs": funcs_with_strings,
            "funcs_with_callers": funcs_with_callers,
        }
