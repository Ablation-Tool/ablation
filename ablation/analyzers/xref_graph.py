"""
xref_graph.py -- x86-64 ELF cross-reference graph: strings, call graph, callers.

Closes the primary capability gap vs. Ghidra: knowing what strings a function
references and who calls it. Both dramatically improve BERT embedding quality.

Key outputs per function VA:
  strings_at(va)  -- printable strings the function references (via RIP-relative LEA/MOV)
  callees(va)     -- VAs this function calls directly
  callers(va)     -- VAs that call this function
  plt_name(va)    -- imported symbol name if va is a PLT entry

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
        # Augment _func_starts with discovered callees -- catches leaf functions
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
                    # GOT address; PLT entry is typically GOT - plt_offset, but
                    # we store the GOT VA and also try to find PLT entry
                    self._plt[rel.address] = rel.symbol.name
        except Exception:
            pass
        # PLT section disassembly to recover stub VA -> name mapping.
        # Modern gcc/ld with IBT/CET produces three sections:
        #   .plt      -- resolver + legacy stubs (PLT[0])
        #   .plt.sec  -- per-function stubs: ENDBR64 + JMP [RIP+offset]
        #   .plt.got  -- GOT-backed stubs (non-lazy)
        # We scan all three; .plt.sec is the critical one for modern binaries.
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
                        # Skip ENDBR64 (f3 0f 1e fa) -- 4 bytes, continue
                        if insn.mnemonic == 'endbr64':
                            continue
                        # Any other prefix before jmp: skip
                        if insn.mnemonic not in ('endbr64', 'nop'):
                            break
            except Exception:
                pass

        _scan_plt_section('.plt', skip_first=True)   # skip resolver stub at PLT[0]
        _scan_plt_section('.plt.sec', skip_first=False)
        _scan_plt_section('.plt.got', skip_first=False)

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
        Flat-scan disassembly: iterate text sections once, attribute every call
        and RIP-relative string-load to its containing function via binary search.
        Breaking at 'ret' is avoided so functions with multiple return paths are
        fully covered.
        """
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

        # Phase 1: collect function starts from prologue heuristic
        for vaddr, offset, size in text_sections:
            chunk = self.data[offset: offset + size]
            if not chunk:
                continue
            if not func_starts:
                for i in range(len(chunk) - 3):
                    if chunk[i] == 0x55 and chunk[i + 1:i + 3] == b'\x48\x89':
                        all_func_starts.add(vaddr + i)

        self._func_starts = all_func_starts
        sorted_starts = sorted(all_func_starts)

        if not sorted_starts:
            return

        # Phase 2: flat scan -- attribute instructions to containing function
        # by bisect on sorted_starts
        for vaddr, offset, size in text_sections:
            chunk = self.data[offset: offset + size]
            if not chunk:
                continue

            for insn in md.disasm(chunk, vaddr):
                mnem = insn.mnemonic
                op = insn.op_str
                ia = insn.address

                # Find containing function: largest start <= ia
                idx = bisect.bisect_right(sorted_starts, ia) - 1
                if idx < 0:
                    continue
                fva = sorted_starts[idx]
                # Sanity: don't attribute beyond 8KB from function start
                if ia - fva > 8192:
                    continue

                # Direct calls
                if mnem in ('call', 'callq') and op.startswith('0x'):
                    try:
                        target = int(op, 16)
                        if fva not in self._callees:
                            self._callees[fva] = set()
                        self._callees[fva].add(target)
                    except ValueError:
                        pass

                # RIP-relative string loads
                elif mnem in ('lea', 'mov') and '[rip' in op:
                    target = _parse_rip_target(ia, insn.size, op)
                    if target and self._rodata_start <= target < self._rodata_end:
                        s = self._strings.get(target)
                        if s:
                            if fva not in self._str_refs:
                                self._str_refs[fva] = set()
                            self._str_refs[fva].add(s)

        # Phase 3: build reverse edges from callees
        for caller_va, callee_set in self._callees.items():
            for callee in callee_set:
                if callee not in self._callers:
                    self._callers[callee] = set()
                self._callers[callee].add(caller_va)

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
