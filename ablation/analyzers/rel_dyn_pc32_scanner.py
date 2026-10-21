"""
rel_dyn_pc32_scanner.py: Detect exec/net sink calls via R_386_PC32 relocations in i386 ELF.

4 things that weren't possible before in Ablation:

1. **Find exec/net imports BinaryContext misses in i386 PIC ELFs.** BinaryContext
   extracts PLT entries from `.rel.plt` (R_386_JUMP_SLOT). Some i386 shared objects
   use R_386_PC32 direct-call fixups in `.rel.dyn` instead — these binaries report
   plt=0 yet import system(), popen(), fork(), connect(), recv(), etc. This scanner
   reads `.rel.dyn` directly from the ELF headers, bypassing LIEF/BinaryContext.

2. **Report the exact call-site VA for every matched relocation.** R_386_PC32
   stores the call site offset in the relocation entry (`r_offset`). The scanner
   maps this to a VA (file_offset + load_bias) so downstream capstone traces can
   start at the right instruction without a separate symbol search.

3. **Classify sinks by family.** Each hit is tagged EXEC (shell/process) or NET
   (socket/network) so callers can run SAC-level classification without re-reading
   the relocation table.

4. **Work standalone on raw ELF bytes.** No BinaryContext, no LIEF required — the
   scanner parses ELF32 section headers and `.rel.dyn` data using only `struct`.
   This is intentional: the scanner exists precisely to cover binaries that fail
   normal BinaryContext import extraction.

Root cause of the gap: i386 PIC shared objects historically used two call models.
  - PLT stub model (R_386_JUMP_SLOT): BinaryContext handles these correctly.
  - Direct-call model (R_386_PC32): the GOT-relative call fixup is in `.rel.dyn`,
    not `.rel.plt`. BinaryContext's `_build_plt()` only scans `.rel.plt` / `.rela.plt`.

Examples found in IBM-RE: libevfbpv.so (system via R_386_PC32 at 0x3ac87e),
libevfbsc.so, libevfrpv.so, libevfrsc.so (net sinks), liblinux.so (fork + socket).

Usage:
    scanner = RelDynPc32Scanner.from_path('/path/to/i386.so')
    hits = scanner.scan()
    print(scanner.report(hits))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


EXEC_SINKS: Set[str] = {
    'system', 'popen', 'fork', 'vfork', 'execve', 'execvp', 'execl', 'execle',
    'execvpe', 'execveat', 'posix_spawn', 'posix_spawnp',
}
NET_SINKS: Set[str] = {
    'socket', 'bind', 'listen', 'accept', 'accept4', 'connect',
    'recv', 'recvfrom', 'recvmsg', 'send', 'sendto', 'sendmsg',
    'gethostbyname', 'getaddrinfo',
}

# R_386_PC32 type value in ELF spec
_R386_PC32 = 2


@dataclass
class Pc32Hit:
    """A single R_386_PC32 relocation targeting an exec or net sink."""
    r_offset: int
    sym_name: str
    family: str      # 'EXEC' or 'NET'
    load_bias: int   # VA = r_offset + load_bias (0 for .so, non-zero for PIE)

    @property
    def call_va(self) -> int:
        return self.r_offset + self.load_bias

    def fmt(self) -> str:
        return (
            f"[{self.family}] {self.sym_name} via R_386_PC32 at "
            f"offset 0x{self.r_offset:x} (call VA 0x{self.call_va:x})"
        )


class RelDynPc32Scanner:
    """
    Scans an i386 ELF's .rel.dyn section for R_386_PC32 relocations that
    target exec-class (EXEC) or network (NET) sink functions.

    The scanner parses ELF32 section headers and the dynamic symbol table
    directly from raw bytes, without LIEF or BinaryContext. This is intentional —
    it exists specifically to cover the case where BinaryContext reports plt=0
    yet the binary imports exec/net symbols via .rel.dyn.
    """

    def __init__(self, data: bytes, path: str = '') -> None:
        self._data = data
        self._path = path
        self._load_bias = 0   # 0 for shared objects; non-zero only for ET_EXEC with non-zero load
        self._rel_dyn: Optional[Tuple[int, int]] = None    # (offset, size) in file
        self._dynsym: Optional[Tuple[int, int, int]] = None  # (offset, entsize, count)
        self._dynstr: Optional[Tuple[int, int]] = None     # (offset, size)
        self._parsed = False

    # ── Construction ─────────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> 'RelDynPc32Scanner':
        data = Path(path).read_bytes()
        obj = cls(data, path)
        return obj

    @classmethod
    def from_context(cls, ctx) -> 'RelDynPc32Scanner':
        """Accept a BinaryContext; extracts path and reads raw bytes."""
        if not ctx.path:
            raise ValueError("BinaryContext has no path")
        return cls.from_path(ctx.path)

    # ── ELF32 parsing ────────────────────────────────────────────────────────────

    def _parse_elf(self) -> bool:
        """Parse ELF32 section headers, locate .rel.dyn, .dynsym, .dynstr."""
        d = self._data
        if len(d) < 52 or d[:4] != b'\x7fELF':
            return False
        e_class = d[4]
        if e_class != 1:    # ELFCLASS32 only
            return False
        ei_data = d[5]      # 1=LSB, 2=MSB
        if ei_data != 1:    # only LE i386
            return False

        def u16(off: int) -> int:
            return struct.unpack_from('<H', d, off)[0]
        def u32(off: int) -> int:
            return struct.unpack_from('<I', d, off)[0]

        e_shoff = u32(32)
        e_shentsize = u16(46)
        e_shnum = u16(48)
        e_shstrndx = u16(50)

        if e_shoff == 0 or e_shentsize < 40 or e_shnum == 0:
            return False

        # Read section name string table
        shstr_off = e_shoff + e_shstrndx * e_shentsize
        if shstr_off + e_shentsize > len(d):
            return False
        shstr_data_off = u32(shstr_off + 16)
        shstr_size = u32(shstr_off + 20)

        def sh_name(name_off: int) -> str:
            start = shstr_data_off + name_off
            end = d.find(b'\x00', start)
            if end == -1 or end > shstr_data_off + shstr_size:
                return ''
            return d[start:end].decode('ascii', errors='replace')

        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            if sh + e_shentsize > len(d):
                break
            sh_type = u32(sh + 4)
            sh_offset = u32(sh + 16)
            sh_size = u32(sh + 20)
            sh_entsize = u32(sh + 36)
            sh_link = u32(sh + 24)   # for SHT_REL: linked .dynsym section index
            name_off = u32(sh)
            name = sh_name(name_off)

            # SHT_REL = 9
            if sh_type == 9 and name == '.rel.dyn':
                self._rel_dyn = (sh_offset, sh_size)

            # SHT_DYNSYM = 11
            if sh_type == 11 and name == '.dynsym':
                count = sh_size // sh_entsize if sh_entsize else 0
                self._dynsym = (sh_offset, sh_entsize, count)

            # SHT_STRTAB = 3, name == '.dynstr'
            if sh_type == 3 and name == '.dynstr':
                self._dynstr = (sh_offset, sh_size)

        self._parsed = True
        return self._rel_dyn is not None and self._dynsym is not None and self._dynstr is not None

    def _sym_name(self, sym_idx: int) -> str:
        """Look up a symbol name by index in .dynsym."""
        if not self._dynsym or not self._dynstr:
            return ''
        sym_off, sym_entsize, sym_count = self._dynsym
        if sym_idx >= sym_count:
            return ''
        entry_off = sym_off + sym_idx * sym_entsize
        name_off = struct.unpack_from('<I', self._data, entry_off)[0]
        str_off = self._dynstr[0] + name_off
        end = self._data.find(b'\x00', str_off)
        if end == -1:
            return ''
        raw = self._data[str_off:end].decode('ascii', errors='replace')
        # Strip versioning suffix (@GLIBC_2.0 etc.)
        return raw.split('@')[0]

    # ── Scan ─────────────────────────────────────────────────────────────────────

    def scan(self) -> List[Pc32Hit]:
        """
        Scan .rel.dyn for R_386_PC32 relocations targeting EXEC or NET sinks.

        Returns a list of Pc32Hit objects, one per matched relocation entry.
        """
        if not self._parsed:
            if not self._parse_elf():
                return []
        if not self._rel_dyn:
            return []

        hits: List[Pc32Hit] = []
        d = self._data
        rel_off, rel_size = self._rel_dyn

        # .rel.dyn entries are 8 bytes each: r_offset (4), r_info (4)
        n_entries = rel_size // 8
        for i in range(n_entries):
            entry_off = rel_off + i * 8
            if entry_off + 8 > len(d):
                break
            r_offset, r_info = struct.unpack_from('<II', d, entry_off)
            r_type = r_info & 0xFF
            r_sym = r_info >> 8
            if r_type != _R386_PC32:
                continue
            name = self._sym_name(r_sym)
            if not name:
                continue
            if name in EXEC_SINKS:
                family = 'EXEC'
            elif name in NET_SINKS:
                family = 'NET'
            else:
                continue
            hits.append(Pc32Hit(r_offset, name, family, self._load_bias))

        return hits

    # ── Report ───────────────────────────────────────────────────────────────────

    def report(self, hits: List[Pc32Hit]) -> str:
        if not hits:
            return f"RelDynPc32Scanner: {self._path or '(bytes)'} — 0 EXEC/NET hits in .rel.dyn R_386_PC32"
        exec_hits = [h for h in hits if h.family == 'EXEC']
        net_hits = [h for h in hits if h.family == 'NET']
        lines = [
            f"RelDynPc32Scanner: {self._path or '(bytes)'}",
            f"  {len(hits)} R_386_PC32 hits: {len(exec_hits)} EXEC, {len(net_hits)} NET",
        ]
        if exec_hits:
            lines.append("  EXEC sinks:")
            for h in exec_hits:
                lines.append(f"    {h.fmt()}")
        if net_hits:
            lines.append("  NET sinks:")
            for h in net_hits:
                lines.append(f"    {h.fmt()}")
        return '\n'.join(lines)

    @property
    def exec_names(self) -> Set[str]:
        """Quick property: set of exec sink names found (for pipeline use)."""
        return {h.sym_name for h in self.scan() if h.family == 'EXEC'}

    @property
    def net_names(self) -> Set[str]:
        """Quick property: set of net sink names found (for pipeline use)."""
        return {h.sym_name for h in self.scan() if h.family == 'NET'}
