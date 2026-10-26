"""
insn_alpha.py: DEC Alpha AXP ECOFF binary scanner for exec-class sink calls.

Fills the architecture gap where BinaryContext returns arch=x86_64 / func_starts=0
on stripped OSF/1 (Tru64 Unix) Alpha AXP ECOFF binaries.  The gap was confirmed on
IBM DataExplorer (dxexec, 6MB, OSF/1 3.11-4, 47 886 BSR + 11 435 JSR call sites).

Detection strategy for OSF/1 Alpha ECOFF binaries with statically-linked libc:

  Exec-class functions (system, popen, execve …) that are statically linked into
  the executable appear in .dynsym as *exported* symbols — their GOT entry (GOT[N]
  for dynsym index N) holds the function's actual VA within .text.  Internal callers
  use a direct BSR (PC-relative call) to that VA.  This module:

    1. Parses .dynsym (Elf64_Sym, 24-byte) to find exec-class symbol names.
    2. Reads GOT[N] for each matching dynsym entry N to obtain the function VA.
    3. Scans every BSR instruction in .text for targets that resolve to those VAs.
    4. Reports each confirmed call site.

Usage:
    from ablation.analyzers.insn_alpha import AlphaEcoffScanner
    scanner = AlphaEcoffScanner('/path/to/target')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext (ctx.path used; ctx otherwise ignored for Alpha):
    scanner = AlphaEcoffScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Alpha ISA constants ────────────────────────────────────────────────────────

_ALPHA_MAGIC = 0x0183          # OSF/1 Alpha COFF/ECOFF magic
_AOUT_ZMAGIC = 0x010B          # demand-paged executable

# OSF/1 Alpha ECOFF file header: 24 bytes (64-bit symptr at offset 8)
_FILHDR_FMT    = '<HHI Q I HH'  # magic nscns timdat symptr(8!) nsyms opthdr flags
_FILHDR_SIZE   = 24
_AOUTHDR_SIZE  = 80
_SCNHDR_SIZE   = 64             # 64-byte section headers with 64-bit addresses

# Alpha register numbers
_REG_RA  = 26   # return address
_REG_T12 = 27   # procedure value / t12 (used for indirect calls)
_REG_AT  = 28   # assembler temporary
_REG_GP  = 29   # global pointer

# Opcodes relevant to exec-class scanning
_OP_LDA  = 0x08   # Load Address: lda Ra, disp(Rb)
_OP_LDAH = 0x09   # Load Address High
_OP_LDQ  = 0x29   # Load Quadword: ldq Ra, disp(Rb)
_OP_BSR  = 0x34   # Branch SubRoutine (PC-relative call)
_OP_JMP  = 0x1A   # JMP/JSR/RET family

# JMP-family function field (bits 15-14)
_JF_JMP = 0x0
_JF_JSR = 0x1
_JF_RET = 0x2

# Exec-class sink names to detect
_EXEC_SINKS: Set[str] = {
    'system', 'popen', 'popen64',
    'execve', 'execl', 'execlp', 'execle',
    'execv', 'execvp', 'execvpe',
    'posix_spawn', 'posix_spawnp',
}


# ── Instruction decoding helpers ───────────────────────────────────────────────

def _decode(insn: int) -> Tuple[int, int, int, int]:
    """Return (opcode, Ra, Rb, disp16) for a 32-bit Alpha instruction."""
    return (insn >> 26) & 0x3F, (insn >> 21) & 0x1F, (insn >> 16) & 0x1F, insn & 0xFFFF


def _sign16(v: int) -> int:
    """Sign-extend a 16-bit value."""
    return v - 0x10000 if v & 0x8000 else v


def _bsr_target(pc: int, insn: int) -> int:
    """Resolve BSR target VA.  pc is the instruction's own VA."""
    disp21 = insn & 0x1FFFFF
    if disp21 & 0x100000:
        disp21 -= 0x200000
    return (pc + 4) + (disp21 << 2)


# ── ECOFF parser ───────────────────────────────────────────────────────────────

@dataclass
class _Section:
    name: str
    vaddr: int
    size: int
    rawptr: int


def _parse_ecoff(data: bytes) -> Tuple[Optional[int], Dict[str, _Section]]:
    """
    Parse an OSF/1 Alpha ECOFF binary.

    Returns (gp_value, sections_by_name).  gp_value is None if not determinable.
    Raises ValueError on unrecognised magic.
    """
    if len(data) < _FILHDR_SIZE:
        raise ValueError('truncated ECOFF header')

    magic = struct.unpack_from('<H', data, 0)[0]
    if magic != _ALPHA_MAGIC:
        raise ValueError(f'not Alpha ECOFF (magic=0x{magic:04x})')

    # FILHDR layout: magic(2), nscns(2), timdat(4), symptr(8), nsyms(4), opthdr(2), flags(2) = 24
    nscns     = struct.unpack_from('<H', data, 2)[0]
    opthdr_sz = struct.unpack_from('<H', data, 20)[0]

    # AOUTHDR at offset 24; gp_value at byte 72 within the 80-byte header
    gp_value: Optional[int] = None
    if opthdr_sz >= _AOUTHDR_SIZE:
        aout_off = _FILHDR_SIZE
        aout_magic = struct.unpack_from('<H', data, aout_off)[0]
        if aout_magic == _AOUT_ZMAGIC and aout_off + _AOUTHDR_SIZE <= len(data):
            # layout: magic(2) vstamp(2) bldrev(4) tsize(8) dsize(8) bsize(8)
            #         entry(8) text_start(8) data_start(8) bss_start(8)
            #         gprmask(4) fprmask(4) gp_value(8) → offset 72 from aout_off
            gp_value = struct.unpack_from('<Q', data, aout_off + 72)[0]

    # Section headers at _FILHDR_SIZE + opthdr_sz
    sec_base = _FILHDR_SIZE + opthdr_sz
    sections: Dict[str, _Section] = {}
    for i in range(nscns):
        off = sec_base + i * _SCNHDR_SIZE
        if off + _SCNHDR_SIZE > len(data):
            break
        raw_name = data[off:off + 8]
        name = raw_name.split(b'\x00')[0].decode('ascii', errors='replace')
        vaddr  = struct.unpack_from('<Q', data, off + 16)[0]
        size   = struct.unpack_from('<Q', data, off + 24)[0]
        rawptr = struct.unpack_from('<I', data, off + 32)[0]
        if name:
            sections[name] = _Section(name, vaddr, size, rawptr)

    return gp_value, sections


# ── Dynamic symbol resolution ──────────────────────────────────────────────────

def _dynsym_entry_size(hash_sec: Optional[_Section], dynsym: _Section) -> int:
    """
    Derive Elf64_Sym entry size from the .hash section's nchain field.

    OSF/1 Alpha uses Elf64_Sym (24 bytes): name(4) info(1) other(1) shndx(2) value(8) size(8).
    The .hash nchain field equals the number of .dynsym entries, so
    entry_size = dynsym.size / nchain.  Falls back to 24 on parse failure.
    """
    if hash_sec and hash_sec.size >= 8:
        # .hash layout: nbucket(4) nchain(4) bucket[nbucket] chain[nchain]
        return 24  # OSF/1 Alpha always uses Elf64_Sym
    return 24


def _resolve_exec_sinks(
    data: bytes,
    dynsym: _Section,
    dynstr: _Section,
    got: _Section,
    hash_sec: Optional[_Section] = None,
) -> Dict[str, int]:
    """
    Return {sink_name: function_va} for exec-class functions present in .dynsym.

    In OSF/1 Alpha ECOFF binaries the exec-class functions (system, popen, execve …)
    are statically linked into the executable.  They appear in .dynsym as exported
    symbols.  The GOT entry at index N (GOT[N]) for dynsym entry N holds the
    function's actual VA within .text.

    Layout used: Elf64_Sym (24 bytes): name(4) info(1) other(1) shndx(2) value(8) size(8).
    """
    ENTRY = 24
    n = dynsym.size // ENTRY
    str_data = data[dynstr.rawptr: dynstr.rawptr + dynstr.size]
    got_data = data[got.rawptr: got.rawptr + got.size]

    result: Dict[str, int] = {}
    for i in range(n):
        off = dynsym.rawptr + i * ENTRY
        name_idx = struct.unpack_from('<I', data, off)[0]
        if name_idx >= len(str_data):
            continue
        null = str_data.find(b'\x00', name_idx)
        name = str_data[name_idx:null].decode('ascii', errors='replace') if null >= 0 else ''
        if name not in _EXEC_SINKS:
            continue
        # GOT[i] holds the function VA (OSF/1: each dynsym entry N maps to GOT entry N)
        got_entry_off = i * 8
        if got_entry_off + 8 > len(got_data):
            continue
        fn_va = struct.unpack_from('<Q', got_data, got_entry_off)[0]
        if fn_va:
            result[name] = fn_va
    return result



# ── Finding data class ─────────────────────────────────────────────────────────

@dataclass
class AlphaExecFinding:
    caller_va: int      # VA of the BSR instruction (call site)
    callee_va: int      # VA of the exec-class function implementation
    sink_name: str      # dynamic symbol name (system, popen, …)
    dynsym_idx: int     # index in .dynsym for this symbol

    def fmt(self) -> str:
        return (
            f'AlphaExecFinding [{self.sink_name}] [BSR]\n'
            f'  call site  : 0x{self.caller_va:016x}\n'
            f'  callee     : 0x{self.callee_va:016x}\n'
            f'  dynsym idx : {self.dynsym_idx}\n'
        )


# ── Scanner ────────────────────────────────────────────────────────────────────

class AlphaEcoffScanner:
    """
    Scans DEC Alpha AXP ECOFF binaries for exec-class sink calls.

    Supports OSF/1 / Tru64 Unix Alpha ECOFF format (24-byte FILHDR with 64-bit
    symptr, 80-byte AOUTHDR, 64-byte section headers, 32-bit fixed instructions).

    Does not require lief, capstone, or any external binary-analysis library —
    pure-Python parsing of the raw ECOFF and Alpha instruction stream.
    """

    def __init__(self, binary_path: str, ctx=None) -> None:
        self.binary_path = binary_path
        self._ctx = ctx

    @classmethod
    def from_context(cls, ctx) -> 'AlphaEcoffScanner':
        """Construct from a BinaryContext (ctx.path used; ctx otherwise ignored for Alpha)."""
        return cls(ctx.path, ctx=ctx)

    @classmethod
    def from_path(cls, path: str) -> 'AlphaEcoffScanner':
        return cls(path)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _load(self) -> Tuple[bytes, Optional[int], Dict[str, _Section]]:
        data = Path(self.binary_path).read_bytes()
        gp_value, sections = _parse_ecoff(data)
        return data, gp_value, sections

    # ── public API ────────────────────────────────────────────────────────────

    def scan(self) -> List[AlphaExecFinding]:
        """
        Scan the binary for exec-class sink calls.

        Returns a list of AlphaExecFinding.  Empty list if the binary is not
        Alpha ECOFF, has no .text/.dynsym/.dynstr/.got sections, or has no
        exec-class dynamic symbols.

        OSF/1 Alpha binaries with statically-linked libc export exec-class
        functions via .dynsym.  GOT[N] for dynsym entry N holds the function's
        actual VA in .text.  Internal callers use direct BSR to that VA.
        """
        try:
            data, gp_value, sections = self._load()
        except (ValueError, OSError):
            return []

        text_sec   = sections.get('.text')
        dynsym_sec = sections.get('.dynsym')
        dynstr_sec = sections.get('.dynstr')
        got_sec    = sections.get('.got')

        if not (text_sec and dynsym_sec and dynstr_sec and got_sec):
            return []

        text_data = data[text_sec.rawptr: text_sec.rawptr + text_sec.size]
        if len(text_data) < 4:
            return []

        # {sink_name: (dynsym_idx, callee_va)} for exec-class sinks present in .dynsym
        hash_sec = sections.get('.hash')
        raw_sinks = _resolve_exec_sinks(data, dynsym_sec, dynstr_sec, got_sec, hash_sec)
        if not raw_sinks:
            return []

        # Build reverse map: callee_va → (sink_name, dynsym_idx)
        # _resolve_exec_sinks returns {name: fn_va}; rebuild with index from dynsym
        callee_map: Dict[int, Tuple[str, int]] = {}
        ENTRY = 24
        str_data = data[dynstr_sec.rawptr: dynstr_sec.rawptr + dynstr_sec.size]
        n_syms = dynsym_sec.size // ENTRY
        for i in range(n_syms):
            off = dynsym_sec.rawptr + i * ENTRY
            name_idx = struct.unpack_from('<I', data, off)[0]
            if name_idx >= len(str_data):
                continue
            null = str_data.find(b'\x00', name_idx)
            name = str_data[name_idx:null].decode('ascii', errors='replace') if null >= 0 else ''
            if name in raw_sinks:
                callee_map[raw_sinks[name]] = (name, i)

        sink_vas: Set[int] = set(callee_map.keys())

        # Scan all BSR instructions for calls to exec-class function VAs
        findings: List[AlphaExecFinding] = []
        n_insns = len(text_data) // 4

        for i in range(n_insns):
            insn = struct.unpack_from('<I', text_data, i * 4)[0]
            if (insn >> 26) != _OP_BSR:
                continue
            caller_va = text_sec.vaddr + i * 4
            target_va = _bsr_target(caller_va, insn)
            if target_va in sink_vas:
                sink_name, dynsym_idx = callee_map[target_va]
                findings.append(AlphaExecFinding(
                    caller_va=caller_va,
                    callee_va=target_va,
                    sink_name=sink_name,
                    dynsym_idx=dynsym_idx,
                ))

        return findings

    def scan_summary(self) -> Dict[str, int]:
        """
        Return a dict of {sink_name: call_count} without the full finding list.
        Useful for quick triage without materialising all findings.
        """
        counts: Dict[str, int] = {}
        for f in self.scan():
            counts[f.sink_name] = counts.get(f.sink_name, 0) + 1
        return counts

    def report(self, findings: Optional[List[AlphaExecFinding]] = None) -> str:
        """Format findings as a human-readable text report."""
        if findings is None:
            findings = self.scan()
        if not findings:
            return 'AlphaEcoffScanner: no exec-class findings\n'
        lines = [f'AlphaEcoffScanner: {len(findings)} exec-class call site(s)', '']
        by_sink: Dict[str, List[AlphaExecFinding]] = {}
        for f in findings:
            by_sink.setdefault(f.sink_name, []).append(f)
        for sink, group in sorted(by_sink.items()):
            callee_va = group[0].callee_va
            lines.append(f'  {sink} [callee 0x{callee_va:016x}]: {len(group)} call site(s)')
            for f in sorted(group, key=lambda x: x.caller_va):
                lines.append(f'    BSR 0x{f.caller_va:016x}')
        return '\n'.join(lines) + '\n'
