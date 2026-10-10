"""
CppVtableReconstructorAnalyzer — standalone C++ virtual dispatch reconstruction.

Three-layer pipeline (no external tools required):

  Layer 1  scan_vtables()    — extract vtables from any ELF; uses
           RELA-based approach (dynamic ELF, any arch) with raw code-pointer
           scan fallback (static/non-PIE binaries).  ET_DYN and ET_EXEC both
           handled correctly via _va_to_file_offset().

  Layer 2  name_slots()      — name each slot via export symbols, BinaryContext
           string xrefs, and callee function names; no corpus build needed

  Layer 3  trace_consumers() — find call sites that dispatch through known
           vtable slots; groups by enclosing function when symbols are available
           x86-64:      full encoding coverage via VtableDispatchScanner
           ARM64:       BLR site detection via vtable_resolver
           Others:      vtable-pointer literal scan (_trace_generic); covers
                        LoongArch64, MIPS, PPC32, PPC64, RISC-V, and any other
                        arch where the compiler embeds the vtable VA as a
                        pointer-sized literal in .text

Output artifacts:
  report()          — human-readable annotated call graph
  emit_ida_script() — type-annotation + comment script for the full
                      producer-to-consumer chain

Supports:  any ELF for vtable extraction and slot naming.
Consumer tracing: x86-64 and ARM64 full ISA coverage; all other arches via
pointer literal scan (catches direct vtable loads; misses register-indirect).

Relationship to existing modules:
  ELFVtableReconstructor   — x86-64 only, by class name or VA; no naming/script
  VtableResolver           — ARM64 BLR resolution; no naming/script
  CppVtableReconstructorAnalyzer — arch-agnostic; naming + annotation output
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import lief

_SHF_WRITE    = 0x1   # ELF SHF_WRITE: section is writable at runtime
_SHF_EXECINSTR = 0x4  # ELF SHF_EXECINSTR: section contains executable machine instructions


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SlotSpec:
    """One vtable slot: index, byte offset from vtable_ptr, target VA, name."""
    slot_index: int
    slot_offset: int        # byte offset = slot_index * 8
    func_va: int
    func_name: str          # empty string if not resolved
    name_source: str        # 'export' | 'ctx_name' | 'string_xref' | 'callee_name' | 'unknown'


@dataclass
class VtableSpec:
    """
    One C++ vtable.

    va is the vtable_ptr address — the value stored in object vptr fields.
    In the Itanium C++ ABI this points to vfunc[0], which is 16 bytes past
    the start of the vtable array (after offset-to-top and RTTI pointer).
    has_itanium_header is set when that 16-byte header is detected.

    ctor_sites lists VAs where this vtable VA appears in the binary's data
    sections (vptr slots in subclass vtables or global objects).

    section_name names the ELF section that contains this vtable.
    writable is True when that section is writable at runtime — meaning any
    kernel or process write primitive that reaches the vtable data can
    overwrite a slot and redirect the next virtual dispatch call.
    Normal vtables live in .rodata or .data.rel.ro (read-only after RELRO);
    a vtable in .data is mutable for the entire lifetime of the process.
    """
    va: int
    slots: List[SlotSpec]
    type_name: str              # inferred; empty if unknown
    ctor_sites: List[int]       # VAs of vptr slots referencing this vtable
    has_itanium_header: bool = False
    section_name: str = ''      # ELF section name, e.g. '.rodata' or '.data'
    writable: bool = False      # True when section lacks SHF_WRITE protection

    def slot_by_index(self, idx: int) -> Optional[SlotSpec]:
        for s in self.slots:
            if s.slot_index == idx:
                return s
        return None

    def slot_by_offset(self, off: int) -> Optional[SlotSpec]:
        for s in self.slots:
            if s.slot_offset == off:
                return s
        return None

    def named_slots(self) -> List[SlotSpec]:
        return [s for s in self.slots if s.func_name]


@dataclass
class TypePropSite:
    """One function that is a consumer of a vtable type."""
    func_va: int
    func_name: str
    role: str = 'consumer'
    slot_calls: List[Tuple[int, int, str]] = field(default_factory=list)
    # each entry: (call_pc, slot_index, slot_name)


@dataclass
class VtableReconstructorResult:
    vtables: List[VtableSpec]
    propagation: List[TypePropSite]
    binary_path: str
    arch: str
    named_slot_count: int
    total_slot_count: int
    resolved_call_count: int


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _elf_arch(data: bytes) -> str:
    """Normalize ELF e_machine to an arch string."""
    if len(data) < 20:
        return 'unknown'
    e_machine = struct.unpack_from('<H', data, 18)[0]
    return {
        0x3e:  'x86_64',
        0xb7:  'arm64',
        0x102: 'loongarch64',
        0x14:  'ppc32',
        0x15:  'ppc64',
        0xf3:  'riscv',
        0x08:  'mips',
    }.get(e_machine, f'elf_{e_machine:#x}')


def _strip_lib_prefix(name: str) -> str:
    """Remove common library prefixes to produce a clean slot name."""
    for prefix in (
        'BN_', 'RSA_', 'EC_', 'EVP_', 'AES_', 'SHA_', 'HMAC_',
        'SSL_', 'TLS_', 'ossl_', 'CRYPTO_', 'ERR_', 'DSA_', 'DH_',
    ):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name.lstrip('_')


def _looks_like_slot_name(s: str) -> bool:
    """Heuristic: is this string a plausible vtable slot name?"""
    if len(s) < 3 or len(s) > 32:
        return False
    if ' ' in s or '%' in s:        # error messages, format strings
        return False
    if not s.replace('_', '').isalnum():
        return False
    return True


def _binary_search_le(sorted_list: List[int], va: int) -> int:
    """Return the largest element <= va, or 0 if none."""
    lo, hi, result = 0, len(sorted_list) - 1, 0
    while lo <= hi:
        mid = (lo + hi) >> 1
        if sorted_list[mid] <= va:
            result = sorted_list[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class CppVtableReconstructorAnalyzer:
    """
    Standalone C++ vtable reconstructor.

    Minimum viable (no BinaryContext):
        analyzer = CppVtableReconstructorAnalyzer.from_path('/path/to/lib.so')
        result   = analyzer.scan()
        print(CppVtableReconstructorAnalyzer.report(result))
        print(CppVtableReconstructorAnalyzer.emit_ida_script(
                  result.vtables, result.propagation))

    Full (with BinaryContext for slot naming):
        ctx      = BinaryContext.load_or_build('/path/to/lib.so')
        analyzer = CppVtableReconstructorAnalyzer.from_context(ctx)
        result   = analyzer.scan()
    """

    def __init__(self, elf_path: str, ctx=None):
        self._path = elf_path
        self._ctx = ctx
        with open(elf_path, 'rb') as fh:
            self._data = fh.read()
        self._arch = _elf_arch(self._data)
        self._lief: Optional[lief.ELF.Binary] = None

    @classmethod
    def from_path(cls, elf_path: str) -> 'CppVtableReconstructorAnalyzer':
        return cls(elf_path)

    @classmethod
    def from_context(cls, ctx) -> 'CppVtableReconstructorAnalyzer':
        return cls(ctx.binary_path, ctx=ctx)

    # ── LIEF access ──────────────────────────────────────────────────────────

    def _binary(self) -> lief.ELF.Binary:
        if self._lief is None:
            parsed = lief.parse(self._path)
            if parsed is None:
                raise ValueError(f'lief could not parse {self._path} as ELF')
            self._lief = parsed
        return self._lief

    def _section(self, name: str) -> Optional[lief.ELF.Section]:
        for sec in self._binary().sections:
            if sec.name == name:
                return sec
        return None

    def _va_to_file_offset(self, va: int) -> Optional[int]:
        """Convert a virtual address to its file byte offset.

        Walks section headers and returns ``sec.offset + (va - sec.virtual_address)``
        for the section that contains *va*.  Returns ``None`` when no section covers
        the address.  ET_DYN and ET_EXEC both work correctly: the answer is the
        actual position to index into ``self._data``.
        """
        for sec in self._binary().sections:
            if sec.size == 0:
                continue
            sec_va = sec.virtual_address
            if sec_va <= va < sec_va + sec.size:
                return int(sec.offset) + (va - sec_va)
        return None

    def _section_for_va(self, va: int) -> Tuple[str, bool]:
        """Return (section_name, writable) for the ELF section that contains va.

        writable is True when the section has SHF_WRITE (0x1) set — meaning the
        section is writable at runtime and any kernel write primitive reaching
        this vtable can overwrite dispatch slots.  Returns ('', False) when no
        section covers the address.
        """
        for sec in self._binary().sections:
            if sec.size == 0:
                continue
            if sec.virtual_address <= va < sec.virtual_address + sec.size:
                return sec.name, bool(sec.flags & _SHF_WRITE)
        return '', False

    def _text_range(self) -> Tuple[int, int]:
        """Return (text_va, text_end)."""
        sec = self._section('.text')
        if sec is None:
            return 0, 0
        return sec.virtual_address, sec.virtual_address + sec.size

    def _all_exec_range(self) -> Tuple[int, int]:
        """Return (min_exec_va, max_exec_va) across all executable sections."""
        lo, hi = 0xffffffffffffffff, 0
        for sec in self._binary().sections:
            if sec.size == 0:
                continue
            if sec.flags & _SHF_EXECINSTR:
                lo = min(lo, sec.virtual_address)
                hi = max(hi, sec.virtual_address + sec.size)
        return (lo, hi) if lo < hi else (0, 0)

    def _data_range(self) -> Tuple[int, int]:
        """Return (min_data_va, max_data_va) across well-known data sections."""
        _DATA_SECTIONS = frozenset([
            '.rodata', '.data.rel.ro', '.data', '.bss',
            '.got', '.got.plt', '.init_array', '.fini_array',
        ])
        lo, hi = 0xffffffffffffffff, 0
        for sec in self._binary().sections:
            if sec.size == 0 or sec.name not in _DATA_SECTIONS:
                continue
            lo = min(lo, sec.virtual_address)
            hi = max(hi, sec.virtual_address + sec.size)
        return (lo, hi) if lo < hi else (0, 0)

    # ── Layer 1: vtable extraction ────────────────────────────────────────────

    def scan_vtables(self, min_slots: int = 3) -> List[VtableSpec]:
        """
        Extract vtable specs from the binary.

        Primary method: group consecutive RELA relocations whose addends
        point into executable sections and whose addresses are in data sections.
        This covers all dynamic C++ ELFs regardless of architecture.

        Fallback: scan data section raw bytes for runs of code-pointer values.
        Active when no vtable-like relocation runs are found (static binaries,
        non-PIE executables with absolute addresses in vtable slots).
        """
        try:
            specs = self._scan_via_relocations(min_slots)
        except (ValueError, struct.error):
            return []
        if not specs:
            try:
                specs = self._scan_via_bytes(min_slots)
            except (ValueError, struct.error):
                pass
        self._find_ctor_sites(specs)
        return specs

    # Relocation-based scan

    def _scan_via_relocations(self, min_slots: int) -> List[VtableSpec]:
        b = self._binary()
        text_lo, text_hi = self._all_exec_range()
        data_lo, data_hi = self._data_range()

        if text_lo >= text_hi:
            return []

        # Map relocation address → target function VA for all text-pointing relocs
        # that land in data sections (vtable slot locations → function VAs)
        reloc_map: Dict[int, int] = {}
        for rel in b.relocations:
            addend = getattr(rel, 'addend', 0) or 0
            rva = rel.address
            if text_lo <= addend < text_hi and data_lo <= rva < data_hi:
                reloc_map[rva] = addend

        if not reloc_map:
            return []

        # Group consecutive 8-byte-aligned entries into vtable runs
        sorted_rvas = sorted(reloc_map)
        results: List[VtableSpec] = []
        run: List[int] = [sorted_rvas[0]]

        for rva in sorted_rvas[1:]:
            if rva == run[-1] + 8:
                run.append(rva)
            else:
                if len(run) >= min_slots:
                    results.append(self._make_spec_from_run(run, reloc_map))
                run = [rva]

        if len(run) >= min_slots:
            results.append(self._make_spec_from_run(run, reloc_map))

        return results

    def _make_spec_from_run(self, run: List[int], reloc_map: Dict[int, int]) -> VtableSpec:
        vtable_va = run[0]
        slots = [
            SlotSpec(i, i * 8, reloc_map[rva], '', 'unknown')
            for i, rva in enumerate(run)
        ]
        has_header = self._check_itanium_header(vtable_va)
        sec_name, writable = self._section_for_va(vtable_va)
        return VtableSpec(
            va=vtable_va,
            slots=slots,
            type_name='',
            ctor_sites=[],
            has_itanium_header=has_header,
            section_name=sec_name,
            writable=writable,
        )

    def _check_itanium_header(self, vtable_va: int) -> bool:
        """
        Return True if the 16 bytes before vtable_va look like an Itanium
        vtable header: [offset_to_top=0][RTTI pointer into data section].
        """
        # Convert vtable_va to a file offset so this works for both ET_DYN
        # (PIE, VA≈file_offset) and ET_EXEC (non-PIE, VA >> file_offset).
        hdr_va = vtable_va - 16
        hdr_off = self._va_to_file_offset(hdr_va)
        if hdr_off is None or hdr_off + 16 > len(self._data):
            return False
        raw = self._data
        ott = struct.unpack_from('<q', raw, hdr_off)[0]
        if ott != 0:
            return False
        rtti_ptr = struct.unpack_from('<Q', raw, hdr_off + 8)[0]
        if rtti_ptr == 0:
            return False
        data_lo, data_hi = self._data_range()
        return data_lo <= rtti_ptr < data_hi

    # Byte-scan fallback

    def _scan_via_bytes(self, min_slots: int) -> List[VtableSpec]:
        """Scan data sections for runs of values that point into .text."""
        text_lo, text_hi = self._all_exec_range()
        if text_lo >= text_hi:
            return []

        raw = self._data
        results: List[VtableSpec] = []
        _VTABLE_DATA_SECTIONS = ['.rodata', '.data.rel.ro', '.data']

        for sec_name in _VTABLE_DATA_SECTIONS:
            sec = self._section(sec_name)
            if sec is None or sec.size < 24:
                continue
            sec_va = sec.virtual_address
            sec_off = int(sec.offset)   # ELF file offset, not VA
            sec_size = sec.size

            run_start_i: Optional[int] = None
            run_ptrs: List[int] = []

            for i in range(0, sec_size - 7, 8):
                ptr = struct.unpack_from('<Q', raw, sec_off + i)[0]
                if text_lo <= ptr < text_hi:
                    if run_start_i is None:
                        run_start_i = i
                    run_ptrs.append(ptr)
                else:
                    if run_start_i is not None and len(run_ptrs) >= min_slots:
                        vtable_va = sec_va + run_start_i
                        slots = [
                            SlotSpec(j, j * 8, p, '', 'unknown')
                            for j, p in enumerate(run_ptrs)
                        ]
                        has_hdr = self._check_itanium_header(vtable_va)
                        results.append(VtableSpec(
                            va=vtable_va,
                            slots=slots,
                            type_name='',
                            ctor_sites=[],
                            has_itanium_header=has_hdr,
                            section_name=sec_name,
                            writable=bool(sec.flags & _SHF_WRITE),
                        ))
                    run_start_i = None
                    run_ptrs = []

            if run_start_i is not None and len(run_ptrs) >= min_slots:
                vtable_va = sec_va + run_start_i
                slots = [
                    SlotSpec(j, j * 8, p, '', 'unknown')
                    for j, p in enumerate(run_ptrs)
                ]
                has_hdr = self._check_itanium_header(vtable_va)
                results.append(VtableSpec(
                    va=vtable_va,
                    slots=slots,
                    type_name='',
                    ctor_sites=[],
                    has_itanium_header=has_hdr,
                    section_name=sec_name,
                    writable=bool(sec.flags & _SHF_WRITE),
                ))

        return results

    # Constructor site detection

    def _find_ctor_sites(self, specs: List[VtableSpec]) -> None:
        """
        Find VAs that reference each vtable's VA.

        Method 1: relocations whose addend equals the vtable VA (vptr slots
        in subclass vtable structs or static object initializers).
        Method 2: raw 8-byte little-endian byte search in .text
        (covers static binaries where vtable VA is embedded as movabs literal).
        VA is computed as text_sec.virtual_address + byte_offset, converting
        the intra-section byte offset to virtual address space.
        """
        b = self._binary()
        vtable_set: Dict[int, VtableSpec] = {s.va: s for s in specs}

        # Method 1: relocations
        for rel in b.relocations:
            addend = getattr(rel, 'addend', 0) or 0
            spec = vtable_set.get(addend)
            if spec is not None:
                spec.ctor_sites.append(rel.address)

        # Method 2: raw 8-byte search in .text (fallback for static binaries)
        text_sec = self._section('.text')
        if text_sec is None:
            return
        raw = self._data
        text_va = text_sec.virtual_address
        text_off = int(text_sec.offset)   # ELF file offset, not VA
        text_bytes = raw[text_off: text_off + text_sec.size]

        for va, spec in vtable_set.items():
            if spec.ctor_sites:
                continue    # relocation method was sufficient
            needle = struct.pack('<Q', va)
            pos = 0
            while True:
                idx = text_bytes.find(needle, pos)
                if idx == -1 or len(spec.ctor_sites) >= 64:
                    break
                spec.ctor_sites.append(text_va + idx)   # VA = section_va + offset
                pos = idx + 8

    # ── Layer 2: slot naming ──────────────────────────────────────────────────

    def name_slots(self, specs: List[VtableSpec]) -> None:
        """
        Name slots in place (mutates each SlotSpec).
        Attempts, in order: export symbol → BinaryContext name →
        string xref → callee name.
        Also infers a vtable type name for each spec.
        """
        b = self._binary()
        # Build fast export symbol map: va → name
        export_map: Dict[int, str] = {}
        for sym in b.exported_symbols:
            if sym.value and sym.name:
                export_map[sym.value] = sym.name
        # Include symtab if present (not stripped)
        try:
            for sym in b.symtab_symbols:
                if sym.value and sym.name and sym.value not in export_map:
                    export_map[sym.value] = sym.name
        except Exception:
            pass

        for spec in specs:
            for slot in spec.slots:
                name, source = self._name_func(slot.func_va, export_map)
                if name:
                    slot.func_name = name
                    slot.name_source = source
            if not spec.type_name:
                spec.type_name = self._infer_type_name(spec)

    def _name_func(self, func_va: int,
                   export_map: Dict[int, str]) -> Tuple[str, str]:
        # 1. Export or symtab symbol
        sym_name = export_map.get(func_va)
        if sym_name:
            return sym_name, 'export'

        if self._ctx is None:
            return '', 'unknown'

        # 2. BinaryContext confirmed name
        try:
            name = self._ctx.name(func_va)
            if name and not name.startswith('fn_0x') and not name.startswith('sub_'):
                return name, 'ctx_name'
        except Exception:
            pass

        # 3. String literals referenced in the function body
        try:
            for s in self._ctx.strings_in_func(func_va):
                s = s.strip()
                if _looks_like_slot_name(s):
                    return s.lower(), 'string_xref'
        except Exception:
            pass

        # 4. Named callees: most informative imported name
        try:
            for callee_va in self._ctx.callees_of(func_va)[:16]:
                cname = self._ctx.name(callee_va)
                if not cname or cname.startswith('fn_0x'):
                    continue
                # Skip very generic names
                if cname in ('malloc', 'free', 'memcpy', 'memset', 'printf',
                             'abort', 'exit', '__assert_fail'):
                    continue
                clean = _strip_lib_prefix(cname)
                if len(clean) >= 3:
                    return clean.lower(), 'callee_name'
        except Exception:
            pass

        return '', 'unknown'

    def _infer_type_name(self, spec: VtableSpec) -> str:
        """Derive a vtable type name from the most common prefix of slot names."""
        named = [s.func_name for s in spec.slots if s.func_name]
        if not named:
            return f'vtable_{spec.va:08x}'
        # Find longest common prefix across all slot names
        common = named[0]
        for n in named[1:]:
            new_common = ''
            for a, b in zip(common, n):
                if a == b:
                    new_common += a
                else:
                    break
            common = new_common
            if not common:
                break
        # Strip trailing separators and short noise
        common = common.rstrip('_.-')
        if len(common) >= 3:
            return common + '_vtable'
        # Fallback: use the most-common word component
        from collections import Counter
        words: List[str] = []
        for n in named:
            words.extend(n.split('_'))
        freq = Counter(w for w in words if len(w) >= 3)
        if freq:
            top = freq.most_common(1)[0][0]
            return top + '_vtable'
        return f'vtable_{spec.va:08x}'

    # ── Layer 3: consumer tracing ─────────────────────────────────────────────

    def trace_consumers(self, spec: VtableSpec) -> List[TypePropSite]:
        """
        Find every call site that dispatches through any known slot of spec.

        x86-64: delegates to VtableDispatchScanner (full encoding coverage)
        ARM64:  delegates to vtable_resolver.detect_blr_sites (BLR pattern)
        Others (LA64, MIPS, PPC, …): _trace_generic scans .text for the
                vtable VA packed as a pointer-sized literal (arch-agnostic).
        """
        if self._arch == 'x86_64':
            return self._trace_x86(spec)
        if self._arch == 'arm64':
            return self._trace_arm64(spec)
        return self._trace_generic(spec)

    def _func_starts_sorted(self) -> List[int]:
        """Return sorted function start VAs from symbol table (best-effort)."""
        b = self._binary()
        starts: Set[int] = set()
        for sym in b.exported_symbols:
            if sym.value and str(sym.type) == 'TYPE.FUNC':
                starts.add(sym.value)
        try:
            for sym in b.symtab_symbols:
                if sym.value and str(sym.type) == 'TYPE.FUNC':
                    starts.add(sym.value)
        except Exception:
            pass
        return sorted(starts)

    def _enclosing_func(self, call_va: int,
                         func_starts: List[int]) -> int:
        """Return the function start VA that encloses call_va, or call_va itself."""
        result = _binary_search_le(func_starts, call_va)
        return result if result else call_va

    def _trace_generic(self, spec: VtableSpec) -> List[TypePropSite]:
        """
        Generic consumer tracer for LoongArch64, MIPS, PPC, and any other arch
        not covered by the ISA-specific x86-64 and ARM64 tracers.

        Strategy: scan .text bytes for the vtable VA packed as a pointer-sized
        little-endian or big-endian literal.  This catches ``la.abs``/``movabs``-
        style vtable pointer loads where the compiler embeds the absolute address
        directly in the instruction stream — a reliable pattern for non-PIE
        static binaries and a partial-coverage pattern for PIE (where ASLR means
        the literal value is a relocation, not the final VA).

        Returns at most 64 sites per vtable to bound cost on large binaries.
        """
        text_sec = self._section('.text')
        if text_sec is None:
            return []
        text_va  = text_sec.virtual_address
        text_off = int(text_sec.offset)
        text_data = self._data[text_off: text_off + text_sec.size]

        func_starts = self._func_starts_sorted()
        consumers: Dict[int, TypePropSite] = {}

        # Determine pointer width and byte order from arch token.
        # _elf_arch() tokens: 'ppc32', 'ppc64', 'mips', 'loongarch64', 'riscv', …
        ptr_width = 4 if self._arch == 'ppc32' else 8
        if self._arch in ('ppc32', 'ppc64', 'mips'):
            # PPC is always big-endian; MIPS default is BE (check EI_DATA byte for LE)
            ei_data = self._data[5] if len(self._data) > 5 else 2
            endian = '<' if ei_data == 1 else '>'
        else:
            endian = '<'  # x86_64, arm64, loongarch64, riscv, …
        fmt = endian + ('I' if ptr_width == 4 else 'Q')

        needle = struct.pack(fmt, spec.va)
        pos = 0
        hits = 0
        while hits < 64:
            idx = text_data.find(needle, pos)
            if idx == -1:
                break
            site_va = text_va + idx
            fn_va = self._enclosing_func(site_va, func_starts)
            if fn_va not in consumers:
                fn_name = (
                    self._ctx.name(fn_va)
                    if self._ctx else f'fn_0x{fn_va:x}'
                )
                consumers[fn_va] = TypePropSite(
                    func_va=fn_va,
                    func_name=fn_name,
                    role='consumer',
                )
            consumers[fn_va].slot_calls.append((site_va, -1, 'vtable_load'))
            pos = idx + ptr_width
            hits += 1

        return sorted(consumers.values(), key=lambda p: p.func_va)

    def _trace_x86(self, spec: VtableSpec) -> List[TypePropSite]:
        from ablation.analyzers.vtable_dispatch_scanner import VtableDispatchScanner

        scanner = VtableDispatchScanner.from_path(self._path)
        slot_map: Dict[str, int] = {
            (s.func_name or f'slot_{s.slot_index}'): s.slot_offset
            for s in spec.slots
        }
        dr = scanner.scan(slot_map)
        func_starts = self._func_starts_sorted()
        consumers: Dict[int, TypePropSite] = {}

        for slot_key, sites in dr.slot_offsets.items():
            slot_obj = next(
                (s for s in spec.slots
                 if (s.func_name or f'slot_{s.slot_index}') == slot_key),
                None,
            )
            slot_idx = slot_obj.slot_index if slot_obj else -1

            for site in sites:
                fn_va = self._enclosing_func(site.call_va, func_starts)
                if fn_va not in consumers:
                    fn_name = (
                        self._ctx.name(fn_va)
                        if self._ctx else f'fn_0x{fn_va:x}'
                    )
                    consumers[fn_va] = TypePropSite(
                        func_va=fn_va,
                        func_name=fn_name,
                        role='consumer',
                    )
                consumers[fn_va].slot_calls.append(
                    (site.call_va, slot_idx, slot_key)
                )

        return sorted(consumers.values(), key=lambda p: p.func_va)

    def _trace_arm64(self, spec: VtableSpec) -> List[TypePropSite]:
        from ablation.analyzers.vtable_resolver import detect_blr_sites

        text_sec = self._section('.text')
        if text_sec is None:
            return []
        text_va = text_sec.virtual_address
        text_off = int(text_sec.offset)   # file offset, not VA
        text_data = self._data[text_off: text_off + text_sec.size]

        blr_sites = detect_blr_sites(text_data, text_va, text_sec.size)
        func_starts = self._func_starts_sorted()
        consumers: Dict[int, TypePropSite] = {}

        for site in blr_sites:
            slot_obj = spec.slot_by_offset(site.slot_offset)
            if slot_obj is None:
                continue
            fn_va = self._enclosing_func(site.blr_pc, func_starts)
            if fn_va not in consumers:
                fn_name = (
                    self._ctx.name(fn_va)
                    if self._ctx else f'fn_0x{fn_va:x}'
                )
                consumers[fn_va] = TypePropSite(
                    func_va=fn_va,
                    func_name=fn_name,
                    role='consumer',
                )
            slot_name = slot_obj.func_name or f'slot_{slot_obj.slot_index}'
            consumers[fn_va].slot_calls.append(
                (site.blr_pc, slot_obj.slot_index, slot_name)
            )

        return sorted(consumers.values(), key=lambda p: p.func_va)

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def scan(self, min_slots: int = 3) -> VtableReconstructorResult:
        """Run all three layers and return a complete result."""
        specs = self.scan_vtables(min_slots)
        self.name_slots(specs)

        propagation: List[TypePropSite] = []
        for spec in specs:
            if spec.ctor_sites:             # only trace vtables with evidence
                propagation.extend(self.trace_consumers(spec))

        named = sum(1 for s in specs for sl in s.slots if sl.func_name)
        total = sum(len(s.slots) for s in specs)
        resolved = sum(len(p.slot_calls) for p in propagation)

        return VtableReconstructorResult(
            vtables=specs,
            propagation=propagation,
            binary_path=self._path,
            arch=self._arch,
            named_slot_count=named,
            total_slot_count=total,
            resolved_call_count=resolved,
        )

    # ── Output: IDAPython script ──────────────────────────────────────────────

    @staticmethod
    def emit_ida_script(specs: List[VtableSpec],
                         propagation: List[TypePropSite]) -> str:
        """
        Generate an IDAPython script that:
          1. Parses a C struct declaration for each vtable
          2. Calls idc.set_cmt() at every resolved call site
          3. Calls idc.set_cmt() at every detected ctor reference site

        Paste into IDA Pro Python console (Edit → Run Script) or run via
        File → Script file. Eliminates manual set_type propagation.

        For full type propagation, call idc.set_type() on producer functions
        manually after the struct is declared. IDA 8.x decompiler can then
        auto-propagate through local variables.
        """
        lines = [
            '# Generated by ablation CppVtableReconstructorAnalyzer',
            '# Paste into IDA Python console: Edit > Run Script',
            'import idc',
            '',
        ]

        for spec in specs:
            type_name = spec.type_name or f'vtable_{spec.va:08x}'
            lines.append(
                f'# ── {type_name} @ {spec.va:#010x}  '
                f'[{len(spec.slots)} slots] ──────────────────'
            )

            # C struct declaration
            struct_lines = [f'struct {type_name} {{']
            for slot in spec.slots:
                sname = slot.func_name or f'slot_{slot.slot_index}'
                struct_lines.append(
                    f'    void *(*{sname})(void *self);  /* slot {slot.slot_index} */'
                )
            struct_lines.append('};')

            lines.append('idc.parse_decls(')
            lines.append('    """')
            for ln in struct_lines:
                lines.append(f'    {ln}')
            lines.append('    """, 0)')
            lines.append('')

            # Ctor reference annotations
            for ctor_va in spec.ctor_sites[:16]:
                lines.append(
                    f'idc.set_cmt({ctor_va:#x}, '
                    f'"vptr → {type_name}", 0)'
                )
            if len(spec.ctor_sites) > 16:
                lines.append(f'# ... {len(spec.ctor_sites) - 16} more ctor refs omitted')
            lines.append('')

            # Call site annotations (from consumer tracing)
            for prop in propagation:
                if prop.role != 'consumer':
                    continue
                for call_pc, slot_idx, slot_name in prop.slot_calls:
                    slot_obj = spec.slot_by_index(slot_idx)
                    if slot_obj is None:
                        continue
                    lines.append(
                        f'idc.set_cmt({call_pc:#x}, '
                        f'"{type_name}->{slot_name}(...)", 0)'
                    )
            lines.append('')

        return '\n'.join(lines)

    # ── Output: human-readable report ────────────────────────────────────────

    @staticmethod
    def report(result: VtableReconstructorResult) -> str:
        lines = [
            f'CppVtableReconstructorAnalyzer  {result.binary_path}',
            (
                f'arch={result.arch}  vtables={len(result.vtables)}'
                f'  slots={result.total_slot_count}'
                f'  named={result.named_slot_count}'
                f'  call_sites={result.resolved_call_count}'
            ),
            '',
        ]
        for spec in result.vtables:
            type_name = spec.type_name or f'vtable_{spec.va:08x}'
            hdr = '  [Itanium ABI header]' if spec.has_itanium_header else ''
            lines.append(
                f'VTable  {type_name}  @ {spec.va:#010x}'
                f'  [{len(spec.slots)} slots]{hdr}'
            )
            if spec.ctor_sites:
                ctors = [f'{c:#x}' for c in spec.ctor_sites[:4]]
                suffix = f' … +{len(spec.ctor_sites)-4}' if len(spec.ctor_sites) > 4 else ''
                lines.append(f'  vptr refs: {", ".join(ctors)}{suffix}')
            for slot in spec.slots:
                sname = slot.func_name or '(unnamed)'
                src = f'  [{slot.name_source}]' if slot.func_name else ''
                lines.append(
                    f'  slot {slot.slot_index:2d}  '
                    f'+{slot.slot_offset:#05x}  '
                    f'{slot.func_va:#010x}  {sname}{src}'
                )
            lines.append('')

        if result.propagation:
            lines.append('Call Sites:')
            for prop in sorted(result.propagation, key=lambda p: p.func_va):
                fn = prop.func_name or f'fn_0x{prop.func_va:x}'
                lines.append(f'  {fn} @ {prop.func_va:#010x}  [{prop.role}]')
                for call_pc, slot_idx, slot_name in sorted(prop.slot_calls):
                    lines.append(
                        f'    {call_pc:#010x}  slot {slot_idx}  → {slot_name}'
                    )
            lines.append('')

        return '\n'.join(lines)
