"""
CommandTableScanner — finds (name_ptr, handler_fn_ptr, ...) dispatch tables in ELF data segments.

Background
----------
Gap this fills: server binaries compiled with an internal command/RPC dispatch loop store their
handler table as a static array of (char *, fn_ptr, ...) structs in a data section.  These tables
are accessed via global variables using RIP-relative addressing (not as code-level constants), so
SemanticSearcher's LEA-pattern scan and SinkArgClassifier's call-site scan both miss them.  Manual
RE of IBM Storage Defender Sentinel dispatch (session 12) required a raw binary search across data
bytes to locate the Q-shell command table — a ~45-minute procedure that should take <1 second.

Algorithm
---------
1. Parse ELF load segments to determine:
   - text_range  : set of (va_start, va_end) tuples for EXEC segments
   - rodata_range: set of (va_start, va_end) tuples for non-EXEC read-only segments
   Both ranges are used for pointer validity checks.

2. For each stride in [2, 3, 4] (words per entry):
   Scan every data section (non-executable, read-write or read-only) in 8-byte steps.
   At each position: check whether the next `stride` 8-byte values form a valid entry:
     - word[name_word]   : VA falls in rodata_range, first byte at that offset is printable ASCII
     - word[fn_word]     : VA falls in text_range

3. Count consecutive valid entries.  When a run of MIN_RUN or more entries is found, record it as
   a CommandTable.  Runs are de-duplicated across stride variants.

4. For each entry: read the name string from the rodata offset (up to 64 bytes, null-terminated).

Handles both PIE (base_va=0) and non-PIE ET_EXEC (base_va=0x400000 or similar) binaries by
reading the virtual addresses directly from the ELF segment table rather than assuming a base.

Usage
-----
    from ablation.analyzers.command_table_scanner import CommandTableScanner

    # Using an existing BinaryContext (avoids ELF re-parse):
    scanner = CommandTableScanner.from_context(ctx)
    tables  = scanner.scan()
    print(CommandTableScanner.report(tables))

    # Standalone:
    scanner = CommandTableScanner.from_path('/opt/ie/bin/dispatch')
    tables  = scanner.scan()
    for tbl in tables:
        for entry in tbl.entries:
            print(f'  {entry.name:24s}  handler={entry.handler_va:#010x}')
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple


_MIN_RUN        = 3     # minimum consecutive valid entries to record a table
_MAX_NAME_LEN   = 128   # cap on null-scan for command name string
# Entry layouts to try as (stride_words, fn_word_idx, name_word_idx).
# fn_word_idx  : index of the handler fn_ptr within each entry
# name_word_idx: index of the name/help string ptr within each entry
# Covers: 3-word entries with fn at any of the 3 positions,
#         2-word entries with fn first or second,
#         4-word entries with fn at any of the 4 positions.
_LAYOUTS = [
    # stride, fn_word_idx, name_word_idx
    (3, 2, 0),   # (help_ptr, ?, fn_ptr)  — dispatch format found in DS-Sentinel
    (3, 2, 1),   # (?, name_ptr, fn_ptr)
    (3, 1, 0),   # (name_ptr, fn_ptr, help_ptr)
    (3, 0, 1),   # (fn_ptr, name_ptr, help_ptr)
    (3, 0, 2),   # (fn_ptr, ?, name_ptr)
    (3, 1, 2),   # (help_ptr, fn_ptr, name_ptr)
    (2, 1, 0),   # (name_ptr, fn_ptr)
    (2, 0, 1),   # (fn_ptr, name_ptr)
    (4, 3, 0),
    (4, 3, 1),
    (4, 3, 2),
    (4, 0, 1),
    (4, 0, 2),
    (4, 1, 2),
    (4, 2, 1),
]


@dataclass
class CommandEntry:
    """One entry in a command dispatch table."""
    table_offset: int    # file offset of this entry
    entry_va:     int    # virtual address of this entry in the binary
    name:         str    # extracted command name string (empty if unreadable)
    name_va:      int    # VA of the name string pointer
    handler_va:   int    # VA of the handler function
    stride:       int    # words per entry (entry size = stride * 8 bytes)
    fn_word_idx:  int = 1   # which word-index within the entry is the fn_ptr
    name_word_idx:int = 0   # which word-index within the entry is the name_ptr
    extra_ptrs:   List[int] = field(default_factory=list)  # remaining pointer words

    def fmt(self) -> str:
        extra = ''
        if self.extra_ptrs:
            extra = '  extra=[' + ', '.join(f'{p:#010x}' for p in self.extra_ptrs) + ']'
        return (
            f'  {self.name:<24s}  handler={self.handler_va:#010x}'
            f'  entry@{self.entry_va:#010x}{extra}'
        )


@dataclass
class CommandTable:
    """A run of consecutive valid command-dispatch entries."""
    start_va:      int               # VA of the first entry
    start_offset:  int               # file offset of the first entry
    stride:        int               # words per entry
    fn_word_idx:   int = 1           # which word holds the handler fn_ptr
    name_word_idx: int = 0           # which word holds the name string ptr
    entries:       List[CommandEntry] = field(default_factory=list)

    @property
    def end_va(self) -> int:
        return self.start_va + len(self.entries) * self.stride * 8

    def fmt(self) -> str:
        return (
            f'CommandTable @{self.start_va:#010x}  '
            f'stride={self.stride}  fn_word={self.fn_word_idx}  name_word={self.name_word_idx}  '
            f'entries={len(self.entries)}'
        )


class CommandTableScanner:
    """
    Locate command/handler dispatch tables in an ELF binary's data segments.

    Effective on both stripped non-PIE ET_EXEC binaries and PIE shared objects.
    Designed specifically for binaries where command tables are static global
    arrays not reachable via SemanticSearcher's RIP-LEA scan.
    """

    def __init__(self, binary_path: str):
        self._path   = binary_path
        with open(binary_path, 'rb') as fh:
            self._data = fh.read()
        self._text_ranges:   List[Tuple[int, int, int]] = []  # (va_start, va_end, file_off)
        self._rodata_ranges: List[Tuple[int, int, int]] = []  # (va_start, va_end, file_off)
        self._data_ranges:   List[Tuple[int, int, int]] = []  # (va_start, va_end, file_off) — scan targets
        self._parse_elf()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, path: str) -> 'CommandTableScanner':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'CommandTableScanner':
        path = getattr(ctx, 'binary_path', None) or getattr(ctx, 'path', None)
        return cls(path)

    # ------------------------------------------------------------------
    # ELF segment parsing
    # ------------------------------------------------------------------

    def _parse_elf(self) -> None:
        data = self._data
        if len(data) < 64 or data[:4] != b'\x7fELF':
            return

        e_phoff     = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum     = struct.unpack_from('<H', data, 56)[0]
        e_shoff     = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum     = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx  = struct.unpack_from('<H', data, 62)[0]

        PT_LOAD = 1
        PF_X    = 1
        PF_W    = 2
        PF_R    = 4

        # Collect load segments
        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            p_type   = struct.unpack_from('<I', data, ph)[0]
            p_flags  = struct.unpack_from('<I', data, ph + 4)[0]
            p_offset = struct.unpack_from('<Q', data, ph + 8)[0]
            p_vaddr  = struct.unpack_from('<Q', data, ph + 16)[0]
            p_filesz = struct.unpack_from('<Q', data, ph + 32)[0]
            if p_type != PT_LOAD or p_filesz == 0:
                continue
            va_end = p_vaddr + p_filesz
            if p_flags & PF_X:
                self._text_ranges.append((p_vaddr, va_end, p_offset))
            elif p_flags & PF_W:
                self._data_ranges.append((p_vaddr, va_end, p_offset))
            elif p_flags & PF_R:
                self._rodata_ranges.append((p_vaddr, va_end, p_offset))

        # Fall back to section headers for rodata if no explicit R-only segment
        if not self._rodata_ranges and e_shoff and e_shstrndx < e_shnum:
            shstr_sh   = e_shoff + e_shstrndx * e_shentsize
            shstr_off  = struct.unpack_from('<Q', data, shstr_sh + 24)[0]
            SHF_ALLOC  = 0x2
            SHF_WRITE  = 0x1
            SHF_EXEC   = 0x4
            for i in range(e_shnum):
                sh      = e_shoff + i * e_shentsize
                sh_name = struct.unpack_from('<I', data, sh)[0]
                sh_flags = struct.unpack_from('<Q', data, sh + 8)[0]
                sh_addr  = struct.unpack_from('<Q', data, sh + 16)[0]
                sh_off   = struct.unpack_from('<Q', data, sh + 24)[0]
                sh_size  = struct.unpack_from('<Q', data, sh + 32)[0]
                if sh_size == 0 or not (sh_flags & SHF_ALLOC):
                    continue
                if sh_flags & SHF_EXEC:
                    continue
                name_end = data.find(b'\x00', shstr_off + sh_name)
                sh_name_str = data[shstr_off + sh_name:name_end].decode('ascii', errors='replace')
                if sh_name_str.startswith('.rodata') or sh_name_str == '.data.rel.ro':
                    self._rodata_ranges.append((sh_addr, sh_addr + sh_size, sh_off))
                elif not (sh_flags & SHF_WRITE):
                    self._rodata_ranges.append((sh_addr, sh_addr + sh_size, sh_off))

    # ------------------------------------------------------------------
    # VA helpers
    # ------------------------------------------------------------------

    def _in_text(self, va: int) -> bool:
        return any(lo <= va < hi for lo, hi, _ in self._text_ranges)

    def _in_rodata(self, va: int) -> bool:
        return any(lo <= va < hi for lo, hi, _ in self._rodata_ranges)

    def _in_text_or_rodata(self, va: int) -> bool:
        return self._in_text(va) or self._in_rodata(va)

    def _va_to_file_off(self, va: int) -> Optional[int]:
        for lo, hi, foff in self._text_ranges + self._rodata_ranges + self._data_ranges:
            if lo <= va < hi:
                return foff + (va - lo)
        return None

    def _read_string(self, va: int) -> str:
        off = self._va_to_file_off(va)
        if off is None or off >= len(self._data):
            return ''
        end = self._data.find(b'\x00', off, off + _MAX_NAME_LEN)
        raw = self._data[off:end if end != -1 else off + _MAX_NAME_LEN]
        if not raw or not (0x20 <= raw[0] <= 0x7e):
            return ''
        return raw.decode('ascii', errors='replace')

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------

    def _read_words(self, file_pos: int, stride: int) -> Optional[List[int]]:
        """Read stride 8-byte words from file_pos. Returns None if out of range."""
        end = file_pos + stride * 8
        if end > len(self._data):
            return None
        return [struct.unpack_from('<Q', self._data, file_pos + i * 8)[0] for i in range(stride)]

    def _is_valid_entry(self, file_pos: int, stride: int, fn_wi: int, name_wi: int) -> bool:
        """
        Check whether stride 8-byte words at file_pos form a valid command entry
        given that word[fn_wi] is the fn_ptr and word[name_wi] is the name ptr.
        """
        words = self._read_words(file_pos, stride)
        if words is None:
            return False
        fn_va   = words[fn_wi]
        name_va = words[name_wi]
        if not self._in_text(fn_va):
            return False
        if not self._in_rodata(name_va):
            return False
        # Name first byte must be printable ASCII
        name_off = self._va_to_file_off(name_va)
        if name_off is None or name_off >= len(self._data):
            return False
        if not (0x21 <= self._data[name_off] <= 0x7e):
            return False
        # All non-fn, non-name words must be either null, in text, or in rodata
        for wi, va in enumerate(words):
            if wi == fn_wi or wi == name_wi:
                continue
            if va != 0 and not self._in_text_or_rodata(va):
                return False
        return True

    def _extract_entry(self, file_pos: int, va: int, stride: int,
                       fn_wi: int, name_wi: int) -> CommandEntry:
        words = self._read_words(file_pos, stride)
        assert words is not None
        fn_va   = words[fn_wi]
        name_va = words[name_wi]
        extra   = [v for i, v in enumerate(words) if i != fn_wi and i != name_wi]
        return CommandEntry(
            table_offset  = file_pos,
            entry_va      = va,
            name          = self._read_string(name_va),
            name_va       = name_va,
            handler_va    = fn_va,
            stride        = stride,
            fn_word_idx   = fn_wi,
            name_word_idx = name_wi,
            extra_ptrs    = extra,
        )

    def _data_file_va(self, file_pos: int) -> int:
        """Best-effort file_offset → VA for entries in data or rodata ranges."""
        for lo, hi, foff in self._data_ranges + self._rodata_ranges:
            size = hi - lo
            if foff <= file_pos < foff + size:
                return lo + (file_pos - foff)
        return file_pos

    def scan(self) -> List[CommandTable]:
        """
        Scan all data and rodata segments for command dispatch tables.

        Tries all layouts in _LAYOUTS (stride, fn_word_idx, name_word_idx) and
        returns all runs of MIN_RUN or more consecutive valid entries.
        Tables are de-duplicated by start VA and sorted by start VA.
        """
        tables: List[CommandTable] = []
        seen_start_vas: Set[int] = set()

        # Command dispatch tables contain fn_ptrs and are stored in writable data segments.
        # Scanning rodata (which may be hundreds of MB of model/constant data) is
        # both slow and unproductive for fn_ptr discovery.
        scan_regions = self._data_ranges

        for stride, fn_wi, name_wi in _LAYOUTS:
            entry_size = stride * 8
            for va_lo, va_hi, file_off in scan_regions:
                region_size = va_hi - va_lo
                pos = file_off
                end = file_off + region_size
                current_run: List[CommandEntry] = []
                run_start_pos = pos

                while pos + entry_size <= end:
                    if self._is_valid_entry(pos, stride, fn_wi, name_wi):
                        entry_va = self._data_file_va(pos)
                        if not current_run:
                            run_start_pos = pos
                        current_run.append(
                            self._extract_entry(pos, entry_va, stride, fn_wi, name_wi)
                        )
                        # Once aligned on a valid entry, step by entry_size (not 8)
                        # so the next check lands on the consecutive entry and doesn't
                        # break the run by validating mid-entry garbage bytes.
                        pos += entry_size
                    else:
                        if current_run:
                            if len(current_run) >= _MIN_RUN:
                                start_va = self._data_file_va(run_start_pos)
                                if start_va not in seen_start_vas:
                                    seen_start_vas.add(start_va)
                                    tables.append(CommandTable(
                                        start_va      = start_va,
                                        start_offset  = run_start_pos,
                                        stride        = stride,
                                        fn_word_idx   = fn_wi,
                                        name_word_idx = name_wi,
                                        entries       = current_run[:],
                                    ))
                            current_run = []
                        pos += 8  # slide by one word to find the next valid table start

                # Flush run at end of region
                if len(current_run) >= _MIN_RUN:
                    start_va = self._data_file_va(run_start_pos)
                    if start_va not in seen_start_vas:
                        seen_start_vas.add(start_va)
                        tables.append(CommandTable(
                            start_va      = start_va,
                            start_offset  = run_start_pos,
                            stride        = stride,
                            fn_word_idx   = fn_wi,
                            name_word_idx = name_wi,
                            entries       = current_run[:],
                        ))

        tables.sort(key=lambda t: t.start_va)
        return tables

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def report(tables: List[CommandTable]) -> str:
        if not tables:
            return 'CommandTableScanner: no dispatch tables found'
        lines = [f'CommandTableScanner: {len(tables)} table(s) found']
        for tbl in tables:
            lines.append(f'\n  {tbl.fmt()}')
            for entry in tbl.entries:
                lines.append(entry.fmt())
        return '\n'.join(lines)
