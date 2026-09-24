"""
Go binary dangerous-call-site scanner with pre-built callgraph, itab resolver, and session caching.

Design principles:
  - Rodata-first: extract all strings + itabs in one pass, then disassemble only targeted functions.
  - Pre-built callgraph: single text scan builds {callee -> callers} + {caller -> callees}.
    All subsequent lookups are O(1) dict access, not 90-120s re-scans.
  - Namespace filter: only Fortinet-namespaced functions (configurable). Skip deferwrap/gowrap/funcN.
  - Go itab resolver: scan .rodata for interface method tables with full struct validation.
    Correct layout: inter(*interfacetype) at +0x00, _type(*_type) at +0x08, hash+pad at +0x10,
    fun[] at +0x18. Hash match validation eliminates false positives. Kind byte check (0x14)
    confirms inter pointer really is an interface type descriptor.
  - Method index extraction: backtrack from 'call reg' to find [base+offset] load, compute
    method_index = (offset - 0x18) // 8. Enables precise CHA resolution.
  - Session caching: SQLite WAL-mode (incremental upserts, cross-tool interop) with pickle
    fallback for legacy compatibility.
  - Go 1.17+ register ABI: arg0=(rax,rbx), arg1=(rcx,rdx), arg2=(rdi,rsi), arg3=(r8,r9).
    fmt.Sprintf: format=(rax=data,rbx=len), variadic=(rcx=slice_data,rdi=len,rsi=cap).
    Tainted variadic value at [rcx + 0x08] (data ptr of first iface in slice).

Go itab struct layout (Go 1.17+, 64-bit):
  +0x00  inter   *interfacetype   ptr into .rodata
  +0x08  _type   *_type           ptr into .rodata (concrete type)
  +0x10  hash    uint32           copy of _type.hash at _type+0x10
  +0x14  _       [4]byte          alignment padding, MUST be 0x00000000
  +0x18  fun[0]  uintptr          first method ptr -> .text
  +0x20  fun[1]  uintptr          second method ptr -> .text
  ...

Validation fingerprints (from Gemini itab analysis):
  1. itab+0x14 == 0x00000000 (zero padding)
  2. uint32(itab+0x10) == uint32(_type_va + 0x10) (hash match)
  3. byte(inter_va + 0x17) == 0x14 (kindInterface: optional, filters non-interface types)

Usage:
    scanner = GoDangerousCallerScanner('/path/to/binary')
    scanner.build()       # or loads from cache if available

    # Rodata search (fast, pre-indexed)
    for va, s in scanner.rodata_search(['SELECT', 'INSERT', 'UPDATE'], require_format=True):
        print(f"{va:#x}: {s}")

    # Find dangerous call sites in Fortinet functions
    for hit in scanner.scan(['fmt.Sprintf', 'os/exec.Command']):
        print(hit)

    # O(1) caller lookup
    for entry in scanner.callers_of('getValueForSQL'):
        print(entry)

    # Resolve interface dispatch with method index
    for site_va, method_idx, candidates in scanner.resolve_indirect_calls(func_va):
        print(f"  {site_va:#x} method[{method_idx}] -> {candidates}")

CLI:
    python -m ablation.analyzers.go_dangerous_callers /path/to/binary [--targets ...] [--rodata-sql]
"""

from __future__ import annotations

import hashlib
import os
import pickle
import re
import sqlite3
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import capstone
import capstone.x86
import lief

from ablation.analyzers.go_pclntab import GoFuncTable

_SKIP_SUFFIX = re.compile(r'\.(deferwrap\d*|gowrap\d*|func\d+)$')
_CACHE_DIR = os.path.expanduser('~/.cache/ablation/go_re')
_CACHE_VERSION = 3  # increment when cache schema changes


@dataclass
class DangerousCallHit:
    func_name: str
    func_va: int
    call_va: int
    call_target_va: int
    call_target_name: str
    string_refs: List[Tuple[int, str]] = field(default_factory=list)

    def __str__(self) -> str:
        srefs = '; '.join(f'{va:#x}:"{s[:60]}"' for va, s in self.string_refs[:3])
        return (
            f"[CALL] {self.func_name}\n"
            f"  call={self.call_va:#010x} -> {self.call_target_name} ({self.call_target_va:#010x})\n"
            f"  strings: {srefs or '(none)'}"
        )


class GoDangerousCallerScanner:
    """
    Stateful scanner. Call build() once per binary. All subsequent queries are O(1).
    State is cached to disk keyed by binary SHA256; next session loads instantly.

    Cache backend: SQLite WAL-mode (primary) with pickle fallback.
    SQLite enables incremental upserts and cross-tool interop without full-graph
    deserialization overhead.
    """

    def __init__(self, binary_path: str, namespace: str = '',
                 cache_dir: str = _CACHE_DIR):
        self.binary_path = binary_path
        self.namespace = namespace
        self.cache_dir = cache_dir
        self._data: Optional[bytes] = None
        self._lb = None
        self._ft: Optional[GoFuncTable] = None
        self._sections: List[Tuple[int, int, int]] = []  # (va_start, va_end, file_off)

        # Pre-computed indexes (cached to disk)
        self.rodata_strings: Dict[int, str] = {}           # va -> printable string
        self.func_map: Dict[int, Tuple[int, str]] = {}     # func_va -> (func_end, func_name)
        self.all_names: Dict[int, str] = {}                # va -> name (all pclntab funcs)
        # static_calls[callee_va] = {(caller_fva, call_va)}: O(1) "who calls X"
        self.static_calls: Dict[int, Set[Tuple[int, int]]] = {}
        self.func_callees: Dict[int, List[int]] = {}       # func_va -> [callee_va, ...]
        # indirect_calls[func_va] = [(site_va, op_str, method_index)]
        # method_index = (load_offset - 0x18) // 8, or -1 if not resolved
        self.indirect_calls: Dict[int, List[Tuple[int, str, int]]] = {}
        self.func_strings: Dict[int, List[Tuple[int, str]]] = {}    # func_va -> [(str_va, str)]
        # itab_map[inter_va][type_va] = [method_va, ...]
        # inter_va = interfacetype descriptor VA (at itab+0x00)
        # type_va  = concrete _type descriptor VA (at itab+0x08)
        self.itab_map: Dict[int, Dict[int, List[int]]] = {}
        # Reverse: method_va -> [(inter_va, type_va)]: for CHA: all types implementing a method
        self.method_implementations: Dict[int, List[Tuple[int, int]]] = {}
        # Slot index: (inter_va, slot_idx) -> [method_va, ...] across all concrete types
        # Enables CHA from method_index: given slot N, find all concrete implementations
        self.slot_methods: Dict[Tuple[int, int], List[int]] = {}
        self._built = False

    # ------------------------------------------------------------------ build

    def build(self, force: bool = False) -> 'GoDangerousCallerScanner':
        self._data = open(self.binary_path, 'rb').read()
        sha = hashlib.sha256(self._data).hexdigest()[:16]

        db_path = os.path.join(self.cache_dir, f'{sha}.db')
        pkl_path = os.path.join(self.cache_dir, f'{sha}.pkl')

        if not force:
            if os.path.exists(db_path):
                if self._load_sqlite(db_path):
                    return self
            elif os.path.exists(pkl_path):
                if self._load_pickle(pkl_path):
                    # Migrate to SQLite on next forced rebuild
                    return self

        self._lb = lief.parse(self.binary_path)
        self._build_section_map()
        self._ft = GoFuncTable.from_binary(self._data)
        self._extract_rodata_strings()
        self._build_func_map()
        self._build_all_names()
        self._build_callgraph()
        self._build_itab_map()
        os.makedirs(self.cache_dir, exist_ok=True)
        self._save_sqlite(db_path)
        self._built = True
        return self

    # ---------------------------------------------------------- section map

    def _build_section_map(self):
        self._sections = []
        for sect in self._lb.sections:
            if sect.size > 0:
                self._sections.append(
                    (sect.virtual_address,
                     sect.virtual_address + sect.size,
                     sect.offset))

    def _va_to_file_off(self, va: int) -> Optional[int]:
        for s, e, off in self._sections:
            if s <= va < e:
                return off + (va - s)
        return None

    def _read_va_u32(self, va: int) -> Optional[int]:
        foff = self._va_to_file_off(va)
        if foff is None or foff + 4 > len(self._data):
            return None
        return struct.unpack_from('<I', self._data, foff)[0]

    def _read_va_u8(self, va: int) -> Optional[int]:
        foff = self._va_to_file_off(va)
        if foff is None or foff >= len(self._data):
            return None
        return self._data[foff]

    # ---------------------------------------------------------- cache: SQLite

    def _save_sqlite(self, path: str):
        con = sqlite3.connect(path)
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('PRAGMA synchronous=NORMAL')
        con.executescript('''
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS functions (
                ea INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                end_ea INTEGER,
                is_target_ns INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS call_edges (
                caller_ea INTEGER NOT NULL,
                callee_ea INTEGER NOT NULL,
                call_type INTEGER NOT NULL,
                call_site INTEGER NOT NULL,
                PRIMARY KEY (caller_ea, callee_ea, call_site)
            );
            CREATE INDEX IF NOT EXISTS idx_callee ON call_edges(callee_ea);
            CREATE INDEX IF NOT EXISTS idx_caller ON call_edges(caller_ea);
            CREATE TABLE IF NOT EXISTS indirect_sites (
                func_ea INTEGER NOT NULL,
                site_ea INTEGER NOT NULL,
                op_str TEXT,
                method_index INTEGER DEFAULT -1,
                PRIMARY KEY (func_ea, site_ea)
            );
            CREATE TABLE IF NOT EXISTS itabs (
                inter_va INTEGER NOT NULL,
                type_va INTEGER NOT NULL,
                slot_idx INTEGER NOT NULL,
                method_va INTEGER NOT NULL,
                PRIMARY KEY (inter_va, type_va, slot_idx)
            );
            CREATE INDEX IF NOT EXISTS idx_itabs_method ON itabs(method_va);
            CREATE INDEX IF NOT EXISTS idx_itabs_slot ON itabs(inter_va, slot_idx);
            CREATE TABLE IF NOT EXISTS rodata_strings (
                va INTEGER PRIMARY KEY,
                string TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS func_strings (
                func_va INTEGER NOT NULL,
                str_va INTEGER NOT NULL,
                string TEXT NOT NULL,
                PRIMARY KEY (func_va, str_va)
            );
        ''')
        con.execute("INSERT OR REPLACE INTO meta VALUES ('version', ?)", (str(_CACHE_VERSION),))

        con.executemany(
            'INSERT OR REPLACE INTO rodata_strings VALUES (?, ?)',
            self.rodata_strings.items())

        for va, (end_va, name) in self.func_map.items():
            con.execute(
                'INSERT OR REPLACE INTO functions VALUES (?, ?, ?, 1)',
                (va, name, end_va))
        for va, name in self.all_names.items():
            if va not in self.func_map:
                con.execute(
                    'INSERT OR IGNORE INTO functions VALUES (?, ?, ?, 0)',
                    (va, name, None))

        for callee_va, callers in self.static_calls.items():
            for caller_fva, call_va in callers:
                con.execute(
                    'INSERT OR IGNORE INTO call_edges VALUES (?, ?, 0, ?)',
                    (caller_fva, callee_va, call_va))

        for func_va, sites in self.indirect_calls.items():
            for site_va, op_str, method_idx in sites:
                con.execute(
                    'INSERT OR REPLACE INTO indirect_sites VALUES (?, ?, ?, ?)',
                    (func_va, site_va, op_str, method_idx))

        for inter_va, type_slots in self.itab_map.items():
            for type_va, methods in type_slots.items():
                for slot_idx, method_va in enumerate(methods):
                    con.execute(
                        'INSERT OR REPLACE INTO itabs VALUES (?, ?, ?, ?)',
                        (inter_va, type_va, slot_idx, method_va))

        for func_va, refs in self.func_strings.items():
            for str_va, s in refs:
                con.execute(
                    'INSERT OR REPLACE INTO func_strings VALUES (?, ?, ?)',
                    (func_va, str_va, s))

        con.commit()
        con.close()

    def _load_sqlite(self, path: str) -> bool:
        try:
            con = sqlite3.connect(path)
            con.row_factory = sqlite3.Row
            ver = con.execute("SELECT value FROM meta WHERE key='version'").fetchone()
            if not ver or int(ver['value']) != _CACHE_VERSION:
                con.close()
                return False

            self.rodata_strings = {
                r['va']: r['string']
                for r in con.execute('SELECT va, string FROM rodata_strings')}

            self.func_map = {}
            self.all_names = {}
            for r in con.execute('SELECT ea, name, end_ea, is_target_ns FROM functions'):
                self.all_names[r['ea']] = r['name']
                if r['is_target_ns']:
                    self.func_map[r['ea']] = (r['end_ea'] or r['ea'] + 0x1000, r['name'])

            self.static_calls = {}
            self.func_callees = {}
            for r in con.execute('SELECT caller_ea, callee_ea, call_site FROM call_edges'):
                callee_va = r['callee_ea']
                caller_fva = r['caller_ea']
                call_va = r['call_site']
                if callee_va not in self.static_calls:
                    self.static_calls[callee_va] = set()
                self.static_calls[callee_va].add((caller_fva, call_va))
                if caller_fva not in self.func_callees:
                    self.func_callees[caller_fva] = []
                if callee_va not in self.func_callees[caller_fva]:
                    self.func_callees[caller_fva].append(callee_va)

            self.indirect_calls = {}
            for r in con.execute(
                    'SELECT func_ea, site_ea, op_str, method_index FROM indirect_sites'):
                fva = r['func_ea']
                if fva not in self.indirect_calls:
                    self.indirect_calls[fva] = []
                self.indirect_calls[fva].append(
                    (r['site_ea'], r['op_str'], r['method_index']))

            self.itab_map = {}
            self.method_implementations = {}
            self.slot_methods = {}
            for r in con.execute(
                    'SELECT inter_va, type_va, slot_idx, method_va FROM itabs'):
                inter_va = r['inter_va']
                type_va = r['type_va']
                slot_idx = r['slot_idx']
                method_va = r['method_va']
                if inter_va not in self.itab_map:
                    self.itab_map[inter_va] = {}
                if type_va not in self.itab_map[inter_va]:
                    self.itab_map[inter_va][type_va] = []
                lst = self.itab_map[inter_va][type_va]
                while len(lst) <= slot_idx:
                    lst.append(0)
                lst[slot_idx] = method_va
                if method_va not in self.method_implementations:
                    self.method_implementations[method_va] = []
                self.method_implementations[method_va].append((inter_va, type_va))
                key = (inter_va, slot_idx)
                if key not in self.slot_methods:
                    self.slot_methods[key] = []
                self.slot_methods[key].append(method_va)

            self.func_strings = {}
            for r in con.execute('SELECT func_va, str_va, string FROM func_strings'):
                fva = r['func_va']
                if fva not in self.func_strings:
                    self.func_strings[fva] = []
                self.func_strings[fva].append((r['str_va'], r['string']))

            con.close()
            self._built = True
            return True
        except Exception:
            return False

    def _load_pickle(self, path: str) -> bool:
        try:
            with open(path, 'rb') as f:
                state = pickle.load(f)
            if state.get('_version', 0) != _CACHE_VERSION:
                return False
            self.rodata_strings = state['rodata_strings']
            self.func_map = state['func_map']
            self.all_names = state['all_names']
            self.static_calls = state['static_calls']
            self.func_callees = state['func_callees']
            self.indirect_calls = state.get('indirect_calls', {})
            self.func_strings = state['func_strings']
            self.itab_map = state.get('itab_map', {})
            self.method_implementations = state.get('method_implementations', {})
            self.slot_methods = state.get('slot_methods', {})
            self._built = True
            return True
        except Exception:
            return False

    # ---------------------------------------------------------- internal build

    def _extract_rodata_strings(self, min_len: int = 4, max_len: int = 512):
        rd = self._lb.get_section('.rodata')
        if not rd:
            return
        rd_data = bytes(rd.content)
        rd_start = rd.virtual_address
        i = 0
        while i < len(rd_data):
            j = i
            while j < len(rd_data) and 0x20 <= rd_data[j] < 0x7f:
                j += 1
            slen = j - i
            if slen >= min_len:
                s = rd_data[i:i + min(slen, max_len)].decode('ascii', errors='replace')
                self.rodata_strings[rd_start + i] = s
            i = max(j + 1, i + 1)

    def _build_func_map(self):
        if not self._ft:
            return
        sorted_vas = sorted(self._ft.names.keys())
        for i, va in enumerate(sorted_vas):
            name = self._ft.names[va]
            if self.namespace not in name:
                continue
            if _SKIP_SUFFIX.search(name):
                continue
            end_va = sorted_vas[i + 1] if i + 1 < len(sorted_vas) else va + 0x1000
            self.func_map[va] = (end_va, name)

    def _build_all_names(self):
        if self._ft:
            self.all_names = dict(self._ft.names)

    def _build_callgraph(self):
        """
        Single pass over .text. Builds:
          static_calls[callee_va]     : O(1) "who calls X"
          func_callees[caller_fva]    : forward traversal
          indirect_calls[caller_fva]  : interface dispatch sites with method_index
          func_strings[caller_fva]    : LEA string refs per function

        Method index extraction (from Gemini doc):
          Backtrack from 'call reg' through window of recent instructions.
          Look for MOV dest_reg, [base_reg + offset] where offset >= 0x18 and
          (offset - 0x18) % 8 == 0. Then method_index = (offset - 0x18) // 8.

        Go 1.17+ ABI: interface in (rax=itab_ptr, rbx=data_ptr).
        Method dispatch: mov rcx, [rax + 0x18 + 8*slot] then call rcx.
        """
        text_sect = self._lb.get_section('.text')
        if not text_sect:
            return
        text_start_va = text_sect.virtual_address
        text_off = text_sect.offset
        text_bytes = self._data[text_off:text_off + text_sect.size]

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        rd_vas = set(self.rodata_strings.keys())
        sorted_func_vas = sorted(self.func_map.keys())
        func_ends = {va: self.func_map[va][0] for va in sorted_func_vas}

        def enclosing_fva(va: int) -> Optional[int]:
            lo, hi = 0, len(sorted_func_vas) - 1
            result = None
            while lo <= hi:
                mid = (lo + hi) // 2
                if sorted_func_vas[mid] <= va:
                    result = sorted_func_vas[mid]
                    lo = mid + 1
                else:
                    hi = mid - 1
            if result is not None and va < func_ends[result]:
                return result
            return None

        # Rolling window of last 10 instructions per basic block for method index backtracking
        insn_window: List[object] = []

        for insn in md.disasm(text_bytes, text_start_va):
            caller_fva = enclosing_fva(insn.address)
            if caller_fva is None:
                insn_window.clear()
                continue

            if insn.mnemonic == 'lea':
                try:
                    disp = insn.operands[1].mem.disp
                    target = insn.address + insn.size + disp
                    if target in rd_vas:
                        if caller_fva not in self.func_strings:
                            self.func_strings[caller_fva] = []
                        entry = (target, self.rodata_strings[target])
                        if entry not in self.func_strings[caller_fva]:
                            self.func_strings[caller_fva].append(entry)
                except (IndexError, AttributeError):
                    pass

            elif insn.mnemonic == 'call':
                try:
                    op = insn.operands[0]
                    if op.type == capstone.x86.X86_OP_IMM:
                        callee_va = op.imm
                        if callee_va not in self.static_calls:
                            self.static_calls[callee_va] = set()
                        self.static_calls[callee_va].add((caller_fva, insn.address))
                        if caller_fva not in self.func_callees:
                            self.func_callees[caller_fva] = []
                        if callee_va not in self.func_callees[caller_fva]:
                            self.func_callees[caller_fva].append(callee_va)
                    else:
                        # Indirect call: extract method index by backtracking
                        method_idx = -1
                        call_reg = None
                        if op.type == capstone.x86.X86_OP_REG:
                            call_reg = op.reg
                        elif op.type == capstone.x86.X86_OP_MEM and op.mem.index == 0:
                            pass  # call [reg+N]: less common, skip backtrack

                        if call_reg is not None:
                            for prev in reversed(insn_window):
                                try:
                                    if prev.mnemonic not in ('mov', 'movq'):
                                        continue
                                    dst = prev.operands[0]
                                    src = prev.operands[1]
                                    if (dst.type == capstone.x86.X86_OP_REG and
                                            dst.reg == call_reg and
                                            src.type == capstone.x86.X86_OP_MEM and
                                            src.mem.disp >= 0x18 and
                                            (src.mem.disp - 0x18) % 8 == 0):
                                        method_idx = (src.mem.disp - 0x18) // 8
                                        break
                                except (IndexError, AttributeError):
                                    continue

                        if caller_fva not in self.indirect_calls:
                            self.indirect_calls[caller_fva] = []
                        self.indirect_calls[caller_fva].append(
                            (insn.address, insn.op_str, method_idx))
                except (IndexError, AttributeError):
                    pass

            # Maintain rolling window (cap at 10)
            insn_window.append(insn)
            if len(insn_window) > 10:
                insn_window.pop(0)
            # Clear window at function boundaries
            if insn.mnemonic == 'ret':
                insn_window.clear()

    def _build_itab_map(self):
        """
        Go itab layout (64-bit, Go 1.17+):
          +0x00  inter   *interfacetype   -> .data.rel.ro (interface type descriptor)
          +0x08  _type   *_type           -> .data.rel.ro (concrete type descriptor)
          +0x10  hash    uint32           copy of _type.hash (at _type+0x10)
          +0x14  _       [4]byte          alignment padding (MUST == 0x00000000)
          +0x18  fun[0]  uintptr          -> .text (first method)
          +0x20  fun[1]  uintptr          -> .text (second method)
          ...

        IMPORTANT: itabs live in .data.rel.ro, NOT .rodata.
        Type descriptors (interfacetype, _type) also live in .data.rel.ro.

        Validation fingerprints (verified against .data.rel.ro.itablink ground truth,
        all 1439 itabs in FCTDas match f8-as-_type pattern):
          1. itab+0x14 == 0x00000000 (zero padding, eliminates ~99% of false positives)
          2. uint32(itab+0x10) == uint32(at type_ptr+0x10) (_type is at itab+0x08)
          3. byte(at inter_ptr+0x17) == 0x14 (kindInterface, inter is at itab+0x00)
          4. At least one .text pointer at itab+0x18

        Builds:
          itab_map[inter_va][type_va] = [method_va, ...]
          method_implementations[method_va] = [(inter_va, type_va), ...]
          slot_methods[(inter_va, slot_idx)] = [method_va, ...]  (CHA index)
        """
        text_sect = self._lb.get_section('.text')
        if not text_sect:
            return
        text_lo = text_sect.virtual_address
        text_hi = text_lo + text_sect.size

        # Itabs are in .data.rel.ro, not .rodata
        scan_sect = self._lb.get_section('.data.rel.ro')
        if not scan_sect:
            scan_sect = self._lb.get_section('.rodata')
        if not scan_sect:
            return

        scan_data  = bytes(scan_sect.content)
        scan_start = scan_sect.virtual_address
        scan_len   = len(scan_data)

        def is_text_ptr(v: int) -> bool:
            return text_lo <= v < text_hi

        def is_mapped_ptr(v: int) -> bool:
            if not v:
                return False
            for svs, sve, _ in self._sections:
                if svs <= v < sve:
                    return True
            return False

        n_zero_pad = 0
        n_hash_match = 0
        n_validated = 0

        for off in range(0, scan_len - 0x20, 8):
            inter_ptr = struct.unpack_from('<Q', scan_data, off)[0]
            type_ptr  = struct.unpack_from('<Q', scan_data, off + 8)[0]

            if is_text_ptr(inter_ptr) or is_text_ptr(type_ptr):
                continue
            if not is_mapped_ptr(inter_ptr) or not is_mapped_ptr(type_ptr):
                continue

            # Zero padding at +0x14 is the primary pre-filter
            padding = struct.unpack_from('<I', scan_data, off + 0x14)[0]
            if padding != 0:
                continue
            n_zero_pad += 1

            # Hash match: itab+0x10 must equal _type+0x10 (where _type is at itab+0x08)
            itab_hash = struct.unpack_from('<I', scan_data, off + 0x10)[0]
            type_hash = self._read_va_u32(type_ptr + 0x10)
            if type_hash is None or type_hash != itab_hash:
                continue
            n_hash_match += 1

            # Kind byte at inter+0x17 must be 0x14 (kindInterface)
            kind = self._read_va_u8(inter_ptr + 0x17)
            if kind != 0x14:
                continue

            # Methods start at +0x18
            methods = []
            moff = off + 0x18
            while moff + 8 <= scan_len:
                mptr = struct.unpack_from('<Q', scan_data, moff)[0]
                if not is_text_ptr(mptr):
                    break
                methods.append(mptr)
                moff += 8
            if not methods:
                continue

            n_validated += 1
            inter_va = inter_ptr
            type_va  = type_ptr

            if inter_va not in self.itab_map:
                self.itab_map[inter_va] = {}
            self.itab_map[inter_va][type_va] = methods

            for slot_idx, mva in enumerate(methods):
                if mva not in self.method_implementations:
                    self.method_implementations[mva] = []
                self.method_implementations[mva].append((inter_va, type_va))
                key = (inter_va, slot_idx)
                if key not in self.slot_methods:
                    self.slot_methods[key] = []
                self.slot_methods[key].append(mva)

        print(f'  itab: {n_zero_pad} zero-pad, {n_hash_match} hash-match, '
              f'{n_validated} kind-validated itabs')

    # ---------------------------------------------------------- public queries

    def scan(self, dangerous_targets: List[str]) -> List[DangerousCallHit]:
        """
        Find Fortinet-namespaced functions that statically call dangerous targets.
        O(1) per target after build().
        """
        if not self._built:
            self.build()

        target_va_map: Dict[int, str] = {
            va: name for va, name in self.all_names.items()
            if any(t in name for t in dangerous_targets)
        }

        hits: List[DangerousCallHit] = []
        seen: Set[Tuple[int, int]] = set()

        for callee_va, callee_name in target_va_map.items():
            for func_va, call_va in self.static_calls.get(callee_va, set()):
                if func_va not in self.func_map:
                    continue
                key = (func_va, callee_va)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(DangerousCallHit(
                    func_name=self.func_map[func_va][1],
                    func_va=func_va,
                    call_va=call_va,
                    call_target_va=callee_va,
                    call_target_name=callee_name,
                    string_refs=self.func_strings.get(func_va, []),
                ))

        hits.sort(key=lambda h: h.func_va)
        return hits

    def callers_of(self, func_name_substr: str) -> List[Tuple[int, str, int, str]]:
        """
        All Fortinet-namespaced callers of functions whose name contains func_name_substr.
        Returns: [(callee_va, callee_name, caller_func_va, caller_func_name)]
        O(1) lookup.
        """
        if not self._built:
            self.build()
        results = []
        for va, name in self.all_names.items():
            if func_name_substr not in name:
                continue
            for func_va, call_va in self.static_calls.get(va, set()):
                if func_va not in self.func_map:
                    continue
                results.append((va, name, func_va, self.func_map[func_va][1]))
        return sorted(results)

    def rodata_search(self, keywords: List[str], require_format: bool = True) -> List[Tuple[int, str]]:
        """
        Keyword search across all rodata strings. O(n) in rodata string count.
        """
        results = []
        for va, s in self.rodata_strings.items():
            s_lower = s.lower()
            if any(kw.lower() in s_lower for kw in keywords):
                if require_format and not any(f in s for f in ['%s', '%v', '%d', '%q', '%x']):
                    continue
                results.append((va, s))
        return sorted(results)

    def xrefs_to_va(self, target_va: int) -> List[Tuple[int, str]]:
        """
        All Fortinet callers of target_va (static calls only). O(1).
        """
        return [
            (call_va, self.func_map[fva][1])
            for fva, call_va in self.static_calls.get(target_va, set())
            if fva in self.func_map
        ]

    def xrefs_to_string_va(self, target_va: int) -> List[Tuple[int, str]]:
        """
        All Fortinet functions that LEA-ref a rodata string at target_va. O(n) in func_strings.
        """
        results = []
        for func_va, refs in self.func_strings.items():
            for sva, s in refs:
                if sva == target_va and func_va in self.func_map:
                    results.append((func_va, self.func_map[func_va][1]))
        return results

    def resolve_indirect_calls(self, func_va: int) -> List[Tuple[int, int, List[str]]]:
        """
        For each indirect call site in func_va, return candidate concrete implementations.

        Uses method index extracted during callgraph build (from backtracked instruction window).
        When method_index >= 0: query slot_methods[(inter_va, method_index)] for all concrete
        implementations at that slot position across all known interface types: precise CHA.
        When method_index == -1: fall back to all Fortinet method implementations (noisy).

        Returns: [(call_site_va, method_index, [candidate_func_names])]

        Go ABI note: interface dispatch pattern is
          MOV rcx, [rax + 0x18 + 8*N]   ; load fun[N] from itab
          CALL rcx                        ; dispatch
        method_index N is extracted by backtracking from the CALL.
        """
        if not self._built:
            self.build()
        results = []
        for call_va, op_str, method_idx in self.indirect_calls.get(func_va, []):
            if method_idx >= 0:
                # Precise CHA: find all concrete methods at this slot across all interfaces
                candidates = []
                for (inter_va, slot_idx), method_vas in self.slot_methods.items():
                    if slot_idx != method_idx:
                        continue
                    for mva in method_vas:
                        mname = self.all_names.get(mva, '')
                        if self.namespace in mname:
                            candidates.append(mname)
                # Deduplicate, cap noise
                candidates = list(dict.fromkeys(candidates))[:20]
            else:
                # Fallback: all Fortinet method implementations (broad)
                candidates = [
                    self.all_names[mva]
                    for mva in self.method_implementations
                    if self.namespace in self.all_names.get(mva, '')
                ][:10]
            results.append((call_va, method_idx, candidates))
        return results

    def itab_implementations(self, method_name_substr: str) -> Dict[str, List[str]]:
        """
        Find all concrete types that implement a method containing method_name_substr.
        Returns: {concrete_type_name: [method_names]}
        Uses pclntab names for type identification where available.
        """
        if not self._built:
            self.build()
        target_method_vas = {
            va for va, name in self.all_names.items()
            if method_name_substr in name
        }
        result: Dict[str, List[str]] = {}
        for mva in target_method_vas:
            mname = self.all_names[mva]
            for inter_va, type_va in self.method_implementations.get(mva, []):
                type_name = self.all_names.get(type_va, f'<type:{type_va:#x}>')
                if type_name not in result:
                    result[type_name] = []
                result[type_name].append(mname)
        return result

    def cha_for_method_index(self, method_index: int,
                             inter_va: Optional[int] = None) -> List[Tuple[int, str]]:
        """
        Class hierarchy analysis: all concrete method implementations at a given slot index.
        If inter_va is provided, filter to that interface type only.
        Returns: [(method_va, func_name)] sorted by method_va.
        """
        if not self._built:
            self.build()
        results = []
        for (iva, slot_idx), method_vas in self.slot_methods.items():
            if slot_idx != method_index:
                continue
            if inter_va is not None and iva != inter_va:
                continue
            for mva in method_vas:
                mname = self.all_names.get(mva, f'<{mva:#x}>')
                results.append((mva, mname))
        return sorted(results)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Go binary dangerous-call-site scanner (rodata-first, pre-built callgraph)')
    parser.add_argument('binary', help='Path to Go ELF binary')
    parser.add_argument('--targets', nargs='+',
                        default=['fmt.Sprintf', 'os/exec.Command',
                                 'os/exec.(*Cmd).Run', 'os/exec.(*Cmd).Start',
                                 'os/exec.(*Cmd).Output', 'os/exec.(*Cmd).CombinedOutput'],
                        help='Dangerous call target name substrings')
    parser.add_argument('--namespace', default='',
                        help='Namespace filter for function names')
    parser.add_argument('--rodata-sql', action='store_true',
                        help='Print rodata SQL strings with format specifiers')
    parser.add_argument('--callers-of',
                        help='Print callers of functions containing this substring')
    parser.add_argument('--resolve-indirect', type=lambda x: int(x, 0),
                        help='Resolve indirect calls for function at this VA (hex)')
    parser.add_argument('--cha', type=int,
                        help='CHA: show all concrete implementations at method slot N')
    parser.add_argument('--force', action='store_true',
                        help='Rebuild callgraph even if cache exists')
    args = parser.parse_args()

    scanner = GoDangerousCallerScanner(args.binary, namespace=args.namespace)
    scanner.build(force=args.force)

    if args.rodata_sql:
        print('\n=== RODATA SQL STRINGS WITH FORMAT SPECIFIERS ===')
        for va, s in scanner.rodata_search(
                ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'FROM']):
            print(f'  {va:#x}: {repr(s[:120])}')

    if args.callers_of:
        print(f'\n=== CALLERS OF: {args.callers_of} ===')
        for callee_va, callee_name, caller_fva, caller_name in scanner.callers_of(args.callers_of):
            print(f'  {caller_fva:#010x} {caller_name}')
            print(f'    calls {callee_va:#x} {callee_name}')

    if args.resolve_indirect:
        print(f'\n=== INDIRECT CALLS IN {args.resolve_indirect:#x} ===')
        for site_va, method_idx, candidates in scanner.resolve_indirect_calls(args.resolve_indirect):
            print(f'  {site_va:#010x} method[{method_idx}]:')
            for c in candidates[:5]:
                print(f'    {c}')

    if args.cha is not None:
        print(f'\n=== CHA: SLOT {args.cha} IMPLEMENTATIONS ===')
        for mva, mname in scanner.cha_for_method_index(args.cha):
            print(f'  {mva:#010x}: {mname}')

    print(f'\n=== DANGEROUS CALL SITES (targets: {args.targets}) ===')
    hits = scanner.scan(args.targets)
    print(f'Found {len(hits)} sites in {args.namespace}-namespaced functions\n')
    for hit in hits:
        print(hit)
        print()

    print(f'\n=== ITAB SUMMARY ===')
    print(f'  {len(scanner.itab_map)} interface types with concrete implementations')
    n_types = sum(len(types) for types in scanner.itab_map.values())
    print(f'  {n_types} (interface, concrete_type) pairs total')
    print(f'  {len(scanner.method_implementations)} method VAs resolved via itab')
    print(f'  {len(scanner.slot_methods)} (interface, slot) pairs in CHA index')
