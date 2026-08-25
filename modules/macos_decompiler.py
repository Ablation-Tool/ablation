#!/usr/bin/env python3
"""
macOS Decompiler Module — ablation
Lifts Mach-O x86_64 and arm64 functions to annotated pseudocode.

Pipeline:
  Phase 0: Mach-O parse (LIEF)
  Phase 1: ObjC metadata extraction (__DATA selrefs, classrefs, ivar offsets)
  Phase 2: Disassembly (capstone)
  Phase 3: ObjC pre-recognition (pattern layer above IR)
  Phase 4: BBL splitting
  Phase 5: CFG construction (networkx DiGraph)
  Phase 6: pyvex lifting (per BBL → VEX IR, already SSA-like)
  Phase 7: Dominance analysis + loop detection
  Phase 8: Structured control flow recovery (simplified Cifuentes)
  Phase 9: Type annotation (ObjC metadata + ablation address tables)
  Phase 10: Pseudocode emission

Integration: pass address_table from anyconnect_re.py method dicts to
annotate call targets with known method names.

Synthesized from:
  Engineering a Compiler 2nd ed. (9780080916613)
  Practical Binary Analysis (practical-binary-analysis)
  Decompiling Java (9781430207399)
  The Art of Mac Malware (the-art-of-mac-malware)
"""

import struct
import re
import json
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Set, Any
from pathlib import Path

try:
    import lief
    LIEF_OK = True
except ImportError:
    LIEF_OK = False

try:
    import capstone
    CS_OK = True
except ImportError:
    CS_OK = False

try:
    import pyvex
    import archinfo as archinfo_mod
    PYVEX_OK = True
except ImportError:
    PYVEX_OK = False

try:
    import networkx as nx
    NX_OK = True
except ImportError:
    NX_OK = False


# ── VEX register map (amd64) ──────────────────────────────────────────────────

AMD64_REG = {
    16: 'rax', 24: 'rcx', 32: 'rdx', 40: 'rbx',
    48: 'rsp', 56: 'rbp', 64: 'rsi', 72: 'rdi',
    80: 'r8', 88: 'r9', 96: 'r10', 104: 'r11',
    112: 'r12', 120: 'r13', 128: 'r14', 136: 'r15',
    184: 'rip',
}
AMD64_REG_INV = {v: k for k, v in AMD64_REG.items()}

# arm64 ABI calling convention registers
ARM64_ARGS = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']

# x86_64 ABI: rdi, rsi, rdx, rcx, r8, r9
AMD64_ARGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']


# ── Branch mnemonics ──────────────────────────────────────────────────────────

X86_TERMINATORS = {
    'ret', 'retq', 'retf', 'retn',
    'jmp', 'jmpq',
    'je', 'jne', 'jz', 'jnz',
    'jg', 'jl', 'jge', 'jle',
    'ja', 'jb', 'jae', 'jbe',
    'jo', 'jno', 'js', 'jns',
    'jp', 'jnp', 'jpe', 'jpo',
    'jcxz', 'jecxz', 'jrcxz',
    'ud2', 'int3', 'hlt',
}

X86_COND_BRANCHES = {
    'je', 'jne', 'jz', 'jnz',
    'jg', 'jl', 'jge', 'jle',
    'ja', 'jb', 'jae', 'jbe',
    'jo', 'jno', 'js', 'jns',
    'jp', 'jnp', 'jpe', 'jpo',
    'jcxz', 'jecxz', 'jrcxz',
}

ARM64_TERMINATORS = {
    'ret', 'b', 'bl', 'br', 'blr',
    'cbz', 'cbnz', 'tbz', 'tbnz',
    'b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge',
    'b.lo', 'b.ls', 'b.hi', 'b.hs',
    'b.mi', 'b.pl', 'b.vs', 'b.vc',
    'b.al', 'udf',
}

ARM64_COND_BRANCHES = {
    'cbz', 'cbnz', 'tbz', 'tbnz',
    'b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge',
    'b.lo', 'b.ls', 'b.hi', 'b.hs',
    'b.mi', 'b.pl', 'b.vs', 'b.vc',
}


# ── ObjC ABI constants ────────────────────────────────────────────────────────

BLOCK_ISA_STACK  = 0xC2000000  # NSConcreteStackBlock
BLOCK_ISA_GLOBAL = 0xC3000000  # NSConcreteGlobalBlock
BLOCK_ISA_HEAP   = 0xC6000000  # NSConcreteMallocBlock

OBJC_MSGSEND_NAMES = {
    '_objc_msgSend', '_objc_msgSend_stret',
    '_objc_msgSendSuper', '_objc_msgSendSuper_stret',
    '_objc_msgSendSuper2', '_objc_msgSend_fixup',
}

ATOMIC_GETTER_NAMES = {
    '_objc_getProperty', 'objc_getProperty',
    '__objc_getProperty_atomic',
}
ATOMIC_SETTER_NAMES = {
    '_objc_setProperty', 'objc_setProperty',
    '_objc_setProperty_atomic', '__objc_setProperty_atomic',
    '_objc_setProperty_nonatomic', '_objc_copyStruct',
}

# ARC memory management functions inserted by clang (ARC Implementation ch3)
ARC_RETAIN_NAMES = {
    '_objc_retain', 'objc_retain',
    '_objc_retainAutoreleasedReturnValue', 'objc_retainAutoreleasedReturnValue',
    '_objc_retainAutoreleaseReturnValue', 'objc_retainAutoreleaseReturnValue',
}
ARC_RELEASE_NAMES = {
    '_objc_release', 'objc_release',
    '_objc_autorelease', 'objc_autorelease',
    '_objc_autoreleaseReturnValue', 'objc_autoreleaseReturnValue',
}
ARC_STORE_NAMES = {
    '_objc_storeStrong', 'objc_storeStrong',
    '_objc_storeWeak', 'objc_storeWeak',
    '_objc_loadWeakRetained', 'objc_loadWeakRetained',
    '_objc_copyWeak', 'objc_copyWeak',
    '_objc_destroyWeak', 'objc_destroyWeak',
}
ARC_NAMES = ARC_RETAIN_NAMES | ARC_RELEASE_NAMES | ARC_STORE_NAMES

# arm64 intra-procedure scratch registers used in stubs/trampolines (AAPCS64)
ARM64_STUB_REGS = {'x16', 'x17'}  # IP0/IP1 — linker-used indirect call targets


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ObjCMethod:
    sel: str
    imp_va: int
    type_enc: str = ''

@dataclass
class ObjCClass:
    name: str
    methods: List[ObjCMethod] = field(default_factory=list)
    ivars: Dict[str, int] = field(default_factory=dict)  # name → offset

@dataclass
class BasicBlock:
    start: int
    instrs: List[Any]  # capstone CsInsn
    successors: List[int] = field(default_factory=list)  # target VAs
    branch_type: str = 'fall'  # 'fall' | 'uncond' | 'cond' | 'call' | 'ret' | 'trap'
    vex: Optional[Any] = None  # pyvex IRSB

@dataclass
class ObjCCall:
    """Recognized ObjC message send at a call site."""
    va: int
    receiver_reg: str  # register holding receiver (usually rdi/x0)
    selector: str      # resolved selector string
    args: List[str] = field(default_factory=list)
    method_name: str = ''  # from address table, if known

@dataclass
class StructNode:
    """Node in the structured control flow tree."""
    kind: str  # 'seq' | 'if' | 'while' | 'dowhile' | 'basic' | 'goto'
    bbl: Optional[int] = None        # for kind='basic'
    condition: str = ''              # for if/while
    then_branch: Optional['StructNode'] = None
    else_branch: Optional['StructNode'] = None
    body: Optional['StructNode'] = None
    children: List['StructNode'] = field(default_factory=list)
    goto_target: int = 0


@dataclass
class DecompResult:
    """Decompilation result for one function."""
    va: int
    name: str
    arch: str
    pseudocode: str
    cfg_dot: str
    bbls: Dict[int, BasicBlock]
    objc_calls: List[ObjCCall]
    annotations: Dict[str, Any]  # security findings


# ── ObjC metadata extractor ───────────────────────────────────────────────────

class ObjCMetadata:
    """Extracts ObjC runtime metadata from Mach-O __DATA sections."""

    def __init__(self, binary):
        self.binary = binary
        self.selrefs: Dict[int, str] = {}      # VA → selector string
        self.classrefs: Dict[int, str] = {}    # VA → class name
        self.classes: Dict[str, ObjCClass] = {}
        self.msgSend_stubs: Set[int] = set()   # VAs of objc_msgSend stubs
        self._extract()

    def _extract(self):
        if not LIEF_OK or not hasattr(self.binary, 'sections'):
            return
        # Build VA-indexed section content cache
        self._sec_cache: list = []  # list of (va, end_va, bytes)
        for s in self.binary.sections:
            if s.size:
                raw = bytes(s.content)
                self._sec_cache.append((s.virtual_address, s.virtual_address + s.size, raw))
        # Detect LC_DYLD_CHAINED_FIXUPS: pointers in __DATA are encoded as
        # chained rebase entries, not raw VAs. Decode: actual_va = image_base + (raw & 0xFFFFFFFFF)
        self._chained_fixups = False
        self._image_base = 0x100000000  # arm64 Mach-O default
        for cmd in self.binary.commands:
            cn = str(cmd.command)
            if 'CHAINED_FIXUPS' in cn:
                self._chained_fixups = True
                break
        # Determine image base from first __TEXT segment
        for seg in (self.binary.segments if hasattr(self.binary, 'segments') else []):
            if seg.name.strip('\x00') == '__TEXT' and seg.virtual_address:
                self._image_base = seg.virtual_address & ~0xFFF
                break
        self._extract_selrefs()
        self._extract_classrefs()
        self._extract_method_lists()
        self._extract_stubs()

    def _get_section(self, segname, sectname):
        for s in self.binary.sections:
            sn = s.name.strip('\x00')
            if hasattr(s, 'segment') and s.segment:
                sg = s.segment.name.strip('\x00')
            else:
                sg = ''
            if sn == sectname and (segname in sg or not segname):
                return s
        return None

    def _decode_ptr(self, raw: int) -> int:
        """Decode a raw 8-byte pointer value to an actual VA.

        Handles both plain absolute VAs and LC_DYLD_CHAINED_FIXUPS rebase encodings.
        Chained rebase: actual_va = image_base + (raw & 0xFFFFFFFFF)  [36-bit target field]
        """
        if not self._chained_fixups:
            return raw
        # DYLD_CHAINED_PTR_64_REBASE: bit 63 = bind flag (0 = rebase)
        if raw >> 63:
            return 0  # bind entry — no local VA
        target = raw & 0xFFFFFFFFF  # low 36 bits
        high8 = (raw >> 36) & 0xFF  # bits 36-43 (top byte of actual VA)
        return (high8 << 56) | (self._image_base + target)

    def _extract_selrefs(self):
        sec = self._get_section('__DATA', '__objc_selrefs')
        if sec is None:
            sec = self._get_section('__DATA_CONST', '__objc_selrefs')
        if sec is None:
            return
        content = bytes(sec.content)
        for i in range(0, len(content) - 7, 8):
            ptr_va = sec.virtual_address + i
            raw = struct.unpack_from('<Q', content, i)[0]
            target_va = self._decode_ptr(raw)
            if not target_va:
                continue
            sel = self._read_cstring(target_va)
            if sel:
                self.selrefs[ptr_va] = sel

    def _extract_classrefs(self):
        sec = self._get_section('__DATA', '__objc_classrefs')
        if sec is None:
            sec = self._get_section('__DATA_CONST', '__objc_classrefs')
        if sec is None:
            return
        content = bytes(sec.content)
        for i in range(0, len(content) - 7, 8):
            ptr_va = sec.virtual_address + i
            raw = struct.unpack_from('<Q', content, i)[0]
            target_va = self._decode_ptr(raw)
            if not target_va:
                continue
            name = self._resolve_classptr(target_va)
            if name:
                self.classrefs[ptr_va] = name

    # ------------------------------------------------------------------
    # classlist + method list parser
    # ------------------------------------------------------------------
    # method_map:  selector_name → [imp_va, ...]
    # imp_map:     imp_va → 'ClassName.selector'
    # classes:     class_name → ObjCClass (already declared above)
    # ------------------------------------------------------------------

    def _extract_method_lists(self):
        """Walk __objc_classlist, parse class_ro_t, extract method tables.

        Handles two method_list_t formats:
          - Absolute (flags bit 31 = 0): entries are 24-byte {sel_ptr, types_ptr, imp_ptr}
          - Relative (flags bit 31 = 1): entries are 12-byte {sel_rel, types_rel, imp_rel}
            used by arm64 macOS 12+ binaries compiled with -objc_relative_method_lists
        """
        self.method_map: Dict[str, list] = {}   # sel_name → [imp_va]
        self.imp_map:    Dict[int, str]  = {}   # imp_va   → 'Class.sel'

        # Prefer DATA_CONST, fall back to DATA
        classlist = (self._get_section('__DATA_CONST', '__objc_classlist') or
                     self._get_section('__DATA',       '__objc_classlist'))
        if classlist is None:
            return

        clcontent = bytes(classlist.content)
        n_classes = len(clcontent) // 8

        for ci in range(n_classes):
            raw_cls = struct.unpack_from('<Q', clcontent, ci * 8)[0]
            cls_va  = self._decode_ptr(raw_cls)
            if not cls_va:
                cls_va = raw_cls & ~7
            if not cls_va:
                continue

            # -- class_t (5 × 8-byte fields): metacls, super, cache, vtable, data --
            cls_raw = self._read_at(cls_va, 48)
            if len(cls_raw) < 40:
                continue

            # Walk both the class and its metaclass
            for is_meta in (False, True):
                if is_meta:
                    meta_raw_ptr = struct.unpack_from('<Q', cls_raw, 0)[0]
                    meta_va = self._decode_ptr(meta_raw_ptr)
                    if not meta_va:
                        meta_va = meta_raw_ptr & ~7
                    if not meta_va:
                        continue
                    target_raw = self._read_at(meta_va, 48)
                    if len(target_raw) < 40:
                        continue
                else:
                    target_raw = cls_raw

                raw_data = struct.unpack_from('<Q', target_raw, 32)[0]
                ro_va    = self._decode_ptr(raw_data) & ~7
                if not ro_va:
                    ro_va = raw_data & ~7
                if not ro_va:
                    continue

                # -- class_ro_t offsets --
                # [0x00] flags uint32  [0x04] instanceStart  [0x08] instanceSize
                # [0x10] ivarLayout ptr  [0x18] name ptr
                # [0x20] baseMethods ptr  [0x28] baseProtocols  [0x30] ivars
                ro_raw = self._read_at(ro_va, 64)
                if len(ro_raw) < 40:
                    continue

                raw_name = struct.unpack_from('<Q', ro_raw, 24)[0]
                name_va  = self._decode_ptr(raw_name) if raw_name else 0
                if not name_va:
                    name_va = raw_name
                class_name = self._read_cstring(name_va) if name_va else ''
                if not class_name:
                    continue

                prefix = '+' if is_meta else '-'

                # Register class in self.classes
                if not is_meta and class_name not in self.classes:
                    self.classes[class_name] = ObjCClass(name=class_name)

                raw_ml = struct.unpack_from('<Q', ro_raw, 32)[0]
                ml_va  = self._decode_ptr(raw_ml) & ~7
                if not ml_va:
                    ml_va = raw_ml & ~7
                if not ml_va:
                    continue

                self._parse_method_list(ml_va, class_name, prefix)

    def _parse_method_list(self, ml_va: int, class_name: str, prefix: str):
        """Parse one method_list_t at ml_va, register entries into method_map/imp_map."""
        ml_hdr = self._read_at(ml_va, 8)
        if len(ml_hdr) < 8:
            return

        flags, count = struct.unpack_from('<II', ml_hdr)
        if count == 0 or count > 4096:
            return

        relative = bool(flags & 0x80000000)   # bit 31: relative method selectors
        entry_size = 12 if relative else 24
        entries_va = ml_va + 8

        for mi in range(count):
            entry_va = entries_va + mi * entry_size
            entry_raw = self._read_at(entry_va, entry_size)
            if len(entry_raw) < entry_size:
                break

            if relative:
                # Each field is a signed int32 offset FROM that field's address
                sel_rel, _types_rel, imp_rel = struct.unpack_from('<iii', entry_raw)

                # selector reference: the int32 at entry_va+0 points to a selref slot
                # which in turn points to the selector string
                selref_va = entry_va + sel_rel
                selref_raw = self._read_at(selref_va, 8)
                if len(selref_raw) < 8:
                    continue
                raw_selptr = struct.unpack_from('<Q', selref_raw)[0]
                sel_str_va = self._decode_ptr(raw_selptr)
                if not sel_str_va:
                    sel_str_va = raw_selptr
                sel_name = self._read_cstring(sel_str_va) if sel_str_va else ''

                # implementation: int32 relative from (entry_va + 8)
                imp_field_va = entry_va + 8
                imp_va = imp_field_va + imp_rel

                # Handle stubs: if imp points to a __stubs trampoline, resolve one hop
                imp_va = imp_va & ~1  # clear thumb bit (arm32 compat)

            else:
                # Absolute: {sel_ptr(8), types_ptr(8), imp(8)}
                sel_ptr_raw, _types_raw, imp_va = struct.unpack_from('<QQQ', entry_raw)
                sel_str_va = self._decode_ptr(sel_ptr_raw)
                if not sel_str_va:
                    sel_str_va = sel_ptr_raw
                sel_name = self._read_cstring(sel_str_va) if sel_str_va else ''
                imp_va = self._decode_ptr(imp_va) if imp_va else 0

            if not sel_name or not imp_va:
                continue

            full_name = f'{prefix}[{class_name} {sel_name}]'
            if sel_name not in self.method_map:
                self.method_map[sel_name] = []
            self.method_map[sel_name].append(imp_va)
            self.imp_map[imp_va] = full_name

            # Also extend class record
            if class_name in self.classes and prefix == '-':
                self.classes[class_name].methods.append(sel_name)

    def _extract_stubs(self):
        for sym in self.binary.symbols:
            n = sym.name
            if any(ms in n for ms in OBJC_MSGSEND_NAMES):
                if sym.value:
                    self.msgSend_stubs.add(sym.value)

    def _read_at(self, va: int, n: int = 256) -> bytes:
        """Read n bytes at va using pre-built section cache (no LIEF VA lookup)."""
        for (sec_va, sec_end, sec_raw) in self._sec_cache:
            if sec_va <= va < sec_end:
                off = va - sec_va
                return sec_raw[off:min(off + n, len(sec_raw))]
        return b''

    def _read_cstring(self, va: int) -> str:
        raw = self._read_at(va, 256)
        if not raw:
            return ''
        end = raw.find(b'\x00')
        s = raw[:end] if end >= 0 else raw
        try:
            return s.decode('utf-8', errors='replace').strip('\x00')
        except Exception:
            return ''

    def _resolve_classptr(self, va: int) -> str:
        # ObjC class_t: [0x20] = data_ptr → class_ro_t
        # class_ro_t: [0x18] = name_ptr (null-terminated class name)
        try:
            raw = self._read_at(va, 48)
            if len(raw) < 40:
                return ''
            raw_data = struct.unpack_from('<Q', raw, 32)[0]
            data_ptr = self._decode_ptr(raw_data) & ~7
            if not data_ptr:
                # Fallback: treat raw_data as direct VA masked
                data_ptr = raw_data & ~7
            if not data_ptr:
                return ''
            ro_raw = self._read_at(data_ptr, 32)
            if len(ro_raw) < 32:
                return ''
            raw_name = struct.unpack_from('<Q', ro_raw, 24)[0]
            name_ptr = self._decode_ptr(raw_name) if raw_name else 0
            if not name_ptr:
                name_ptr = raw_name
            return self._read_cstring(name_ptr) if name_ptr else ''
        except Exception:
            return ''

    def resolve_selref(self, va: int) -> Optional[str]:
        return self.selrefs.get(va)

    def resolve_classref(self, va: int) -> Optional[str]:
        return self.classrefs.get(va)

    def is_msgsend_stub(self, va: int) -> bool:
        return va in self.msgSend_stubs


# ── Disassembler wrapper ──────────────────────────────────────────────────────

class Disassembler:
    def __init__(self, binary, arch: str):
        self.binary = binary
        self.arch = arch
        if CS_OK:
            if arch == 'x86_64':
                self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            self.cs.detail = True
        else:
            self.cs = None

    def disasm(self, va: int, max_bytes: int = 4096) -> List[Any]:
        if not self.cs:
            return []
        try:
            code = bytes(self.binary.get_content_from_virtual_address(va, max_bytes))
            return list(self.cs.disasm(code, va))
        except Exception:
            return []

    def disasm_func(self, va: int, end_va: int = 0) -> List[Any]:
        """Disassemble until ret/end_va, scanning up to 32KB."""
        instrs = []
        limit = end_va if end_va else va + 32768
        for instr in self.disasm(va, min(32768, limit - va + 64)):
            instrs.append(instr)
            if instr.address >= limit:
                break
            if instr.mnemonic in ('ret', 'retq', 'ud2', 'int3'):
                break
        return instrs


# ── BBL splitter ──────────────────────────────────────────────────────────────

def _parse_branch_target(instr, arch: str) -> Optional[int]:
    """Extract branch target VA from operand string."""
    try:
        op = instr.op_str.strip()
        # immediate: '0x1234', '4660'
        if op.startswith('0x'):
            return int(op, 16)
        if op.lstrip('-').isdigit():
            return int(op)
        # x86: 'near ptr 0x...' or direct hex
        m = re.search(r'0x([0-9a-fA-F]+)', op)
        if m:
            return int(m.group(1), 16)
    except Exception:
        pass
    return None


def split_bbls(instrs: List[Any], arch: str) -> List[BasicBlock]:
    """Split linear instruction list into basic blocks."""
    if not instrs:
        return []

    terminators = X86_TERMINATORS if arch == 'x86_64' else ARM64_TERMINATORS
    cond_branches = X86_COND_BRANCHES if arch == 'x86_64' else ARM64_COND_BRANCHES

    # Pass 1: find all leaders
    leaders: Set[int] = {instrs[0].address}
    for i, instr in enumerate(instrs):
        m = instr.mnemonic.lower()
        if m in terminators:
            if i + 1 < len(instrs):
                leaders.add(instrs[i + 1].address)
            target = _parse_branch_target(instr, arch)
            if target:
                leaders.add(target)

    # Pass 2: split
    bbls: List[BasicBlock] = []
    current: List[Any] = []
    for instr in instrs:
        if instr.address in leaders and current:
            bbls.append(_make_bbl(current, arch, terminators, cond_branches))
            current = []
        current.append(instr)
    if current:
        bbls.append(_make_bbl(current, arch, terminators, cond_branches))

    # Pass 3: wire successors
    addr_to_bbl: Dict[int, BasicBlock] = {b.start: b for b in bbls}
    for i, bbl in enumerate(bbls):
        last = bbl.instrs[-1]
        m = last.mnemonic.lower()
        if bbl.branch_type in ('ret', 'trap'):
            pass
        elif bbl.branch_type == 'uncond':
            target = _parse_branch_target(last, arch)
            if target and target in addr_to_bbl:
                bbl.successors = [target]
        elif bbl.branch_type == 'cond':
            target = _parse_branch_target(last, arch)
            if i + 1 < len(bbls):
                fallthrough = bbls[i + 1].start
                bbl.successors = []
                if target and target in addr_to_bbl:
                    bbl.successors.append(target)
                bbl.successors.append(fallthrough)
        else:  # fall
            if i + 1 < len(bbls):
                bbl.successors = [bbls[i + 1].start]

    return bbls


def _make_bbl(instrs: List[Any], arch: str,
              terminators: Set[str], cond_branches: Set[str]) -> BasicBlock:
    last = instrs[-1]
    m = last.mnemonic.lower()
    if m in ('ret', 'retq', 'retf', 'retn'):
        bt = 'ret'
    elif m in ('ud2', 'int3', 'hlt', 'udf'):
        bt = 'trap'
    elif m in ('jmp', 'jmpq', 'b', 'br') and arch == 'x86_64':
        bt = 'uncond'
    elif m == 'b' and arch == 'arm64':
        bt = 'uncond'
    elif m in ('blr', 'bl', 'call', 'callq'):
        bt = 'call'
    elif m in cond_branches or (arch == 'arm64' and m.startswith('b.')):
        bt = 'cond'
    elif m in terminators:
        bt = 'uncond'
    else:
        bt = 'fall'
    return BasicBlock(start=instrs[0].address, instrs=instrs, branch_type=bt)


# ── CFG builder ───────────────────────────────────────────────────────────────

def build_cfg(bbls: List[BasicBlock]) -> 'nx.DiGraph':
    if not NX_OK:
        raise ImportError('networkx required')
    G = nx.DiGraph()
    for bbl in bbls:
        G.add_node(bbl.start, bbl=bbl)
        for s in bbl.successors:
            G.add_edge(bbl.start, s)
    return G


# ── VEX lifter ────────────────────────────────────────────────────────────────

class VEXLifter:
    def __init__(self, binary, arch: str):
        self.binary = binary
        self.arch = arch
        if arch == 'x86_64':
            self.vex_arch = archinfo_mod.arch_from_id('amd64')
        else:
            self.vex_arch = archinfo_mod.arch_from_id('aarch64')

    def lift_bbl(self, bbl: BasicBlock) -> Optional[Any]:
        if not PYVEX_OK:
            return None
        try:
            n_bytes = sum(i.size for i in bbl.instrs)
            code = bytes(self.binary.get_content_from_virtual_address(bbl.start, n_bytes))
            irsb = pyvex.lift(code, bbl.start, self.vex_arch,
                              max_bytes=n_bytes, max_inst=len(bbl.instrs),
                              opt_level=0)
            bbl.vex = irsb
            return irsb
        except Exception:
            return None


# ── ObjC pre-recognition pass ─────────────────────────────────────────────────

class ObjCRecognizer:
    """Scan BBLs for ObjC patterns before IR analysis."""

    def __init__(self, meta: ObjCMetadata, addr_table: Dict[int, str],
                 arch: str):
        self.meta = meta
        self.addr_table = addr_table  # VA → method name
        self.arch = arch

    def scan(self, bbls: List[BasicBlock]) -> List[ObjCCall]:
        calls = []
        for bbl in bbls:
            calls.extend(self._scan_bbl(bbl))
        return calls

    def _scan_bbl(self, bbl: BasicBlock) -> List[ObjCCall]:
        results = []
        instrs = bbl.instrs
        n = len(instrs)
        for i, instr in enumerate(instrs):
            m = instr.mnemonic.lower()
            if self.arch == 'x86_64':
                if m in ('call', 'callq'):
                    results.extend(self._check_x86_call(instrs, i))
            else:
                if m in ('bl', 'blr'):
                    results.extend(self._check_arm64_call(instrs, i))
        return results

    def _check_x86_call(self, instrs: List[Any], idx: int) -> List[ObjCCall]:
        results = []
        instr = instrs[idx]
        target_va = _parse_branch_target(instr, 'x86_64')
        if target_va is None:
            return []

        # Resolve stub name
        target_name = self.addr_table.get(target_va, '')
        if not target_name:
            # Check binary symbols
            target_name = self._resolve_sym(target_va)

        is_msgsend = any(ms in target_name for ms in OBJC_MSGSEND_NAMES) or \
                     self.meta.is_msgsend_stub(target_va)
        is_getter = any(g in target_name for g in ATOMIC_GETTER_NAMES)
        is_setter = any(s in target_name for s in ATOMIC_SETTER_NAMES)
        is_arc = any(a in target_name for a in ARC_NAMES)

        if is_msgsend:
            sel, recv = self._x86_extract_sel_recv(instrs, idx)
            oc = ObjCCall(
                va=instr.address,
                receiver_reg=recv,
                selector=sel,
                method_name=target_name,
            )
            results.append(oc)
        elif is_arc:
            arc_name = target_name.lstrip('_')
            oc = ObjCCall(
                va=instr.address,
                receiver_reg='rdi',
                selector=f'<{arc_name}>',
                method_name=target_name,
            )
            results.append(oc)
        elif is_getter or is_setter:
            kind = 'getter' if is_getter else 'setter'
            oc = ObjCCall(
                va=instr.address,
                receiver_reg='rdi',
                selector=f'<atomic {kind}>',
                method_name=target_name,
            )
            results.append(oc)
        elif target_name:
            oc = ObjCCall(
                va=instr.address,
                receiver_reg='rdi',
                selector='',
                method_name=target_name,
            )
            results.append(oc)

        return results

    def _x86_extract_sel_recv(self, instrs: List[Any], call_idx: int
                               ) -> Tuple[str, str]:
        """Scan backwards from call to find selector (rsi) and receiver (rdi)."""
        sel = ''
        recv = 'rdi'
        for j in range(call_idx - 1, max(call_idx - 10, -1), -1):
            prev = instrs[j]
            pm = prev.mnemonic.lower()
            op = prev.op_str
            # lea rsi, [rip + off] → load selref
            if pm in ('lea', 'mov') and 'rsi' in op:
                m = re.search(r'0x([0-9a-fA-F]+)', op)
                if m:
                    va = int(m.group(1), 16)
                    resolved = self.meta.resolve_selref(va)
                    if resolved:
                        sel = resolved
            # lea rdi, [rip + off] → load classref / self
            if pm in ('lea', 'mov') and 'rdi' in op:
                m = re.search(r'0x([0-9a-fA-F]+)', op)
                if m:
                    va = int(m.group(1), 16)
                    classname = self.meta.resolve_classref(va)
                    if classname:
                        recv = f'[{classname} class]'
        return sel, recv

    def _check_arm64_call(self, instrs: List[Any], idx: int) -> List[ObjCCall]:
        results = []
        instr = instrs[idx]
        m = instr.mnemonic.lower()
        op = instr.op_str.strip()

        # bl #target or blr x16/x17 (IP0/IP1 = intra-procedure scratch = stub target)
        target_va = _parse_branch_target(instr, 'arm64')
        target_name = self.addr_table.get(target_va, '') if target_va else ''
        if not target_name and target_va:
            target_name = self._resolve_sym(target_va)

        # blr through x16 or x17 = indirect call through stub (AAPCS64: IP0/IP1)
        is_stub_indirect = m == 'blr' and any(r in op for r in ARM64_STUB_REGS)
        is_msgsend = is_stub_indirect or \
                     any(ms in target_name for ms in OBJC_MSGSEND_NAMES)

        is_arc = any(a in target_name for a in ARC_NAMES)
        is_getter = any(g in target_name for g in ATOMIC_GETTER_NAMES)
        is_setter = any(s in target_name for s in ATOMIC_SETTER_NAMES)

        if is_msgsend:
            sel = self._arm64_extract_sel(instrs, idx)
            recv = self._arm64_extract_recv(instrs, idx)
            oc = ObjCCall(
                va=instr.address,
                receiver_reg=recv,
                selector=sel,
                method_name=target_name or '_objc_msgSend',
            )
            results.append(oc)
        elif is_arc:
            arc_name = target_name.lstrip('_')
            oc = ObjCCall(
                va=instr.address,
                receiver_reg='x0',
                selector=f'<{arc_name}>',
                method_name=target_name,
            )
            results.append(oc)
        elif is_getter or is_setter:
            kind = 'getter' if is_getter else 'setter'
            oc = ObjCCall(
                va=instr.address,
                receiver_reg='x0',
                selector=f'<atomic {kind}>',
                method_name=target_name,
            )
            results.append(oc)
        elif target_name:
            oc = ObjCCall(
                va=instr.address,
                receiver_reg='x0',
                selector='',
                method_name=target_name,
            )
            results.append(oc)
        return results

    def _arm64_extract_recv(self, instrs: List[Any], call_idx: int) -> str:
        """Scan backwards for x0 load (receiver/self in ObjC ABI)."""
        for j in range(call_idx - 1, max(call_idx - 12, -1), -1):
            prev = instrs[j]
            pm = prev.mnemonic.lower()
            op = prev.op_str
            if pm in ('ldr', 'mov', 'add') and op.startswith('x0'):
                m = re.search(r'0x([0-9a-fA-F]+)', op)
                if m:
                    va = int(m.group(1), 16)
                    classname = self.meta.resolve_classref(va)
                    if classname:
                        return f'[{classname} class]'
        return 'x0'

    def _arm64_extract_sel(self, instrs: List[Any], call_idx: int) -> str:
        """Scan backwards for adrp+add or adrp+ldr+ldr pattern loading selector into x1.

        AAPCS64 ObjC convention: x0=receiver, x1=SEL (selector), x2...=args.
        Two common patterns (from Art of Mac Malware + LLVM codegen):
          Pattern A: adrp xN, PAGE; add x1, xN, #OFF  (loads selref VA directly)
          Pattern B: adrp xN, PAGE; ldr x1, [xN, #OFF]; ldr x1, [x1]  (deref selref)
        """
        adrp_page: Dict[str, int] = {}  # reg → page base
        for j in range(call_idx - 1, max(call_idx - 16, -1), -1):
            prev = instrs[j]
            pm = prev.mnemonic.lower()
            op = prev.op_str

            # Track ADRP: adrp xN, #page
            if pm == 'adrp':
                parts = [p.strip() for p in op.split(',')]
                if len(parts) == 2:
                    m = re.search(r'0x([0-9a-fA-F]+)', parts[1])
                    if m:
                        adrp_page[parts[0]] = int(m.group(1), 16)
                continue

            # Pattern A: add x1, xN, #OFF → selref VA = PAGE + OFF
            if pm == 'add' and op.startswith('x1'):
                parts = [p.strip() for p in op.split(',')]
                if len(parts) == 3:
                    base_reg = parts[1]
                    m = re.search(r'#?0x([0-9a-fA-F]+)', parts[2])
                    if m and base_reg in adrp_page:
                        va = adrp_page[base_reg] + int(m.group(1), 16)
                        resolved = self.meta.resolve_selref(va)
                        if resolved:
                            return resolved
                        # Try direct read as cstring
                        s = self.meta._read_cstring(va)
                        if s:
                            return s

            # Pattern B: ldr x1, [xN, #OFF] → load selref pointer then deref
            if pm == 'ldr' and op.startswith('x1'):
                parts = [p.strip() for p in op.split(',', 1)]
                if len(parts) == 2:
                    mem = parts[1].strip('[]')
                    m_base = re.match(r'(x\d+)', mem)
                    m_off = re.search(r'#?0x([0-9a-fA-F]+)', mem)
                    if m_base and m_off and m_base.group(1) in adrp_page:
                        va = adrp_page[m_base.group(1)] + int(m_off.group(1), 16)
                        resolved = self.meta.resolve_selref(va)
                        if resolved:
                            return resolved
                # Also catch plain ldr x1, [xN] after we have adrp context
                m = re.search(r'0x([0-9a-fA-F]+)', op)
                if m:
                    va = int(m.group(1), 16)
                    resolved = self.meta.resolve_selref(va)
                    if resolved:
                        return resolved
        return ''

    def _resolve_sym(self, va: int) -> str:
        if not hasattr(self, '_sym_cache'):
            self._sym_cache: Dict[int, str] = {}
        if va in self._sym_cache:
            return self._sym_cache[va]
        result = ''
        try:
            for sym in self.meta.binary.symbols:
                if sym.value == va and sym.name:
                    result = sym.name
                    break
        except Exception:
            pass
        self._sym_cache[va] = result
        return result


# ── Dominance and loop analysis ───────────────────────────────────────────────

class DominanceInfo:
    def __init__(self, G: 'nx.DiGraph', entry: int):
        self.G = G
        self.entry = entry
        self.idom: Dict[int, int] = {}
        self.dom_tree: 'nx.DiGraph' = nx.DiGraph()
        self.back_edges: Set[Tuple[int, int]] = set()
        self.loop_headers: Set[int] = set()
        self.ipdom: Dict[int, int] = {}
        self._compute()

    def _compute(self):
        if not NX_OK or self.entry not in self.G:
            return
        # Forward dominators
        try:
            self.idom = nx.immediate_dominators(self.G, self.entry)
        except Exception:
            return
        for node, dom in self.idom.items():
            if node != dom:
                self.dom_tree.add_edge(dom, node)

        # Back edges: (u→v) where v dominates u
        for u, v in self.G.edges():
            if u == v:
                self.back_edges.add((u, v))
                self.loop_headers.add(v)
                continue
            if v in self.idom and self._dominates(v, u):
                self.back_edges.add((u, v))
                self.loop_headers.add(v)

        # Post-dominators (reverse CFG)
        exits = [n for n in self.G.nodes() if self.G.out_degree(n) == 0]
        if not exits:
            return
        # Build a lightweight reverse graph (no node data — avoids ctypes deepcopy)
        Gr = nx.DiGraph()
        Gr.add_nodes_from(self.G.nodes())
        for u, v in self.G.edges():
            Gr.add_edge(v, u)
        virtual_exit = -1  # use sentinel int instead of object()
        Gr.add_node(virtual_exit)
        for e in exits:
            Gr.add_edge(virtual_exit, e)
        try:
            raw_pdom = nx.immediate_dominators(Gr, virtual_exit)
            self.ipdom = {k: v for k, v in raw_pdom.items()
                          if k != virtual_exit and v != virtual_exit}
        except Exception:
            pass

    def _dominates(self, dom: int, node: int) -> bool:
        """True if dom dominates node in the dominator tree."""
        cur = node
        visited = set()
        while cur != self.entry and cur not in visited:
            visited.add(cur)
            parent = self.idom.get(cur, cur)
            if parent == dom:
                return True
            if parent == cur:
                break
            cur = parent
        return cur == dom

    def post_dom(self, node: int) -> Optional[int]:
        return self.ipdom.get(node)


# ── Structured control flow recovery ─────────────────────────────────────────

class Structurer:
    """
    Simplified Cifuentes interval-based structuring.
    Produces a tree of StructNode objects.
    """

    def __init__(self, G: 'nx.DiGraph', entry: int, dom: DominanceInfo,
                 bbls: Dict[int, BasicBlock]):
        self.G = G
        self.entry = entry
        self.dom = dom
        self.bbls = bbls

    def structure(self) -> StructNode:
        """Entry point: structure the whole function."""
        order = self._rpo()
        return self._structure_region(order, set())

    def _rpo(self) -> List[int]:
        """Reverse post-order traversal of CFG (excluding back edges)."""
        if self.entry not in self.G:
            return []
        fwd = nx.DiGraph()
        for u, v in self.G.edges():
            if (u, v) not in self.dom.back_edges:
                fwd.add_edge(u, v)
        for n in self.G.nodes():
            fwd.add_node(n)
        try:
            return list(nx.dfs_preorder_nodes(fwd, self.entry))
        except Exception:
            return list(self.G.nodes())

    def _structure_region(self, nodes: List[int], visited: Set[int]) -> StructNode:
        """Recursively structure a list of nodes in RPO."""
        children: List[StructNode] = []
        i = 0
        while i < len(nodes):
            n = nodes[i]
            if n in visited:
                i += 1
                continue
            visited.add(n)

            bbl = self.bbls.get(n)
            if bbl is None:
                i += 1
                continue

            succs = [s for s in self.G.successors(n)
                     if (n, s) not in self.dom.back_edges]

            if n in self.dom.loop_headers:
                # Loop: collect body nodes (reachable before back edge)
                body_nodes = self._loop_body(n)
                body = self._structure_region(
                    [x for x in self._rpo() if x in body_nodes],
                    set(visited)
                )
                visited.update(body_nodes)
                cond = self._bbl_condition(bbl)
                # Post-test loop (do-while): the back-edge latching node is a
                # conditional branch whose taken-edge re-enters the header.
                # This matches the ARM64 post-test pattern from ARM64 Assembly ch5.
                latching = [u for u, v in self.dom.back_edges if v == n]
                is_dowhile = False
                if latching:
                    lat_bbl = self.bbls.get(latching[0])
                    if lat_bbl and lat_bbl.branch_type == 'cond':
                        is_dowhile = True
                kind = 'dowhile' if is_dowhile else 'while'
                sn = StructNode(kind=kind, bbl=n, condition=cond, body=body)

            elif len(succs) == 2:
                # If/else: find convergence (immediate post-dominator)
                taken, fallthrough = succs[0], succs[1]
                conv = self.dom.post_dom(n)
                then_nodes = self._region_up_to(taken, conv)
                else_nodes = self._region_up_to(fallthrough, conv)
                then_struct = self._structure_region(then_nodes, set(visited))
                else_struct = self._structure_region(else_nodes, set(visited))
                visited.update(then_nodes)
                visited.update(else_nodes)
                cond = self._bbl_condition(bbl)
                sn = StructNode(
                    kind='if', bbl=n, condition=cond,
                    then_branch=then_struct,
                    else_branch=else_struct if else_nodes else None,
                )

            else:
                sn = StructNode(kind='basic', bbl=n)

            children.append(sn)
            i += 1

        if len(children) == 1:
            return children[0]
        return StructNode(kind='seq', children=children)

    def _loop_body(self, header: int) -> Set[int]:
        """Nodes in the natural loop with the given header."""
        body = {header}
        # Back-predecessors of header → walk backwards up to header
        latching = [u for u, v in self.dom.back_edges if v == header]
        worklist = list(latching)
        while worklist:
            n = worklist.pop()
            if n not in body:
                body.add(n)
                for p in self.G.predecessors(n):
                    if p not in body:
                        worklist.append(p)
        return body

    def _region_up_to(self, start: int, end: Optional[int]) -> List[int]:
        """Nodes reachable from start before reaching end in RPO."""
        if start == end or end is None:
            return []
        visited: Set[int] = set()
        result: List[int] = []
        worklist = [start]
        while worklist:
            n = worklist.pop(0)
            if n in visited or n == end:
                continue
            visited.add(n)
            result.append(n)
            for s in self.G.successors(n):
                if (n, s) not in self.dom.back_edges:
                    worklist.append(s)
        # Return in RPO
        rpo_set = {x: i for i, x in enumerate(self._rpo())}
        result.sort(key=lambda x: rpo_set.get(x, 9999))
        return result

    def _bbl_condition(self, bbl: BasicBlock) -> str:
        """Extract condition string from the last branch instruction."""
        if not bbl.instrs:
            return '?'
        last = bbl.instrs[-1]
        m = last.mnemonic.lower()
        cond_map = {
            'je': 'ZF==1', 'jne': 'ZF==0', 'jz': 'ZF==1', 'jnz': 'ZF==0',
            'jg': 'ZF==0 && SF==OF', 'jl': 'SF!=OF',
            'jge': 'SF==OF', 'jle': 'ZF==1 || SF!=OF',
            'ja': 'CF==0 && ZF==0', 'jb': 'CF==1',
            'jae': 'CF==0', 'jbe': 'CF==1 || ZF==1',
            'js': 'SF==1', 'jns': 'SF==0',
            'b.eq': 'Z==1', 'b.ne': 'Z==0', 'b.lt': 'N!=V', 'b.ge': 'N==V',
            'b.le': 'Z==1 || N!=V', 'b.gt': 'Z==0 && N==V',
            'cbz': f'{last.op_str.split(",")[0]}==0',
            'cbnz': f'{last.op_str.split(",")[0]}!=0',
            'tbz': f'{last.op_str.split(",")[0]} bit==0',
            'tbnz': f'{last.op_str.split(",")[0]} bit!=0',
        }
        return cond_map.get(m, f'{m}({last.op_str})')


# ── Pseudocode emitter ────────────────────────────────────────────────────────

class PseudocodeEmitter:
    def __init__(self, bbls: Dict[int, BasicBlock],
                 objc_calls: List[ObjCCall],
                 addr_table: Dict[int, str],
                 meta: ObjCMetadata,
                 arch: str):
        self.bbls = bbls
        self.call_map: Dict[int, ObjCCall] = {oc.va: oc for oc in objc_calls}
        self.addr_table = addr_table
        self.meta = meta
        self.arch = arch

    def emit(self, tree: StructNode, indent: int = 0) -> str:
        lines = []
        self._emit_node(tree, lines, indent)
        return '\n'.join(lines)

    def _emit_node(self, node: StructNode, lines: List[str], indent: int):
        pad = '    ' * indent
        if node.kind == 'seq':
            for child in node.children:
                self._emit_node(child, lines, indent)
        elif node.kind == 'basic':
            self._emit_bbl(node.bbl, lines, indent)
        elif node.kind == 'while':
            lines.append(f'{pad}while ({node.condition}):')
            if node.body:
                self._emit_node(node.body, lines, indent + 1)
            else:
                lines.append(f'{pad}    pass')
        elif node.kind == 'if':
            lines.append(f'{pad}if ({node.condition}):')
            if node.then_branch:
                self._emit_node(node.then_branch, lines, indent + 1)
            else:
                lines.append(f'{pad}    pass')
            if node.else_branch:
                lines.append(f'{pad}else:')
                self._emit_node(node.else_branch, lines, indent + 1)
        elif node.kind == 'dowhile':
            lines.append(f'{pad}do:')
            if node.body:
                self._emit_node(node.body, lines, indent + 1)
            lines.append(f'{pad}while ({node.condition})')
        elif node.kind == 'goto':
            lines.append(f'{pad}goto 0x{node.goto_target:x}')

    def _emit_bbl(self, bbl_start: Optional[int], lines: List[str], indent: int):
        if bbl_start is None:
            return
        bbl = self.bbls.get(bbl_start)
        if not bbl:
            return
        pad = '    ' * indent
        lines.append(f'{pad}# BBL 0x{bbl_start:x}')

        for instr in bbl.instrs:
            va = instr.address
            m = instr.mnemonic.lower()

            # Check if this instruction is a recognized ObjC call
            if va in self.call_map:
                oc = self.call_map[va]
                pseudo = self._format_objc_call(oc)
                lines.append(f'{pad}{pseudo}  # 0x{va:x}')
                continue

            # Emit simplified pseudo for common patterns
            pseudo = self._instr_to_pseudo(instr)
            if pseudo:
                lines.append(f'{pad}{pseudo}  # 0x{va:x}')

    def _format_objc_call(self, oc: ObjCCall) -> str:
        recv = oc.receiver_reg
        # ARC runtime calls — show compactly (suppress as ARC boilerplate)
        if any(a in oc.method_name for a in ARC_NAMES):
            short = oc.method_name.lstrip('_')
            return f'/* ARC: {short}({recv}) */'
        if oc.selector:
            if oc.selector.startswith('<') and oc.selector.endswith('>'):
                # atomic getter/setter or ARC call
                return f'{recv}.{oc.selector}'
            if oc.args:
                return f'result = [{recv} {oc.selector}:{", ".join(oc.args)}]'
            return f'result = [{recv} {oc.selector}]'
        name = oc.method_name.lstrip('_')
        return f'{name}({recv})'

    def _instr_to_pseudo(self, instr) -> str:
        m = instr.mnemonic.lower()
        op = instr.op_str

        if m in ('ret', 'retq'):
            return 'return rax' if self.arch == 'x86_64' else 'return x0'
        if m == 'nop':
            return ''
        if m in ('push', 'pop', 'pushq', 'popq'):
            return ''  # suppress prologue/epilogue
        if m in ('mov', 'movq', 'movl', 'movzx', 'movsx', 'movsxd'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                dst, src = parts
                return f'{self._clean(dst)} = {self._clean(src)}'
        if m in ('lea', 'leaq'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                dst, src = parts
                return f'{self._clean(dst)} = &{self._clean(src)}'
        if m in ('add', 'addq'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                dst, src = parts
                return f'{self._clean(dst)} += {self._clean(src)}'
        if m in ('sub', 'subq'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                dst, src = parts
                return f'{self._clean(dst)} -= {self._clean(src)}'
        if m in ('xor', 'xorq') and op.split(',')[0].strip() == op.split(',')[-1].strip():
            dst = op.split(',')[0].strip()
            return f'{self._clean(dst)} = 0'
        if m in ('test', 'testq', 'testl'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                return f'flags = {self._clean(parts[0])} & {self._clean(parts[1])}'
        if m in ('cmp', 'cmpq', 'cmpl'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                return f'flags = {self._clean(parts[1])} - {self._clean(parts[0])}'
        if m in ('call', 'callq'):
            target = _parse_branch_target(instr, 'x86_64')
            if target:
                name = self.addr_table.get(target, f'0x{target:x}')
                return f'{name}()'
            return f'call({op})'
        if m in ('jmp', 'jmpq'):
            target = _parse_branch_target(instr, 'x86_64')
            if target:
                name = self.addr_table.get(target, f'0x{target:x}')
                return f'→ {name}'
            return f'→ {op}'
        if m.startswith('j'):
            target = _parse_branch_target(instr, 'x86_64')
            return f'branch_if({self._cond(m)}) → 0x{target:x}' if target else ''
        # arm64 instructions (Practical RE ARM ch2; ARM64 Assembly ch3/5)
        if m == 'bl':
            target = _parse_branch_target(instr, 'arm64')
            if target:
                name = self.addr_table.get(target, f'0x{target:x}')
                return f'{name}()'
            return f'bl {op}'
        if m == 'blr':
            return f'call_indirect({op})'
        if m == 'adrp':
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                return f'{parts[0]} = PAGE({parts[1]})'
            return f'adrp {op}'
        if m == 'ldr':
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                src = parts[1].strip()
                if src.startswith('[') and src.endswith(']'):
                    inner = src[1:-1].replace(',', ' +').replace('#', '')
                    return f'{parts[0]} = *({inner})'
                return f'{parts[0]} = {src}'
        if m in ('str', 'stur'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                dst = parts[1].strip()
                if dst.startswith('[') and dst.endswith(']'):
                    inner = dst[1:-1].replace(',', ' +').replace('#', '')
                    return f'*({inner}) = {parts[0]}'
        if m == 'ldp':
            parts = [p.strip() for p in op.split(',')]
            if len(parts) == 3:
                mem = parts[2].strip()
                if mem.startswith('[') and mem.endswith(']'):
                    return f'{parts[0]}, {parts[1]} = load_pair({mem[1:-1]})'
        if m == 'stp':
            parts = [p.strip() for p in op.split(',')]
            if len(parts) == 3:
                mem = parts[2].strip()
                if mem.startswith('[') and mem.endswith(']'):
                    return f'store_pair({parts[0]}, {parts[1]}) → {mem[1:-1]}'
        if m == 'add':
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 3:
                return f'{parts[0]} = {parts[1]} + {parts[2]}'
        if m == 'sub':
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 3:
                return f'{parts[0]} = {parts[1]} - {parts[2]}'
        if m == 'mov':
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                return f'{parts[0]} = {parts[1]}'
        if m == 'movz':
            parts = [p.strip() for p in op.split(',')]
            if len(parts) >= 2:
                return f'{parts[0]} = {parts[1]}'
        if m in ('cbz', 'cbnz'):
            parts = [p.strip() for p in op.split(',')]
            cond = '==' if m == 'cbz' else '!='
            return f'if ({parts[0]} {cond} 0) goto {parts[-1]}'
        if m in ('tbz', 'tbnz'):
            parts = [p.strip() for p in op.split(',')]
            cond = '==' if m == 'tbz' else '!='
            return f'if ({parts[0]}[{parts[1]}] {cond} 0) goto {parts[-1]}'
        if m.startswith('b.') or m in ('beq', 'bne', 'blt', 'bgt', 'ble', 'bge'):
            target = _parse_branch_target(instr, 'arm64')
            cond_str = m.replace('b.', '')
            return f'if ({cond_str}) goto 0x{target:x}' if target else f'{m} {op}'
        if m == 'b':
            target = _parse_branch_target(instr, 'arm64')
            return f'goto 0x{target:x}' if target else f'b {op}'
        if m == 'ret':
            return 'return x0'
        if m in ('cmp', 'cmn'):
            parts = [p.strip() for p in op.split(',', 1)]
            if len(parts) == 2:
                return f'flags = {parts[0]} {"- " if m == "cmp" else "+ "}{parts[1]}'
        if m in ('and', 'orr', 'eor', 'bic'):
            parts = [p.strip() for p in op.split(',')]
            ops = {'and': '&', 'orr': '|', 'eor': '^', 'bic': '& ~'}
            if len(parts) >= 3:
                return f'{parts[0]} = {parts[1]} {ops[m]} {parts[2]}'
        if m in ('lsl', 'lsr', 'asr', 'ror'):
            parts = [p.strip() for p in op.split(',')]
            ops = {'lsl': '<<', 'lsr': '>>', 'asr': '>>', 'ror': '>>>'}
            if len(parts) >= 3:
                return f'{parts[0]} = {parts[1]} {ops[m]} {parts[2]}'
        if m in ('mul', 'madd', 'msub'):
            parts = [p.strip() for p in op.split(',')]
            if m == 'mul' and len(parts) >= 3:
                return f'{parts[0]} = {parts[1]} * {parts[2]}'
        if m in ('nop', 'hint'):
            return ''
        return f'{m} {op}'

    def _clean(self, s: str) -> str:
        """Simplify register/memory notation."""
        s = s.strip()
        # strip size qualifiers: qword ptr, dword ptr, etc.
        s = re.sub(r'\b(?:qword|dword|word|byte)\s+ptr\s+', '', s, flags=re.I)
        # [rbp - 0x10] → *(rbp - 0x10)
        if s.startswith('[') and s.endswith(']'):
            return f'*({s[1:-1]})'
        return s

    def _cond(self, m: str) -> str:
        conds = {
            'je': 'Z', 'jne': '!Z', 'jz': 'Z', 'jnz': '!Z',
            'jg': '>', 'jl': '<', 'jge': '>=', 'jle': '<=',
            'ja': 'u>', 'jb': 'u<', 'jae': 'u>=', 'jbe': 'u<=',
            'js': 'S', 'jns': '!S',
        }
        return conds.get(m, m)


# ── Security annotation pass ──────────────────────────────────────────────────

class SecurityAnnotator:
    """
    Post-decompilation security pattern analysis.
    Flags TOCTOU windows, nil-guard sequences, VLA allocas, block captures.
    """

    def __init__(self, objc_calls: List[ObjCCall], bbls: Dict[int, BasicBlock],
                 arch: str):
        self.objc_calls = objc_calls
        self.bbls = bbls
        self.arch = arch

    def annotate(self) -> Dict[str, Any]:
        findings = {}
        findings['toctou_windows'] = self._find_toctou()
        findings['nil_guards'] = self._find_nil_guards()
        findings['vla_alloca'] = self._find_vla_alloca()
        findings['atomic_getter_sequences'] = self._find_atomic_seqs()
        return findings

    def _find_toctou(self) -> List[Dict]:
        """Sequential reads of the same atomic property = TOCTOU at get-use."""
        sels_in_order = [(oc.va, oc.selector) for oc in self.objc_calls
                         if oc.selector and not oc.selector.startswith('<')]
        findings = []
        for i in range(len(sels_in_order) - 1):
            va1, sel1 = sels_in_order[i]
            va2, sel2 = sels_in_order[i + 1]
            if sel1 == sel2:
                findings.append({
                    'type': 'TOCTOU_SAME_PROPERTY',
                    'selector': sel1,
                    'reads': [hex(va1), hex(va2)],
                    'note': 'Two sequential reads of same property not atomic as get-use pair',
                })
        return findings

    def _find_nil_guards(self) -> List[Dict]:
        """Detect missing nil checks after objc_msgSend returns."""
        findings = []
        for bbl_start, bbl in self.bbls.items():
            instrs = bbl.instrs
            for i, instr in enumerate(instrs):
                if instr.mnemonic.lower() in ('call', 'callq'):
                    # Check if next instruction tests rax for nil
                    if i + 1 < len(instrs):
                        nxt = instrs[i + 1]
                        nm = nxt.mnemonic.lower()
                        if nm not in ('test', 'cmp', 'mov') or 'rax' not in nxt.op_str:
                            oc = next((o for o in self.objc_calls
                                       if o.va == instr.address), None)
                            if oc and oc.selector:
                                findings.append({
                                    'type': 'MISSING_NIL_GUARD',
                                    'va': hex(instr.address),
                                    'selector': oc.selector,
                                    'note': 'msgSend return not tested for nil',
                                })
        return findings[:20]  # cap

    def _find_vla_alloca(self) -> List[Dict]:
        """Detect attacker-influenced sub rsp, <reg> (VLA stack alloc)."""
        findings = []
        for bbl_start, bbl in self.bbls.items():
            for instr in bbl.instrs:
                m = instr.mnemonic.lower()
                if m in ('sub', 'subq') and 'rsp' in instr.op_str:
                    op = instr.op_str
                    # sub rsp, reg (not immediate) → VLA / alloca pattern
                    if not re.search(r',\s*0x', op) and not re.search(r',\s*\d+$', op):
                        findings.append({
                            'type': 'VLA_ALLOCA',
                            'va': hex(instr.address),
                            'instr': f'{m} {op}',
                            'note': 'sub rsp with non-immediate → attacker-influenced stack allocation',
                        })
        return findings

    def _find_atomic_seqs(self) -> List[Dict]:
        """Flag sequences of atomic getter calls on same object."""
        getter_seqs = []
        run = []
        for oc in self.objc_calls:
            if 'getProperty' in oc.method_name or 'getter' in oc.selector.lower():
                run.append(oc)
            else:
                if len(run) >= 2:
                    getter_seqs.append({
                        'type': 'SEQUENTIAL_ATOMIC_GETTERS',
                        'vas': [hex(o.va) for o in run],
                        'selectors': [o.selector for o in run],
                        'note': 'Sequential atomic reads; not atomic as a group',
                    })
                run = []
        return getter_seqs


# ── CFG dot emitter ───────────────────────────────────────────────────────────

def _cfg_to_dot(G: 'nx.DiGraph', bbls: Dict[int, BasicBlock],
                addr_table: Dict[int, str]) -> str:
    lines = ['digraph CFG {', '  node [shape=box fontname=monospace fontsize=9]']
    for n in G.nodes():
        bbl = bbls.get(n)
        label = f'0x{n:x}'
        if bbl and bbl.instrs:
            last = bbl.instrs[-1]
            label += f'\\n[{bbl.branch_type}]\\n{last.mnemonic} {last.op_str[:20]}'
        name = addr_table.get(n, '')
        if name:
            label = f'{name}\\n' + label
        lines.append(f'  "0x{n:x}" [label="{label}"]')
    for u, v in G.edges():
        lines.append(f'  "0x{u:x}" -> "0x{v:x}"')
    lines.append('}')
    return '\n'.join(lines)


# ── Main Decompiler class ─────────────────────────────────────────────────────

class MacOSDecompiler:
    """
    macOS Mach-O decompiler with ObjC ABI awareness.
    Callable from ablation address tables (NE_1095_140_2_METHODS, etc.).

    Usage:
        dec = MacOSDecompiler('/path/to/binary',
                              address_table=NE_1095_140_2_METHODS,
                              arch='x86_64')
        result = dec.decompile(0x1001f4a40)
        print(result.pseudocode)
        print(result.annotations)
    """

    def __init__(self, binary_path: str,
                 address_table: Optional[Dict[str, Any]] = None,
                 arch: Optional[str] = None):
        self.binary_path = binary_path
        # address_table: {name: {va, ...}} OR {va: name}
        self.addr_table: Dict[int, str] = {}
        if address_table:
            self._build_addr_table(address_table)

        if not LIEF_OK:
            raise ImportError('lief required')
        self.binary = lief.parse(binary_path)
        if self.binary is None:
            raise ValueError(f'LIEF failed to parse {binary_path}')

        # Handle fat binary: pick the right arch slice
        fat_types = []
        try:
            fat_types.append(lief.MachO.FatBinary)
        except AttributeError:
            pass
        try:
            fat_types.append(lief.lief_macho.FatBinary)
        except AttributeError:
            pass
        if fat_types and isinstance(self.binary, tuple(fat_types)):
            self.binary = self._pick_slice(self.binary, arch or 'x86_64')

        # Auto-detect arch from binary if not specified
        if arch is None:
            cpu = str(self.binary.header.cpu_type)
            arch = 'arm64' if 'ARM64' in cpu else 'x86_64'
        self.arch = arch

        self.meta = ObjCMetadata(self.binary)
        self.disasm = Disassembler(self.binary, arch)
        self.lifter = VEXLifter(self.binary, arch) if PYVEX_OK else None

    def _build_addr_table(self, tbl):
        """Accept {name: {va: int, ...}} or {va: name} or list of (va, name)."""
        if isinstance(tbl, dict):
            for key, val in tbl.items():
                if isinstance(key, int):
                    self.addr_table[key] = str(val)
                elif isinstance(key, str) and isinstance(val, dict):
                    va = val.get('va') or val.get('address') or val.get('offset')
                    if va:
                        self.addr_table[int(va)] = key
                elif isinstance(key, str) and isinstance(val, int):
                    self.addr_table[val] = key

    def _pick_slice(self, fat, arch: str):
        cpu_map = {'x86_64': lief.MachO.CPU_TYPES.x86_64,
                   'arm64': lief.MachO.CPU_TYPES.ARM64}
        want = cpu_map.get(arch)
        for binary in fat:
            if want and binary.header.cpu_type == want:
                return binary
        return fat[0]

    def decompile(self, va: int, end_va: int = 0,
                  func_name: str = '') -> DecompResult:
        """Decompile one function starting at va."""
        name = func_name or self.addr_table.get(va, f'sub_{va:x}')

        # Phase 2: disassemble
        instrs = self.disasm.disasm_func(va, end_va)
        if not instrs:
            return DecompResult(va, name, self.arch, '# no instructions', '',
                                {}, [], {})

        # Phase 4: BBL split
        bbls_list = split_bbls(instrs, self.arch)
        bbls = {b.start: b for b in bbls_list}

        # Phase 5: CFG
        G = build_cfg(bbls_list) if NX_OK else None

        # Phase 3: ObjC pre-recognition
        recognizer = ObjCRecognizer(self.meta, self.addr_table, self.arch)
        objc_calls = recognizer.scan(bbls_list)

        # Phase 6: VEX lifting (per BBL)
        if self.lifter:
            for bbl in bbls_list:
                self.lifter.lift_bbl(bbl)

        # Phase 7: Dominance analysis
        dom = DominanceInfo(G, va) if G is not None and NX_OK else None

        # Phase 8: Structuring
        tree = None
        if dom is not None:
            try:
                structurer = Structurer(G, va, dom, bbls)
                tree = structurer.structure()
            except Exception:
                tree = None

        # Phase 10: Pseudocode emission
        emitter = PseudocodeEmitter(bbls, objc_calls, self.addr_table,
                                    self.meta, self.arch)
        if tree is not None:
            pseudocode = emitter.emit(tree)
        else:
            # Fallback: flat linear emission
            lines = []
            for bbl in bbls_list:
                emitter._emit_bbl(bbl.start, lines, 0)
            pseudocode = '\n'.join(lines)

        # CFG dot
        cfg_dot = _cfg_to_dot(G, bbls, self.addr_table) if G else ''

        # Phase 9: Security annotation
        annotator = SecurityAnnotator(objc_calls, bbls, self.arch)
        annotations = annotator.annotate()

        return DecompResult(
            va=va,
            name=name,
            arch=self.arch,
            pseudocode=f'// {name} @ 0x{va:x}\n\n{pseudocode}',
            cfg_dot=cfg_dot,
            bbls=bbls,
            objc_calls=objc_calls,
            annotations=annotations,
        )

    def decompile_all(self, method_table: Dict[str, Any]) -> Dict[str, DecompResult]:
        """Decompile every method in an ablation address table."""
        results = {}
        for name, entry in method_table.items():
            if isinstance(entry, dict):
                va = entry.get('va') or entry.get('address')
            elif isinstance(entry, int):
                va = entry
            else:
                continue
            if not va:
                continue
            try:
                results[name] = self.decompile(int(va), func_name=name)
            except Exception as e:
                results[name] = DecompResult(
                    int(va), name, self.arch,
                    f'# decompile error: {e}', '', {}, [], {}
                )
        return results

    def selrefs(self) -> Dict[int, str]:
        return self.meta.selrefs

    def classrefs(self) -> Dict[int, str]:
        return self.meta.classrefs

    def classes(self) -> Dict[str, 'ObjCClass']:
        return self.meta.classes

    def method_map(self) -> Dict[str, list]:
        """selector name → list of implementation VAs."""
        return getattr(self.meta, 'method_map', {})

    def imp_map(self) -> Dict[int, str]:
        """imp VA → '+/-[ClassName selector]' full name."""
        return getattr(self.meta, 'imp_map', {})

    def lookup_imp(self, class_name: str, selector: str) -> Optional[int]:
        """Return implementation VA for a method, or None."""
        imap = self.imp_map()
        prefix_inst = f'-[{class_name} {selector}]'
        prefix_cls  = f'+[{class_name} {selector}]'
        for va, name in imap.items():
            if name in (prefix_inst, prefix_cls):
                return va
        return None

    def decompile_method(self, class_name: str, selector: str,
                         end_va: int = 0) -> 'DecompResult':
        """Decompile by class name + selector (no VA needed).

        Looks up the implementation address in imp_map, then calls decompile().
        Raises KeyError if the method is not found.
        """
        va = self.lookup_imp(class_name, selector)
        if va is None:
            raise KeyError(f'Method not found: {class_name} {selector!r}')
        imap = self.imp_map()
        full_name = imap.get(va, f'[{class_name} {selector}]')
        return self.decompile(va, func_name=full_name, end_va=end_va)

    def dump_classes(self) -> str:
        """Return a text summary of all parsed ObjC classes and their methods."""
        lines = []
        for cname, cls in sorted(self.meta.classes.items()):
            lines.append(f'@interface {cname}')
            imap = getattr(self.meta, 'imp_map', {})
            # Gather all methods (instance + class) for this class
            methods_all = [(va, nm) for va, nm in imap.items()
                           if f'[{cname} ' in nm]
            methods_all.sort(key=lambda x: x[0])
            for va, nm in methods_all:
                prefix = nm[0]  # '+' or '-'
                sel = nm[nm.index(' ')+1:-1]
                lines.append(f'  {prefix} (id){sel}  // 0x{va:x}')
            lines.append('@end')
            lines.append('')
        return '\n'.join(lines)

    def xref_selector(self, selector: str) -> List[int]:
        """Return all VAs in selrefs that reference the given selector."""
        return [va for va, sel in self.meta.selrefs.items() if sel == selector]


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        description='macOS Mach-O decompiler — ablation module')
    ap.add_argument('binary', help='Path to Mach-O binary')
    ap.add_argument('--va', type=lambda x: int(x, 16),
                    help='Virtual address of function to decompile')
    ap.add_argument('--method', metavar='CLASS.selector',
                    help='Decompile by ObjC method name, e.g. NSObject.init')
    ap.add_argument('--name', default='', help='Function name override')
    ap.add_argument('--end', type=lambda x: int(x, 16), default=0,
                    help='End VA (optional)')
    ap.add_argument('--dot', action='store_true', help='Print CFG in DOT format')
    ap.add_argument('--json', action='store_true', help='Output JSON')
    ap.add_argument('--selrefs', action='store_true', help='Dump selrefs table')
    ap.add_argument('--classrefs', action='store_true', help='Dump classrefs table')
    ap.add_argument('--classes', action='store_true', help='Dump all ObjC classes + methods')
    ap.add_argument('--imps', action='store_true', help='Dump imp VA → method name table')
    ap.add_argument('--xref', metavar='SELECTOR', help='Find all selrefs to a selector')
    args = ap.parse_args()

    dec = MacOSDecompiler(args.binary)

    if args.selrefs:
        for va, sel in sorted(dec.selrefs().items()):
            print(f'0x{va:016x}  {sel}')
        return

    if args.classrefs:
        for va, cls in sorted(dec.classrefs().items()):
            print(f'0x{va:016x}  {cls}')
        return

    if args.classes:
        print(dec.dump_classes())
        return

    if args.imps:
        for va, nm in sorted(dec.imp_map().items()):
            print(f'0x{va:016x}  {nm}')
        return

    if args.xref:
        for va in dec.xref_selector(args.xref):
            print(f'0x{va:016x}')
        return

    if args.method:
        if '.' in args.method:
            cls_name, sel = args.method.split('.', 1)
        else:
            print('--method requires CLASS.selector format', file=sys.stderr)
            sys.exit(1)
        result = dec.decompile_method(cls_name, sel, end_va=args.end)

    elif args.va:
        result = dec.decompile(args.va, args.end, args.name)

    else:
        ap.print_help()
        return

    if args.json:
        out = {
            'va': hex(result.va),
            'name': result.name,
            'arch': result.arch,
            'pseudocode': result.pseudocode,
            'objc_calls': [
                {'va': hex(oc.va), 'selector': oc.selector,
                 'receiver': oc.receiver_reg, 'method': oc.method_name}
                for oc in result.objc_calls
            ],
            'annotations': result.annotations,
        }
        print(json.dumps(out, indent=2))
    else:
        print(result.pseudocode)
        if result.annotations:
            print('\n// Security annotations:')
            for k, v in result.annotations.items():
                if v:
                    print(f'//   {k}: {json.dumps(v, indent=4)}')
        if args.dot:
            print('\n' + result.cfg_dot)


if __name__ == '__main__':
    main()
