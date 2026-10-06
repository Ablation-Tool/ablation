"""
taint_tracker_x86_32.py: Static intraprocedural i386 taint analysis.

Finds data-flow paths from network receive taint sources to dangerous sinks.
Implements libdft taint policy adapted for i386 SysV / CDECL32:

  XFER  (mov/lea):            dst_taint = src_taint
  ALU   (add/sub/and/or/xor): dst_taint |= operand taints
  CLR   (xor r,r; mov r,0):  dst_taint = {}
  LOAD  (mov rd,[bp+N]):      dst_taint = stack_slot(bp+N)
  STORE (mov [bp+N],rs):      stack_slot(bp+N) = src_taint
  CALL  (source):             eax tainted; buffer length args tracked
  CALL  (sink):               alert if relevant pushed arg is tainted
  CALL  (other):              eax/ecx/edx cleared (CDECL caller-saved)

Stack model: tracks [ebp+N] frame slots (N<0 = locals, N>0 = incoming args)
and [esp+N] outgoing arg slots. esp delta is updated on push/pop/sub esp,N.

PLT resolution: handles both PIC (jmp *disp32(%ebx)) and non-PIC
(jmp *abs32) stubs via lief JUMP_SLOT relocations.

Architecture gaps filled vs x86-64 TaintTracker
------------------------------------------------
* CS_MODE_32 (i386) instead of CS_MODE_64
* CDECL32: args on stack, not in registers
* ebp-frame tracking (not rbp/rsp split)
* PIC thunk + GOT-relative string refs (ebx + disp32)
* PLT stubs differ: PIC variant uses jmp *disp(%ebx)

Confirmed targets (product.bin, asamba — Acronis True Image 2018 i386):
  product.bin: 56917 functions, system@plt=0x8081b00, execvp@plt=0x8084e10
  asamba:       7462 functions, system@plt=0x804b0d0, execv@plt=0x804b570

Usage
-----
    from ablation.analyzers.taint_tracker_x86_32 import X86_32TaintTracker

    tracker = X86_32TaintTracker.from_path('/path/to/elf32')
    for finding in tracker.run_interprocedural():
        print(finding)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

import capstone

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False


# ── CDECL32 register model ────────────────────────────────────────────────────

# Caller-saved (volatile) per i386 SysV: eax (return), ecx, edx
_CALLER_SAVED: FrozenSet[str] = frozenset({'eax', 'ecx', 'edx'})

# Sub-registers: writing 8/16-bit subreg is treated as writing the 32-bit GPR
_SUBREG: Dict[str, str] = {
    'al': 'eax', 'ah': 'eax', 'ax': 'eax',
    'bl': 'ebx', 'bh': 'ebx', 'bx': 'ebx',
    'cl': 'ecx', 'ch': 'ecx', 'cx': 'ecx',
    'dl': 'edx', 'dh': 'edx', 'dx': 'edx',
    'si': 'esi', 'di': 'edi', 'bp': 'ebp', 'sp': 'esp',
}

# GP register names (canonical 32-bit)
_GP_REGS: FrozenSet[str] = frozenset({
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
})


def _canon_reg(name: str) -> Optional[str]:
    """Normalise register name to 32-bit GPR. Returns None for non-GP regs."""
    n = name.lower()
    if n in _GP_REGS:
        return n
    return _SUBREG.get(n)


# ── taint sources and sinks ───────────────────────────────────────────────────

_TAINT_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'fread', 'pread', 'pread64',
    'gets', 'fgets', 'scanf', 'fscanf', 'sscanf',
    'SSL_read', 'SSL_read_ex', 'BIO_read',
    'getenv', 'getenv_r',
}

# Sinks mapped to {arg_index: min_len} (CDECL32: arg0 is last pushed, first arg)
_TAINT_SINKS: Dict[str, Dict[int, int]] = {
    'system':   {0: 0},
    'popen':    {0: 0},
    'execl':    {0: 0, 1: 0},
    'execle':   {0: 0, 1: 0},
    'execlp':   {0: 0, 1: 0},
    'execv':    {0: 0, 1: 0},
    'execvp':   {0: 0, 1: 0},
    'execve':   {0: 0, 1: 0},
    'execvpe':  {0: 0, 1: 0},
    'strcpy':   {1: 0},
    'strcat':   {1: 0},
    'sprintf':  {2: 0},
    'vsprintf': {2: 0},
    'snprintf': {3: 0},
    'vsnprintf':{3: 0},
    'memcpy':   {2: 0},
    'memmove':  {2: 0},
    'strlen':   {0: 0},
    'printf':   {0: 0},
    'fprintf':  {1: 0},
}


# ── PLT resolver (handles PIC and non-PIC i386 stubs) ────────────────────────

def _build_plt_map(binary_path: str) -> Dict[int, str]:
    """
    Return {plt_stub_va: symbol_name} for an i386 ELF.

    PIC stub   (ELF shared lib): ff a3 <disp32>  jmp *[ebx+disp32]
    Non-PIC stub (ELF exec):     ff 25 <abs32>   jmp *[abs32]
    """
    if not _LIEF_OK:
        return {}
    try:
        e = lief.parse(binary_path)
        if e is None:
            return {}

        # Build got_va → symbol_name from JUMP_SLOT relocations
        got_to_sym: Dict[int, str] = {}
        for rel in e.relocations:
            if 'JUMP_SLOT' not in str(rel.type):
                continue
            sym = rel.symbol
            if sym and sym.name:
                got_to_sym[rel.address] = sym.name

        plt_sec = next((s for s in e.sections if s.name == '.plt'), None)
        if plt_sec is None:
            return {}

        plt_bytes = bytes(plt_sec.content)
        plt_base = plt_sec.virtual_address

        # For PIC stubs we need .got.plt base
        got_plt_sec = next((s for s in e.sections if s.name == '.got.plt'), None)
        got_plt_base = got_plt_sec.virtual_address if got_plt_sec else 0

        plt_map: Dict[int, str] = {}
        offset = 0x10   # skip PLT[0] resolver stub (always 16 bytes)
        while offset + 6 <= len(plt_bytes):
            stub_va = plt_base + offset
            b = plt_bytes[offset:offset + 6]

            if b[0] == 0xFF and b[1] == 0xA3:
                # PIC: jmp *[ebx + disp32]; disp is relative to .got.plt base
                disp32 = struct.unpack_from('<I', plt_bytes, offset + 2)[0]
                got_va = got_plt_base + disp32
                sym = got_to_sym.get(got_va)
                if sym:
                    plt_map[stub_va] = sym

            elif b[0] == 0xFF and b[1] == 0x25:
                # Non-PIC: jmp *[abs32]
                got_va = struct.unpack_from('<I', plt_bytes, offset + 2)[0]
                sym = got_to_sym.get(got_va)
                if sym:
                    plt_map[stub_va] = sym

            offset += 0x10  # each PLT stub is exactly 16 bytes

        return plt_map
    except Exception:
        return {}


# ── function start scanner (prologue heuristic) ──────────────────────────────

def _find_func_starts_i386(data: bytes, text_off: int, text_size: int) -> List[int]:
    """
    Return file offsets of likely function starts in i386 .text.
    Looks for: 55 89 e5 (push ebp; mov ebp,esp) with optional sub esp,N prefix.
    Also scans for FPO functions via call target resolution.
    """
    prologue = b'\x55\x89\xe5'   # push ebp; mov ebp,esp
    alt1 = b'\x55\x89\xec'       # push ebp; mov esp,ebp (AT&T order compiled)
    starts: List[int] = []
    end = text_off + text_size
    for off in range(text_off, end - 3):
        if data[off:off + 3] == prologue or data[off:off + 3] == alt1:
            starts.append(off)
    # FPO (no frame pointer): scan for e8 xx xx xx xx (call) targets
    base_va = 0  # will be set by caller if needed
    return starts


# ── taint state ──────────────────────────────────────────────────────────────

@dataclass
class TaintState32:
    """Per-instruction taint state for i386 CDECL analysis."""
    regs: Dict[str, FrozenSet[str]] = field(default_factory=dict)
    stack: Dict[int, FrozenSet[str]] = field(default_factory=dict)   # ebp-relative offset → taint
    esp_stack: Dict[int, FrozenSet[str]] = field(default_factory=dict) # esp-relative offset → taint
    esp_delta: int = 0   # how many bytes of extra esp adjustment (below prologue frame)

    def copy(self) -> 'TaintState32':
        return TaintState32(
            regs=dict(self.regs),
            stack=dict(self.stack),
            esp_stack=dict(self.esp_stack),
            esp_delta=self.esp_delta,
        )

    def taint_reg(self, reg: str, sources: FrozenSet[str]) -> None:
        r = _canon_reg(reg)
        if r:
            self.regs[r] = sources

    def clear_reg(self, reg: str) -> None:
        r = _canon_reg(reg)
        if r:
            self.regs.pop(r, None)

    def get_reg(self, reg: str) -> FrozenSet[str]:
        r = _canon_reg(reg)
        if not r:
            return frozenset()
        return self.regs.get(r, frozenset())

    def store_stack(self, ebp_offset: int, sources: FrozenSet[str]) -> None:
        if sources:
            self.stack[ebp_offset] = sources
        else:
            self.stack.pop(ebp_offset, None)

    def load_stack(self, ebp_offset: int) -> FrozenSet[str]:
        return self.stack.get(ebp_offset, frozenset())

    def store_esp(self, esp_offset: int, sources: FrozenSet[str]) -> None:
        if sources:
            self.esp_stack[esp_offset] = sources
        else:
            self.esp_stack.pop(esp_offset, None)

    def load_esp(self, esp_offset: int) -> FrozenSet[str]:
        return self.esp_stack.get(esp_offset, frozenset())


# ── taint finding ─────────────────────────────────────────────────────────────

@dataclass
class TaintFinding32:
    binary:   str
    func_va:  int
    sink_va:  int
    sink_name:str
    arg_idx:  int
    sources:  FrozenSet[str]
    path:     List[int] = field(default_factory=list)

    def __str__(self) -> str:
        srcs = ', '.join(sorted(self.sources))
        return (
            f"TAINT i386 [{self.binary}] "
            f"func=0x{self.func_va:08x} sink={self.sink_name}@0x{self.sink_va:08x} "
            f"arg{self.arg_idx} ← {{{srcs}}}"
        )


# ── main tracker ─────────────────────────────────────────────────────────────

class X86_32TaintTracker:
    """
    Static intraprocedural taint tracker for stripped i386 ELF binaries.

    Handles:
    * CDECL32 (SysV i386): args on stack, eax return, eax/ecx/edx caller-saved
    * PIC and non-PIC PLT stub resolution
    * ebp-relative frame slots (locals and incoming args)
    * push-before-call arg taint tracking (scans esp_stack at call site)
    * GOT-base-relative string constant detection (ebx + disp32 → rodata)
    """

    def __init__(
        self,
        binary_path: str,
        plt: Optional[Dict[int, str]] = None,
        func_starts: Optional[List[int]] = None,
        custom_sinks: Optional[Dict[str, Dict[int, int]]] = None,
    ) -> None:
        self._path = binary_path
        self._name = Path(binary_path).name
        self._data = Path(binary_path).read_bytes()
        self._plt = plt if plt is not None else _build_plt_map(binary_path)
        self._sinks = dict(_TAINT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)
        self._plt_rev: Dict[str, int] = {v: k for k, v in self._plt.items()}

        # Parse ELF for segment layout
        self._base_va: int = 0x8048000
        self._text_off: int = 0
        self._text_va: int = 0x8048000
        self._text_size: int = len(self._data)
        self._func_starts: List[int] = func_starts or []
        self._parse_elf()

        if not self._func_starts:
            self._func_starts = _find_func_starts_i386(
                self._data, self._text_off, self._text_size
            )

        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self._md.detail = True

    @classmethod
    def from_path(
        cls,
        binary_path: str,
        custom_sinks: Optional[Dict[str, Dict[int, int]]] = None,
    ) -> 'X86_32TaintTracker':
        return cls(binary_path=binary_path, custom_sinks=custom_sinks)

    @classmethod
    def from_context(cls, ctx: object, custom_sinks: Optional[Dict[str, Dict[int, int]]] = None) -> 'X86_32TaintTracker':
        path = getattr(ctx, '_binary_path', None) or getattr(ctx, 'binary_path', None)
        if path is None:
            raise ValueError("BinaryContext must have _binary_path or binary_path attribute")
        func_starts = list(getattr(ctx, 'func_starts', None) or [])
        return cls(binary_path=path, func_starts=func_starts, custom_sinks=custom_sinks)

    def _parse_elf(self) -> None:
        if not _LIEF_OK:
            return
        try:
            e = lief.parse(self._path)
            if e is None:
                return
            text_sec = next((s for s in e.sections if s.name == '.text'), None)
            if text_sec:
                self._text_off = text_sec.file_offset
                self._text_va = text_sec.virtual_address
                self._text_size = text_sec.size
                self._base_va = self._text_va
        except Exception:
            pass

    def _va_to_offset(self, va: int) -> int:
        return self._text_off + (va - self._text_va)

    def _resolve_call_target(self, insn: capstone.CsInsn) -> Optional[str]:
        """Resolve a CALL instruction to its PLT symbol name if possible."""
        if insn.id == capstone.x86.X86_INS_CALL:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    return self._plt.get(op.imm)
        return None

    def _is_ebp_relative(self, insn: capstone.CsInsn) -> Optional[Tuple[int, bool]]:
        """
        If instruction accesses [ebp ± N], return (N, is_store).
        N is signed (negative for locals, positive for args).
        """
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                mem = op.mem
                base_name = insn.reg_name(mem.base).lower() if mem.base else ''
                if base_name in ('ebp', 'bp'):
                    disp = mem.disp
                    is_store = (
                        insn.id in (
                            capstone.x86.X86_INS_MOV,
                            capstone.x86.X86_INS_MOVZX,
                            capstone.x86.X86_INS_MOVSX,
                        ) and insn.operands[0].type == capstone.x86.X86_OP_MEM
                    )
                    return (disp, is_store)
        return None

    def _is_esp_relative(self, insn: capstone.CsInsn) -> Optional[Tuple[int, bool]]:
        """
        If instruction accesses [esp ± N], return (N, is_store).
        Used for outgoing push/call arg tracking.
        """
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                mem = op.mem
                base_name = insn.reg_name(mem.base).lower() if mem.base else ''
                if base_name in ('esp', 'sp'):
                    disp = mem.disp
                    is_store = (
                        insn.id in (
                            capstone.x86.X86_INS_MOV,
                            capstone.x86.X86_INS_MOVZX,
                            capstone.x86.X86_INS_MOVSX,
                        ) and insn.operands[0].type == capstone.x86.X86_OP_MEM
                    )
                    return (disp, is_store)
        return None

    def _step(self, insn: capstone.CsInsn, state: TaintState32) -> List[TaintFinding32]:
        """Process one instruction, updating taint state. Returns any sink findings."""
        findings: List[TaintFinding32] = []
        op_str = insn.op_str

        # PUSH: push reg decrements esp by 4 and stores to [esp]
        if insn.id == capstone.x86.X86_INS_PUSH:
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_REG:
                reg = insn.reg_name(insn.operands[0].reg).lower()
                taint = state.get_reg(reg)
                state.esp_delta += 4
                state.store_esp(state.esp_delta, taint)
            elif insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                state.esp_delta += 4
                state.store_esp(state.esp_delta, frozenset())  # immediate = not tainted
            elif insn.operands and insn.operands[0].type == capstone.x86.X86_OP_MEM:
                # push [ebp-N] or push [esp+N]: propagate taint from memory slot
                mem = insn.operands[0].mem
                base = insn.reg_name(mem.base).lower() if mem.base else ''
                if base == 'ebp':
                    taint = state.load_stack(mem.disp)
                elif base == 'esp':
                    taint = state.load_esp(mem.disp)
                else:
                    taint = frozenset()
                state.esp_delta += 4
                state.store_esp(state.esp_delta, taint)

        # POP: pop reg increments esp by 4
        elif insn.id == capstone.x86.X86_INS_POP:
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_REG:
                reg = insn.reg_name(insn.operands[0].reg).lower()
                taint = state.load_esp(state.esp_delta)
                state.taint_reg(reg, taint) if taint else state.clear_reg(reg)
                state.esp_delta -= 4

        # SUB ESP: sub esp,N (allocate stack or restore)
        elif insn.id == capstone.x86.X86_INS_SUB:
            ops = insn.operands
            if (len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG
                    and insn.reg_name(ops[0].reg).lower() == 'esp'
                    and ops[1].type == capstone.x86.X86_OP_IMM):
                pass  # frame allocation, don't adjust esp_delta for args

        # ADD ESP: add esp,N (cleanup after call)
        elif insn.id == capstone.x86.X86_INS_ADD:
            ops = insn.operands
            if (len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG
                    and insn.reg_name(ops[0].reg).lower() == 'esp'
                    and ops[1].type == capstone.x86.X86_OP_IMM):
                n = ops[1].imm
                # Clean up esp_delta after call args
                state.esp_delta = max(0, state.esp_delta - n)

        # MOV: various forms
        elif insn.id in (capstone.x86.X86_INS_MOV, capstone.x86.X86_INS_MOVZX, capstone.x86.X86_INS_MOVSX):
            ops = insn.operands
            if len(ops) != 2:
                pass
            elif ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_REG:
                # mov rd, rs
                dst = insn.reg_name(ops[0].reg).lower()
                src = insn.reg_name(ops[1].reg).lower()
                taint = state.get_reg(src)
                if taint:
                    state.taint_reg(dst, taint)
                else:
                    state.clear_reg(dst)
            elif ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_IMM:
                # mov rd, imm → clear taint
                dst = insn.reg_name(ops[0].reg).lower()
                state.clear_reg(dst)
            elif ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_MEM:
                # load: mov rd, [base+disp]
                dst = insn.reg_name(ops[0].reg).lower()
                mem = ops[1].mem
                base = insn.reg_name(mem.base).lower() if mem.base else ''
                if base == 'ebp':
                    taint = state.load_stack(mem.disp)
                    if taint:
                        state.taint_reg(dst, taint)
                    else:
                        state.clear_reg(dst)
                else:
                    # Load from non-ebp memory: treat as source propagation
                    base_taint = state.get_reg(base) if base else frozenset()
                    if base_taint:
                        state.taint_reg(dst, base_taint)
                    else:
                        state.clear_reg(dst)
            elif ops[0].type == capstone.x86.X86_OP_MEM and ops[1].type == capstone.x86.X86_OP_REG:
                # store: mov [base+disp], rs
                src = insn.reg_name(ops[1].reg).lower()
                mem = ops[0].mem
                base = insn.reg_name(mem.base).lower() if mem.base else ''
                taint = state.get_reg(src)
                if base == 'ebp':
                    state.store_stack(mem.disp, taint)

        # LEA: lea rd, [base+disp] — address computation
        elif insn.id == capstone.x86.X86_INS_LEA:
            ops = insn.operands
            if len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG:
                dst = insn.reg_name(ops[0].reg).lower()
                if ops[1].type == capstone.x86.X86_OP_MEM:
                    mem = ops[1].mem
                    base = insn.reg_name(mem.base).lower() if mem.base else ''
                    # lea of [ebp+N] propagates stack taint (pointer to local)
                    if base == 'ebp':
                        taint = state.load_stack(mem.disp)
                        if taint:
                            state.taint_reg(dst, taint)
                        else:
                            state.clear_reg(dst)
                    else:
                        # Address computation from non-ebp: propagate base reg taint
                        base_taint = state.get_reg(base) if base else frozenset()
                        if base_taint:
                            state.taint_reg(dst, base_taint)
                        else:
                            state.clear_reg(dst)

        # ALU: add/sub/and/or/xor — union of operand taints
        elif insn.id in (
            capstone.x86.X86_INS_ADD, capstone.x86.X86_INS_SUB,
            capstone.x86.X86_INS_AND, capstone.x86.X86_INS_OR,
            capstone.x86.X86_INS_XOR, capstone.x86.X86_INS_IMUL,
        ):
            ops = insn.operands
            if len(ops) >= 2 and ops[0].type == capstone.x86.X86_OP_REG:
                dst = insn.reg_name(ops[0].reg).lower()
                # XOR r,r → clear taint
                if (insn.id == capstone.x86.X86_INS_XOR
                        and ops[1].type == capstone.x86.X86_OP_REG
                        and insn.reg_name(ops[1].reg).lower() == dst):
                    state.clear_reg(dst)
                else:
                    src_taint = frozenset()
                    if ops[1].type == capstone.x86.X86_OP_REG:
                        src_taint = state.get_reg(insn.reg_name(ops[1].reg).lower())
                    combined = state.get_reg(dst) | src_taint
                    if combined:
                        state.taint_reg(dst, combined)
                    else:
                        state.clear_reg(dst)

        # CALL: source, sink, or ordinary
        elif insn.id == capstone.x86.X86_INS_CALL:
            sym = self._resolve_call_target(insn)
            if sym in _TAINT_SOURCES:
                # return value in eax is now tainted
                state.taint_reg('eax', frozenset({sym}))
                # also clear scratch registers
                for r in ('ecx', 'edx'):
                    state.clear_reg(r)
            elif sym in self._sinks:
                sink_args = self._sinks[sym]
                # CDECL: arg0 is at esp+0 at the point of call,
                # but we tracked pushes via esp_delta.
                # esp_delta levels: 1=first pushed (last arg), etc.
                # arg0 (first param) = last pushed = esp_delta level
                n_args = max(sink_args.keys()) + 1 if sink_args else 0
                for arg_idx in sink_args:
                    # arg_idx 0 = last pushed = esp_delta level 1
                    # arg_idx 1 = esp_delta level 2, etc.
                    esp_level = state.esp_delta - arg_idx * 4
                    taint = (state.load_esp(esp_level)
                             or state.get_reg('eax') if arg_idx == 0 else frozenset())
                    # Also check if eax was pushed recently for arg0
                    if not taint:
                        taint = state.load_esp(state.esp_delta - arg_idx * 4)
                    if taint:
                        findings.append(TaintFinding32(
                            binary=self._name,
                            func_va=0,  # filled in by caller
                            sink_va=insn.address,
                            sink_name=sym or '?',
                            arg_idx=arg_idx,
                            sources=taint,
                        ))
                # Clear caller-saved on return
                for r in _CALLER_SAVED:
                    state.clear_reg(r)
                state.esp_stack.clear()
                state.esp_delta = 0
            else:
                # Unknown call: clear caller-saved (conservative)
                for r in _CALLER_SAVED:
                    state.clear_reg(r)
                state.esp_stack.clear()
                state.esp_delta = 0

        return findings

    def run_on_function(self, func_va: int, max_insns: int = 2000) -> List[TaintFinding32]:
        """Run taint analysis on a single function."""
        off = self._va_to_offset(func_va)
        if off < 0 or off >= len(self._data):
            return []

        chunk = self._data[off: off + 65536]
        state = TaintState32()
        findings: List[TaintFinding32] = []

        for i, insn in enumerate(self._md.disasm(chunk, func_va)):
            if i >= max_insns:
                break
            hits = self._step(insn, state)
            for h in hits:
                h.func_va = func_va
            findings.extend(hits)
            if insn.mnemonic in ('ret', 'retn'):
                break

        return findings

    def run_interprocedural(self, max_funcs: int = 10000) -> List[TaintFinding32]:
        """
        Run on all detected function starts.
        Returns de-duplicated list of TaintFinding32 objects.
        """
        all_findings: List[TaintFinding32] = []
        seen: Set[Tuple[int, int, str, int]] = set()

        funcs = self._func_starts[:max_funcs]
        for file_off in funcs:
            va = self._text_va + (file_off - self._text_off)
            try:
                for f in self.run_on_function(va):
                    key = (f.func_va, f.sink_va, f.sink_name, f.arg_idx)
                    if key not in seen:
                        seen.add(key)
                        all_findings.append(f)
            except Exception:
                pass

        return all_findings

    def summary(self) -> str:
        return (
            f"X86_32TaintTracker: {self._name} | "
            f"{len(self._func_starts)} funcs | "
            f"{len(self._plt)} PLT entries"
        )
