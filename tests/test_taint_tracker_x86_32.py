"""Unit tests for X86_32TaintTracker: i386 CDECL32 taint propagation.

All expected values derived from capstone 5.x disassembly of hand-encoded byte
sequences. Test numbers correspond to the 9 cases in x86-32-taint-tracker-audit.md §8.
"""

import struct
from unittest.mock import MagicMock, patch

import capstone
import pytest

from ablation.analyzers.taint_tracker_x86_32 import (
    TaintFinding32,
    TaintState32,
    X86_32TaintTracker,
    _TAINT_SINKS,
    _build_plt_map,
)

# ── test constants ────────────────────────────────────────────────────────────

BASE_VA    = 0x8048000
SYSTEM_PLT = 0x804b0d0
EXECV_PLT  = 0x804b570
RECV_PLT   = 0x804c000
STRCPY_PLT = 0x804c100

DEFAULT_PLT = {
    SYSTEM_PLT: 'system',
    EXECV_PLT:  'execv',
    RECV_PLT:   'recv',
    STRCPY_PLT: 'strcpy',
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_tracker(plt: dict = None) -> X86_32TaintTracker:
    """Build a minimal X86_32TaintTracker with no real binary."""
    t = object.__new__(X86_32TaintTracker)
    t._path       = '/dev/null'
    t._name       = 'test'
    t._data       = b'\x90' * 0x10000
    t._base_va    = BASE_VA
    t._text_off   = 0
    t._text_va    = BASE_VA
    t._text_size  = 0x10000
    t._func_starts = []
    t._plt     = plt if plt is not None else dict(DEFAULT_PLT)
    t._plt_rev = {v: k for k, v in t._plt.items()}
    t._sinks   = dict(_TAINT_SINKS)
    t._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    t._md.detail = True
    return t


def _call(from_va: int, to_va: int) -> bytes:
    """Encode CALL rel32 from from_va to to_va."""
    rel = (to_va - from_va - 5) & 0xFFFFFFFF
    return b'\xe8' + struct.pack('<I', rel)


def _run(code: bytes, va: int = BASE_VA, plt: dict = None, pre_regs: dict = None):
    """Disassemble i386 code, optionally pre-seed register taint, return (state, findings)."""
    t = _make_tracker(plt)
    state = TaintState32()
    if pre_regs:
        for reg, sources in pre_regs.items():
            state.taint_reg(reg, frozenset(sources))
    findings = []
    for insn in t._md.disasm(code, va):
        hits = t._step(insn, state)
        findings.extend(hits)
    return state, findings


# ── PLT map helpers ───────────────────────────────────────────────────────────

def _mock_elf_for_plt(stub_type: str) -> MagicMock:
    """
    Return a mock lief ELF with minimal .plt section and JUMP_SLOT relocs.

    stub_type='nonpic': jmp *[abs32]      (ff 25) — executable style
    stub_type='pic':    jmp *[ebx+disp32] (ff a3) — shared lib style
    """
    GOT_ADDR     = 0x0804A000
    GOT_PLT_ADDR = 0x0804A000
    PLT_VA       = BASE_VA

    resolver = b'\x90' * 16
    if stub_type == 'nonpic':
        sys_stub  = b'\xff\x25' + struct.pack('<I', GOT_ADDR)     + b'\x90' * 10
        execv_stub = b'\xff\x25' + struct.pack('<I', GOT_ADDR + 4) + b'\x90' * 10
    else:
        sys_stub  = b'\xff\xa3' + struct.pack('<I', 0)             + b'\x90' * 10
        execv_stub = b'\xff\xa3' + struct.pack('<I', 4)             + b'\x90' * 10
    plt_bytes = resolver + sys_stub + execv_stub

    def _rel(addr, name):
        r = MagicMock()
        r.type    = 'R_386_JUMP_SLOT'
        r.address = addr
        r.symbol  = MagicMock()
        r.symbol.name = name
        return r

    plt_sec = MagicMock()
    plt_sec.name            = '.plt'
    plt_sec.content         = list(plt_bytes)
    plt_sec.virtual_address = PLT_VA

    got_plt_sec = MagicMock()
    got_plt_sec.name            = '.got.plt'
    got_plt_sec.virtual_address = GOT_PLT_ADDR

    elf = MagicMock()
    elf.relocations = [_rel(GOT_ADDR, 'system'), _rel(GOT_ADDR + 4, 'execv')]
    elf.sections    = [plt_sec, got_plt_sec]
    return elf


# ── test 1: PLT map — non-PIC (ff 25) stubs ──────────────────────────────────

def test_plt_map_nonpic():
    """_build_plt_map resolves system and execv from non-PIC jmp *[abs32] stubs."""
    with patch('ablation.analyzers.taint_tracker_x86_32.lief') as mock_lief:
        mock_lief.parse.return_value = _mock_elf_for_plt('nonpic')
        result = _build_plt_map('/dev/null')
    assert 'system' in result.values()
    assert 'execv'  in result.values()


# ── test 2: PLT map — PIC (ff a3) stubs ──────────────────────────────────────

def test_plt_map_pic():
    """_build_plt_map resolves system and execv from PIC jmp *[ebx+disp32] stubs."""
    with patch('ablation.analyzers.taint_tracker_x86_32.lief') as mock_lief:
        mock_lief.parse.return_value = _mock_elf_for_plt('pic')
        result = _build_plt_map('/dev/null')
    assert 'system' in result.values()
    assert 'execv'  in result.values()


# ── test 3: CDECL32 arg0 tainted ─────────────────────────────────────────────

def test_cdecl32_arg0_tainted():
    """push tainted_eax; call system → finding with arg_idx=0, source 'recv'."""
    # push eax (50) at BASE_VA; call system (e8 ...) at BASE_VA+1
    code = b'\x50' + _call(BASE_VA + 1, SYSTEM_PLT)
    _, findings = _run(code, pre_regs={'eax': ['recv']})
    assert len(findings) == 1
    assert findings[0].sink_name == 'system'
    assert findings[0].arg_idx  == 0
    assert 'recv' in findings[0].sources


# ── test 4: CDECL32 arg1 tainted ─────────────────────────────────────────────

def test_cdecl32_arg1_tainted():
    """push tainted_src(eax); push clean_dst(ebx); call strcpy → finding at arg_idx=1."""
    # CDECL args pushed right-to-left: src (arg1) first, dst (arg0) second.
    # After two pushes esp_delta=8; arg1 → esp_stack[4], arg0 → esp_stack[8].
    code = (
        b'\x50'                            # push eax  (tainted src = arg1)
        + b'\x53'                          # push ebx  (clean dst  = arg0)
        + _call(BASE_VA + 2, STRCPY_PLT)
    )
    _, findings = _run(code, pre_regs={'eax': ['recv']})
    assert any(f.sink_name == 'strcpy' and f.arg_idx == 1 for f in findings), (
        f"expected strcpy arg1 finding, got {findings}"
    )


# ── test 5: xor self-clear ────────────────────────────────────────────────────

def test_xor_clear():
    """xor eax,eax clears taint; push eax; call system → no finding."""
    code = (
        b'\x31\xc0'                        # xor eax, eax
        + b'\x50'                          # push eax
        + _call(BASE_VA + 3, SYSTEM_PLT)
    )
    _, findings = _run(code, pre_regs={'eax': ['recv']})
    assert findings == []


# ── test 6: ebp frame store/load ─────────────────────────────────────────────

def test_ebp_store_load():
    """Taint stored via mov [ebp-4],eax; reloaded via mov ecx,[ebp-4]; push ecx → finding."""
    # mov [ebp-4], eax = 89 45 fc  (fc = -4 signed byte)
    # mov ecx, [ebp-4] = 8b 4d fc
    # push ecx         = 51
    # call system      = e8 ...     (starts at BASE_VA + 7)
    code = (
        b'\x89\x45\xfc'                    # mov [ebp-4], eax
        + b'\x8b\x4d\xfc'                 # mov ecx, [ebp-4]
        + b'\x51'                          # push ecx
        + _call(BASE_VA + 7, SYSTEM_PLT)
    )
    _, findings = _run(code, pre_regs={'eax': ['recv']})
    assert len(findings) == 1
    assert findings[0].sink_name == 'system'
    assert 'recv' in findings[0].sources


# ── test 7: source call taints return register ────────────────────────────────

def test_source_taint():
    """call recv@plt taints eax; push eax; call system → finding with source 'recv'."""
    # call recv at BASE_VA (5 bytes); push eax at BASE_VA+5; call system at BASE_VA+6
    code = (
        _call(BASE_VA, RECV_PLT)           # call recv → eax = tainted{recv}
        + b'\x50'                          # push eax
        + _call(BASE_VA + 6, SYSTEM_PLT)
    )
    _, findings = _run(code)
    assert any(
        f.sink_name == 'system' and 'recv' in f.sources
        for f in findings
    ), f"expected system finding with source recv, got {findings}"


# ── test 8: immediate push is not tainted ────────────────────────────────────

def test_no_false_positive_imm():
    """push imm8(0x42); call system → no finding (constant literal is not tainted)."""
    code = (
        b'\x6a\x42'                        # push 0x42 (imm8, sign-extended)
        + _call(BASE_VA + 2, SYSTEM_PLT)
    )
    _, findings = _run(code)
    assert findings == []


# ── test 9: from_context attribute extraction ─────────────────────────────────

def test_from_context():
    """from_context reads _binary_path and func_starts from a BinaryContext-like object."""
    class FakeCtx:
        _binary_path = '/dev/null'
        func_starts  = [0x8048100, 0x8048200]

    tracker = X86_32TaintTracker.from_context(FakeCtx())
    assert tracker._path == '/dev/null'
    assert tracker._func_starts == [0x8048100, 0x8048200]
