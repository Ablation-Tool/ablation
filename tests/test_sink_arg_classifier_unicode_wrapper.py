"""Unit tests for SinkArgClassifier UNICODE_WRAPPER verdict.

Tests verify that functions following the VMware VDDK Unicode-to-POSIX
wrapper pattern (Unicode_GetAllocBytes called before a POSIX exec sink)
are classified as UNICODE_WRAPPER rather than UNKNOWN or ARG_PROPAGATED.
"""

import struct
import pytest

_CS_OK   = False
_LIEF_OK = False
try:
    import capstone
    _CS_OK = True
except ImportError:
    pass
try:
    import lief
    _LIEF_OK = True
except ImportError:
    pass

_SKIP_DEPS = pytest.mark.skipif(
    not (_CS_OK and _LIEF_OK),
    reason='capstone and lief required',
)

from ablation.analyzers.sink_arg_classifier import (
    SinkArgClassifier,
    RODATA_CONST,
    ARG_PROPAGATED,
    UNKNOWN,
    UNICODE_WRAPPER,
)
import capstone as _cap


# ── test VA layout ─────────────────────────────────────────────────────────────
BASE_VA    = 0x400000   # function start
UGAB_PLT   = 0x401000   # Unicode_GetAllocBytes PLT stub VA
POPEN_PLT  = 0x401010   # popen PLT stub VA
SYSTEM_PLT = 0x401020   # system PLT stub VA
RODATA_VA  = 0x402000   # start of .rodata
RODATA_END = 0x403000   # end of .rodata

DEFAULT_PLT = {
    UGAB_PLT:   'Unicode_GetAllocBytes',
    POPEN_PLT:  'popen',
    SYSTEM_PLT: 'system',
}


def _call_rel32(from_va: int, to_va: int) -> bytes:
    """Encode: e8 <rel32>  (CALL to_va from from_va)."""
    rel = to_va - (from_va + 5)
    return b'\xe8' + struct.pack('<i', rel)


def _make_clf(code: bytes, func_va: int = BASE_VA, plt: dict = None) -> SinkArgClassifier:
    """
    Build a SinkArgClassifier from a raw x86-64 byte sequence without a real ELF.

    Sets all internal state manually to bypass LIEF ELF parsing.
    The data buffer contains `code` starting at func_va.
    """
    used_plt = plt if plt is not None else DEFAULT_PLT

    # Pad code to _MAX_FUNC_BYTES so _read_va() doesn't bail on size check.
    from ablation.analyzers.sink_arg_classifier import _MAX_FUNC_BYTES
    padded_code = code + b'\x90' * (_MAX_FUNC_BYTES - len(code))

    clf = SinkArgClassifier.__new__(SinkArgClassifier)
    clf._path       = '/dev/null'
    clf._data       = padded_code
    clf._plt        = used_plt
    clf._plt_rev    = {v: k for k, v in used_plt.items()}
    clf._rodata     = [(RODATA_VA, RODATA_END)]
    clf._func_starts = [func_va]
    clf._sinks      = {'popen': 0, 'system': 0}
    clf._snprintf_plts = {}
    clf._plt_caller_counts = {va: 1 for va in used_plt}
    clf._dead_sinks = []
    clf._bin        = None

    cs = _cap.Cs(_cap.CS_ARCH_X86, _cap.CS_MODE_64)
    cs.detail = True
    clf._md = cs

    # Map VA → data offset: subtract func_va
    clf._va_to_file_offset = lambda va: va - func_va

    return clf


# ── tests ──────────────────────────────────────────────────────────────────────

@_SKIP_DEPS
def test_unicode_wrapper_popen():
    """call Unicode_GetAllocBytes; mov rdi, rax; call popen → UNICODE_WRAPPER."""
    func_va = BASE_VA

    # Prologue
    prologue = (
        b'\x55'             # push rbp
        b'\x48\x89\xe5'    # mov rbp, rsp
        b'\x49\x89\xfd'    # mov r13, rdi   (save unicode arg)
    )
    # call Unicode_GetAllocBytes
    ugab_call_va = func_va + len(prologue)
    ugab_call = _call_rel32(ugab_call_va, UGAB_PLT)

    # mov rdi, rax; call popen
    mid = b'\x48\x89\xc7'  # mov rdi, rax
    popen_call_va = func_va + len(prologue) + len(ugab_call) + len(mid)
    popen_call = _call_rel32(popen_call_va, POPEN_PLT)

    epilogue = b'\x5d\xc3'  # pop rbp; ret

    code = prologue + ugab_call + mid + popen_call + epilogue
    clf = _make_clf(code, func_va)

    results = clf.classify_all()
    assert results, 'expected at least one result'
    popen_results = [r for r in results if r.sink_name == 'popen']
    assert popen_results, 'expected popen result'
    assert popen_results[0].verdict == UNICODE_WRAPPER, (
        f'expected UNICODE_WRAPPER, got {popen_results[0].verdict}: {popen_results[0].detail}'
    )


@_SKIP_DEPS
def test_unicode_wrapper_system():
    """call Unicode_GetAllocBytes; mov rdi, rax; call system → UNICODE_WRAPPER."""
    func_va = BASE_VA

    prologue = (
        b'\x55'
        b'\x48\x89\xe5'
        b'\x49\x89\xfd'
    )
    ugab_call_va = func_va + len(prologue)
    ugab_call = _call_rel32(ugab_call_va, UGAB_PLT)
    mid = b'\x48\x89\xc7'  # mov rdi, rax
    sys_call_va = func_va + len(prologue) + len(ugab_call) + len(mid)
    sys_call = _call_rel32(sys_call_va, SYSTEM_PLT)
    code = prologue + ugab_call + mid + sys_call + b'\xc3'

    clf = _make_clf(code, func_va)
    results = clf.classify_all()
    sys_results = [r for r in results if r.sink_name == 'system']
    assert sys_results, 'expected system result'
    assert sys_results[0].verdict == UNICODE_WRAPPER


@_SKIP_DEPS
def test_no_unicode_wrapper_without_ugab():
    """popen without prior Unicode_GetAllocBytes call → NOT UNICODE_WRAPPER."""
    func_va = BASE_VA

    # Direct: mov rdi, rdi; call popen (no Unicode_GetAllocBytes)
    prologue = b'\x55\x48\x89\xe5'
    # mov rdi, rdi is a no-op that sets rdi from rdi — trace should give ARG_PROPAGATED
    mov = b'\x48\x89\xff'  # mov rdi, rdi (rdi is entry arg → ARG_PROPAGATED)
    popen_call_va = func_va + len(prologue) + len(mov)
    popen_call = _call_rel32(popen_call_va, POPEN_PLT)
    code = prologue + mov + popen_call + b'\xc3'

    clf = _make_clf(code, func_va)
    results = clf.classify_all()
    popen_results = [r for r in results if r.sink_name == 'popen']
    assert popen_results, 'expected popen result'
    # Should NOT be UNICODE_WRAPPER — no UGAB call present
    assert popen_results[0].verdict != UNICODE_WRAPPER, (
        'should not classify as UNICODE_WRAPPER without Unicode_GetAllocBytes'
    )
    # rdi = rdi = entry arg → ARG_PROPAGATED
    assert popen_results[0].verdict == ARG_PROPAGATED


@_SKIP_DEPS
def test_unicode_wrapper_not_triggered_if_ugab_after_sink():
    """Unicode_GetAllocBytes call AFTER popen call → popen is NOT UNICODE_WRAPPER.

    The wrapper detection checks only the first 30 instructions before the sink call.
    If UGAB appears after the sink, the sink is classified normally.
    """
    func_va = BASE_VA

    prologue = b'\x55\x48\x89\xe5'
    # popen first, then UGAB — popen should NOT be UNICODE_WRAPPER
    mov = b'\x48\x89\xff'  # mov rdi, rdi (entry arg)
    popen_call_va = func_va + len(prologue) + len(mov)
    popen_call = _call_rel32(popen_call_va, POPEN_PLT)
    # Unicode_GetAllocBytes after popen
    ugab_call_va = popen_call_va + len(popen_call)
    ugab_call = _call_rel32(ugab_call_va, UGAB_PLT)

    code = prologue + mov + popen_call + ugab_call + b'\xc3'
    clf = _make_clf(code, func_va)
    results = clf.classify_all()
    popen_results = [r for r in results if r.sink_name == 'popen']
    assert popen_results
    # UGAB is AFTER popen, so popen scan window doesn't see it
    assert popen_results[0].verdict != UNICODE_WRAPPER
