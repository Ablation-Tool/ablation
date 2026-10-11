# EcuC28xDecoder — FORGE Audit + DEV & TEST ORCHESTRATION PLAN

**Module:** `ablation/analyzers/ecu_c28x_decoder.py`  
**Version:** v2.71.0  
**Date:** 2026-10-10  
**Auditor:** Claude Sonnet 4.6  

---

## SAFE CODE 10-Section Audit

### §1 Input Validation
- `__init__` with path argument: opens the file via `open(data, 'rb')` and catches
  `FileNotFoundError`. `PermissionError` and `OSError` propagate — the caller is responsible.
  This is documented in the module docstring. **PASS**
- `decode_one(byte_off)`: `byte_off + 2 > len(data)` guard before any `unpack_from`.
  For 32-bit instructions an additional `byte_off + 4 > len(data)` check is applied
  before reading w2. **PASS**
- `insn_length(byte_off)`: same `byte_off + 2 > len(data)` guard; returns 0 at EOF. **PASS**
- `disassemble(start, end)`: clamps `end = min(end, len(self._data))`. Loop terminates
  on `decode_one` returning None. **PASS**
- `function_starts()`: `off + 2 <= n` and `off + 4 <= n` guards before all unpack calls.
  Both branches correctly advance `off` (by 4 for 32-bit, by 2 for 16-bit). **PASS**

### §2 Command Injection
No subprocess, os.system, Popen, eval, or exec calls. **PASS**

### §3 Path Traversal
The path argument is passed only to `open()` for reading the user's own file. No path
construction from decoded instruction content. **PASS**

### §4 Secret/Credential Exposure
No credentials, API keys, or secrets anywhere in the module. **PASS**

### §5 Integer Overflow / Underflow
Python integers are unbounded; no overflow is possible. The signed-offset computation
`w2 - 0x10000` for values ≥ 0x8000 yields a correct negative Python int. The addr22
extraction `((w1 & 0x3F) << 16) | w2` is bounded to [0, 0x3FFFFF]. **PASS**

### §6 Memory Safety
Pure Python. No ctypes, no C extensions, no mmap. `struct.unpack_from()` raises
`struct.error` on truncated input — guarded by the length checks in §1. **PASS**

### §7 Error Handling
- `FileNotFoundError` caught for path-based construction and re-raised with context.
- `PermissionError` / `OSError` propagate to the caller — documented, not a gap.
- No `struct.error` can escape because all `unpack_from` calls are preceded by length
  guards that ensure sufficient bytes. **PASS**

### §8 Data Leakage
No network calls, no file writes, no logging. **PASS**

### §9 Dependencies
`struct`, `dataclasses`, `pathlib`, `typing` — stdlib only. No new dependencies. **PASS**

### §10 Logic Correctness
- `_is_32bit()` patterns: verified against SPRU430F per-instruction encoding pages. The
  16-bit specials in the 0x76xx range (LRET=0x7614, LC *XAR7=0x7604, etc.) all have
  `w1 & 0xFFC0 == 0x7600`, which is distinct from the LCR #22bit test (0x7640). No
  overlap exists among the 15 `_is_32bit` conditions. **PASS**
- Branch target computation: `target = word_va + 2 + off16` correctly models C28x
  post-instruction PC (word_va + 2 for a 32-bit instruction) plus the signed offset. **PASS**
- `addr22 = ((w1 & 0x3F) << 16) | w2`: correct for all LB/LC/LCR/FFC 22-bit
  instructions. The upper 6 bits are in w1[5:0]; the lower 16 bits are w2. **PASS**
- `function_starts()` correctly skips indirect call forms (LC *XAR7, LCR *XARn) since
  their target is runtime-determined. Only direct-address LC/LCR/FFC are included. **PASS**
- `word_va = self._base_va + byte_off // 2`: correct conversion from byte offset to word
  address. Integer division is exact since byte_off is always even (instruction-aligned). **PASS**
- Condition code extraction: `cond = w1 & 0xF` for B and BF; the 4-bit COND occupies
  bits [3:0] in both encodings, confirmed from SPRU430F. **PASS**

**gate_passed: True** — 0 HIGH, 0 CRITICAL findings.

---

## DEV & TEST ORCHESTRATION PLAN

### Test 1 — Import smoke test
```python
from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder, C28xInsn
```
Expected: no ImportError.

### Test 2 — from_path on missing file raises FileNotFoundError
```python
try:
    EcuC28xDecoder.from_path('/nonexistent_c28x.bin')
    assert False
except FileNotFoundError:
    pass
```

### Test 3 — insn_length returns 0 at EOF
```python
dec = EcuC28xDecoder.from_bytes(b'\x14\x76')  # LRET (0x7614)
assert dec.insn_length(0) == 2
assert dec.insn_length(1) == 0   # only 1 byte left
assert dec.insn_length(2) == 0   # past end
```

### Test 4 — LRET decoded as RETURN (16-bit)
```python
import struct
data = struct.pack('<H', 0x7614)
dec = EcuC28xDecoder.from_bytes(data)
insn = dec.decode_one(0)
assert insn is not None
assert insn.mnemonic == 'LRET'
assert insn.insn_type == 'RETURN'
assert not insn.is_32bit
assert insn.word_va == 0
```

### Test 5 — LRETR decoded as RETURN (16-bit)
```python
data = struct.pack('<H', 0x0006)
dec = EcuC28xDecoder.from_bytes(data)
insn = dec.decode_one(0)
assert insn.mnemonic == 'LRETR'
assert insn.insn_type == 'RETURN'
```

### Test 6 — B UNC (unconditional branch) decoded as BRANCH (32-bit)
```python
# B UNC, +5  →  w1=0xFFEF (COND=UNC=0xF), w2=0x0005
data = struct.pack('<HH', 0xFFEF, 0x0005)
dec = EcuC28xDecoder.from_bytes(data, base_va=0x100)
insn = dec.decode_one(0)
assert insn.mnemonic == 'B'
assert insn.is_32bit
assert insn.insn_type == 'BRANCH'
assert insn.cond is None          # UNC → no condition label
assert insn.word_va == 0x100      # base_va
assert insn.target == 0x100 + 2 + 5   # word_va + 2 + offset
```

### Test 7 — LC 22bit decoded as CALL with correct target
```python
# LC to 0x003F8000:  addr22=0x03F800
# upper6 = (0x03F800 >> 16) & 0x3F = 0x03
# lower16 = 0xF800
# w1 = 0x0080 | 0x03 = 0x0083, w2 = 0xF800
data = struct.pack('<HH', 0x0083, 0xF800)
dec = EcuC28xDecoder.from_bytes(data)
insn = dec.decode_one(0)
assert insn.mnemonic == 'LC'
assert insn.insn_type == 'CALL'
assert insn.target == 0x03F800
```

### Test 8 — LCR #22bit decoded as CALL with correct target
```python
# LCR to 0x001000:  w1 = 0x7640 | 0x00 = 0x7640, w2 = 0x1000
data = struct.pack('<HH', 0x7640, 0x1000)
dec = EcuC28xDecoder.from_bytes(data)
insn = dec.decode_one(0)
assert insn.mnemonic == 'LCR'
assert insn.insn_type == 'CALL'
assert insn.target == 0x1000
```

### Test 9 — function_starts collects LC and LCR targets
```python
buf = b''
buf += struct.pack('<HH', 0x0080, 0x0200)   # LC to 0x000200
buf += struct.pack('<HH', 0x7640, 0x0400)   # LCR to 0x000400
buf += struct.pack('<HH', 0x00C0, 0x0600)   # FFC to 0x000600
buf += struct.pack('<H', 0x7614)            # LRET (16-bit, no target)
dec = EcuC28xDecoder.from_bytes(buf)
starts = dec.function_starts()
assert starts == [0x000200, 0x000400, 0x000600]
```

### Test 10 — BF EQ with negative offset
```python
# BF EQ, -3  →  w1=0x56C1 (COND=EQ=0x1), w2=0xFFFD (-3)
data = struct.pack('<HH', 0x56C1, 0xFFFD)
dec = EcuC28xDecoder.from_bytes(data, base_va=0x20)
insn = dec.decode_one(0)
assert insn.mnemonic == 'BF'
assert insn.cond == 'EQ'
assert insn.target == 0x20 + 2 - 3   # 0x1F
```
