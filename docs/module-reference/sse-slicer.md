# SSE Slicer

**File:** `modules/sse_slicer.py`

## Why this exists

Two gaps existed before this module:

1. **STR/STP writers to BSS targets required manual identification.** In stripped ARM64 binaries, finding every instruction that writes a specific BSS address (e.g., a global struct field like `gILinkKey`) required manual disassembly browsing. No automated backward-slice tool existed in the Ablation pipeline.

2. **EmTaint-style Structured Symbolic Expression analysis was absent.** The EmTaint approach (provenance trees for memory access expressions) enables precise identification of all writers to a target address, distinguishing "exact" writers (statically resolved EA equals target) from "possible" writers (EA involves a memory load that could resolve to target). No SSE-based backward slicer existed for stripped ARM64.

Note: "SSE" in this module name is **Structured Symbolic Expression** (from the EmTaint paper), NOT x86 Streaming SIMD Extensions.

---

## Algorithm

Implements the EmTaint SSE backward-slicing approach for ARM64:

- **SSE node types**: `Const(v)`, `Add(sse, imm)`, `Sub(sse, imm)`, `Mem(sse, imm)`, `Unknown(reg, pc)`
- **Backward slicer** (`backward_sse`): walks backward from each STR/STP site, building an SSE tree for the base register. Stops at function boundary or `max_depth` (default 128) instructions.
- **EA evaluation**: `ea_sse.eval()` resolves the SSE tree to a concrete address. If it evaluates to a value in `[target, target+size)` → **EXACT WRITER**. If the tree contains `Mem` nodes and cannot be resolved → **POSSIBLE WRITER**.
- **Bounds**: `_MAX_BINARY_BYTES=256MB` cap; recursive slicer bounded by `max_depth`.

Handles ARM64 instructions: ADRP, ADD/SUB immediate, LDR (64-bit), STR/STP (64-bit), MOV (ORR xZR form), BL/BLR (invalidates x0-x18).

---

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap in `scan()` |

---

## Usage

```python
from pathlib import Path
from modules.sse_slicer import scan, backward_sse, decode_spu_word

# Scan a binary for all STR/STP writers to target BSS address
exact, possible = scan(
    binary=Path('/path/to/libwechatnetwork.so'),
    target=0x3d4648,       # target BSS address (e.g., &gILinkKey)
    target_size=72,        # size of the target struct/array in bytes
    text_start=0xdd130,    # .text section VA start
    text_size=0x2de650,    # .text section size in bytes
    verbose=False,
)
print(f"Exact writers: {len(exact)}, Possible writers: {len(possible)}")
```

**CLI:**
```bash
python3 modules/sse_slicer.py \
    --binary libwechatnetwork.so \
    --target 0x3d4648 \
    --size 72 \
    --text-start 0xdd130 \
    --text-size 0x2de650 \
    [--verbose]
```

---

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings.

- `scan()`: `Path.stat().st_size` guard at line 307 before `Path.read_bytes()` at line 311. Cap: `_MAX_BINARY_BYTES=256MB`.
- `backward_sse()`: recursive but bounded by `max_depth=128` (default), preventing runaway recursion on adversarial inputs.
- No bare `except:`. No lief.parse(). No HTTP reads. No subprocess.
