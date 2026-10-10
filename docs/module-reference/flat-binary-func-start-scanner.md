# FlatBinaryFuncStartScanner

**File:** `ablation/analyzers/flat_binary_func_start_scanner.py`

---

## Why this exists

2 things that were not possible before in Ablation:

**1. No function-start discovery for flat ROM images without a known ISA.**  Every per-ISA decoder
(`EcuSH2aDecoder`, `EcuVLEDecoder`, `EcuM68kDecoder`) exposes its own `function_starts()` method,
but all of them require you to already know the ISA before you call them.  For a ROM that arrives
without metadata — no ELF header, no debug info, unknown vendor — there was no path from "raw
bytes" to "set of function entry addresses" without a manual identification step first.
`FlatBinaryFuncStartScanner` bridges that gap: it calls `EcuArchDetector` internally, selects the
right prologue catalog automatically, and returns a combined function-start set without requiring
any caller knowledge of the ISA.

**2. No call-target harvesting from the reset entry point.**  `function_starts()` in each decoder
is purely a prologue pattern scan.  That misses functions whose first instruction is not a
recognizable prologue form (leaf functions that open with a branch, functions reached only through
indirect dispatch, etc.).  `FlatBinaryFuncStartScanner` adds a second signal: it follows the reset
vector, linearly decodes branch/call instructions in the detected ISA, and recursively collects
all reachable call targets.  The union of call targets and prologue hits covers both classes.

---

## Usage

```python
from ablation.analyzers.flat_binary_func_start_scanner import FlatBinaryFuncStartScanner

# Auto-detect ISA and scan
scanner = FlatBinaryFuncStartScanner(rom_bytes, base_va=0x0)
result = scanner.scan()
print(result.arch, result.confidence)
for va in result.function_starts:
    print(hex(va))

# Force ISA (skip detection)
result = FlatBinaryFuncStartScanner.from_path("unknown.bin").scan(arch="sh2a")

# All call targets vs. all prologue hits
print(result.call_targets)
print(result.prologue_hits)
```

### Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `data` | — | `bytes`, file path (`str`/`Path`), or buffer |
| `base_va` | 0 | Load address of byte 0 in the target address space |
| `max_call_depth` | 64 | Maximum BFS depth for call-target harvesting |

---

## FuncStartResult fields

```python
@dataclass
class FuncStartResult:
    arch: str              # detected ISA or "unknown"
    confidence: str        # "HIGH" / "MEDIUM" / "LOW"
    function_starts: list[int]   # sorted union of call_targets + prologue_hits
    call_targets: list[int]      # VAs harvested by following call instructions
    prologue_hits: list[int]     # VAs found by prologue pattern scan
    detect_result: Optional[ArchDetectResult]  # raw EcuArchDetector output
```

---

## How it works

### Step 1 — ISA identification

`EcuArchDetector` runs five discriminators and returns HIGH/MEDIUM/LOW confidence.

When confidence is HIGH or MEDIUM, only that ISA's call scanner and prologue catalog run.

When confidence is LOW (or arch is `unknown`), all five catalogs run and the results are
unioned.  This handles pathological ROMs where the first 4 KB is dominated by calibration
tables, which can suppress the confidence level.

### Step 2 — Call-target harvesting

Starting from the reset entry point (decoded from the ISA-specific reset vector location):

- Linear decode walks instructions in the detected ISA
- Direct call instructions (BSR / BL / PPC BL / SH-2A BSR) yield call targets
- Each new target is pushed to the BFS queue
- The scan stops at the first return instruction per function, or after 512 instructions

Indirect calls (JSR / BLR / BX LR / SH-2A JSR) are not resolved — they require a taint
trace.  Direct calls only.

### Step 3 — Prologue pattern scan

Full image scan for ISA-specific prologue byte sequences:

| ISA | Pattern | Notes |
|---|---|---|
| `arm_cm` | Thumb2 PUSH with LR bit: `hw & 0xFF00 == 0xB500` | LE halfword |
| `m68k` | LINK.W A6, #-N: `0x4E56` + negative 16-bit word | BE halfword |
| `ppc32` | MFLR r0: `7C 08 02 A6` | BE word |
| `ppc_vle` | e_stwu r1, -N(r1): first halfword `0x1C21` + negative D8 | BE word |
| `sh2a` | STS.L PR, @-R15: `0x4F22`; leaf: `(hw & 0xF0FF) == 0x002A` not preceded by `0x4F22` | BE halfword |

---

## Supported ISAs

Same five as `EcuArchDetector`: `arm_cm`, `m68k`, `ppc32`, `ppc_vle`, `sh2a`.

---

## Limitations

- Indirect calls are not resolved.  Use `EcuSH2aDecoder` / `EcuVLEDecoder` with a manual
  `WindowAnalyzer` trace for JSR targets.
- Call-target harvesting is BFS from the reset vector only.  Functions reachable only via
  interrupt vectors or RTOS task entry points will appear in prologue hits but not call targets.
- ARM Cortex-M: BLX with register form (indirect) is skipped.  Only BL (absolute offset) and
  BLX (with imm offset, to ARM mode) are harvested.
- PPC VLE: `se_bl` (short 16-bit form of BL) is not currently harvested in the call scanner.
  It does appear as a `ppc_vle` prologue hit via `e_stwu` scan.
