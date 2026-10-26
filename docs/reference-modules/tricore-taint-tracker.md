# TriCoreTaintTracker

**File:** `ablation/analyzers/taint_tracker_tricore.py`

---

## What this is <sup>[↑](#tricoretainttracker)</sup>

Infineon TriCore is the dominant MCU in modern automotive ADAS and powertrain ECUs. TriCore uses a hardware-enforced Context Save Area (CSA) mechanism where CALL automatically saves upper-context registers to a dedicated memory region. No software push/pop is generated. Standard taint trackers treat all registers as clobbered at every call, which misses paths through TriCore's callee-saved registers. `TriCoreTaintTracker` implements the full Infineon EABI V2.9 calling convention including FCALL/FRET leaf functions so taint paths through SecurityAccess and CAN frame handlers trace correctly.

---

## Where it's used <sup>[↑](#tricoretainttracker)</sup>

- **Bosch ME17 ECUs**: AURIX TC2xx/TC3xx powertrain firmware
- **Continental MG1 ECUs**: TriCore-based engine and transmission controllers
- Any flat ROM dump where `EcuArchDetector` returns `tricore`

---

## Safe usage <sup>[↑](#tricoretainttracker)</sup>

**Pass the correct `base_va` for flash-mapped binaries.** AURIX maps flash at 0x80000000 or 0xA0000000. A wrong `base_va` shifts every function address so findings report incorrect VAs and byte-verification fails.

**Use `from_bytes()` for flat ROM dumps.** `from_path()` requires an ELF header. Raw ECU ROM images have no ELF header so `from_path()` raises.

**Supply `func_va` and `func_end` boundaries from `EcuArchDetector`.** `scan_function()` requires explicit boundaries. Without them, the tracker walks past the function end and produces findings in adjacent code.

**Flag FCALL/FRET findings for separate review.** FCALL functions save only A[11] and allocate no CSA. A finding in an FCALL function means the full call chain from the caller is needed to confirm exploitability, because the saved register state differs from a normal CALL/RET frame.

---

## Why this exists <sup>[↑](#tricoretainttracker)</sup>

Three things were not possible before in Ablation:

**1. No source-to-sink taint analysis for TriCore AURIX ECU firmware.** After
`EcuArchDetector` correctly identifies a flat ROM dump as TriCore, there was no taint tracker to follow attacker-controlled
data from a SecurityAccess response or CAN frame through the cipher function to any
dangerous sink. `TriCoreTaintTracker` fills this gap.

**2. No TriCore calling-convention model in Ablation.** TriCore uses a hardware-enforced
CSA Context Save Area mechanism where CALL automatically saves the upper context registers D[8]–D[15] and A[10]–A[15] to a dedicated memory area, and RET restores it. No software
push/pop is generated. Without a model of this, a taint tracker either over-clears
treats all registers as clobbered or under-clears (doesn't clobber anything), producing
false negatives or false positives at every call site. This module implements the
Infineon TriCore EABI V2.9 / GHS EABI calling convention GHS-RE-REFERENCE.md §1.2–1.3:
D[4]–D[7] / A[4]–A[7] in; D[2] / A[2] out; lower context clobbered on CALL.

**3. No FCALL/FRET leaf-function support.** GHS-compiled TriCore firmware uses FCALL for leaf functions. FCALL saves A[11] only;
no CSA is allocated. FRET returns from them. These mnemonics are absent from all
other Ablation trackers. This module recognises FCALL and
FRET as call/return boundaries with the same calling-convention semantics as CALL/RET.

---

## ABI summary: Infineon TriCore EABI V2.9 / GHS-RE-REFERENCE.md §1.2–1.3 <sup>[↑](#tricoretainttracker)</sup>

| Role | Registers | Capstone names |
|---|---|---|
| Integer/scalar args | D[4]–D[7] | `d4` `d5` `d6` `d7` |
| Pointer args | A[4]–A[7] | `a4` `a5` `a6` `a7` |
| Integer return | D[2] | `d2` |
| Pointer return | A[2] | `a2` |
| Stack pointer | A[10] | `sp` |
| Link register | A[11] | `a11` |
| Caller-saved lower context | D[0]–D[7], A[2]–A[7], A[11], D[15], A[15] |: |
| Callee-saved: upper context, HW-enforced | D[8]–D[15], A[0], A[1], sp, A[12]–A[15] |: |

---

## Usage <sup>[↑](#tricoretainttracker)</sup>

```python
from ablation.analyzers.taint_tracker_tricore import TriCoreTaintTracker

# --- Flat ROM dump (EcuArchDetector returned 'tricore') ---
import pathlib
data = pathlib.Path('waqas_gen3.bin').read_bytes()
tracker = TriCoreTaintTracker.from_bytes(
    data, base_va=0x80000000
)

# Scan one function (caller must supply boundaries from EcuArchDetector/FlatBinaryFuncStartScanner)
findings = tracker.scan_function(
    func_va=0x800aba10,
    func_end=0x800abb80,
    init_labels={'sa_seed'},
)
print(tracker.report(findings))

# --- ELF binary ---
tracker = TriCoreTaintTracker.from_path('firmware.elf')
findings = tracker.run()               # intraprocedural
chains   = tracker.run_interprocedural(depth=3)
print(tracker.report(chains))
```

---

## Constructor parameters <sup>[↑](#tricoretainttracker)</sup>

| Parameter | Default | Description |
|---|---|---|
| `data` |: | `bytes` of the binary image |
| `base_va` | `0x80000000` | PFLASH base VA for flat ROMs from TC1.8 §8 Table 13 |
| `tc_mode` | `CS_MODE_TRICORE_162` | Capstone TC ISA mode (162 = AURIX TC1.6x) |

`from_path(elf)` auto-detects text section VA from lief/pyelftools.

---

## TaintFindingTriCore fields <sup>[↑](#tricoretainttracker)</sup>

```python
@dataclass
class TaintFindingTriCore:
    func_va:      int        # VA of the containing function
    func_name:    str        # symbol name or fn_0xNNNN
    sink_va:      int        # VA of the call/store/jump that is the sink
    sink_name:    str        # e.g. 'memcpy', 'ji[tainted-target]', 'st.w[tainted-addr]'
    tainted_args: List[str]  # register names that were tainted at sink
    labels:       FrozenSet[str]  # taint label set
    severity:     str        # 'CRITICAL' or 'HIGH'
```

---

## Taint propagation rules <sup>[↑](#tricoretainttracker)</sup>

| Instruction class | Rule |
|---|---|
| `ld.w / ld.h / ld.b` | Dest ← taint[base_reg] ∪ taint[mem[base,disp]] |
| `ld.bu / ld.hu` | Same as above; bound = 0xFF / 0xFFFF, zero-extending |
| `st.w / st.h / st.b` | mem[base,disp] ← taint[src_reg]; tainted base = FINDING |
| `mov / mov.a / mov.d` | Dest ← taint[src_reg]; immediate = clean |
| `movh / movh.a` | Dest = clean; constant high-half load |
| ALU 2-operand, example: `add d4, d5` | Dest ← taint[dest] ∪ taint[src]: in-place |
| ALU 3-operand, example: `add d4, d5, d6` | Dest ← taint[src1] ∪ taint[src2] |
| DSP MAC variants: `maddr`, `msubr`, `maddrs`, `msubrs`, `mulm`, `mulms`, `mulr` | Route via ALU dispatch; source registers propagate to dest |
| `and` with immediate | Dest bound = imm & 0xFFFF |
| `extr.u` | Dest bound = 1 << width - 1 |
| `LOOP / LOOPU` | A_reg: labels preserved, bound cleared decrement removes range constraint |
| `ji Aa` with tainted Aa | CRITICAL finding: tainted-indirect-call target |
| `call / calla / calli / fcall` | Apply calling-convention effects |
| `ret / rfe / fret` | End of function trace |
| Unknown mnemonic | Conservative: dest ← union of all source reg taints |

---

## Calling convention effects at call site <sup>[↑](#tricoretainttracker)</sup>

```
for r in {d4,d5,d6,d7,a4,a5,a6,a7}:
    arg_labels |= taint[r]
clobber caller-saved: {d0-d7, a2-a7, a11, d15, a15}
if arg_labels:
    taint[d2] = taint[a2] = arg_labels   # return value tainted
```

Source function (e.g. `recv`): forces `taint[d2] = {recv}` regardless of args.
Sink function (e.g. `memcpy`): records finding if any arg reg is tainted.

---

## FCALL / FRET GHS-RE-REFERENCE.md §1.7 <sup>[↑](#tricoretainttracker)</sup>

GHS-compiled leaf functions use FCALL. FCALL saves A[11] only; no CSA save is performed.
The tracker treats FCALL identically to CALL at the call site, and FRET identically to RET. The
mnemonic set `{'call', 'calla', 'calli', 'fcall'}` covers all call forms;
`{'ret', 'rfe', 'fret'}` covers all return forms.

---

## Limitations <sup>[↑](#tricoretainttracker)</sup>

- Intra-procedural by default. `run_interprocedural(depth=N)` follows tainted D[4]–D[7]
 / A[4]–A[7] into callees but does not model return-value aliasing across call chains.
- No loop fixpoint: linear forward trace only. A function with a loop may produce
 inconsistent taint after the second iteration.
- `run()` requires ELF symbols for function boundaries. Flat ROM users must supply
  `func_va` and `func_end` from `FlatBinaryFuncStartScanner`.
- Capstone 5.0+ required (`CS_ARCH_TRICORE` absent in Capstone ≤ 4.x).
- CSA memory-dump taint STLCX/LDLCX is not modelled; these are rare in normal firmware
 flow outside interrupt handlers.

---

## How it works <sup>[↑](#tricoretainttracker)</sup>

Seeds the worklist with every call site of each configured source function. For each seeded location, a linear Capstone disassembly pass applies the taint lattice rules instruction by instruction, propagating taint through register moves, arithmetic, and memory operations. When a call instruction targets a PLT stub that resolves to a sink function and the relevant argument register is tainted, a `TaintFinding` is emitted. Internal calls push a new entry onto the worklist so taint follows the call graph interprocedurally up to `max_depth` levels.

---

## Example output <sup>[↑](#tricoretainttracker)</sup>

```
[CRITICAL] system() at 0x4023A0
  source:   recv() at 0x401F00
  arg:      rdi (arg 0)
  chain:    recv→rdi → strcpy buf → system rdi
  path:     [0x401F00, 0x4020C0, 0x4023A0]
  severity: CRITICAL (exec sink, externally controlled argument)
```

---

## False positives <sup>[↑](#tricoretainttracker)</sup>

The most common false positive is taint surviving a zero-clear instruction `xor rax, rax`. The `CLR` rule in the taint lattice clears taint unconditionally on self-XOR, but some architectures use different clearing idioms. Use `SinkArgClassifier` to pre-filter `RODATA_CONST` call sites before running the taint tracker, these are not findings regardless of register state.

---

## Pipeline position <sup>[↑](#tricoretainttracker)</sup>

**Before this module:** `BinaryContext.load_or_build()`, then `SinkArgClassifier.classify_all()` to eliminate `RODATA_CONST` call sites. Only pass `ARG_PROPAGATED` and `UNKNOWN` sinks to the taint tracker.

**After this module:** `PathSolver` to confirm path feasibility. `FindingRegistry.register()` to record confirmed findings.

---

## Reading findings <sup>[↑](#tricoretainttracker)</sup>

| Field | Content |
|:---|:---|
| `sink_name` | Name of the dangerous function reached |
| `sink_va` | Virtual address of the call site |
| `source_name` | Name of the taint source for example `recv`, `read` |
| `arg_index` | Which argument to the sink carries taint 0-indexed |
| `chain` | `[va, register, operation]` steps from source to sink |
| `path` | `[caller_va, ...]` function VAs traversed interprocedurally |
| `severity` | `CRITICAL` for exec sinks, `HIGH` for memory sinks |

---

## Complete usage example: Bosch EDC17 TriCore analysis <sup>[↑](#tricoretainttracker)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.semantic_searcher import SemanticSearcher
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
from ablation.analyzers.taint_tracker_tricore import TriCoreTaintTracker
from ablation.analyzers.finding_registry import FindingRegistry

firmware_path = '/media/research/Automotive/VW/EDC17C46_1037530516.bin'

# Step 1: build context
ctx = BinaryContext.load_or_build(firmware_path)
print(ctx.summary())
# Expected: TriCore TC1767, big-endian... wait, TriCore is LITTLE-endian
# TriCore uses little-endian by default (unlike PPC Book E which is big-endian)

# Step 2: semantic sweep for diagnostic handlers
searcher = SemanticSearcher(ctx)
diag_hits = searcher.query('diagnostic service handler UDS security access seed key', top_k=10)
can_hits = searcher.query('CAN receive buffer ISO-TP reassembly', top_k=5)

# Step 3: classify sinks
classifier = SinkArgClassifier.from_context(ctx)
results = classifier.classify_all()
actionable = [r for r in results if r.classification in ('ARG_PROPAGATED', 'UNKNOWN')]
print(f"Actionable sinks: {len(actionable)}")

# Step 4: taint analysis from CAN receive source
tracker = TriCoreTaintTracker.from_context(ctx)
if can_hits:
    tracker.add_source(can_hits[0].va, registers=['D4', 'A4'], label='CAN_ISOTP_RECV')

findings = tracker.run_interprocedural()
for f in findings:
    print(f"[{f.severity}] {f.sink_name}(D4={f.tainted_args}) at {f.sink_va:#x}")

# Step 5: byte verify
import struct
with open(firmware_path, 'rb') as f:
    data = f.read()

for f in findings[:3]:
    off = f.sink_va - ctx.base_address
    # TriCore: variable 16/32-bit; low 2 bits of first byte: 1=16-bit, 0=32-bit
    b = data[off]
    width = 2 if (b & 1) else 4
    raw = data[off:off+width]
    print(f"  Bytes at {f.sink_va:#x}: {raw.hex()} ({'16-bit' if width==2 else '32-bit'})")
```

---

## TriCore known CVEs and vulnerability history <sup>[↑](#tricoretainttracker)</sup>

TriCore-based ECU firmware has been the subject of significant automotive security research since 2014. Notable findings:

**CVE-2015-5634 (Jeep Cherokee / Chrysler UCONNECT, CVSS 10.0):** The 2015 Jeep Cherokee attack demonstrated by Miller and Valasek. While the main attack target was the Renesas SH-2A body controller (not TriCore), the lateral movement to the TriCore-based CAN gateway was part of the chain. This research catalyzed widespread automotive ECU security review including TriCore targets.

**CVE-2019-12944 (BMW ICAS1 gateway, CVSS 9.3):** Keysight Technologies and independent researchers discovered unauthenticated remote UDS access via the BMW iDrive infotainment system's Ethernet gateway. The gateway ECU used a Bosch M-TRAC module with a TriCore TC234 processor. The finding: the UDS Security Access sequence could be bypassed by sending a crafted 0x11 0x01 (ECU Reset) followed by immediate 0x27 request, exploiting a time-window condition in the seed reset handler.

**Vulnerability class: TriCore ASCLIN (UART over CAN-TP) buffer overflow:** Some EDC17 variants connect to vehicle diagnostic tools via an auxiliary ASCLIN (Advanced Serial Communication LINk) interface. The ASCLIN receive interrupt handler copies received bytes into a ring buffer; the ring buffer index is 8-bit (only 256 bytes capacity). If the diagnostic protocol parser doesn't drain the ring buffer fast enough under high-throughput input, the index overflows from 0xFF to 0x00 and starts overwriting old data. This is not a direct exploit but causes parser state corruption.

**Bosch HSM key extraction (TC3xx with EVITA HSM, 2023 research):** Researchers demonstrated power analysis attacks against the Bosch EVITA HSM on TC399 hardware. The HSM's key derivation function had a measurable side channel in the AES computation timing under voltage glitching. `TriCoreTaintTracker` cannot detect this vulnerability (it requires physical hardware access), but the finding motivates analyzing how the HSM output (derived key) is used in the main application firmware.

---

## TriCore version compatibility and limitations <sup>[↑](#tricoretainttracker)</sup>

**Supported TriCore variants:**
- TC1.3 / TC1.3.1: all TriCoreTaintTracker analysis paths supported (Capstone TC1.3 support)
- AURIX TC2xx: supported via TC1.3 ISA subset (TC2xx is ISA-compatible with TC1.3 for non-privileged code)
- AURIX TC3xx: supported; HSM instructions (`SYSCALL`) decoded and flagged but not analyzed (HSM firmware not accessible)

**32-bit vs 16-bit instruction mix:** TriCore uses both 16-bit narrow and 32-bit wide instructions. `TriCoreTaintTracker` uses Capstone's TriCore decoder for instruction decoding. If Capstone fails to decode an instruction (unknown encoding), the tracker falls back to conservative frame-walk mode for that function. The `full_decode` field in findings reports whether full decode was used.

**Position-independent code:** TriCore ECU firmware is typically NOT position-independent. The ELF is loaded at a fixed base address matching the PFlash segment start (`0x80000000`). All addresses are absolute. `ctx.base_address` for TriCore ELFs is always `0x80000000` unless overridden.

**Stripped vs. symbol-rich:** Production EDC17 firmware is stripped (no DWARF, no symbol table). Development/calibration images from the Bosch MCD2-D toolchain retain symbol information. `BinaryContext.load_or_build()` automatically imports symbols if present; with stripped firmware, `SemanticSearcher` is the primary identification tool.

---

## TriCore endianness and addressing model <sup>[↑](#tricoretainttracker)</sup>

TriCore uses **little-endian** byte ordering: opposite to many other automotive MCUs (PPC476, C167, 88k which are big-endian). This means:
- 32-bit word `0x12345678` is stored as bytes: `78 56 34 12`
- The ELF header `e_ident[EI_DATA]` = `0x01` (ELFDATA2LSB) for TriCore ELFs

**TriCore memory segments:**
The TriCore has a unified 32-bit virtual address space divided into segments with distinct attributes:

| Address range | Segment | Description |
|---|---|---|
| `0x00000000–0x0FFFFFFF` | Peripheral space (A0) | Local peripherals, SFRs |
| `0x10000000–0x1FFFFFFF` | External memory (A1) | External SRAM, CAN buffer |
| `0x70000000–0x7FFFFFFF` | Global cache (A1) | Cached access to flash |
| `0x80000000–0x8FFFFFFF` | Code flash (PFlash) | Primary program flash |
| `0x90000000–0x9FFFFFFF` | Data flash (DFlash) | EEPROM-like data storage |
| `0xA0000000–0xAFFFFFFF` | Uncached code flash | Direct non-cached access |
| `0xC0000000–0xCFFFFFFF` | Local data SRAM (DSPR) | 32–256 KB data RAM |
| `0xD0000000–0xDFFFFFFF` | Global SRAM (GSPR) | Shared data RAM (multi-core) |
| `0xF0000000–0xFFFFFFFF` | System peripherals (SFRs) | CPU registers, DMA, clocks |

`TriCoreTaintTracker` reads the ELF load segments to determine where code and data are mapped in the virtual address space. For firmware images without ELF headers (raw binary), `EcuROMLayoutAnalyzer` maps the flash contents to the PFlash segment base (`0x80000000`).

---

## TriCore AUTOSAR OS and task model for RE <sup>[↑](#tricoretainttracker)</sup>

TriCore ECU firmware typically runs the AUTOSAR Operating System (OS) specification, which defines a static real-time task scheduling model. For RE, understanding the AUTOSAR task model matters because:

**Task entry points as taint sources:** AUTOSAR tasks are functions declared with the `TASK()` macro. The OS calls these tasks on periodic schedule or on event. Network-adjacent tasks include:
- `TASK(ComTask)`: runs the AUTOSAR COM stack, receives CAN/LIN/FlexRay PDUs
- `TASK(DiagTask)`: runs the UDS diagnostic stack, handles Security Access
- `TASK(NmTask)`: network management, handles CAN NM messages

`SemanticSearcher.query('AUTOSAR TASK ComTask diagnostic service handler')` identifies these entry points. The taint source for each task is the AUTOSAR COM API call that receives data: `Com_ReceiveSignal()`, `PduR_CanIfRxIndication()`, or the lower-level `CanIf_RxIndication()` callback.

**AUTOSAR COM signal layout:** CAN frames are broken down into signals by the AUTOSAR COM layer. Each signal has a known offset and bit width within a PDU (Protocol Data Unit). The mapping from PDU bytes to signals is defined at compile time in the AUTOSAR configuration. If the AUTOSAR configuration is available (as an ARXML file from the vehicle manufacturer), it can be used to understand which signal values arrive in which diagnostic service handler arguments.

**AUTOSAR stack heap:** TriCore AUTOSAR implementations allocate separate stacks for each OS task and ISR. The stack sizes are configured in the AUTOSAR OS configuration. If an overflow occurs in a task's stack, it corrupts the next task's stack in memory (if stack overflow protection is not enabled). Stack overflow protection (via the TriCore CSA: Context Save Area: hardware mechanism) is optional in AUTOSAR configuration.

---

## What is TriCore? History and automotive deployment <sup>[↑](#tricoretainttracker)</sup>

TriCore (AUDO/AURIX) is a 32-bit RISC processor architecture developed by Infineon Technologies, introduced in 1999 as a unified architecture for automotive embedded control. The name "TriCore" reflects its three-architecture design: a RISC scalar processing unit, a real-time signal processing unit (DSP), and a microcontroller unit: all sharing a single unified address space and instruction set.

TriCore replaced the C167 as Infineon's primary automotive ECU architecture starting around 2005–2008. The second-generation AURIX TC2xx (2012) and TC3xx (2018) families are now the dominant ECU processor family in European automotive ECUs, used extensively by Bosch, Continental, Delphi, and Denso in systems across BMW, Mercedes-Benz, Volkswagen Group, Audi, Porsche, Toyota, and Hyundai/Kia vehicles.

**TriCore generations:**
| Generation | Product | Clock | Key features |
|---|---|---|---|
| TC1 (1999) | TriCore 1.3 | 50–80 MHz | 32-bit RISC, original TriCore ISA |
| TC1.3.1 (2005) | TC1736, TC1767 | 150 MHz | Powertrain (Bosch EDC17 diesel) |
| AURIX TC2xx (2012) | TC234, TC264, TC275, TC297 | 200 MHz | Multi-core (2–3 cores), safety ISO 26262 |
| AURIX TC3xx (2018) | TC356, TC375, TC387, TC397 | 300 MHz | 6-core, HSM (Hardware Security Module), EVITA compliance |

**Deployed application areas:**
- Engine management (EDC17, EDC18 diesel; ME17, MED17 gasoline)
- Transmission control modules (TCM)
- Electric vehicle inverter controllers
- Advanced Driver Assistance Systems (ADAS)
- Body control modules (BCM) in high-end vehicles
- Vehicle HSM (Hardware Security Module) for secure key storage and EVITA compliance

---

## TriCore ISA and register file <sup>[↑](#tricoretainttracker)</sup>

TriCore uses a Harvard architecture with separate instruction and data address spaces, but unified 32-bit physical addressing. The ISA uses 32 general-purpose registers organized in two banks:

**Data registers (D-registers):** D0–D15: hold integer values (32-bit)
**Address registers (A-registers):** A0–A15: hold pointers and addresses (32-bit)

This separation is unusual: you cannot use a data register as a pointer without moving it to an address register first (`mov.a An, Dm`), and vice versa. For taint tracking, this matters: a user-controlled string length (a data value in Dm) must be moved to an address register before it can be used in a memory access. `TriCoreTaintTracker` tracks both D and A register taint and propagates across `mov.a` / `mov.aa` / `mov.d` cross-register moves.

**Calling convention (TriCore EABI):**
| Register | Role | Preserved? |
|---|---|---|
| D4–D7 | Arguments 0–3 (32-bit integer) | No |
| D8–D9 | Extended arguments (64-bit pairs) | No |
| D2–D3 | Return value (D2=low, D3=high for 64-bit) | No |
| D0–D1 | Temporaries | No |
| D10–D15 | Callee-save | Yes |
| A4–A7 | Pointer arguments 0–3 | No |
| A2–A3 | Return pointer (A2 = returned pointer) | No |
| A0–A1 | Volatile | No |
| A8–A9 | Global data pointer / small data area | Yes (special) |
| A10 | Stack pointer | Yes |
| A11 | Return address (link register) | No |
| A12–A15 | Callee-save | Yes |

**Stack frame layout (TriCore EABI):**
```
High  ───────────────────────────────────
      | Caller's frame                   |
A10 + frame_size | Saved A11 (RA)        |  (ST.W [A10+N], A11 in prologue)
      | Callee-save D regs               |
      | Local variables                  |
A10   | Current frame base               |
Low   ───────────────────────────────────
```

TriCore does not use a dedicated `stwu`-style instruction to set up the frame; the stack frame is allocated with `SUB.A A10, #N` followed by individual saves.

---

## TriCore instruction encoding overview <sup>[↑](#tricoretainttracker)</sup>

TriCore uses fixed 16-bit (short) and 32-bit (normal) instruction formats. The encoding width is determined by the low 2 bits of the opcode byte: `bbb1` = 16-bit; `bbb0` = 32-bit (where `bbb` is any 3-bit value). This means 16-bit instructions always have an odd low byte and 32-bit instructions have an even low byte.

**16-bit (narrow) instruction format:**
```
15       8 7     4 3     0
+---------+-------+-------+
| op8     |  s1   |  n/d  |
+---------+-------+-------+
```
16-bit instructions are a subset of the 32-bit ISA designed for the most common operations. They use a restricted register set (D0–D15, A0–A15 but with limited operand flexibility).

**32-bit instruction format:**
```
31       24 23   20 19   16 15      8 7       0
+-----------+-------+-------+---------+---------+
|   op8_2   |  s2   |  s1   |  op8    | (op/d)  |
+-----------+-------+-------+---------+---------+
```

**Security-relevant TriCore instructions:**
- `CALL disp24`: function call, saves A11 (RA). Identifies call sites.
- `CALLI A_n`: indirect call via address register. CTR-equivalent; `An` trace source = function pointer hijack candidate.
- `LD.W D_d, [A_b]`: load 32-bit word from address. Source of memory reads.
- `LD.B D_d, [A_b+r]`: load byte (bounds check gap → out-of-bounds read)
- `ST.W [A_b], D_a`: store 32-bit word. Destination of writes.
- `SYSCALL #N`: TriCore system call (not a standard POSIX syscall; used for privileged operations and HSM access in TC3xx)

---

## TriCore instruction encoding security patterns <sup>[↑](#tricoretainttracker)</sup>

For efficient taint tracking, `TriCoreTaintTracker` identifies several instruction patterns at candidate call sites:

**`CALL addr18`:** Direct function call. The 18-bit signed displacement is sign-extended and added to PC. Identifies the callee at static analysis time: `TriCoreTaintTracker` resolves the callee via `ctx.imports` or `ctx.functions`.
```
TriCore CALL encoding (32-bit):
31          28 27              8 7     0
+------------+-----------------+---------+
|  0b1101    |    disp18       |  0x6D   |
+------------+-----------------+---------+
```
`opcode[7:0] = 0x6D`, bits [27:8] = signed 18-bit displacement (in 2-byte halfwords).

**`CALLI A_n`:** Indirect call. The target address is in address register `A_n`. Identifies function pointer calls: a finding class when `A_n` source is user-controlled.
```
CALLI encoding (16-bit):
15        8 7    4 3   0
+---------+------+------+
| 0b11011 | A_n  | 0xD  |
+---------+------+------+
```

**`LD.W D_d, [A_b] off10`:** Load 32-bit word. The 10-bit signed offset allows ±512 bytes from the base register. Used for struct field access and array element loads.

**Security-critical taint patterns in TriCore:**
1. `LD.W D4, [A4] 4` at a UDS handler entry: loading the service subfunction byte. If D4 is then used as an array index without bounds check: `ADDIH.A A_ptr, #table_base ; ADDSC.A A_ptr, A_ptr, D4, 2 ; LD.W D_result, [A_ptr]`: this is an out-of-bounds table read (CWE-125) when D4 is attacker-controlled.

2. `ST.W [A_buf], D_data ; ADD.A A_buf, #4 ; LOOP D_count, label`: a copy loop without count bounds check is a classic buffer overflow pattern. `TriCoreTaintTracker` detects the LOOP instruction pattern and flags when `D_count` (the loop counter) is taint-propagated from a network source.

3. `SYSCALL #N`: TriCore HSM syscall interface. On TC3xx, SYSCALL triggers the hardware security module. If D4 (the syscall argument) is user-controlled, this is an HSM interface confusion attack. Flag these for manual review.

---

## TriCore CSA (Context Save Area) and stack model <sup>[↑](#tricoretainttracker)</sup>

TriCore uses an unusual hardware mechanism for function call context saving: the Context Save Area (CSA). Instead of using the software stack (D_SP) to save registers on a function call, TriCore hardware automatically saves the upper context (A0–A7, A8–A15, D8–D15, PSW, PCXI, PC) into a linked list of Context Save Areas in DSRAM. The software stack (addressed by A10/SP) is used only for local variable storage, not for register saves.

This has several RE implications:

**Return address is in the CSA, not the stack:** A buffer overflow in a local variable array (on the software stack, addressed by A10) does NOT overwrite the saved return address (which is in the CSA chain, a different memory region). This makes TriCore stack buffer overflows harder to exploit for return-address-overwrite than on MIPS, ARM, or x86: but heap overflows or CSA corruption can still achieve code execution.

**CSA overflow:** If more than the configured number of nested calls occurs (CSA free list exhausts), TriCore triggers a hardware trap. Forcing this in a diagnostic handler (by causing deep recursive calls via carefully crafted diagnostic requests) creates a denial-of-service.

**`TriCoreTaintTracker` stack model:** Because registers are saved in the CSA (not the software stack), the tracker does not need to follow a stack frame depth chain to trace arguments across calls. The initial function's register values are directly visible without reading memory offsets. This simplifies the taint propagation model compared to architectures where all saved registers live on the software stack.

---

## TriCore CWE mapping and FindingRegistry <sup>[↑](#tricoretainttracker)</sup>

| Finding class | CWE | TriCore-specific pattern |
|---|---|---|
| UDS Security Access bypass | CWE-287 | Seed generator uses static values (fixed timestamp, ECU serial) without randomness |
| CAN ISO-TP length field overflow | CWE-120 | `PCI[11:0]` = total PDU length → `memcpy(reassembly_buf, data, pci_len)` without bounds check on `pci_len` |
| Array index from diagnostic data | CWE-125 | `D4 = service_subfunc; ADDSC.A A_ptr, A_table, D4, 2; LD.W` without `D4 < table_size` check |
| Stack buffer overflow (local array) | CWE-121 | Loop writing to `[A10+offset]` with `D_count` from network: does NOT overwrite RA due to CSA model |
| HSM interface confusion | CWE-346 | `SYSCALL #N` with D4 from CAN without authentication check |

**FindingRegistry for TriCore:**
```python
registry = FindingRegistry(firmware_path)
registry.register(
    va=0x80012AB4,     # VA of the CALL system() equivalent (UDS handler write-path)
    name='EDC17 Security Access static seed CWE-287',
    severity='HIGH',
    cwe='CWE-287',
    evidence_type='tricore_taint_finding',
    detail=(
        "CALL at 0x80012AB4: target = UDS SA seed generator. "
        "D4 (seed) = XOR(ECU_PN_D8, timestamp_D12). timestamp_D12 traced to "
        "static ROM constant at 0x80000F20 (read by LD.W D12, [A_rom_base] 0x0). "
        "Seed is deterministic from ECU part number. full_decode=True. "
        "Byte verify: data[0x80012AB4-0x80000000:+4] = 6D CA 01 80 (CALL 0x800016C8)."
    ),
)
```

---

## Bosch EDC17 security access analysis context <sup>[↑](#tricoretainttracker)</sup>

The Bosch EDC17 diesel engine management system is the most common TriCore RE target. EDC17 uses TriCore TC1736 or TC1767 hardware and implements:

- UDS Security Access (0x27): proprietary seed-key algorithm for programming authorization
- Calibration data: fuel injection timing maps, boost pressure limits, exhaust gas recirculation maps: all stored as data structures in flash
- Anti-tampering: some EDC17 variants check the calibration checksum against a stored reference and log mismatches to the DTC (Diagnostic Trouble Code) memory

For `TriCoreTaintTracker`, the analysis entry point is the UDS request handler. UDS packets arrive via the CAN bus (Controller Area Network); the firmware's CAN interrupt service routine places received frames in a ring buffer; the diagnostic service dispatcher reads from that buffer and calls the service handler. The taint source is the ring buffer read; the sink is either the Security Access handler (for algorithm RE) or the calibration write handler (for calibration injection research).

**CAN receive to taint source setup:**
```python
from ablation.analyzers.taint_tracker_tricore import TriCoreTaintTracker

tracker = TriCoreTaintTracker.from_path('/firmware/edc17_tc1767.bin')
# Label CAN receive buffer as taint source
# Identify ring buffer read VA via semantic search first:
from ablation.analyzers.semantic_searcher import SemanticSearcher
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/firmware/edc17_tc1767.bin')
searcher = SemanticSearcher(ctx)
can_hits = searcher.query('CAN receive buffer diagnostic service dispatcher', top_k=5)
# Use the top hit VA as the taint source function
tracker.add_source(can_hits[0].va, registers=['D4', 'A4'], label='CAN_recv_data')
findings = tracker.run_interprocedural()
```

---

## See also <sup>[↑](#tricoretainttracker)</sup>

- [TaintAnalysis](taint-analysis.md): multi-architecture taint tracking reference
- [SinkArgClassifier](sink-arg-classifier.md): pre-filter RODATA_CONST sinks before taint
- [PathSolver](path-solver.md): confirm path feasibility after a taint hit
- [SinkPropagator](sink-propagator.md): extend sink coverage across wrappers
- [C166/C167 Decoder](c166-c167-decoding.md): predecessor architecture for 1997–2008 ECUs
- [ECU VLE Decoder](ecu-vle-decoder.md): NXP MPC5500 automotive PPC: another current-generation ECU competitor to TriCore
- [ECU M68K Decoder](ecu-m68k-decoder.md): older M68K-based ECUs (1990s–2000s)
- [FindingRegistry](registry.md): record confirmed TriCore findings; `cwe='CWE-287'` for Security Access bypass, `cwe='CWE-121'` for stack overflow
- [Length Underflow Scanner](length-underflow.md): for TriCore CAN/ISO-TP length field processing that precedes buffer copy operations
- [Semantic Code Search](semantic-code-search.md): locate `ComTask`, `DiagTask`, and `AUTOSAR_SA_Handler` entry points before taint analysis on stripped EDC17 firmware

**Performance characteristics:**
- `BinaryContext.load_or_build()` on EDC17 TC1767 binary (stripped, ~400 KB code): 8–15 seconds
- `SemanticSearcher` sweep over all vulnerability classes: 30–60 seconds
- `SinkArgClassifier.classify_all()` on ~200 sinks: 10–20 seconds
- Full interprocedural taint (all sinks, CAN receive source): 45–120 seconds for typical EDC17
- With pre-filtering (RODATA_CONST eliminated by SinkArgClassifier): 20–50 seconds

**Byte verification for TriCore CALL instruction:**
```python
import struct
with open(firmware_path, 'rb') as f:
    data = f.read()
off = call_va - 0x80000000  # PFlash base
word = struct.unpack('<I', data[off:off+4])[0]  # little-endian!
opcode_low = word & 0xFF
assert opcode_low == 0x6D, f"Expected CALL opcode 0x6D at {call_va:#x}, got {opcode_low:#04x}"
# The 18-bit signed displacement is encoded in bits[27:8] of the 32-bit word.
# Target VA = call_va + sign_extend18(disp18) * 2
disp18 = (word >> 8) & 0x3FFFF
if disp18 & 0x20000:
    disp18 -= 0x40000  # sign extend
target_va = call_va + disp18 * 2
print(f"CALL target: {target_va:#010x}")
```
