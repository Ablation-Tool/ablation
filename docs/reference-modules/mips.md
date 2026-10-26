# MIPS32TaintTracker

Taint analysis, sink classification, structural lifting, and semantic search across MIPS-32/64 big-endian and little-endian, nanoMIPS, and RouterOS embedded firmware targets.

---

## Why this exists <sup>[↑](#mips32tainttracker)</sup>

1. MIPS-32 big-endian is the dominant ISA for consumer routing firmware. Mikrotik RouterOS, older Cisco IOS images, and embedded HTTP/SNMP stacks ship as MIPS-32 BE ELF. The architecture's load-delay slot makes naive taint propagation incorrect: the instruction immediately after a branch executes before the branch takes effect, so a linear-order tracker produces false results for any register written in a delay slot. `MIPS32TaintTracker` processes delay slots as part of the preceding branch, matching the hardware execution model.

2. MIPS sink classification requires a platform-specific approach. `sprintf` argument position differs by ABI: MIPS32 O32 puts the format in `$a0`; MIPS64 N64 uses `$a0`-`$a7` for all arguments. RouterOS uses a custom allocator whose functions are not in the standard PLT. `SinkArgClassifierMIPS` extends the generic classifier with MIPS-specific argument register slots and RouterOS-specific allocation sink signatures.

3. nanoMIPS is a compressed ISA used in MIPS I7200 and P-class cores for code-density-optimized embedded targets. It is not MIPS16e; it requires a distinct decoder. `taint_tracker_nanomips.py` and `nanomips_decoder.py` provide the instruction model and taint analysis for nanoMIPS binaries, preventing misidentification of 16-bit opcodes as MIPS32 instructions.

---

## How it works <sup>[↑](#mips32tainttracker)</sup>

```mermaid
flowchart TD
    A(["MIPS32TaintTracker.from_path(binary)"]):::input --> B["BinaryContext.load_or_build(binary)\nELF section map + PLT (MIPS-specific .dynamic)\n.reginfo section → GP base address"]:::primary
    B:::primary --> C["insn_mips.from_capstone(code, va)\nDecode MIPS32/64 instruction stream\nDelay-slot awareness: branch insn carries next-insn operand"]:::secondary
    C:::secondary --> D["cfg_mips.build_cfg(insns)\nBranch: beq/bne/bltz/bgtz/j/jal\nDelay slot resolved per branch\nCall edges via jal/jalr (PLT targets labeled)"]:::tertiary
    D:::tertiary --> E["MIPS32TaintTracker.run():\n_MIPSState: O32 ABI seed\n  $a0-$a3 = arg0-arg3\n  $v0/$v1 = return values\n  $t0-$t9 = caller-saved temps\nSources: recv/recvfrom/read/fgets/gets/fread\n  ($v0 = return value = tainted)\nPropagation: lw/lb/lh/lbu (load)\n  sw/sb (store)\n  add/addu/sub (arithmetic)\n  and/or/xor/sll/srl (bitwise)\n  move/lui/ori (immediate/move)"]:::tertiary
    E:::tertiary --> F(["Sinks: system/execve/execl/execvp\n  popen/strcpy/sprintf/memcpy\n  strcat/snprintf (MIPS PLT names)\n  → TaintFinding(severity, source, sink, chain, va)"]):::output

    G(["MIPS64TaintTracker.from_path(binary)"]):::input --> H(["Same pipeline; N64 ABI:\n  $a0-$a7 = arg0-arg7 (8 regs)\n  $v0 = return\n  64-bit register width; ld/sd instead of lw/sw"]):::output

    I(["NanoMIPSTaintTracker.from_path(binary)"]):::input --> J(["nanomips_decoder.py: 16/32/48-bit variable-length encoding\nLinear walk + call graph construction\nO32 ABI (same as MIPS32)\nNo delay slots in nanoMIPS"]):::output

    K(["SinkArgClassifierMIPS.from_path(elf)"]):::input --> L(["classify_all():\nFor each system/exec/str*/sprintf call site:\n  RODATA_CONST: format arg is .rodata string → not exploitable\n  SNPRINTF_RODATA: snprintf format is .rodata → not exploitable\n  ARG_PROPAGATED: format arg from $a0-$a3 caller arg → TAINT\n  UNKNOWN: can't determine statically → TAINT\nEliminate RODATA_CONST before TaintTracker to reduce FPs"]):::output

    M(["mips_analyzer.py (modules/)"]):::input --> N(["MIPSAnalyzer.analyze(binary, arch='mips32'):\nIntegrates BinaryContext + SinkArgClassifierMIPS\n+ MIPS32TaintTracker\nFull findings report for RouterOS / embedded MIPS targets"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
    linkStyle 8 stroke:#2e7d32,stroke-width:3px
```

### Module inventory <sup>[↑](#mips32tainttracker)</sup>

| Module | Role |
|:---|:---|
| `taint_tracker_mips.py` | MIPS-32 labeled-taint tracker; delay-slot-aware; O32 ABI; RouterOS targets |
| `taint_tracker_mips64.py` | MIPS-64 labeled-taint tracker; N64 ABI |
| `taint_tracker_mips_labeled.py` | TCL3-qualified labeled-taint variant; used in coverage gate scope |
| `taint_tracker_nanomips.py` | nanoMIPS labeled-taint tracker; 16/32/48-bit variable-length encoding |
| `insn_mips.py` | MIPS-32/64 instruction decoder with delay-slot model |
| `cfg_mips.py` | MIPS CFG builder: branch/delay-slot edges, JAL/JALR calls |
| `isa_mips.py` | ISA constant tables: register names, ABI modes, calling convention |
| `analysis_mips.py` | CFG fixpoint analysis for labeled taint |
| `nanomips_decoder.py` | nanoMIPS binary decoder: variable-length instruction parsing |
| `sink_arg_classifier_mips.py` | MIPS-specific sink argument classification RODATA_CONST / ARG_PROPAGATED / UNKNOWN |
| `modules/mips_analyzer.py` | Module-level orchestrator for MIPS firmware RE targets |

---

## Usage <sup>[↑](#mips32tainttracker)</sup>

```python
from ablation.analyzers.taint_tracker_mips import MIPS32TaintTracker

# MIPS32TaintTracker
tracker = MIPS32TaintTracker.from_path('/path/to/mips32.elf')
findings = tracker.run()
for f in findings:
    print(f"{f.source_name} → {f.sink_name} @ {f.sink_va:#x}")

# MIPS32TaintTracker
chains = tracker.run_interprocedural(depth=4)

# MIPS32TaintTracker
from ablation.analyzers.taint_tracker_mips64 import MIPS64TaintTracker
tracker64 = MIPS64TaintTracker.from_path('/path/to/mips64.elf')
findings = tracker64.run()

# MIPS32TaintTracker
from ablation.analyzers.sink_arg_classifier_mips import SinkArgClassifierMIPS
clf = SinkArgClassifierMIPS.from_path('/path/to/mips32.elf')
classified = clf.classify_all()
# MIPS32TaintTracker
for va, classification in classified.items():
    if classification not in ('RODATA_CONST', 'SNPRINTF_RODATA'):
        print(f"{va:#x}: {classification} - run taint tracker")

# MIPS32TaintTracker
from ablation.analyzers.binary_lifter import BinaryLifter
lifter = BinaryLifter.from_path('/path/to/mips32.elf', arch='mips32')
print(lifter.lift_function(0x400a00))

# MIPS32TaintTracker
lifter_el = BinaryLifter.from_path('/path/to/mipsel.elf', arch='mips32el')
print(lifter_el.lift_function(0x400a00))
```

---

## Example output <sup>[↑](#mips32tainttracker)</sup>

The following illustrates the format for representative taint findings. Actual function names, addresses, and call chains reflect the specific binary.

```
[CRITICAL] recv → system @ <va>
  Chain: recv($v0) → lw $a0, sp+0x1c → jal system
  Taint: $v0 (recv return, unbound)
  Sink: system - shell injection via unvalidated recv buffer

[HIGH] fgets → sprintf @ <va>
  Chain: fgets($v0) → move $a1, $v0 → jal sprintf($a0=<fmt>, $a1=<tainted>)
  Taint: $v0 (fgets input), $a1 propagated
  Sink: sprintf argument-1 - format-string or buffer overflow candidate

SinkArgClassifier:
  <va>: RODATA_CONST (format from .rodata - not a finding)
  <va>: ARG_PROPAGATED ($a0 from caller) - run taint tracker
  <va>: UNKNOWN - run taint tracker
```

---

## False positives <sup>[↑](#mips32tainttracker)</sup>

**MIPS delay slots in tainted branches produce apparent taint flows that are not real.** When a branch instruction `beq $t0, $zero, target` has a tainted register in the condition, the delay slot's instruction executes regardless of branch direction. A taint sink in the delay slot appears to execute on both branch paths, but it only executes once before the branch takes effect. The tracker models this correctly, but output that shows the delay slot instruction as a taint step may be confusing, it is the branch pre-condition, not a conditional write.

**`SinkArgClassifierMIPS` marks RouterOS custom allocator calls as `UNKNOWN` because they are not in the standard PLT.** RouterOS uses `fast_malloc`/`fast_free` family functions that are not exported or present in standard glibc PLT slots. `SinkArgClassifier` cannot determine their argument positions and marks them `UNKNOWN`. Run `SemanticSearcher.query("allocation function MIPS")` to identify them before classification.

---

## Pipeline position <sup>[↑](#mips32tainttracker)</sup>

**Before this module:** Run `SinkArgClassifierMIPS.classify_all()` to eliminate `RODATA_CONST` and `SNPRINTF_RODATA` sites, this typically reduces TaintTracker input by 40-60% on firmware binaries. For little-endian MIPS (mipsel), specify `arch='mips32el'` or `arch='mips64el'` in `BinaryLifter.from_path()`.

**After this module:** Feed confirmed findings into `FindingRegistry.register()` and write them to `re/<vendor>/<target>_re.py`.

---

## Reading findings <sup>[↑](#mips32tainttracker)</sup>

`MIPS32TaintTracker.from_context(ctx).scan()` returns `List[TaintFinding32Mips]`.

| Field | Type | Content |
|:---|:---|:---|
| `binary` | `str` | Binary path |
| `func_va` | `int` | VA of the function containing the sink call |
| `func_name` | `str` | Name of the function (from `ctx`) |
| `sink_va` | `int` | VA of the sink call instruction |
| `sink_name` | `str` | Sink function name for example `system`, `sprintf` |
| `tainted_args` | `List[int]` | 0-indexed argument positions that are tainted at the call |
| `source_name` | `str` | Taint source label for example `recv`, `read` |

---

## See also <sup>[↑](#mips32tainttracker)</sup>

- [Binary Lifter](binary-lifter.md): `arch='mips32'`/`'mips64'`/`'nanomips'` structural lifting
- [Sink Arg Classifier](sink-arg-classifier.md): generic sink classification; MIPS variant extends it
- [Taint Analysis](taint-analysis.md): labeled-taint model and CFG fixpoint analysis
- [MIPS Analyzer](mips-analyzer.md): module-level orchestrator for MIPS firmware RE
