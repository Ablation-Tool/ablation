# LoongArch64 ISA Support

Full taint-analysis, syscall labeling, and structural lifting support for LoongArch64 binaries: covering TencentOS 4.6 userspace, kernel modules, QEMU, OpenSSL, EDK2/UEFI, and GRUB2 EFI targets.

---

## Why this exists <sup>[↑](#loongarch64-isa-support)</sup>

1. **TencentOS 4.6 ships a LoongArch64 architecture across its full software stack: glibc, OpenSSL, QEMU, kernel modules, and EDK2/GRUB2 EFI images: none of which are supported by ARM64 or x86-64 analysis pipelines.** LoongArch64 uses a distinct ISA Loongson Technology, released 2021 with 32 general-purpose registers, a 4-wide issue pipeline, lp64 ABI $a0-$a7 args, and LASX/LSX vector extensions. Without dedicated instruction decoding and register-state modeling, taint propagation stalls at the first LoongArch-specific mnemonic: `amswap`, `ldgt`, `ld.d`, `pcaddu12i`, and produces no findings. `taint_tracker_loongarch64.py` provides full labeled-taint coverage for the lp64 ABI.

2. **Syscall analysis for LoongArch64 requires a platform-specific syscall table: Linux LoongArch uses a private syscall number space derived from `arch/loongarch/include/uapi/asm/unistd.h` that shares some NR_ constants with RISC-V but diverges on file I/O, memory management, and process control syscalls.** `syscall_loongarch64.py` provides a complete LoongArch64 Linux syscall table with syscall name, argument count, and annotated known-dangerous entries execve, openat with O_CREAT, mmap, mprotect for use during syscall-site taint tracking.

3. **The LoongArch64 CFG builder must handle the `beqz`/`bnez`/`blt`/`bge` branch instruction family with 26-bit PC-relative offsets and the `jirl`/`bl` call family with 28-bit offsets, these do not map directly to any ARM64 or x86-64 CFG patterns.** `cfg_loongarch64.py` and `insn_loongarch64.py` provide the ISA-native instruction model and CFG construction that `_lift_loongarch64()` in `BinaryLifter` and `taint_tracker_loongarch64.py` depend on.

---

## How it works <sup>[↑](#loongarch64-isa-support)</sup>

```mermaid
flowchart TD
    A(["LoongArch64TaintTracker.from_path(binary)"]):::input --> B["BinaryContext.load_or_build(binary)\nELF section map + PLT symbol table\nIdentify .text segment bounds"]:::primary
    B:::primary --> C["insn_loongarch64.from_loongarch_frame(code, va)\nDecode LoongArch64 instruction stream\nImm/Reg/Mem/Sym operands"]:::secondary
    C:::secondary --> D["cfg_loongarch64.build_cfg(insns)\nbb-level BFS over beqz/bnez/blt/bge branch edges\njirl/bl call edges → separate call graph\nProduces CFG[Block[Insn]]"]:::tertiary
    D:::tertiary --> E["LoongArch64TaintTracker.run() or run_interprocedural():\n_LA64State: lp64 ABI seed\n  $a0-$a7 = arg0-arg7 (call args)\n  $a0-$a1 = return value\nSources: recv/recvfrom/recvmsg/read/fgets/gets/fread\n  ($a0 = return value = tainted bytes)\nPropagation: ld.d/ld.w/ld.b (load), st.d/st.w (store)\n  addi.d/add.d/sub.d (arithmetic)\n  andi/ori/xori/slli/srli (bitwise · andi bounds taint range)\n  bl/jirl call → callee taint propagation (interprocedural)"]:::tertiary
    E:::tertiary --> F["Sinks: system/execve/execl/execvp/execle/execvpe\n  popen/strcpy/strcat/sprintf/vsprintf\n  snprintf/vsnprintf/memcpy/memmove/gets\n  → TaintFinding(severity, chain, source, sink, va)"]:::tertiary
    F:::tertiary --> G(["LoongArch64TaintTracker.report(findings) → str\nor findings list for FindingRegistry.register()"]):::output

    H(["syscall_loongarch64.label_syscall(nr) → str\nFull Linux LoongArch64 syscall table\n  nr=220 → execve\n  nr=56 → openat\n  nr=222 → mmap\n  nr=226 → mprotect\n  dangerous_syscalls: frozenset of annotated risky syscalls"]):::input

    I(["BinaryLifter(arch='la64').lift_function(va) → pseudo-C\n_lift_loongarch64 → _LA64State + _walk_ablation_cfg\n_make_la64_emit: calls resolved by PLT name\nloongarch64_max_not_min_scanner.py:\n  Scans for andi/ori with max-not-min integer patterns\n  (CVE-class integer truncation on LoongArch64)"]):::input
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
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

### Module inventory <sup>[↑](#loongarch64-isa-support)</sup>

| Module | Role |
|:---|:---|
| `taint_tracker_loongarch64.py` | Labeled-taint tracker: lp64 ABI, source-to-sink analysis, interprocedural depth control |
| `insn_loongarch64.py` | LoongArch64 instruction decoder: Imm/Reg/Mem/Sym operand model |
| `cfg_loongarch64.py` | CFG builder: beqz/bnez/blt/bge/jirl/bl edges |
| `analysis_loongarch64.py` | CFG-level fixpoint taint analysis |
| `isa_loongarch64.py` | ISA constant tables: register names, ABI mapping, calling convention |
| `loongarch_decoder.py` | Low-level binary decoder (v1) |
| `loongarch_decoder_v2.py` | Low-level binary decoder (v2): handles LASX/LSX vector extensions |
| `syscall_loongarch64.py` | Linux LoongArch64 syscall table with dangerous-syscall annotation |
| `dwarf_loongarch64.py` | DWARF CFI record parsing for LoongArch64 unwind tables |
| `loongarch64_max_not_min_scanner.py` | Standalone scanner: andi/ori integer-truncation patterns |
| `taint_tracker_loongarch64.py` | Labeled-taint: `Taintlabels, bound` model; `andi` zeros upper bits and bounds taint range |

---

## Usage <sup>[↑](#loongarch64-isa-support)</sup>

```python
from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker

# Intraprocedural scan
tracker = LoongArch64TaintTracker.from_path('/path/to/loongarch64.elf')
findings = tracker.run()
for f in findings:
    print(f"[{f.severity}] {f.source_name} → {f.sink_name} @ {f.sink_va:#x}")

# Interprocedural (depth-limited call-graph traversal)
chains = tracker.run_interprocedural(depth=4)

# Structural lifting via BinaryLifter
from ablation.analyzers.binary_lifter import BinaryLifter
lifter = BinaryLifter.from_path('/path/to/la64.elf', arch='la64')
print(lifter.lift_function(0x10430))

# Syscall labeling
from ablation.analyzers.syscall_loongarch64 import label_syscall, dangerous_syscalls
name = label_syscall(220)    # → 'execve'
risky = label_syscall(56)    # → 'openat'
is_dangerous = 220 in dangerous_syscalls  # → True
```

---

## Example output <sup>[↑](#loongarch64-isa-support)</sup>

The following illustrates the format for representative taint findings. Actual function names, virtual addresses, and call chains will reflect the specific binary.

```
[CRITICAL] <source-func> → execve @ <va>
  Chain: recv($a0) → addi.d $a2, $a0, 0 → bl strcpy → bl execve
  Taint: $a0 (recv return, <n> bytes max)
  Sink: execve (syscall nr=220) — direct RCE primitive

[HIGH] <source-func> → sprintf @ <va>
  Chain: fgets($a0) → ld.d $a1, $a0+0x18 → bl sprintf(fmt=$a1)
  Taint: $a0 (fgets input), bound=<bound-value>
  Sink: sprintf format-string argument — format-string candidate
```

---

## False positives <sup>[↑](#loongarch64-isa-support)</sup>

**`andi` instruction bounds the taint range: a tainted value masked with `andi $t0, $t0, 0xff` is reported with `bound=0xff`, which means it can only represent values 0-255.** This bound is used to gate out-of-bounds array index findings: a tainted byte masked to 0xff cannot index a buffer larger than 256 bytes with a resulting out-of-bounds write. If the finding is `buffer_overflow` via an `andi`-bounded index, verify that the destination buffer is at least 256 bytes before escalating.

**LoongArch64 binaries use `pcaddu12i` + `ld.d` pairs to load GOT entries, these look like tainted-memory loads to the tracker but are function pointer resolutions.** The tracker does not resolve GOT slots that resolve to function pointers as calls; they are tracked as pointer-tainted registers. If a taint chain terminates at an `ld.d` from a GOT offset, check whether the address is a function pointer from the import table before reporting as a sink.

---

## Pipeline position <sup>[↑](#loongarch64-isa-support)</sup>

**Before this module:** `BinaryContext.load_or_build()` for PLT symbol resolution. Confirm the binary is LoongArch64 ELF with `readelf -h binary | grep Machine` (should show `LoongArch`). For TencentOS targets, check `/media/cowboy/research/TencentOS/` for available images.

**After this module:** For `execve`/`system` sink findings: run `loongarch64_max_not_min_scanner.py` on the same binary to check for integer-truncation patterns in the taint path. For syscall-site findings: cross-reference with `syscall_loongarch64.label_syscall(nr)` to confirm the kernel interface.

---

## Reading findings <sup>[↑](#loongarch64-isa-support)</sup>

`scan_sources_to_sinks(ctx)` returns `List[TaintFindingLA64]`.

| Field | Type | Content |
|:---|:---|:---|
| `func_va` | `int` | VA of the function containing the sink call |
| `func_name` | `str` | Name of the function (from `ctx`) |
| `sink_va` | `int` | VA of the sink call instruction |
| `sink_name` | `str` | Sink function name for example `system`, `execve` |
| `tainted_args` | `List[str]` | Tainted argument register names at the call for example `['a0']` |
| `source_name` | `str` | Taint source label for example `recv`, `fgets` |
| `severity` | `str` | `'HIGH'` for all findings (default) |

---

## See also <sup>[↑](#loongarch64-isa-support)</sup>

- [LoongArch64 Syscall Labeling](loongarch-syscall-labeling.md): syscall table, dangerous-syscall set, and kernel-interface analysis
- [Binary Lifter](binary-lifter.md): `arch='la64'` structural lifting for LoongArch64 functions
- [Taint Analysis](taint-analysis.md): general labeled-taint model and CFG fixpoint analysis
