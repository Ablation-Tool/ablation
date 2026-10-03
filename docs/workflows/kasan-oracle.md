# KASAN-Oracle Workflow

Scan a KASAN debug kernel build first to identify candidate functions, then verify
each candidate in the stripped production build.

**Why this works:** `CONFIG_KASAN=y` lowers the compiler's optimization threshold.
Result registers stay live longer, stack slots don't get folded, and data flows that
the production optimizer collapses into a single inline remain as explicit call sequences.
The scanner finds more true positives in the debug build. These are not KASAN artifacts
-- they are real code paths the optimizer hid in production.

**Discovered during:** TencentOS 6.6.119 LoongArch64 kernel module analysis.
14 `LA64MaxNotMinScanner` hits in KASAN build; 11 confirmed in production (3 ELIMINATED
due to KASAN-specific codegen divergence).

---

## Prerequisites

Two builds of the same kernel tree:

| Build | Path | Has symbols | KASAN |
|---|---|---|---|
| KASAN debug | `vmlinuz.elf` or debug `.ko` | yes (System.map) | yes |
| Production stripped | production `.ko` | no | no |

Both builds must come from the same source tree. Version mismatch causes function
layout divergence that breaks verification.

---

## Step 1 — Suppress KASAN ghost calls (debug build)

Before scanning the debug build, suppress KASAN/KCOV instrumentation calls.
Without this, every function has a `bl __asan_load8` ghost call that produces
thousands of false scanner hits.

```python
from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2

# Extract KASAN/KCOV VAs from System.map
dec = LoongArchDecoderV2.from_system_map("/boot/System.map-6.6.119+debug")
# dec now tags all __asan_* / __kcov_* BL calls as is_instrumentation=True
```

The `from_system_map()` method parses the System.map format (`<hex_va> <type> <name>`)
and builds the instrumentation VA set automatically. No manual enumeration needed.

For individual `.ko` modules, pass the module's own System.map if available, or
pre-load the KASAN symbol set from the full kernel System.map.

---

## Step 2 — Scan the KASAN debug build

```python
from ablation.analyzers.la64_max_not_min_scanner import LA64MaxNotMinScanner

# For .ko modules (ET_REL): scanner uses section-relative VAs automatically
scanner = LA64MaxNotMinScanner(ko_path_debug)
scanner.decoder = dec           # inject KASAN-aware decoder
hits = scanner.scan()
print(scanner.report(hits))

# For vmlinux: inject System.map symbols for PLT-less call resolution
from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker
tt = LoongArch64TaintTracker.from_system_map(vmlinux_debug_path, system_map_path)
findings = tt.run_interprocedural()
```

Record all hit function names and their file offsets. These are the candidates.

---

## Step 3 — Verify each candidate in the stripped production build

For each candidate function name from Step 2:

1. Locate the corresponding function in the production binary by name (System.map or
   exported symbol) or by structural similarity if stripped.
2. Scan or trace the production function manually.
3. Classify each hit against the KASAN-build hit:

| Outcome | Meaning |
|---|---|
| Production hit: same pattern | **CONFIRMED** — real finding |
| Production hit: different pattern | Verify independently; may be a distinct issue |
| Production: pattern absent | **ELIMINATED** — KASAN codegen artifact |
| Production: function absent | Module not included in production kernel |

```python
# Quick production-build rescan for a specific function VA
scanner_prod = LA64MaxNotMinScanner(ko_path_production)
hits_prod = scanner_prod.scan_function(func_va=production_va)
```

---

## Step 4 — Record the KASAN/production split

Document which hits survived verification and which did not. The split is informative:
a high elimination rate (>50%) signals KASAN-only optimization behavior, not scanner noise.

```
KASAN build:       14 hits across 13 modules
Production:        11 confirmed, 3 ELIMINATED
  ELIMINATED:      mlxsw_i2c (data-path diff), iwlwifi (ACPI path), rpcrdma (codegen diff)
  Elimination rate: 21%
```

---

## When to use this workflow

- Kernel module analysis where the production `.ko` is stripped and short (< 200 functions)
- Any target where a debug build with KASAN is available alongside the production build
- When a production-only scan yields zero hits despite known-buggy code patterns (KASAN
  build can confirm whether optimizer folded the sequence)

Do not use this workflow when only one build is available. In that case, scan the available
build directly and note the optimization level in the finding.

---

## KASAN codegen patterns to recognize and discard

These appear in KASAN builds but are not real findings:

| Pattern | Cause | Action |
|---|---|---|
| `lu12i.w + slti` before every load | KASAN shadow address computation (`ptr >> 3 + offset`) | Discard; mark as `kasan_shadow` via LoongArchDecoderV2 |
| `bl 0x<asan_load8_va>` everywhere | KASAN bounds check before every 8-byte load | Ghost call; is_instrumentation=True |
| `bl 0x<kcov_trace_pc_va>` at function entry | KCOV coverage tracing | Ghost call; is_instrumentation=True |
| Function appears only in KASAN module | Module compiled only for debug tree | Check production kernel config |

---

## Related

- `docs/module-reference/loongarch64.md` — LoongArchDecoderV2 KASAN ghost-call suppression
- `docs/module-reference/loongarch64.md` — LA64MaxNotMinScanner, including ET_REL mode and Vec-growth FP class
- `docs/module-reference/kernel-drivers.md` — ET_REL `.ko` analysis, `.rela.text` relocations
