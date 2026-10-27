<a id="dynamic-sandbox"></a>
# Dynamic Function Emulation

**File:** `ablation/analyzers/dynamic_sandbox.py`

Executes leaf functions in a Unicorn emulator with controlled register inputs and captures behavioral evidence that static analysis cannot produce.

---

## Why this exists <sup>[↑](#dynamic-sandbox)</sup>

Two things were not possible before this module:

1. Distinguish branches in leaf functions without a running device. Static analysis produces a list of possible outcomes for a branchy leaf function but cannot say which one the binary selects for a given input. The sandbox executes the function directly so the real output is observed, not inferred.

2. Provide behavioral evidence for the Hypothesis Engine. The engine scores evidence by family: behavioral strength 1.0, data_flow (0.9), structure (0.75), semantic (0.25). Before DynamicSandbox, the highest-strength evidence any automated analyzer could supply was data_flow. Behavioral evidence requires actual execution, so it was always a gap requiring a running device or a full emulated environment. DynamicSandbox fills that gap on leaf functions without either.

---

## Safety contract <sup>[↑](#dynamic-sandbox)</sup>

The sandbox only executes functions that pass `LeafFunctionChecker`. A function is probe-safe if it has no calls to PLT stubs and no indirect calls outside the binary's load range. Four additional guards prevent runaway execution:

1. PLT stub detection aborts execution immediately on any PLT entry and returns a partial result.
2. A hard instruction-count timeout stops execution at 100,000 instructions.
3. A snapshot/restore cycle resets CPU registers and binary memory to a clean state between probe runs so consecutive probes do not interfere with each other.
4. A halt page at a fixed VA acts as a return address. Execution stops when the function returns rather than running off into unmapped memory.

---

## Usage <sup>[↑](#dynamic-sandbox)</sup>

```python
from ablation.analyzers.dynamic_sandbox import DynamicSandbox, LeafFunctionChecker

# Verify function is safe to execute before probing
checker = LeafFunctionChecker.from_path('/path/to/binary')
if checker.is_leaf(va, ctx):
    sandbox = DynamicSandbox.from_path('/path/to/binary', arch='arm64')
    result = sandbox.run_function(va, args={'x0': 0x10, 'x1': 0x0})
    print(result)
```

### Multi-run behavioral fingerprinting <sup>[↑](#dynamic-sandbox)</sup>

```python
sandbox = DynamicSandbox.from_context(ctx)

input_sets = [
    {},
    {'x0': 0x1, 'x1': 0x1},
    {'x0': 0xFF, 'x1': 0x10},
    {'x0': 0xFFFF_FFFF, 'x1': 0x0},
]

results = sandbox.probe_multiple(va, input_sets)
for r in results:
    print(r.behavioral_signature())
```

Each `SandboxResult.behavioral_signature()` is a compact string `ret=0x1,writes=2,insns=47` that identifies a run's behavior. Two results with the same signature exhibit the same output for the same input, so matching signatures across different binaries indicate structurally equivalent functions.

---

## Architecture support <sup>[↑](#dynamic-sandbox)</sup>

| Arch | Status |
|:---|:---|
| arm64 / aarch64 | Full: argument registers x0–x7, return value x0 |
| x86_64 | Full: argument registers rdi/rsi/rdx/rcx/r8/r9, return value rax |
| la64, mips64 | Stub architecture not yet wired to Unicorn backend |

Both ELF and PE binaries are supported. PE binaries use the IAT range as the abort-hook boundary instead of the PLT range.

---

## API reference <sup>[↑](#dynamic-sandbox)</sup>

| Call | Description |
|:---|:---|
| `DynamicSandbox.from_pathbinary, arch` | Load binary segments into Unicorn and create sandbox |
| `DynamicSandbox.from_context(ctx)` | Same, arch detected from BinaryContext |
| `sandbox.run_functionva, args, max_insns` | Execute function at va with register arguments |
| `sandbox.probe_multipleva, input_sets` | Run the same function with multiple input sets; each run gets a clean restore |
| `LeafFunctionChecker.from_path(binary)` | Build checker from binary's PLT range |
| `checker.is_leafva, ctx` | True if function has no PLT callees |
| `checker.check_reportva, ctx` | Human-readable probe-safety report for va |
| `SandboxResult.behavioral_signature()` | Compact string identifying a run's behavior |

---

## SandboxResult fields <sup>[↑](#dynamic-sandbox)</sup>

| Field | Description |
|:---|:---|
| `va` | Function start VA |
| `input_regs` | Register arguments passed in |
| `output_regs` | Register values captured after execution |
| `return_value` | x0 (arm64) or rax (x86_64) after execution |
| `executed_insns` | Instruction count for the run |
| `memory_writes` | List of address, size, value tuples from write hooks |
| `aborted` | True if execution stopped before return |
| `abort_reason` | Why execution stopped early PLT stub address or timeout |

---

## Hypothesis Engine integration <sup>[↑](#dynamic-sandbox)</sup>

`DynamicProbeAdapter` wires the sandbox into the Hypothesis Engine's `probe_multiple` dispatch. When the engine schedules a `dynamic` probe, the adapter runs the function with four auto-generated input sets and returns an `EvidenceRecord` with family `behavioral`.

Evidence strength depends on how far execution got:

| Outcome | Strength |
|:---|:---|
| PLT call aborted the run | 0.40 partial behavioral |
| Multiple runs, outputs vary by input | 0.60 clean but non-deterministic |
| Multiple runs, consistent behavior observed | 0.75 behavioral fingerprint confirmed |

The adapter is registered automatically. Invoke it by scheduling a `dynamic` probe in a Hypothesis Engine session rather than calling DynamicSandbox directly in that context.

---

## How it works <sup>[↑](#dynamic-sandbox)</sup>

Parses the runtime-specific binary format APK, DEX, `.mpy`, BEAM, Go ELF to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Example output <sup>[↑](#dynamic-sandbox)</sup>

```
[HIGH] DANGEROUS_CALL   Runtime.exec() in com.example.CommandHandler:42
  detail: argument constructed from user-supplied intent extra
  evidence: exec(getIntent().getStringExtra("cmd"))

[MEDIUM] UNTRUSTED_INPUT   eval() in main.js:118
  detail: JSON.parse result passed directly to eval
```

---

## False positives <sup>[↑](#dynamic-sandbox)</sup>

Standard library calls that resemble dangerous patterns for example `exec` used for shell completions, `eval` used for template rendering with static input are not findings. Confirm that the argument reaching the dangerous call is user-controlled before escalating. Obfuscated code Garble-compiled Go, ProGuard-stripped Android produces incomplete call graphs: findings from incomplete graphs carry lower confidence.

---

## Pipeline position <sup>[↑](#dynamic-sandbox)</sup>

**Before this module:** Confirm the target binary format APK, `.mpy`, BEAM, Go ELF before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading output <sup>[↑](#dynamic-sandbox)</sup>

`DynamicSandbox.from_context(ctx).probeva, input_regs` returns a `SandboxResult`:

| Attribute | Content |
|:---|:---|
| `va` | Entry VA of the probed function |
| `input_regs` | `Dict[str, int]`: register values supplied at entry |
| `output_regs` | `Dict[str, int]`: register values on return |
| `return_value` | Return value (`rax`/`r0`) as an integer, or `None` if aborted |
| `executed_insns` | Number of instructions executed before return or abort |
| `memory_writes` | `List[Tuple[address, size, value_bytes]]`: all memory stores during execution |
| `aborted` | `True` if execution was stopped before returning timeout or unsafe access |
| `abort_reason` | Reason string when `aborted=True` |
| `arch` | Architecture of the probe run for example `'arm64'`, `'x86_64'` |

---

## See also <sup>[↑](#dynamic-sandbox)</sup>

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
