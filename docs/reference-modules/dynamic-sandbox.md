# Dynamic Sandbox

**File:** `ablation/analyzers/dynamic_sandbox.py`

Executes leaf functions in a Unicorn emulator with controlled register inputs and captures behavioral evidence that static analysis cannot produce.

---

## Why this exists

Two things were not possible before this module:

1. Distinguish branches in leaf functions without a running device. Static analysis produces a list of possible outcomes for a branchy leaf function but cannot say which one the binary selects for a given input. The sandbox executes the function directly so the real output is observed, not inferred.

2. Provide behavioral evidence for the Hypothesis Engine. The engine scores evidence by family: behavioral (strength 1.0), data_flow (0.9), structure (0.75), semantic (0.25). Before DynamicSandbox, the highest-strength evidence any automated analyzer could supply was data_flow. Behavioral evidence requires actual execution, so it was always a gap requiring a running device or a full emulated environment. DynamicSandbox fills that gap on leaf functions without either.

---

## Safety contract

The sandbox only executes functions that pass `LeafFunctionChecker`. A function is probe-safe if it has no calls to PLT stubs and no indirect calls outside the binary's load range. Four additional guards prevent runaway execution:

1. PLT stub detection aborts execution immediately on any PLT entry and returns a partial result.
2. A hard instruction-count timeout stops execution at 100,000 instructions.
3. A snapshot/restore cycle resets CPU registers and binary memory to a clean state between probe runs so consecutive probes do not interfere with each other.
4. A halt page at a fixed VA acts as a return address. Execution stops when the function returns rather than running off into unmapped memory.

---

## Usage

```python
from ablation.analyzers.dynamic_sandbox import DynamicSandbox, LeafFunctionChecker

# Verify function is safe to execute before probing
checker = LeafFunctionChecker.from_path('/path/to/binary')
if checker.is_leaf(va, ctx):
    sandbox = DynamicSandbox.from_path('/path/to/binary', arch='arm64')
    result = sandbox.run_function(va, args={'x0': 0x10, 'x1': 0x0})
    print(result)
```

### Multi-run behavioral fingerprinting

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

Each `SandboxResult.behavioral_signature()` is a compact string (`ret=0x1,writes=2,insns=47`) that identifies a run's behavior. Two results with the same signature exhibit the same output for the same input, so matching signatures across different binaries indicate structurally equivalent functions.

---

## Architecture support

| Arch | Status |
|:---|:---|
| arm64 / aarch64 | Full: argument registers x0–x7, return value x0 |
| x86_64 | Full: argument registers rdi/rsi/rdx/rcx/r8/r9, return value rax |
| la64, mips64 | Stub (architecture not yet wired to Unicorn backend) |

Both ELF and PE binaries are supported. PE binaries use the IAT range as the abort-hook boundary instead of the PLT range.

---

## API reference

| Call | Description |
|:---|:---|
| `DynamicSandbox.from_path(binary, arch)` | Load binary segments into Unicorn and create sandbox |
| `DynamicSandbox.from_context(ctx)` | Same, arch detected from BinaryContext |
| `sandbox.run_function(va, args, max_insns)` | Execute function at va with register arguments |
| `sandbox.probe_multiple(va, input_sets)` | Run the same function with multiple input sets; each run gets a clean restore |
| `LeafFunctionChecker.from_path(binary)` | Build checker from binary's PLT range |
| `checker.is_leaf(va, ctx)` | True if function has no PLT callees |
| `checker.check_report(va, ctx)` | Human-readable probe-safety report for va |
| `SandboxResult.behavioral_signature()` | Compact string identifying a run's behavior |

---

## SandboxResult fields

| Field | Description |
|:---|:---|
| `va` | Function start VA |
| `input_regs` | Register arguments passed in |
| `output_regs` | Register values captured after execution |
| `return_value` | x0 (arm64) or rax (x86_64) after execution |
| `executed_insns` | Instruction count for the run |
| `memory_writes` | List of (address, size, value) tuples from write hooks |
| `aborted` | True if execution stopped before return |
| `abort_reason` | Why execution stopped early (PLT stub address or timeout) |

---

## Hypothesis Engine integration

`DynamicProbeAdapter` wires the sandbox into the Hypothesis Engine's `probe_multiple` dispatch. When the engine schedules a `dynamic` probe, the adapter runs the function with four auto-generated input sets and returns an `EvidenceRecord` with family `behavioral`.

Evidence strength depends on how far execution got:

| Outcome | Strength |
|:---|:---|
| PLT call aborted the run | 0.40 (partial behavioral) |
| Multiple runs, outputs vary by input | 0.60 (clean but non-deterministic) |
| Multiple runs, consistent behavior observed | 0.75 (behavioral fingerprint confirmed) |

The adapter is registered automatically. Invoke it by scheduling a `dynamic` probe in a Hypothesis Engine session rather than calling DynamicSandbox directly in that context.
