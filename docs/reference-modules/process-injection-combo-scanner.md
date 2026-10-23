# ProcessInjectionComboScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Flag the complete process injection toolkit at import level.** `SinkArgClassifier` classifies individual `VirtualAllocEx` or `WriteProcessMemory` call sites. No prior module checked for the *combination*. The full API triad together enables code injection into a foreign process: allocate memory in the target, write shellcode, then trigger execution. `ProcessInjectionComboScanner` checks whether all three capability groups are present as PLT imports and reports the matching ATT&CK technique. This runs in milliseconds on import data alone, before any disassembly.

## Usage

```python
from ablation.analyzers.process_injection_combo_scanner import ProcessInjectionComboScanner

scanner = ProcessInjectionComboScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = ProcessInjectionComboScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: InjectionFinding

| Field | Type | Description |
|-------|------|-------------|
| `technique` | str | Injection technique name |
| `attck_id` | str | ATT&CK T-ID |
| `matched_apis` | list[str] | Specific API names found in the binary |
| `severity` | str | Always `HIGH` |

## Technique coverage

| Technique | ATT&CK | Required APIs |
|-----------|--------|--------------|
| Classic DLL Injection | T1055.001 | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| PE Injection / Shellcode | T1055.002 | `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`/`ResumeThread` |
| NT Native Injection | T1055 | `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` |
| Process Hollowing | T1055.012 | `CreateProcessA`/`W`, `SuspendThread`, `WriteProcessMemory` |

All four groups are checked in a single scan pass.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- Mock context with classic triad: T1055.001 detected correctly.
- Mock context with only two of three APIs: no finding emitted.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** use `SinkPropagator` to find the call chain from the injection APIs back to user-controlled input. Use `ATTACKLabeler` to tag confirmed findings with the T-ID from `attck_id`.

## See also

- [SinkPropagator](sink-propagator.md): transitive call chain from injection APIs
- [ATTACKLabeler](attandck-labeling.md): ATT&CK technique tagging for findings
- [BinaryContext](binary-context.md): PLT import resolution
