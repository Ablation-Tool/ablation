# DeadSecurityCheckScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect unconditional branches that bypass security check chains.** CVE-2014-1266, the Apple GotoFail bug, was a single misplaced `goto fail;` that inserted an unconditional branch mid-sequence in a chain of TLS verification checks. All subsequent checks became unreachable dead code. The binary appeared to have security checks, but they never executed. `TaintTracker` traces data flow; no prior Ablation module checked whether security conditionals are reachable. `DeadSecurityCheckScanner` finds this structural pattern: an unconditional branch immediately following two or more `cmp`+conditional-branch pairs, leaving subsequent checks dead.

## Usage

```python
from ablation.analyzers.dead_security_check_scanner import DeadSecurityCheckScanner

scanner = DeadSecurityCheckScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = DeadSecurityCheckScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: DeadCheckFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the containing function |
| `func_name` | str | Demangled name or `sub_VA` if stripped |
| `uncond_branch_va` | int | VA of the misplaced unconditional branch instruction |
| `dead_check_va` | int | VA of the first dead instruction after the branch |
| `preceding_checks` | int | Number of conditional check pairs before the branch |
| `note` | str | Description of the pattern |

## Detection logic

The scanner uses a sliding window over function disassembly:

1. Find sequences of `cmp`/`test` + conditional branch pairs (at least 2 consecutive).
2. Check whether the next instruction after the sequence is an unconditional branch.
3. Check whether the instruction after the unconditional branch is another compare or conditional branch (the dead check).
4. If all conditions hold, emit a finding.

Covers x86-64 (`jmp`, `je`, `cmp`, `test`), ARM32/64 (`b`, `beq`, `bne`, `cmp`, `tst`), and MIPS (`j`, `beq`, `bne`).

## False positives

Not every unconditional branch after a check sequence is a GotoFail. Common false positives:
- Loop exit branches
- Switch-case dispatch jumps
- Tail call optimization

Verify each finding with `WindowAnalyzer.dump_text(func_va)` and confirm that the dead instruction is a genuine security check, not a loop or dispatch artifact.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** verify each finding manually. Cross-reference the function with `FindingRegistry` to determine whether it is an auth, crypto verification, or signature check function. A GotoFail in a crypto verification function is HIGH severity; in a logging function it is informational.

## See also

- [CFGBuilder](control-flow-graph-construction.md): full CFG analysis for more precise reachability
- [BinaryContext](binary-context.md): function disassembly
- [PreAuthExposure](preauth-exposure.md): route-level auth bypass analysis
