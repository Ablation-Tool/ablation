<a id="alphatainttracker"></a>
# Alpha AXP Decompilation & Taint Analysis

Recover Alpha ECOFF function logic with CFG/IR-backed pseudo-C, scan direct exec-class calls, and propagate taint across basic blocks. The implemented parser is specifically for Tru64/OSF1-style Alpha ECOFF; generic Alpha ELF support is not provided by this path.

## IR-backed pseudo-C

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/alpha-ecoff-binary', arch='alpha')
print(lifter.lift_function_ir(0x120001000, annotate_structs=True))
```

The Alpha route parses ECOFF sections and GP state, builds a CFG with `AlphaCFGBuilder`, lifts with `AlphaIRLifter`, optionally runs structure-layout analysis, and emits with `PseudoCEmitter`. `alpha_axp` and `axp` are accepted architecture aliases.

`lift_function_ir()` catches loading and lifting errors and returns a diagnostic comment. Check the output before treating it as a successful lift. Pseudo-C expressions and inferred structures remain approximations.

## Exec-call scanning

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner

scanner = AlphaEcoffScanner.from_path('/path/to/alpha-ecoff-binary')
findings = scanner.scan()
print(scanner.report(findings))
```

`AlphaEcoffScanner` parses ECOFF directly without Capstone or LIEF. It scans direct BSR calls to recognized execution sinks and can perform a limited backward argument trace with `trace_arg()`. This is a fast candidate-discovery pass, not decompilation.

## CFG-fixpoint taint analysis

```python
from ablation.analyzers.taint_tracker_alpha import AlphaTaintTracker

tracker = AlphaTaintTracker.from_path('/path/to/alpha-ecoff-binary')
findings = tracker.scan_function(0x120001000)
all_findings = tracker.run_interprocedural(depth=3)
```

By default, `scan_function()` seeds argument registers `r16`–`r21` as tainted, builds a CFG, joins labels at block merges, and reports direct exec-class sink calls with tainted arguments. `run_interprocedural()` iterates return-value propagation up to `depth` rounds and uses symbols or heuristic function candidates.

## Alpha details that affect analysis

Alpha instructions are fixed-width 32-bit instructions. Direct BSR targets are PC-relative, `r26` is the return-address register, and `r29` is the global pointer used by ECOFF code. The ECOFF optional header supplies the GP value used to interpret GP-relative references.

The decoder models instructions from multiple Alpha generations, including byte/word operations introduced after the earliest 21064 implementations. The marketing names 21064, 21164, and 21264 identify hardware generations; they are not separate file formats or separate decompiler APIs.

## Limitations

- This page's loading and IR path is ECOFF-specific. Do not advertise or expect transparent Linux Alpha ELF support.
- Direct BSR calls are much easier to resolve than computed calls. Missing symbols and GP/TOC-like address recovery can hide sink names.
- Initial argument taint is conservative and does not establish attacker reachability.
- CFG merging favors retaining taint, so findings require path and sanitization review.
- IR output is not original C and should be checked against the decoded Alpha instructions.

## Related workflows

- [Native Binary Lifting](binary-lifter.md)
- [Intermediate Representation](binary-lifting.md)
