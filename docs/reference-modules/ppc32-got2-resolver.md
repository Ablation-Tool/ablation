<a id="ppc32got2resolver"></a>
# PowerPC Call Recovery

Resolve PowerPC indirect calls and PLT references, and identify vector-heavy functions through AltiVec/VMX instruction density.

**Files:** `modules/ppc32_got2_resolver.py` · `ablation/analyzers/ppc32_plt_tracer.py` · `ablation/analyzers/ppc64_vmx_density.py`

---

## Why call recovery and density profiling belong together

Stripped PowerPC binaries can hide both the destination of a call and the role of a function. GOT2 and PLT recovery restore selected call relationships; VMX density supplies an independent hint about vector-intensive code. These are different evidence sources that help a user choose functions for closer review.

The tools are building blocks rather than a single vulnerability scanner. Resolver improvements can add supported address idioms, PLT analysis can adapt to another linker layout, and density profiling can remain a lightweight triage pass. None assigns a target to a genuinely dynamic branch without evidence or treats a vector-heavy label as an algorithm or security verdict.

## PPC32 GOT2 indirect-call resolution

Position-independent PPC32 code can load a GOT2-relative target into a register and branch through CTR with `BCTRL`. A linear call scanner sees the branch but not its destination. `PPC32GOT2Resolver` traces the register setup and resolves supported targets into concrete names and addresses.

Use `from_path()` for an ELF binary:

```python
from modules.ppc32_got2_resolver import PPC32GOT2Resolver

resolver = PPC32GOT2Resolver.from_path('/path/to/ppc32-binary')
result = resolver.resolve()
print(result.report())
print(result.stats())

for call in result.resolved:
    print(hex(call.bctrl_va), call.kind, call.name, hex(call.target))
```

`resolve()` accepts an optional function-start list to constrain analysis. `resolve_data_load()` and `resolve_data_loads()` recover data references for annotation. `export_jsonl(result, path)` writes machine-readable results.

### Result interpretation

- `GOT2ResolvedCall` includes `bctrl_va`, `kind`, `target`, `name`, `r30`, `disp`, and `entry_va`.
- `GOT2UnresolvedCall` includes `bctrl_va` and a `reason` such as dynamic dispatch or missing register setup.
- `targets_for(bctrl_va)` returns targets for one site; `by_target()` groups results by destination.

Dynamic or computed branches are genuine indirect dispatch sites, not parser failures. Resolve them with runtime evidence or broader control-flow analysis rather than assigning a guessed target.

## PPC32 PLT tracing

`PPC32PLTTracer` maps imported functions to their callers and helps reconstruct PLT stubs and cross-references:

```python
from ablation.analyzers.ppc32_plt_tracer import PPC32PLTTracer

tracer = PPC32PLTTracer.from_path('/path/to/ppc32-binary')
for symbol in tracer.elf().dangerous_imports():
    sites = tracer.find_callers(symbol)
    print(tracer.report(sites, symbol))
```

`PPC32ELF` also exposes all imports, exports, sections, 32-bit reads, disassembly, direct callers, `BCTRL` sites, and PLT slot lookup. Confirm relocations and stub layout for the specific linker output before merging recovered names into another context.

## AltiVec/VMX density profiling

`VMXDensityScanner` estimates the proportion of VMX instructions per function on big-endian PPC32/PPC64 code. It is useful for prioritizing math, media, physics, rendering, and signal-processing routines without relying on symbols.

```python
from ablation.analyzers.ppc64_vmx_density import VMXDensityScanner

scanner = VMXDensityScanner.from_context(ctx)
results = scanner.scan(threshold=5)
print(scanner.report(results))

for result in results:
    if result.density >= 0.15:
        print(hex(result.va), result.label, result.fmt(ctx.name))
```

Density is `vmx_count / total_insns`. Labels range from `vector_trace` through `vector_light`, `vector_math`, and `vector_heavy`. High density is a heuristic, not proof of function role: short functions and unrelated vectorized code can produce misleading labels.

## Limitations

- GOT2 resolution depends on supported register-setup patterns and valid ELF section/symbol information. Obfuscation and nonstandard loaders require manual work.
- `BCTR`, computed `BCTRL`, vtables, and callbacks may remain unresolved even when the binary is valid.
- PLT layouts differ across linkers and hardening modes; verify recovered stubs against relocation entries.
- VMX detection uses instruction encodings and density, not algorithm identification or vulnerability evidence.

## See also

- [Data-Flow Taint Analysis](taint-analysis.md): confirms attacker-controlled flow after call recovery.
- [Analysis Context & Caching](on-demand-analysis.md): stores recovered names and cross-references.
- [Semantic Code Search](semantic-code-search.md): prioritizes functions for deeper review.
