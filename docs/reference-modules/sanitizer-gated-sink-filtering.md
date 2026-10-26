# Sanitizer-Gated Sink Filtering

Post-process `ARG_PROPAGATED` `SinkArgClassifier` results to detect sanitizer-validated exec sinks: automatically reclassifying sites where a shell-safe allowlist validator is called on the argument before the exec sink with a conditional branch on the return value, reducing the manual triage burden from 30–60 minutes per `ARG_PROPAGATED` site to a single automated pass.

---

## Why this exists

1. **Every `ARG_PROPAGATED` result from `SinkArgClassifier` requires manual disassembly to determine whether the argument passes through a shell-safe validator before reaching the exec sink: a 30–60 minute task per site on a stripped binary.** `SinkSanitizerFilter` automates this: it pairs `SanitizerDetector`'s behavioral signature matching with backward analysis of the exec sink's argument path, identifying whether a confirmed shell-safe function is called on the same argument and whether a conditional branch on its return value guards the exec sink.

2. **Three structural conditions must all be true for a site to be reclassified as `SANITIZER_VALIDATED`:** (1) A `SHELL_SAFE` function (detected by `SanitizerDetector`) is called on the same argument as the exec sink within `_SANITIZER_SCAN_WINDOW` instructions before the sink; (2) the sanitizer's return value is used in a conditional branch `test eax, eax / jz <error>`; and (3) the conditional branch's false edge leads to an error path, not to the exec sink. All three conditions together mean that the exec sink is unreachable without passing the shell-safe allowlist check.

3. `SinkSanitizerFilter.apply()` modifies the `SinkClassification` list in-place: `ARG_PROPAGATED` sites that pass all three conditions are upgraded to `SANITIZER_VALIDATED` and removed from the taint analysis queue. The remaining `ARG_PROPAGATED` sites are the ones that genuinely require `TaintTracker` analysis.

---

## How it works

```mermaid
flowchart TD
    A(["SinkSanitizerFilter.from_context(ctx)"]):::input --> B["apply(classifications: List[SinkClassification]) → int\n  Input: ARG_PROPAGATED SinkArgClassifier results\n  Returns: count of sites reclassified as SANITIZER_VALIDATED"]:::primary
    B:::primary --> C["For each ARG_PROPAGATED site:\n  Disassemble containing function\n  Walk _SANITIZER_SCAN_WINDOW instructions backward from sink\n  Check condition 1: SHELL_SAFE sanitizer called on same arg?\n    SanitizerDetector.lookup(callee_va) → SanitizerProfile\n    If profile.coverage_report.shell_safe() → candidate"]:::secondary
    C:::secondary --> D["Check condition 2: return value in conditional branch?\n  test eax, eax / jne/je/jz pattern\n  Conditional immediately after sanitizer call"]:::tertiary
    D:::tertiary --> E["Check condition 3: branch guards exec sink?\n  False edge → error path (exit/return)\n  True edge → continues to exec sink"]:::tertiary
    E:::tertiary --> F{"All 3 conditions met?"}:::neutral
    F:::neutral --> G(["Reclassify to SANITIZER_VALIDATED\n  classification.verdict = 'SANITIZER_VALIDATED'\n  Remove from TaintTracker queue"]):::output
    F:::neutral --> H(["Keep as ARG_PROPAGATED\n  (genuinely needs TaintTracker)"]):::output
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
    linkStyle 4 stroke:#546e7a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
from ablation.analyzers.sink_sanitizer_filter import SinkSanitizerFilter
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/target.elf')

# Step 1: classify all sink call sites
clf = SinkArgClassifier.from_context(ctx)
results = clf.classify_all()

print(f"Before filter: {sum(1 for r in results if r.verdict == 'ARG_PROPAGATED')} ARG_PROPAGATED")

# Step 2: filter out sanitizer-validated sites
filt = SinkSanitizerFilter.from_context(ctx)
n_reclassified = filt.apply(results)

print(f"Reclassified: {n_reclassified} as SANITIZER_VALIDATED")
print(f"After filter: {sum(1 for r in results if r.verdict == 'ARG_PROPAGATED')} ARG_PROPAGATED (need TaintTracker)")

# Print detailed report
print(filt.report(results))
```

---

## Example output

The following illustrates the filter output format. Actual counts and addresses are binary-specific.

```
SinkSanitizerFilter:
  Input:  <N> ARG_PROPAGATED sites
  Reclassified: <M> as SANITIZER_VALIDATED
    <va>: system  — sanitizer: validate_path() shell_safe=True, branch guards sink
    <va>: popen   — sanitizer: check_filename() shell_safe=True, branch guards sink
  Remaining: <K> ARG_PROPAGATED (feed to TaintTracker)
```

---

## False positives

**Condition 3 conditional branch guards exec sink requires that the false edge leads to an error path, not a partial sanitization.** A sanitizer that is called but whose result is not used to prevent the exec sink call specifically the sanitizer return value is ignored will not be detected and the site will remain `ARG_PROPAGATED`. Verify by checking that the branch is conditional on the sanitizer's return, not on an unrelated condition.

**`_SANITIZER_SCAN_WINDOW` is a fixed instruction count**: a sanitizer called more than `_SANITIZER_SCAN_WINDOW` instructions before the exec sink will not be detected. Increase the window for large functions with long sanitizer-to-sink paths.

---

## Pipeline position

Run `SinkSanitizerFilter.apply()` immediately after `SinkArgClassifier.classify_all()` and before `TaintTracker`. The filter reduces the `ARG_PROPAGATED` queue by removing structurally safe sites, making `TaintTracker` runs faster and the analyst's review queue shorter.

---

## Reading output

`SinkSanitizerFilter.applyclassifications` accepts `List[SinkClassification]` from `SinkArgClassifier` and returns a new `List[SinkClassification]`. `ARG_PROPAGATED` entries where all three sanitizer conditions are confirmed are upgraded to `SANITIZER_VALIDATED`; all other entries pass through unchanged.

Call `SinkSanitizerFilter.reportclassifications` after `apply()` to get a triage summary string showing how many sites were validated vs. remaining.

---

## See also

- [Sink Argument Classifier](sink-argument-classifier.md): produces the `ARG_PROPAGATED` list that this filter processes
- [Sanitizer Recognition](sanitizer-recognition.md): `SanitizerDetector` that identifies `SHELL_SAFE` validators
- [Taint Analysis](taint-analysis.md): processes the remaining `ARG_PROPAGATED` sites after filtering
