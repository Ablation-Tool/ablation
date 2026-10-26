# Native Library Inventory

Batch-triage all native ELF shared libraries in a directory: producing a per-library summary table of size, architecture, export count, JNI interface count, and security score: replacing the repeated per-engagement ad-hoc enumeration of native `.so` files in Android IoT targets that ship 20–80 native libraries per APK.

---

## Why this exists

1. **Android IoT APKs ship 20–80 native `.so` files.** Running `BinaryContext.load_or_build()` individually on each is slow and session-filling. `LibraryInventory.from_dir()` batch-loads all libraries, generating a ranked summary table in a single call. The security score column ranks libraries by attack surface before any analysis: directing the analyst to high-value targets immediately.

2. **`LibInventoryEntry.jni_count` and `has_jni_on_load`** identify the libraries that expose a JNI interface to the Android runtime, these are the entry points for native code execution from Java. A library with `has_jni_on_load=True` runs code before any Java method is called, making it the first-hop attack surface for pre-authentication native code execution.

3. **`security_strings_sample`** provides a three-string excerpt of security-relevant strings from each library `key`, `token`, `password`, `secret`, `admin`, `auth`: giving the analyst a fast preview of whether a library handles credentials before loading the full `BinaryContext`.

---

## How it works

```mermaid
flowchart TD
    A(["LibraryInventory.from_dir(dir_path, pattern='*.so')\n  or .from_paths(paths)"]):::input --> B["scan_one(elf_path) → LibInventoryEntry\n  For each .so:\n    Parse ELF header: arch, class (32/64), size_kb\n    Count exports (dynamic symbol table)\n    Count internal functions (func_starts)\n    Count JNI exports (Java_*)\n    has_jni_on_load: JNI_OnLoad in exports\n    Compute security_score:\n      exports + jni_count * 3 + has_jni_on_load * 10\n    Extract security_strings_sample (key/token/pass/...)"]:::primary
    B:::primary --> C["LibInventoryEntry:\n  path: str\n  size_kb: int\n  arch: str\n  exports: int\n  internal_funcs: int\n  jni_count: int\n  has_jni_on_load: bool\n  security_score: int\n  security_strings_sample: List[str]"]:::secondary
    C:::secondary --> D(["report() → str\n  Sorted table by security_score descending\n  Format: name | size | arch | exports | jni | score"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.library_inventory import LibraryInventory

inventory = LibraryInventory.from_dir('/tmp/apk_extracted/lib/arm64-v8a/')
print(inventory.report())

# Top security-score entries
top = sorted(inventory.entries, key=lambda e: e.security_score, reverse=True)[:5]
for entry in top:
    print(f"  {entry.path}  score={entry.security_score}  jni={entry.jni_count}")
    print(f"    strings: {entry.security_strings_sample}")
```

---

## Example output

The following illustrates library inventory output format. Actual values are APK-specific.

```
LibraryInventory: /tmp/apk_extracted/lib/arm64-v8a/

Library                  | size  | arch   | exports | jni | score
-------------------------|-------|--------|---------|-----|------
libforticlient_jni.so    | <K>kb | arm64  | <E>     | <J> | <S>
libssl.so                | <K>kb | arm64  | <E>     | 0   | <S>
libcrypto.so             | <K>kb | arm64  | <E>     | 0   | <S>
```

---

## False positives

**`security_score` is a heuristic, not a severity rating**: a library with many exports may have a high score but serve only utility functions. A library with a low score and `has_jni_on_load=True` is more critical than its score suggests. Use `security_score` for initial ranking only; validate with `BinaryContext` analysis.

**`security_strings_sample` uses substring matching**: `key` matches `monkey`, `token` matches `autoconf_tokenize`. Review the full string context in `BinaryContext.strings()` before concluding a library handles credentials.

---

## Pipeline position

Run `LibraryInventory` at session start for any Android APK or firmware root filesystem with multiple native libraries. Use the ranked table to select the top 3–5 libraries for full `BinaryContext` analysis, skipping the rest until higher-priority targets are exhausted.

---

## Reading output

`LibraryInventory.scan()` returns a list of `LibInventoryEntry` objects:

| Attribute | Content |
|:---|:---|
| `path` | Absolute path to the library |
| `filename` | Library basename |
| `size_kb` | File size in kilobytes |
| `arch` | Architecture string for example `arm64`, `x86` |
| `exports` | Total count of dynamic symbols with a non-zero value |
| `internal` | BL-target internal function count −1 if unsupported arch |
| `jni` | Count of `Java_*` JNI exports |
| `has_jni_on_load` | `True` if `JNI_OnLoad` is exported |
| `security_score` | Integer 0–10: security interest score; higher = more worth analyzing |
| `plt_hooks` | `List[str]`: critical PLT import labels found |

---

## See also

- [Persistent Analysis Context](persistent-analysis-context.md): `BinaryContext` for full analysis of high-score libraries
- [Cross-Binary Taint Analysis](configurable-taint-reporting.md): `CrossBinaryTaintTracker` for inter-library taint chains
