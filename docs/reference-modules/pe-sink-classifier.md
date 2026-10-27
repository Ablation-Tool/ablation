# pe-sink-classifier

`ablation/analyzers/pe_sink_classifier.py` scans Windows PE binaries for exec-class IAT imports. It fills the gap where `SinkArgClassifier` crashes on PE binaries because it looks up an ELF-only attribute on a PE object.

---

## Why this exists

Three things were not possible before this module:

1. **SinkArgClassifier raises an AttributeError on PE binaries.** It accesses `binary.dynamic_symb` to find PLT entries. PE binaries have no PLT. `lief._lief.PE.Binary` has no `dynamic_symb` attribute. The crash surfaces as an unhandled exception on every PE binary in a multi-format collection.

2. **Windows exec-class APIs have no POSIX equivalent in the ELF scanner catalog.** `SinkArgClassifier` knows `system`, `popen`, `execve`, `execvp`, `execl`, `execlp`. Windows uses `CreateProcessA`, `ShellExecuteA`, `WinExec`, and `_popen`. Without a PE-aware scanner these imports go unreported.

3. **Mixed-format collections had zero exec-import coverage.** IBM-RE directories DS6000, Misc, Pacbase, and ISPF-Tools are examples. Before this module, every Windows PE binary in those directories produced a SAC crash. The real exec-import count per binary was unknown.

---

## What it classifies

| Category | Import names |
|---|---|
| `PROCESS_CREATION` | `CreateProcessA/W`, `CreateProcessAsUserA/W` |
| `SHELL_EXECUTE` | `ShellExecuteA/W`, `ShellExecuteExA/W` |
| `LEGACY_EXEC` | `WinExec` |
| `MSVCRT_SYSTEM` | `system`, `_wsystem` |
| `MSVCRT_POPEN` | `_popen`, `_wpopen` |
| `SERVICE_INSTALL` | `CreateServiceA/W` |

---

## Usage

```python
from ablation.analyzers.pe_sink_classifier import PESinkClassifier

clf = PESinkClassifier.from_path('/path/to/target.exe')
if not clf.is_pe():
    print('not a PE binary')
else:
    results = clf.classify_all()
    print(clf.report(results))

# Summary dict: category -> import list
summary = clf.summary()

# With an existing BinaryContext
clf = PESinkClassifier.from_context(ctx)
```

CLI:

```
python3 -m ablation.analyzers.pe_sink_classifier /path/to/target.exe
```

---

## Example output

```
PESinkClassifier Results
============================================================
Binary: /media/cowboy/research/IBM-RE/ISPF-Tools/tasid.exe

  LEGACY_EXEC:
    WinExec  (from KERNEL32.dll)
  SHELL_EXECUTE:
    ShellExecuteA  (from SHELL32.dll)
```

---

## Limitations

**Import presence only.** The classifier reports which exec-class APIs are imported. It does not trace argument provenance. A `CreateProcessA` import means the binary can spawn a process; it does not mean a command injection is reachable. Full argument tracing on PE binaries requires x86/x86_64 backward register analysis, which is not implemented here.

**Ordinal-only imports.** Some PE binaries import functions by ordinal instead of name. The classifier cannot match ordinal-only imports to exec-class names.

**NE/LE format.** Pre-Win32 executables DOS MZ with NE or LE header are not PE binaries. `is_pe()` returns False for them. These are 16-bit OS2/Windows executables and contain no Win32 exec API imports.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` can load PE32 and PE64 binaries. `ctx.arch` will return `x86_64` or `x86_32`. Use `PESinkClassifier.is_pe()` to confirm the binary is PE before calling `classify_all()`.

**After this module:** If `PROCESS_CREATION` or `SHELL_EXECUTE` imports are found, use `SinkArgClassifier` on the same binary for x86 argument provenance tracing. `SinkArgClassifier` works on x86_64 PE binaries because it uses capstone to scan call sites, not lief dynamic symbols.

---

## Reading output

| Field | Content |
|:---|:---|
| `finding.import_name` | Function name as stored in the IAT |
| `finding.category` | Import category from the table above |
| `finding.dll_name` | DLL name as listed in the PE import table |
| `finding.binary_path` | Path to the PE binary |

---

## See also

- [SinkArgClassifier](sink-arg-classifier.md): x86-64 ELF exec-class argument classifier
- [SinkArgClassifierX86_32](sink-arg-classifier-i386.md): i386 cdecl exec-class argument classifier
- [BinaryContext](binary-context.md): loads PE32/PE64 binaries; `ctx.arch` identifies architecture
