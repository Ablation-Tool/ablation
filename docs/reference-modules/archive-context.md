# ArchiveContext

Cross-object query engine for Unix ar (.a) static archives: find which functions call both symbol_A and symbol_B, find all callers of a symbol, find symbol definitions.

---

## Why this exists

1. **ArArchiveScanner only runs exec-class (system/popen/execve) scans per-member.** It cannot answer "which function in the entire archive calls both `rpc_ses_read` and `strcpy`?" — this requires cross-member correlation.
2. **Manual member-by-member scan is slow at scale.** The solidac.a corpus (666 .o files) required a manual scan to find `rpc0http.o` as the only member calling both `rpc_ses_read` and `strcpy` in the same function. `co_reference_scan()` automates this in one call.
3. **Lazy-loaded contexts.** Building all 666 `ReloObjectContext` instances upfront would be slow. ArchiveContext indexes the archive once and builds contexts on demand — `has_import()` filtering avoids building contexts for non-matching members.

Gap ID: RELO-GAP-003 (solidDB VxWorks PPC440 solidac.a analysis).

---

## How it works

1. Parses the AR archive header (GNU and BSD formats, long name tables).
2. Indexes all ELF32 members: stores raw bytes in `_member_data`, names in `_member_names`.
3. Lazily builds `ReloObjectContext` on first access via `get(name)`.
4. Cross-object queries pre-filter via `has_import()` at the object level before per-function scan.

---

## ArchiveContext

```python
from ablation.analyzers.archive_context import ArchiveContext

arc = ArchiveContext.from_path('/path/to/solidac.a')
# or from bytes:
arc = ArchiveContext(data=raw_bytes, path='<label>')
```

### Key methods

| Method | Returns | Description |
|:---|:---|:---|
| `members()` | `List[str]` | Names of all ELF32 members |
| `get(name)` | `Optional[ReloObjectContext]` | Lazy-built context for a member |
| `get_all()` | `List[Tuple[str, ctx]]` | All members built eagerly (slow for large archives) |
| `co_reference_scan(sym_a, sym_b)` | `List[Tuple[str, str]]` | `(obj, fn)` pairs calling both symbols in same function |
| `find_callers(sym)` | `List[Tuple[str, str]]` | All `(obj, fn)` calling `sym` across the archive |
| `find_definitions(sym)` | `List[Tuple[str, str]]` | All `(obj, sym)` where `sym` is globally defined |
| `imports_of(name)` | `List[str]` | Imports of a specific member |
| `exports_of(name)` | `List[str]` | Exports of a specific member |
| `summary()` | `str` | One-line summary |

---

## Usage

```python
from ablation.analyzers.archive_context import ArchiveContext

arc = ArchiveContext.from_path('lib/solidac.a')
print(arc.summary())
# → ArchiveContext(solidac.a): 666 ELF32 members

# Find the read+strcpy pattern across all 666 objects
for obj, fn in arc.co_reference_scan('rpc_ses_read', 'strcpy'):
    print(f'{obj}::{fn}')
# → rpc0http.o::rpc_http_svc_get

# All callers of SsQmemStrdup across the archive
for obj, fn in arc.find_callers('SsQmemStrdup'):
    print(f'{obj}::{fn}')

# Where is rpc_http_svc_get defined?
for obj, sym in arc.find_definitions('rpc_http_svc_get'):
    print(f'defined in {obj}')

# Deep-dive into a specific member
ctx = arc.get('rpc0http.o')
if ctx:
    print(ctx.disasm('rpc_http_svc_get'))
```

---

## Example output

```
ArchiveContext(solidac.a): 666 ELF32 members

co_reference_scan('rpc_ses_read', 'strcpy'):
  rpc0http.o::rpc_http_svc_get

find_callers('strcpy'):
  rpc0http.o::rpc_http_svc_get
  sse0srpc.o::srpc_connect_init

find_definitions('rpc_http_svc_get'):
  rpc0http.o::rpc_http_svc_get
```

---

## Performance notes

- `co_reference_scan()` and `find_callers()` pre-filter at the object level with `has_import()` before doing per-function scans. For solidac.a (666 members), a co-reference scan for `rpc_ses_read`+`strcpy` builds at most ~5-10 contexts (those that import both symbols), not all 666.
- `get_all()` is eager — avoid on archives with many members. Use targeted queries instead.

---

## Pipeline position

**Before:** Use when you have a `.a` static library and need to identify which members are worth analyzing.

**After:** Call `arc.get(member_name)` to get the `ReloObjectContext`, then `ReloSinkArgClassifier` for arg-provenance analysis.

---

## See also

- [ReloObjectContext](relo-object-context.md): per-member parser
- [ReloSinkArgClassifier](relo-sink-arg-classifier.md): arg-provenance on the member
- [ar-archive-scanner](ar-archive-scanner.md): exec-class scan (linked ELFs or i386)
