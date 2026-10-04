# PE32 Sweep

**File:** `sweeps/pe_sweep.py`

Semantic vulnerability sweep for Windows PE32 (i386) binaries. Adapted from
`fortinet_sweep.py` for targets where the binary format is PE rather than ELF.
Covers `.exe`, `.dll`, `.ocx`, and `.ax` files compiled for x86-32.

---

## When to use

Use `pe_sweep.py` when the research target is a Windows PE32 binary:

- QuickTime for Windows tools and SDKs
- Windows COM/ActiveX components
- Win32 media codecs (`.ax`, `.acm`)
- Any legacy PE32 (i386) executable or library

**Do not** use this sweep on ELF binaries. For those, use `fortinet_sweep.py`
or `base_sweep.py` as appropriate.

---

## Key differences from fortinet_sweep.py

| Aspect | `fortinet_sweep.py` | `pe_sweep.py` |
|---|---|---|
| Binary format | ELF | PE32 |
| Call resolution | ELF PLT (`.plt` section) | PE Import Address Table (IAT) |
| Disassembler mode | Capstone x86-64 | Capstone x86-32 |
| Prologue pattern | `55 48 89` (push rbp; mov rbp,rsp) | `55 8B EC` / `55 89 E5` (push ebp; mov ebp,esp) |
| String index | XRefGraph (ELF `.rodata`) | `.rdata` section scan |
| Taint analysis | Yes (arch-routed) | No (all taint trackers are ELF-only) |
| SinkArgClassifier | Yes (x86-64) | No |

---

## Vulnerability profiles

Extends `base_sweep.VULN_PROFILES` with `PE_WIN_PROFILES`:

| Profile | What it finds |
|---|---|
| `qt_heap_atom_parse` | QuickTime atom size → malloc without bounds check |
| `qt_rtsp_recv_overflow` | RTSP/RTP recv into fixed buffer |
| `qt_registry_plugin_load` | RegQueryValueExA path → LoadLibraryA |
| `qt_path_string_overflow` | lstrcpyA/wsprintfA on file/URL path |
| `win_cmd_exec` | WinExec/CreateProcessA with user-controlled args |
| `win_format_string` | wsprintfA/sprintf with non-literal format |
| `qt_codec_intovf` | Codec stream dimensions integer overflow before alloc |
| `qt_com_stream_overflow` | IStream::Read into fixed buffer via COM/ActiveX |

---

## Usage

Single binary:

```bash
python3 sweeps/pe_sweep.py /path/to/target.exe \
    --vendor apple --product quicktime --version 7.0
```

Directory scan (`.exe`, `.dll`, `.ocx`, `.ax`):

```bash
python3 sweeps/pe_sweep.py /path/to/dir/ \
    --vendor apple --product quicktime --version 7.0
```

Programmatic:

```python
from sentence_transformers import SentenceTransformer
from sweeps.pe_sweep import _sweep_pe_one, _build_win_profiles

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
profiles = _build_win_profiles()

result = _sweep_pe_one("/path/to/PlugInHelper.exe", model, profiles, top_k=5)
print(f"functions found: {result['functions_found']}")
for profile_name, hits in result["semantic"].items():
    if hits and hits[0][0] >= 0.30:
        score, va, calls, desc = hits[0]
        print(f"  {profile_name}: {score:.4f} @ {va:#010x}")
```

---

## IAT resolution

The Import Address Table maps absolute virtual addresses to `dll!FuncName`:

```python
from sweeps.pe_sweep import _build_iat
import lief

pe = lief.parse("target.exe")
iat = _build_iat(pe)
# {0x4203cc: "kernel32.dll!WaitForSingleObject", ...}
```

`iat_address` from lief is an RVA; absolute = `imagebase + iat_address`.

---

## Prologue detection

Only detects standard frame-pointer prologues. Binaries compiled with FPO
(Frame Pointer Omission, common with `/O2`) produce fewer detected functions.
On `PlugInHelper.exe` (2002, MSVC), 23 of ~N total functions are detected.

If prologue coverage is insufficient, consider using the `--no-xref` path in
`base_sweep.py` adapted for PE (future work: add eh_frame equivalent via PE
exception directory parsing for AMD64 PE+ targets).

---

## Limitations

- **No taint analysis**: semantic sweep only. Manual capstone trace required for CONFIRMED findings.
- **i386 only**: AMD64 PE+ (`.exe` on modern Windows) is rejected at startup.
- **FPO blindness**: functions compiled with frame pointer omission are missed.
- **No XRefGraph**: string references limited to immediate push of .rdata VAs.
