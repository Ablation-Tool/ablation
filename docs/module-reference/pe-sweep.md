# PE Sweep

**File:** `sweeps/pe_sweep.py`

Semantic vulnerability sweep for Windows PE (i386 and AMD64) binaries. Adapted from
`fortinet_sweep.py` for targets where the binary format is PE rather than ELF.
Covers `.exe`, `.dll`, `.ocx`, and `.ax` files compiled for x86-32 or x86-64.

---

## When to use

Use `pe_sweep.py` when the research target is a Windows PE binary:

- QuickTime for Windows tools and SDKs
- Windows COM/ActiveX components
- Win32 media codecs (`.ax`, `.acm`)
- Any PE32 (i386) or PE32+ (AMD64) executable or library

**Do not** use this sweep on ELF binaries. For those, use `fortinet_sweep.py`
or `base_sweep.py` as appropriate.

---

## Key differences from fortinet_sweep.py

| Aspect | `fortinet_sweep.py` | `pe_sweep.py` |
|---|---|---|
| Binary format | ELF | PE32 / PE32+ |
| Call resolution | ELF PLT (`.plt` section) | PE IAT; i386: absolute addr; AMD64: RIP-relative |
| Disassembler mode | Capstone x86-64 | CS_MODE_32 (i386) or CS_MODE_64 (AMD64) |
| Prologue pattern (i386) | N/A | `55 8B EC` / `55 89 E5` (PUSH EBP; MOV EBP,ESP) |
| Prologue pattern (AMD64) | N/A | `48 83 EC` (SUB RSP,imm8); `55 48 89 E5` (PUSH RBP; MOV RBP,RSP) |
| String index | XRefGraph (ELF `.rodata`) | `.rdata` section scan |
| Taint analysis | Yes (arch-routed) | No (all taint trackers are ELF-only) |
| SinkArgClassifier | Yes (x86-64) | No |

---

## Architecture support

`pe_sweep.py` detects PE machine type at runtime and routes to the correct path:

- **i386 (IMAGE_FILE_MACHINE_I386):** `CS_MODE_32`; IAT indirect calls via `dword ptr [0xXXXXXX]`; string refs via `push imm32`
- **AMD64 (IMAGE_FILE_MACHINE_AMD64):** `CS_MODE_64`; IAT indirect calls via `qword ptr [rip + offset]`; string refs via `lea reg, [rip + offset]`

ARM and other architectures are rejected at startup.

---

## AMD64 RIP-relative call resolution

Capstone x64 preserves `rip + offset` form and never resolves it to an absolute address.
`pe_sweep.py` computes the IAT slot VA as:

```
slot_va = insn.address + insn.size + offset
```

For example, `call qword ptr [rip + 0x1234]` at VA `0x140001000` with instruction size 6
resolves to IAT slot `0x140002640`. String references via `lea` use the same computation.

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

result = _sweep_pe_one("/path/to/TwTouch.sys", model, profiles, top_k=5)
print(f"arch: {result['arch']}  functions: {result['functions_found']}")
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

### i386

Detects `55 8B EC` (MSVC) and `55 89 E5` (GCC) frame-pointer prologues.
Binaries compiled with FPO (Frame Pointer Omission, `/O2`) produce fewer detected
functions; FPO recovery via E8 call-target scanning supplements prologue detection.

### AMD64

Detects three patterns covering MSVC and GCC/Clang x64 ABIs:

| Pattern | Encoding | Compiler |
|---|---|---|
| `PUSH RBP; MOV RBP,RSP` | `55 48 89 E5` | GCC / Clang frame-pointer |
| `SUB RSP, imm8` | `48 83 EC XX` | MSVC typical (most common) |
| `MOV [RSP+N], RBX` | `48 89 5C 24 XX` | MSVC callee-save preamble |

FPO recovery (E8 rel32 scanning) is shared between i386 and AMD64 since direct call
encoding is identical in both modes.

---

## Limitations

- **No taint analysis**: semantic sweep only. Manual capstone trace required for CONFIRMED findings.
- **FPO blindness**: functions with non-standard prologues (heavy inlining, naked functions) may be missed.
- **No XRefGraph**: string references limited to `.rdata` + prologue-bounded disassembly; no full cross-reference graph.
- **ARM/ARM64 PE**: rejected at startup (no prologue patterns or IAT resolution implemented for those ISAs).
