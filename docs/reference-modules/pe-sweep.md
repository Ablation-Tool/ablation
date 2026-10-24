# PE Sweep

**File:** `sweeps/pe_sweep.py`

Semantic vulnerability sweep for Windows PE i386 and AMD64 binaries. Adapted from
`fortinet_sweep.py` for targets where the binary format is PE rather than ELF.
Covers `.exe`, `.dll`, `.ocx`, and `.ax` files compiled for x86-32 or x86-64.

---

## Why this exists

Three gaps made PE binary analysis slower before this sweep:

1. **`fortinet_sweep.py` is ELF-only.** The base sweep resolves function calls through the ELF PLT and uses ELF section headers to locate `.rodata`. Applying it to a PE binary produces zero call resolutions: PE uses the Import Address Table (IAT) and `.rdata` for both imports and string constants, which ELF parsers do not read.

2. **x86-32 and AMD64 PE binaries use distinct calling conventions that must be handled separately.** i386 PE binaries encode IAT calls as `CALL dword ptr [abs_addr]` and string references as `PUSH imm32`. AMD64 PE binaries use `CALL qword ptr [rip+offset]` and `LEA reg, [rip+offset]`. A single code path cannot handle both correctly. `pe_sweep.py` detects the machine type (`IMAGE_FILE_MACHINE_I386` vs `IMAGE_FILE_MACHINE_AMD64`) and routes to the correct resolution path.

3. **Windows QuickTime/COM/codec binaries were entirely outside automated sweep coverage.** Research targets like QuickTime for Windows, DirectShow codecs (`.ax`), and ActiveX controls (`.ocx`) are PE binaries with x86 code. Without `pe_sweep.py`, every finding in those targets required manual disassembly from scratch. This sweep applies the same semantic query set used on ELF targets to PE binaries.

---

## When to use

Use `pe_sweep.py` when the research target is a Windows PE binary:

- QuickTime for Windows tools and SDKs
- Windows COM/ActiveX components
- Win32 media codecs `.ax` and `.acm`
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
| Prologue pattern (i386) | N/A | `55 8B EC` / `55 89 E5` PUSH EBP; MOV EBP,ESP |
| Prologue pattern (AMD64) | N/A | `48 83 EC` SUB RSP,imm8; `55 48 89 E5` PUSH RBP; MOV RBP,RSP |
| String index | XRefGraph (ELF `.rodata`) | `.rdata` section scan |
| Taint analysis | Yes arch-routed | No all taint trackers are ELF-only |
| SinkArgClassifier | Yes (x86-64) | No |

---

## Architecture support

`pe_sweep.py` detects PE machine type at runtime and routes to the correct path:

- **i386 IMAGE_FILE_MACHINE_I386:** `CS_MODE_32`; IAT indirect calls via `dword ptr [0xXXXXXX]`; string refs via `push imm32`
- **AMD64 IMAGE_FILE_MACHINE_AMD64:** `CS_MODE_64`; IAT indirect calls via `qword ptr [rip + offset]`; string refs via `lea reg, [rip + offset]`

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

Directory scan `.exe`, `.dll`, `.ocx`, and `.ax`:

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
Binaries compiled with FPO Frame Pointer Omission and `/O2` produce fewer detected
functions; FPO recovery via E8 call-target scanning supplements prologue detection.

### AMD64

Detects three patterns covering MSVC and GCC/Clang x64 ABIs:

| Pattern | Encoding | Compiler |
|---|---|---|
| `PUSH RBP; MOV RBP,RSP` | `55 48 89 E5` | GCC / Clang frame-pointer |
| `SUB RSP, imm8` | `48 83 EC XX` | MSVC typical most common |
| `MOV [RSP+N], RBX` | `48 89 5C 24 XX` | MSVC callee-save preamble |

FPO recovery E8 rel32 scanning is shared between i386 and AMD64 since direct call
encoding is identical in both modes.

---

## Deterministic finding: FirmwareAuthBypassProfile (GAP-015)

### Why this exists

Three things were not possible before in Ablation:

1. No cross-vendor detection of unsigned firmware flashers: the gap was found across 8 binaries from a single vendor in the AUO eGalax engagement, any of which would have been caught automatically by this check.
2. Semantic profiles can only detect what IS present; detecting the *absence* of signing imports WinVerifyTrust and Crypt* required a separate deterministic IAT inspector that runs outside the semantic loop.
3. Ordinal-only imports (the eGalaxUpdate2 → HIDdAPI.dll pattern) are invisible to the named-import IAT check; the new detector also inspects imported DLL names to catch firmware-update libraries regardless of whether they're imported by name or ordinal.

`_check_firmware_auth_bypass(pe, iat)` runs on every binary before the semantic sweep. It fires when:

- A firmware-update DLL is imported `hiddapi.dll`, `hidapi.dll`, and `egtouch.dll`, **or**
- A named IAT entry matches a firmware-update substring `DevIAP*`, `IAPFlash`, `FirmwareUpdate`, `DevMCUReset`, and …

**and** no signing import `WinVerifyTrust`, `CryptVerifySignature`, `CryptHashData`, `BCryptVerifySignature`, and … is present.

The result appears as `firmware_auth_bypass` in the per-binary result dict and as a **Deterministic Finding** block before semantic results in the report.

---

## String index fallback: BorlandVCLStringIndex (GAP-016)

### Why this exists

Two things were not possible before in Ablation:

1. Borland BCC32/VCL applications RADStudio, C++ Builder place string literals in `.data` rather than `.rdata`. The prior `.rdata`-only scan returned 0 strings for these targets and misclassified them as out-of-scope (no debug strings = nothing to correlate against).
2. A blind `.data` fallback would add noise from live pointers and struct padding, but those sequences are reliably short or non-ASCII: the same 5-printable-byte minimum filter that protects `.rdata` scanning also works for `.data`, making the fallback safe.

`_build_rdata_strings` now calls `_scan_section_strings(pe, data, ".rdata")` first. When that returns zero strings it retries with `".data"` and prints a `[*] .rdata=0 strings: BCC32/VCL fallback` diagnostic. The underlying `_scan_section_strings` helper is shared between both calls.

---

## Limitations

- **No taint analysis**: semantic sweep only. Manual capstone trace required for CONFIRMED findings.
- **FPO blindness**: functions with non-standard prologues heavy inlining, naked functions may be missed.
- **No XRefGraph**: string references limited to `.rdata` (or `.data` fallback) + prologue-bounded disassembly; no full cross-reference graph.
- **ARM/ARM64 PE**: rejected at startup no prologue patterns or IAT resolution implemented for those ISAs.

---

## How it works

`sweep_directory_pedirectory, model, profiles, top_k` scans a directory for PE files, loads each with `BinaryContext.load_or_build()`, and runs a configurable set of analysis profiles SAC, taint, firmware-auth-bypass across all PE files in parallel. Results are returned as `List[dict]`: one dict per PE file. Uses `SemanticSearcher` and `SinkArgClassifier` internally; not a standalone analysis primitive.

---

## Example output

```
[  1/12] httpsd.exe  — SAC: 3 ARG_PROPAGATED  1 RODATA_CONST
  firmware_auth_bypass: {'has_bypass': True, 'bypass_va': 0x00418200, 'severity': 'HIGH'}

[  2/12] sslvpnd.exe  — SAC: 0 ARG_PROPAGATED  8 RODATA_CONST
  firmware_auth_bypass: {'has_bypass': False}

[  3/12] fcgi_dynamic.exe  — SAC: 1 ARG_PROPAGATED
  firmware_auth_bypass: {'has_bypass': False}
```

---

## False positives

Sweep results inherit false-positive rates of each individual analysis module. Run the sweep for initial triage, then re-run each `ARG_PROPAGATED` hit individually with `TaintTracker` before reporting.

---

## Pipeline position

**Before this module:** Collect PE files into a target directory. Configure profiles and model settings.

**After this module:** Filter sweep output for `has_bypass=True` or `ARG_PROPAGATED` hits. Run targeted analysis on those binaries with `TaintTracker` and `PathSolver`.

---

## Reading output

`sweep_directory_pedirectory, model, profiles, top_k` returns `List[dict]`: one dict per analyzed PE file. The `FirmwareAuthBypassFinding` TypedDict (embedded in each result's `firmware_auth_bypass` key) has these fields:

| Field | Content |
|:---|:---|
| `id` | Finding identifier string such as `'GAP-015'` |
| `title` | Short finding title |
| `severity` | `'CRITICAL'` / `'HIGH'` / `'MEDIUM'` / `'INFO'` |
| `evidence` | `List[str]`: IAT names or import strings that triggered the finding |
| `note` | Human-readable explanation |

Each result dict also contains `binary`, `arch`, `findings` top-k semantic matches, `firmware_iat`, and `signing_iat` keys.

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
