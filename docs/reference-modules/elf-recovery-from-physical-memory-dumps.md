# PS3 SELF Decryption

Decrypt PS3 SELF Signed ELF files programmatically inside a Python pipeline: auto-detecting the correct keyset from the SCE header `key_rev` field, applying AES-128-CBC decryption with the correct ERK/RIV pair, and producing a standard ELF that `BinaryContext.load_or_build()` can parse.

---

## Why this exists

1. **`lief`, `capstone`, and `BinaryContext.load_or_build()` all fail silently on encrypted SELF format**: they see garbage or raise exceptions on the non-ELF magic bytes `0x53434500` (`SCE\0`). Before `PS3SELFDecryptor`, decryption required the external `scetool` binary C, manual build, not importable as a Python library, invoked manually before each analysis session with the correct keyset flags.

2. **Auto-detection from `key_rev` eliminates manual keyset lookup.** The `key_rev` field at bytes 6–7 of the SCE header selects the master keyset (ERK/RIV). `PS3SELFDecryptor.from_path()` reads `key_rev` and selects the correct keyset automatically. Without this, matching `key_rev` to the right ERK/RIV required manual lookup in `scetool`'s `keys.h` for every new SELF file.

3. **`decrypt_to_tmp()` integrates directly into analysis pipelines**, it decrypts to a temporary file and returns the path, enabling `BinaryContext.load_or_build(decryptor.decrypt_to_tmp(self_path))` as a one-liner. The temporary file is managed by the caller; `decrypt()` writes to a caller-specified output path for persistent results.

---

## How it works

```mermaid
flowchart TD
    A(["PS3SELFDecryptor.from_path(self_path)\n  Read SCE header (0x53434500 magic)\n  Extract key_rev (bytes 6-7)\n  Select keyset: ERK, RIV from registered key table"]):::input --> B(["decrypt(in_path, out_path) → SELFDecryptResult\n  Read SELF sections from header\n  AES-128-CBC with ERK/RIV → decrypt encrypted sections\n  Reconstruct ELF segments in output file\n  → SELFDecryptResult(out_path, success, error_msg)"]):::output
    A:::input --> C(["decrypt_to_tmp(in_path, suffix='.elf') → str\n  Creates temp file, calls decrypt()\n  Returns temp file path\n  Caller responsible for cleanup"]):::output
    A:::input --> D(["register_keyset(key_rev, erk, riv)\n  Register additional ERK/RIV pairs\n  Enables support for new PS3 firmware eras"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#2e7d32,stroke-width:3px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.ps3_self_decryptor import PS3SELFDecryptor
from ablation.analyzers.binary_context import BinaryContext
import os

# Decrypt a SELF file
decryptor = PS3SELFDecryptor.from_path('/path/to/eboot.elf')

# Option 1: Persistent output
result = decryptor.decrypt('/path/to/eboot.elf', '/tmp/eboot_decrypted.elf')
if result.success:
    ctx = BinaryContext.load_or_build('/tmp/eboot_decrypted.elf')
    print(ctx.summary())

# Option 2: Temporary pipeline integration
tmp_path = decryptor.decrypt_to_tmp('/path/to/eboot.elf')
try:
    ctx = BinaryContext.load_or_build(tmp_path)
    print(ctx.summary())
finally:
    os.unlink(tmp_path)

# Register a new keyset for an unseen key_rev
PS3SELFDecryptor.register_keyset(
    key_rev=0x0004,
    erk=bytes.fromhex('<32-hex-byte-erk>'),
    riv=bytes.fromhex('<16-hex-byte-riv>')
)
```

---

## Example output

The following illustrates the SELF decryption output format. Actual key_rev and file sizes are SELF-specific.

```
PS3SELFDecryptor: eboot.elf  (SCE magic, key_rev=0x0003)

Keyset: key_rev=0x0003  (registered)
Decrypting: eboot.elf → /tmp/eboot_decrypted.elf
  Encrypted sections: <N>
  AES-128-CBC decryption: OK
  ELF reconstruction: OK

SELFDecryptResult: success=True
BinaryContext: eboot_decrypted.elf  (ELF64, PPC64)  <N> functions
```

---

## False positives

**`from_path()` raises on unknown `key_rev`**: if the SELF file uses a `key_rev` not in the registered keyset table, `PS3SELFDecryptor.from_path()` raises a `KeyError`. Use `register_keyset()` to add new ERK/RIV pairs before calling `from_path()` for new PS3 firmware eras.

**Decrypted output is only valid if the keyset is correct**: an incorrect ERK/RIV produces a file with AES output that appears syntactically valid correct ELF magic after decryption but contains garbage instruction bytes. Verify decryption success by checking that `BinaryContext.load_or_build()` parses correctly and `ctx.func_starts` is non-empty.

---

## Pipeline position

Run `PS3SELFDecryptor.from_path()` before any SELF file analysis. After successful decryption, feed the output path to `BinaryContext.load_or_build()` for all standard Ablation analysis. Follow with `PS3OPDVtableScanner` for vtable reconstruction and `VMXDensityScanner` for vector function labeling.

---

## Reading output

`PS3SELFDecryptor.decryptin_path, out_path` returns a `SELFDecryptResult`:

| Attribute | Content |
|:---|:---|
| `in_path` | Path to the input SELF file |
| `out_path` | Path where the decrypted ELF was written |
| `key_rev` | Key revision byte used for decryption for example `0x0016` |
| `section_count` | Total SELF segments found in the header |
| `decrypted_sections` | Count of segments successfully decrypted |
| `elf_size` | Size of the output ELF in bytes |

Use `decrypt_to_tmp(in_path)` to decrypt to a temporary file and return its path as a string; pass that path directly to `BinaryContext.load_or_build()`.

---

## See also

- [PS3 OPD Virtual Tables](ps3-opd-virtual-tables.md): PS3 Cell PPU vtable reconstruction after SELF decryption
- [VMX/AltiVec Density Ranking](vmx-altivec-density-ranking.md): vector function labeling for PS3 binaries
- [PPC64 ELFv1 Resolution](ppc64-elfv1-resolution.md): PLT patching required on PS3 Cell PPU ELFv1 binaries
