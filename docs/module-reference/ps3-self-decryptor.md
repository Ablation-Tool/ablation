# PS3 SELF Decryptor

Decrypt a PS3 SELF (Signed ELF) into a plain ELF that BinaryContext and Capstone can load.

---

## Why this exists

Three things that weren't possible before in Ablation:

**1. Decrypting PS3 SELF files inside a Python analysis pipeline.** `lief`, `capstone`,
and `BinaryContext.load_or_build()` all fail silently on encrypted SELF format — the
file begins with SCE magic `0x53434500`, not ELF magic, so every parser either errors
or returns an empty context. Before this module, decryption required the external
`scetool` binary, which must be compiled separately and invoked manually before any
analysis session begins.

**2. Auto-detecting the correct keyset from the SELF header.** The `key_rev` field at
bytes 6-7 of the SCE header identifies the master keyset (ERK + RIV). Without this
module, matching `key_rev` to the right 256-bit ERK and 128-bit RIV required manual
lookup in `scetool`'s `keys.h` or the aldostools/webMAN-MOD key table — outside the
analysis loop. `PS3SELFDecryptor.from_path()` reads `key_rev` and selects the keyset
automatically.

**3. Integrating SELF decryption with BinaryContext in one call.** The pattern
`decrypt_to_tmp()` decrypts to a temp ELF and returns the path, which feeds directly
into `BinaryContext.load_or_build()`. The BinaryContext cache then persists the
analysis across sessions without re-decrypting.

---

## How it works

Three decryption stages (naehrwert/scetool `sce.cpp`):

1. **AES-256-CBC** — decrypt the 64-byte `metadata_info` block using the master ERK/RIV.
   Yields a 16-byte per-file key and 16-byte per-file IV.
2. **AES-128-CTR** — decrypt the metadata header + section headers + key table.
3. **AES-128-CTR per section** — decrypt each segment whose `encrypted` field == 3,
   using the per-section key/IV from the decrypted key table.

After decryption, the inner ELF is extracted from the SELF container and written with
page-aligned, non-overlapping `p_offset` values so every standard ELF tool loads it.

---

## Usage

```python
from ablation.analyzers.ps3_self_decryptor import PS3SELFDecryptor
from ablation.analyzers.binary_context import BinaryContext

# Auto-detect keyset from key_rev in SELF header.
elf_path = PS3SELFDecryptor.from_path(eboot_bin).decrypt_to_tmp(eboot_bin)
ctx = BinaryContext.load_or_build(elf_path)

# Explicit key_rev.
decryptor = PS3SELFDecryptor.from_key_rev(0x0016)
result = decryptor.decrypt(eboot_bin, "/tmp/decrypted.elf")
print(f"Decrypted {result.decrypted_sections}/{result.section_count} sections")

# Add a keyset not yet in the built-in table.
PS3SELFDecryptor.register_keyset(0x0017, erk_bytes, riv_bytes)
```

---

## Known keysets

| `key_rev` | Era / context | Source |
|---|---|---|
| `0x0016` | PS3 firmware 3.70 — covers most retail titles (e.g. BLUS30755 GoldenEye) | aldostools/webMAN-MOD `data/keys`, verified against naehrwert/scetool |

Add additional keysets at runtime with `PS3SELFDecryptor.register_keyset(rev, erk, riv)`.

---

## API

### `PS3SELFDecryptor`

| Method | Description |
|---|---|
| `from_path(self_path)` | Auto-detect keyset from `key_rev` in SELF header |
| `from_key_rev(key_rev)` | Explicit keyset selection |
| `register_keyset(rev, erk, riv)` | Add / replace a keyset entry (class method) |
| `decrypt(in_path, out_path)` | Decrypt to `out_path`; returns `SELFDecryptResult` |
| `decrypt_to_tmp(in_path)` | Decrypt to temp file; returns path (caller deletes) |

### `SELFDecryptResult`

| Field | Type | Description |
|---|---|---|
| `in_path` | `str` | Source SELF path |
| `out_path` | `str` | Destination ELF path |
| `key_rev` | `int` | `key_rev` read from SELF header |
| `section_count` | `int` | Total section count from metadata |
| `decrypted_sections` | `int` | Sections that were encrypted and decrypted |
| `elf_size` | `int` | Size of written ELF in bytes |

---

## Requires

- `pycryptodome` (`pip install pycryptodome`) — for AES-CBC and AES-CTR.
  The module imports cleanly without it; `decrypt()` raises `ImportError` if missing.
