<a id="hashalgodiscriminator--xorsolver--cryptoaudit"></a>
# Cryptographic Analysis

  - [What is cryptographic binary analysis?](#what-is-cryptographic-binary-analysis)
  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [False positives](#false-positives)
  - [Pipeline position](#pipeline-position)
  - [Reading findings](#reading-findings)
  - [XorSolver](#xorsolver)
    - [Usage](#usage-1)
    - [XorSolverResult fields](#xorsolverresult-fields)
  - [CryptoAudit](#cryptoaudit)
    - [Usage](#usage-2)
  - [See also](#see-also)

**Files:** `ablation/analyzers/crypto_pattern_detector.py` · `ablation/analyzers/xor_solver.py` · `modules/crypto_audit.py`

---

## What is cryptographic binary analysis? <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

Stripped firmware rarely documents its own cryptography. A binary may implement MD5 for authentication tokens, AES-128-CBC for VPN payloads, or a custom XOR cipher for configuration blob obfuscation, with no symbol names or comments identifying which is which. Audit starts with identifying what cryptographic algorithms are present, then determining whether the key material is recoverable, and finally confirming that the implementation has no critical weaknesses (weak secrets, nonce reuse, TOCTOU in key generation).

`HashAlgoDiscriminator` identifies hash algorithm implementations by matching K-table constants embedded in `.rodata` or as immediate loads in code. Round constants for SHA-256, SHA-1, and MD5 are globally unique 32-bit values; their presence in a function's immediate operands identifies the function without disassembling the round logic. `CustomCBCDetector` finds hand-rolled AES-128-CBC by three structural signatures: a BSS-tracked block pointer pair, an XOR-with-previous-ciphertext back-edge loop, and an `.rodata` IV load at function entry.

`XorSolver` recovers the key from XOR-encrypted firmware blobs. It attempts three attacks in order: a known-plaintext attack (KPA) against ELF/gzip/squashfs magic bytes at known file offsets, an index-of-coincidence key-length estimation followed by per-column frequency analysis, and a Hamming-distance key-length estimator. The `solve()` method tries all three and returns the highest-confidence result.

`CryptoAudit` covers live-endpoint and post-compromise host analysis: JWT decode, forge, and weak-secret testing; SAML XML wrapping and injection; PEM and environment key material extraction; TLS cipher and protocol audit.

## Why this exists <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

1. **Compiled hash implementations leave algorithm-specific K-table constants round constants, magic numbers embedded in `.rodata` or as immediate loads in code: `HashAlgoDiscriminator` identifies these constants against known algorithm fingerprints without requiring disassembly of the full hash round loop.** For example, SHA-256 round constants `0x428a2f98`, `0x71374491`, ... appear as distinct 32-bit values that cannot be misidentified as another algorithm, enabling instant hash algorithm identification from static data.

2. **Hand-rolled AES-128-CBC in ARM32/Thumb2 has a characteristic BSS-tracked block pointer, XOR-with-previous-ciphertext chaining loop, and IV loaded from `.rodata`.** `CustomCBCDetector` identifies these structural patterns without requiring the AES S-box to be present: critical for implementations that use hardware AES acceleration for the block cipher but implement the CBC chaining mode in software. The Fortinet ARM32 pattern was the original motivation.

3. `HashAlgoDiscriminator.scan_function()` and `CustomCBCDetector.scan_function()` integrate directly with `BinaryContext` function boundaries: the same `func_starts` that drive `SemanticSearcher` and `FuncProfiler` drive crypto pattern detection, enabling batch scan of all functions in a binary to identify all crypto implementations in a single pass.

---

## How it works <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

```mermaid
flowchart TD
    A(["HashAlgoDiscriminator(ctx)"]):::input --> B["scan_function(va, size) → HashAlgoMatch\n  extract_constants(va, size):\n    Scan ARM32/Thumb2 MOV/MOVT/LDR immediate loads\n    Collect all 32-bit constant values in function\n  identify(constants) → HashAlgoMatch\n    Match constant set against known K-tables:\n    MD5: 0xd76aa478, 0xe8c7b756, ...\n    SHA-1: 0x5a827999, 0x6ed9eba1, ...\n    SHA-256: 0x428a2f98, 0x71374491, ...\n    SHA-512: 64-bit constants split across MOVT/MOV pairs\n    CRC32: 0xedb88320 (reflected polynomial)"]:::primary
    B:::primary --> C(["HashAlgoMatch:\n  algo: str  (MD5/SHA1/SHA256/SHA512/CRC32/UNKNOWN)\n  matched_constants: List[ConstMatch]\n  confidence: float\n  fmt() → str"]):::output
    A:::input --> D["CustomCBCDetector(ctx)"]:::secondary --> E["scan_function(va, size) → Optional[CBCPattern]\n  Phase 1: BSS pointer pair (block ptr + IV ptr)\n  Phase 2: XOR-with-prev-CT back-edge loop\n  Phase 3: IV load from .rodata at entry"]:::tertiary
    E:::tertiary --> F(["CBCPattern:\n  block_ptr_va: int   (BSS block buffer address)\n  iv_va: int          (IV location in .rodata)\n  xor_loop_va: int    (chaining XOR back-edge)\n  fmt() → str"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

---

## Usage <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

```python
from ablation.analyzers.crypto_pattern_detector import HashAlgoDiscriminator, CustomCBCDetector
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/arm32_firmware.elf')

# Identify all hash implementations
disc = HashAlgoDiscriminator(ctx)
for va, size in zip(ctx.func_starts, ctx.func_sizes):
    match = disc.scan_function(va, size)
    if match.algo != 'UNKNOWN':
        print(f"  {match.algo} at {va:#x}: {match.fmt()}")

# Detect hand-rolled AES-CBC
cbc = CustomCBCDetector(ctx)
for va, size in zip(ctx.func_starts, ctx.func_sizes):
    pattern = cbc.scan_function(va, size)
    if pattern:
        print(f"  Custom CBC at {va:#x}: {pattern.fmt()}")

# Scan a specific range
patterns = cbc.scan_range(va=0x10000, size=0x2000)
print(f"Found {len(patterns)} CBC patterns in range")
```

---

## Example output <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

The following illustrates crypto detection output. Actual addresses and constants are firmware-specific.

```
HashAlgoDiscriminator: arm32_firmware.elf

  SHA-256 at <va>  confidence=0.97
    matched: 0x428a2f98 (K[0]), 0x71374491 (K[1]), 0xb5c0fbcf (K[2])

  MD5 at <va>  confidence=0.99
    matched: 0xd76aa478 (T[1]), 0xe8c7b756 (T[2])

CustomCBCDetector:
  Custom CBC at <va>
    block_ptr: <bss_va>  iv_va: <rodata_va>  xor_loop: <va>
```

---

## False positives <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

**K-table constant matching may fire on coincidental constant sequences**: data structures that happen to contain hash K-values for example test vectors or lookup tables may produce false `HashAlgoMatch` results. Validate by inspecting the surrounding disassembly for the characteristic round-function structure bitwise rotate, and, or, xor operations on 4–8 registers.

**`CustomCBCDetector` requires all three phases to match**: BSS pointer pair alone, without the XOR back-edge and `.rodata` IV, is not flagged as a CBC pattern. This reduces false positives from other BSS-based buffer patterns but may miss unusual CBC implementations that initialize the IV differently.

---

## Pipeline position <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

Run `HashAlgoDiscriminator` and `CustomCBCDetector` during initial binary triage to identify crypto implementations before vulnerability analysis. Identified crypto functions should be excluded from taint tracking to avoid alert fatigue from crypto internals, and named in `BinaryContext` with `ctx.set_name()` for reference in findings.

---

## Reading findings <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

`HashAlgoDiscriminator.scan()` returns a list of `HashAlgoMatch` objects:

| Attribute | Content |
|:---|:---|
| `algo` | Algorithm name for example `'SHA256'`, `'MD5'`, `'CRC32'` |
| `confidence` | Integer 0–100: confidence score based on K-table constant coverage |
| `matched` | `List[ConstMatch]`: each matched constant with `.va` and `.name` |

`CustomCBCDetector.scan()` returns a list of `CBCPattern` objects:

| Attribute | Content |
|:---|:---|
| `outer_func_va` | VA of the outer function or scan range |
| `block_func_va` | VA of the single-block AES call BL target inside the loop |
| `chaining_reg` | Register carrying the previous ciphertext / IV pointer |
| `iv_va` | `Optional[int]`: VA of IV in `.rodata` (None if not resolved) |
| `iv_bytes` | `Optional[bytes]`: 16-byte IV value (None if not resolved) |
| `xor_va` | VA of the first XOR instruction in the loop body |
| `loop_va` | VA of the loop start back-edge target |
| `confidence` | Integer 0–100 |

---

## XorSolver <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

`XorSolver` recovers the repeating-XOR key from an encrypted firmware blob. It does not require knowing the key length in advance.

### Usage <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

```python
from ablation.analyzers.xor_solver import XorSolver

solver = XorSolver('/path/to/encrypted.bin')

# Automated: tries KPA → frequency analysis → Hamming distance, returns best result
result = solver.solve()
print(result.fmt())

if result.key:
    decrypted = result.decrypt(open('/path/to/encrypted.bin', 'rb').read())
    open('/path/to/decrypted.bin', 'wb').write(decrypted)
    # Or:
    solver.decrypt_file('/path/to/decrypted.bin')

# Manual: known-plaintext attack only (fastest, highest confidence if magic matches)
result = solver.kpa_attack(max_probe=64)

# Manual: index-of-coincidence key length estimation
key_len = solver.ic_key_length()
result = solver.freq_attack()   # frequency-based column-by-column recovery
```

### XorSolverResult fields <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

| Field | Type | Description |
|:------|:-----|:------------|
| `key` | `Optional[bytes]` | Recovered key bytes; `None` if recovery failed |
| `key_length` | `Optional[int]` | Key length in bytes |
| `method` | `str` | Attack that succeeded: `'kpa'`, `'hamming+freq'`, or `'manual'` |
| `magic_matched` | `Optional[str]` | KPA magic label (e.g. `'ELF'`, `'gzip'`) if KPA succeeded |
| `confidence` | `float` | 0.0–1.0 confidence estimate |
| `notes` | `str` | Additional diagnostic text |

---

## CryptoAudit <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

`CryptoAudit` in `modules/crypto_audit.py` covers JWT and SAML weakness testing against live endpoints or captured tokens, plus key material extraction from a post-compromise host.

### Usage <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

```python
from modules.crypto_audit import CryptoAudit

audit = CryptoAudit()

# JWT: decode, test alg:none, test empty secret, test known-weak secrets
result = audit.analyze_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.XXXX")
print(result['alg'], result['vulns'])

# Forged JWT with alg:none
forged = audit.forge_jwt_alg_none(result['payload'])

# Key material extraction from a process or config file
keys = audit.extract_key_material('/proc/self/environ')
keys += audit.extract_key_material('/etc/ssl/private/server.key')

# TLS audit: cipher suite and protocol version check
tls = audit.tls_audit('target.example.com', 443)
print(tls)

# Full host audit
report = audit.run_host_audit('/etc/ssl', '/proc/self/environ')
```

---

## See also <sup>[↑](#hashalgodiscriminator--xorsolver--cryptoaudit)</sup>

- [Firmware Signature and Secret Triage](firmware-signature-and-secret-triage.md): key and credential discovery in firmware
- [Generic Vulnerability Profile Sweeps](generic-vulnerability-profile-sweeps.md): `SemanticSearcher` for identifying crypto-adjacent vulnerability patterns
- [Global Symbol and BSS Tracking](global-symbol-and-bss-tracking.md): `BssTaintTracker` that complements CBC BSS pointer detection
