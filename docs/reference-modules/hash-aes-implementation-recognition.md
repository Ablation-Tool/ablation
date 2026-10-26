# Hash and AES Implementation Recognition

Identify hash algorithm implementations MD5, SHA-1, SHA-256, SHA-512, CRC32 and hand-rolled AES-128-CBC in ARM32/Thumb2 disassembly: using K-table constant fingerprinting for hash identification and behavioral pattern matching for CBC mode detection.

---

## Why this exists

1. **Stripped firmware frequently contains inlined or hand-rolled cryptographic implementations that are invisible to symbol-name analysis: a function named `sub_401200` that contains the MD5 K-table constants is provably an MD5 implementation regardless of its name.** `HashAlgoDiscriminator` extracts 32-bit constants from literal pools and immediate loads in a function, then matches against known K-tables MD5 round constants, SHA-1 initial hash values, SHA-256/512 K values, CRC32 polynomial. The match is definitive: no other function in normal firmware contains these exact constant sequences.

2. **`CustomCBCDetector` identifies hand-rolled AES-128-CBC in ARM32 Thumb2 by its behavioral signature: a BSS-tracked block pointer, XOR-with-previous-ciphertext chaining the defining operation of CBC mode, and an IV loaded from `.rodata`.** This pattern appears in network appliance firmware that implements AES-CBC without calling an external library: the implementation is directly auditable for IV reuse, key derivation errors, and padding oracle conditions.

3. **Finding a custom AES-CBC implementation without using a constant-time comparison for CBC-MAC authentication is a common source of padding oracle vulnerabilities in embedded firmware.** `CustomCBCDetector` flags the implementation's location; manual inspection of the MAC comparison at the function's caller determines whether a timing oracle exists.

---

## How it works

```mermaid
flowchart TD
    A(["HashAlgoDiscriminator(binary_data, base_va, arch='arm32')"]):::input --> B["extract_constants(va, size) → List[(va, value)]\n  Capstone ARM32 disassembly of range\n  Collect: LDR [pc, #N] pool loads\n  Collect: MOVW/MOVT constant pairs\n  Collect: MOV #imm (12-bit ARM immediates)"]:::primary
    B:::primary --> C(["identify(constants) → HashAlgoMatch:\n  Match collected 32-bit values against:\n  MD5: {0xd76aa478, 0xe8c7b756, 0x242070db, ...}\n  SHA-1: {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, ...}\n  SHA-256: {0x428a2f98, 0x71374491, 0xb5c0fbcf, ...}\n  SHA-512: {0x428a2f98d728ae22, ...} (64-bit)\n  CRC32: {0x77073096, 0xee0e612c, ...}\n  Returns algorithm name + match count"]):::output

    D(["CustomCBCDetector(binary_data, base_va)"]):::input --> E["scan_range(va, size) → List[CBCPattern]:\n  Look for behavioral CBC signature:\n  1. BSS pointer load (global block pointer)\n  2. XOR r_N, r_N, r_prev (chaining: CT_block XOR prev_CT)\n  3. IV load from .rodata (ldr [pc, #N] where target is in .rodata)\n  4. AES round constant loads (0x63, 0x9e, Rcon table)\n  Returns CBCPattern: block_ptr_va, iv_va, xor_va, confidence"]:::secondary
    E:::secondary --> F(["scan_function(va, size) → Optional[CBCPattern]\n  Wrapper for single-function scan"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.crypto_pattern_detector import HashAlgoDiscriminator, CustomCBCDetector

data = open('/path/to/target.elf', 'rb').read()
base_va = 0   # or actual load VA

# ── Hash identification ───────────────────────────────────────────────────────
discriminator = HashAlgoDiscriminator(data, base_va, arch='arm32')

# Scan a function by VA and size
match = discriminator.scan_function(va=0x401200, size=0x200)
print(match.fmt())
# → "SHA-256 (K-table match, 64/64 constants)"

# Scan any range for constants, then identify
constants = discriminator.extract_constants(va=0x401200, size=0x200)
match2 = HashAlgoDiscriminator.identify(constants)
print(match2.algorithm, match2.match_count)

# ── CBC detection ─────────────────────────────────────────────────────────────
cbc_detector = CustomCBCDetector(data, base_va)
patterns = cbc_detector.scan_range(va=0x401000, size=0x2000)
for p in patterns:
    print(p.fmt())
    print(f"  Block ptr at {p.block_ptr_va:#x}, IV at {p.iv_va:#x}")
```

---

## Example output

The following illustrates the recognition output format. Actual addresses and counts are binary-specific.

```
HashAlgoMatch:
  algorithm: SHA-256
  match_count: 64/64 K-table constants matched
  confidence: HIGH
  first_match_va: <va>

CBCPattern:
  block_ptr_va: <va>  (BSS global block pointer)
  iv_va: <va>         (IV loaded from .rodata)
  xor_va: <va>        (chaining XOR instruction)
  confidence: 0.92
```

---

## False positives

**`HashAlgoDiscriminator` may match CRC32 in firmware that implements Ethernet FCS, this is a legitimate CRC32 implementation, not a cryptographic hash usage.** CRC32 findings should be labeled "implementation found" not "cryptographic use found." Distinguish by context: CRC32 in a network receive path is Ethernet FCS, not a hash function.

**`CustomCBCDetector` requires the AES round constants `0x63`, Rcon table to be present in the scan range.** AES implementations that load their Rcon table from a different section or compute it on-the-fly will score below the confidence threshold and not generate a `CBCPattern` finding. Use `scan_range()` with a wider range if the S-box or Rcon table is in a separate section.

---

## Pipeline position

Run `HashAlgoDiscriminator` and `CustomCBCDetector` after `SemanticSearcher` identifies functions tagged with "crypto", "hash", "cipher", or "encrypt" in their embedding neighborhood. Confirming the algorithm identity with K-table matching provides a definitive label for `BinaryContext.set_name()`. For AES-CBC findings, proceed to manual inspection of the CBC-MAC comparison path to assess padding oracle risk.

---

## See also

## Reading output

`HashAlgoDiscriminatorbinary, load_addr.scanva, size` returns `List[HashAlgoMatch]`:

| Attribute | Content |
|:---|:---|
| `algo` | Algorithm name for example `'SHA-256'`, `'MD5'`, `'SHA-1'`, `'CRC32'` |
| `confidence` | Integer 0–100 |
| `matched` | `List[ConstMatch]`: constant match sites used for identification |

`CustomCBCDetectorbinary, load_addr.scan_rangeva, size` returns `List[CBCPattern]`:

| Attribute | Content |
|:---|:---|
| `outer_func_va` | VA of the function or scan range containing the CBC loop |
| `block_func_va` | VA of the single-block AES call target inside the loop |
| `chaining_reg` | Register carrying the previous ciphertext / IV pointer |
| `iv_va` | VA of the IV in `.rodata`, or `None` if not resolved |
| `iv_bytes` | 16-byte IV value, or `None` if not resolved |
| `xor_va` | VA of the first XOR instruction in the loop body |
| `loop_va` | VA of the loop start back-edge target |
| `confidence` | Integer 0–100 |

---

## See also

- [Cryptographic Analysis](cryptographic-analysis.md): RSA/ECDSA/RNG analysis complementary to hash/AES identification
- [RSA, ECDSA, and Randomness Checks](rsa-ecdsa-and-randomness-checks.md): public key crypto implementation review
- [Source Code Auditing](source-code-auditing.md): for OpenSSL/mbedTLS source-available targets
- [Taint Analysis](taint-analysis.md): after identifying the crypto implementation, trace key material flow
