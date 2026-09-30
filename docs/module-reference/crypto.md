# Crypto Modules

Six independent tools: encrypted region detection, XOR key recovery, cryptographic
posture auditing, BMP LSB steganography / Lagrange secret-sharing key extraction,
hash algorithm identification from K-table constants, and hand-rolled AES-CBC
detection in ARM32 Thumb2 binaries.

---

## EntropyMapper

**File:** `ablation/analyzers/entropy_mapper.py`

Sliding-window Shannon entropy scan. EntropyMapper maps a binary file into entropy regions
to locate encrypted blobs, compressed sections, crypto key material, and packed payloads.

### Entropy scale

```
H ~= 8.0         ENCRYPTED  -- AES ciphertext, XOR keystream, LZMA, squashfs
H ~= 6.0-8.0     CODE/DATA  -- compiled code, mixed sections, crypto key material
H ~= 4.0-6.0     CODE/DATA  -- x86-64/ARM64 .text sections, instruction and data mix
H ~= 0.0-4.0     SPARSE     -- ASCII strings, null regions, padding
```

### Usage

```python
from ablation.analyzers.entropy_mapper import EntropyMapper

mapper = EntropyMapper('/path/to/firmware.raw')
regions = mapper.classify()

for r in regions:
    print(r.fmt())
    # Output: 0x00000000  [ENCRYPTED 7.94]  ████████████████████████████████
    #         0x00020000  [CODE/DATA 5.21]  ████████████

# One-shot classification
result = EntropyMapper.classify_file('/path/to/firmware.raw')
print(result.summary())

# Find encrypted/plaintext transitions
transitions = result.find_transitions(threshold=0.5)
for t in transitions:
    print(f"0x{t.offset:x}: {t.from_class} -> {t.to_class}  delta={t.delta:.2f}")
```

### Typical use cases

**Encrypted firmware layer detection:** Run EntropyMapper on a raw firmware image before
attempting SquashFS extraction. High entropy at the start means the filesystem layer is
encrypted. Use XorSolver to recover the key.

**Key material location:** An 8.0-entropy blob surrounded by 5.0-entropy code regions is
often an embedded AES key, RSA private key, or TLS certificate.

**Packed section detection:** Enterprise firmware sometimes packs individual `.so` libraries.
An ENCRYPTED region inside an ELF `.data` section that starts with a recognizable magic once
decrypted is a packed embedded binary.

---

## XorSolver

**File:** `ablation/analyzers/xor_solver.py`

Automated XOR decryption for firmware. Firmware XOR obfuscation almost always uses a static,
repeating multi-byte key. XorSolver tries three attack modes in priority order.

### Attack modes

**Mode 1: Magic Byte KPA (Known Plaintext Attack)**

When the plaintext at a fixed offset is known (e.g., an ELF magic `\x7fELF` at offset 0),
XOR the ciphertext bytes against the known plaintext to derive the key bytes, then verify that
the derived partial key repeats throughout the ciphertext.

Best for: firmware images where the decrypted result has a known header (ELF, SquashFS, gzip,
ext4, U-Boot, LZMA).

**Mode 2: Hamming Distance Key Length Guesser**

Normalized Hamming distance between adjacent ciphertext blocks is minimized when the guessed
block size equals the true key length. Complexity: O(max_len * N/L).

**Mode 3: Frequency Analysis / Transposition**

Once key length L is known, split the ciphertext into L byte streams (one per key position).
Score each candidate byte for each position against the x86-64/ARM opcode frequency
distribution.

### Usage

```python
from ablation.analyzers.xor_solver import XorSolver

solver = XorSolver('/path/to/encrypted_firmware.raw')

# Full auto -- tries all three modes in priority order
result = solver.solve()
if result.key:
    print(f"Key: {result.key.hex()}")
    decrypted = result.decrypt(open('/path/to/encrypted_firmware.raw', 'rb').read())

# KPA only (fastest -- use when the plaintext magic is known)
result = solver.kpa_attack(max_probe=64)

# Key length only
key_len = solver.guess_key_length(ciphertext_bytes, min_len=1, max_len=64)

# Decrypt with a known key
decrypted = solver.decrypt(ciphertext_bytes, key=b'\xde\xad\xbe\xef')
```

### Known plaintext dictionary

The KPA attack includes a built-in dictionary of firmware magic bytes:

| Magic | Format | File offset |
|---|---|---|
| `\x7fELF` | ELF binary | 0 |
| `hsqs` / `sqsh` | SquashFS | 0 |
| `\x1f\x8b` | gzip | 0 |
| `\xfd7zXZ\x00` | XZ | 0 |
| `LZMA` | LZMA | 0 |
| `\x02\x53\xef` | ext4 superblock | 0x438 |

Add custom entries for vendor-specific container formats by extending `_MAGIC_DICT`.

---

## CryptoAudit

**File:** `ablation/analyzers/crypto_audit.py`

Post-access cryptographic posture auditor. CryptoAudit finds JWTs with weak secrets, SAML
assertion wrapping risks, hardcoded key material, and TLS endpoint weaknesses.

### JWT audit

```python
from ablation.analyzers.crypto_audit import CryptoAudit

auditor = CryptoAudit()

# Crack a JWT against the weak-secret dictionary
result = auditor.crack_jwt(token_string)
if result.cracked:
    print(f"Secret: '{result.secret}'")
    print(f"Claims: {result.claims}")

# Scan a directory for JWTs in config files, logs, and env files
findings = auditor.scan_jwt_files('/path/to/app/config/')
```

### Built-in weak secret dictionary

Ordered by observed frequency in production credential leaks:

```
"" (empty string), "secret", "password", "admin", "key", "test",
"changeme", "12345", "your-256-bit-secret", "jwt_secret", "supersecret", ...
```

### Hardcoded key scan

```python
findings = auditor.scan_binary_keys('/path/to/binary.so')
for f in findings:
    print(f"  0x{f.va:x}: {f.key_type} ({len(f.key_bytes)} bytes)")
```

### TLS posture check

```python
result = auditor.check_tls('api.internal.example.com', port=443)
print(result.summary())
# Checks: protocol version, cipher suite strength, cert expiry, weak curves
```

---

## BmpKeyExtractor / LSBStegoReader / LagrangeKeyExtractor

**File:** `ablation/analyzers/lsb_stego_extractor.py`

Recovers key material hidden in BMP files using LSB steganography combined with a
Lagrange polynomial secret-sharing scheme (Shamir-style, evaluated over rational
arithmetic via imath). Found in stripped ARM32 Android .so binaries where multiple
seeds index into separate polynomials stored in the LSB channel of a BMP asset.

The byte-order behavior matches the imath `mp_int_to_binary` path:
- Output bytes are little-endian.
- Negative polynomial values receive a reverse two's complement transformation:
  carry propagates from MSByte toward LSByte (not the standard direction).
- Bit-aligned integers (nbits % 8 == 0) get one extra trailing zero byte appended.

No external dependencies beyond stdlib. Prime generation uses pure-Python Miller-Rabin.

---

### BmpKeyExtractor

High-level entry point.

```python
from ablation.analyzers.lsb_stego_extractor import BmpKeyExtractor

ext = BmpKeyExtractor('/path/to/keys.bmp')

result = ext.extract('MySeed')
print(result.fmt())
# seed='MySeed'  type_count=2  n_groups=147  n_pts=73
# raw_key_hex (124B): f5d794352a4f64f2...
#   component[0] (62B): f5d794352a4f64f2...
#   component[1] (62B): 320b9aa4d6fbbb43...

# Multiple seeds
for seed in ['SeedA', 'SeedB']:
    r = ext.extract(seed)
    print(f"{seed}: {r.raw_key_hex[:32]}...")
```

---

### LSBStegoReader

Low-level pixel LSB reader. Use when you need raw coordinate pairs without running
the Lagrange reconstruction.

```python
from ablation.analyzers.lsb_stego_extractor import LSBStegoReader

bmp = open('/path/to/keys.bmp', 'rb').read()
reader = LSBStegoReader(bmp[0x36:])        # skip 54-byte BMP header

offset = reader.seed_offset('MySeed')      # hash seed to pixel offset
raw_bytes, next_off = reader.read_bytes(offset, 8)
pairs, type_count, n_groups = reader.extract_coords('MySeed')
print(f"type_count={type_count}, n_groups={n_groups}, pairs={len(pairs)}")
```

---

### LagrangeKeyExtractor

Reconstructs one polynomial component from coordinate pairs via CRT over multiple
63-bit primes.

```python
from ablation.analyzers.lsb_stego_extractor import LagrangeKeyExtractor

kex = LagrangeKeyExtractor()               # 8 default 63-bit primes
n_pts = n_groups // type_count

for comp in range(type_count):
    slice_pairs = pairs[comp * n_pts : (comp + 1) * n_pts]
    hex_str = kex.extract(slice_pairs, n_pts)
    print(f"component {comp}: {len(hex_str)//2}B")
```

---

### Identification checklist

Look for this scheme when:

1. A `.so` imports `read_keys_from_content` or a similarly named symbol.
2. The BMP is a small image with no obvious visual content.
3. `mp_rat_read_string` is called with radix 16 -- coordinates are hex integers.
4. A Vandermonde matrix construction precedes Gaussian elimination over rationals.
5. Output strings are 60-70 bytes each, multiple per seed.

Typical output width: 62 bytes (124 hex chars) per negative component (reverse-TC
applied); 63 bytes (126 hex chars) per positive bit-aligned component (extra byte).

---

## HashAlgoDiscriminator

**File:** `ablation/analyzers/crypto_pattern_detector.py`

Identifies hash algorithms (MD5 / SHA-1 / SHA-256 / SHA-512 / CRC32) from K-table
and round-constant signatures found in compiled ARM32 / Thumb2 code.

Extracts 32-bit constants via two mechanisms:

- **MOVW/MOVT pairs** -- Thumb2 encodes large immediates as a pair of 16-bit half-words.
  `MOVW Rd, #lo16` followed by `MOVT Rd, #hi16` is reconstructed into the full 32-bit
  constant by tracking pending MOVW values per register.

- **LDR Rx, [PC, #N]** -- literal pool loads. The constant is read directly from the
  binary at `(insn_va & ~3) + 4 + N`.

Matched against five algorithm signature tables. The shared SHA-256 / SHA-512 ambiguity
(first eight K-table upper-half words are identical) is resolved by checking for
SHA-512-unique lower-half constants (K[0..3]\_LO, IV[0..3]\_LO).

```python
from ablation.analyzers.crypto_pattern_detector import HashAlgoDiscriminator

disc = HashAlgoDiscriminator(open('/path/to/lib.so', 'rb').read(), load_addr=0)

# Scan a known function range
result = disc.scan_function(va=0xf978, size=0x200)
print(result.fmt())
# MD5  conf=100  [0xf9ba:MD5_K0, 0xf9da:MD5_K1, 0xf9fc:MD5_K2, 0xfa1e:MD5_K3...]

# Match from a list of constants (no disassembly -- e.g., from a prior sweep)
result = HashAlgoDiscriminator.identify([0xd76aa478, 0xe8c7b756, 0x242070db])
# HashAlgoMatch(algo='MD5', confidence=37, matched=[...])

# Get all raw constants in a range (for manual inspection)
pairs = disc.extract_constants(va=0xf978, size=0x200)
# [(0xf9ba, 0xd76aa478), (0xf9da, 0xe8c7b756), ...]
```

### Algorithm signatures

| Algorithm | Discriminating constants | Notes |
|---|---|---|
| MD5 | K[0..7]: 0xd76aa478, 0xe8c7b756, 0x242070db, ... | K-table from sin() |
| SHA-1 | Round constants: 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 | 4 constants cover all 80 rounds |
| SHA-256 | IV H[0..7] + K[0..7]: 0x6a09e667, 0x428a2f98, ... | Shared upper half with SHA-512; disambiguated below |
| SHA-512 | Unique K[0..3] lower halves + IV lower halves: 0xd728ae22, 0xf3bcc908, ... | These values do not appear in SHA-256 |
| CRC32 | Reflected polynomial: 0xedb88320 | |

### Init constants are NOT discriminating

MD5 and SHA-1 share the same four initialization constants (A=0x67452301,
B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476). A function that sets only these values
is an init function common to both algorithms. Use `scan_function` on the block
compress function (which uses the K-table), not the init function.

---

## CustomCBCDetector

**File:** `ablation/analyzers/crypto_pattern_detector.py`

Detects hand-rolled AES-128-CBC patterns in ARM32 Thumb2 binaries. Targets the
structural fingerprint of vendor-implemented CBC where the developer calls a
single-block AES function in a loop and manually handles the CBC chaining, rather
than calling `mbedtls_aes_crypt_cbc`.

### What it detects

```
; pre-loop: IV pointer loaded into chaining register
LDR  r5, [pc, #N]        ; r5 = ptr to IV in .rodata

; loop body:
loop:
  STR  r6, [bss1]        ; update block pointer in BSS
  BL   aes_block_fn      ; single-block AES decrypt/encrypt

  ; XOR 16 bytes of AES output with r5 (prev CT or IV)
  LDRB r2, [r5, #0]  ;  x16, incrementing offset
  EOR  r2, r2, r8
  STRB r2, [r7, #0]

  MOV  r5, r4            ; advance chaining reg = ptr to current CT block
  CMP  ...
  BLO  loop
```

### Scoring heuristic (four signals)

| Signal | Points | How detected |
|---|---|---|
| BL inside a backward-branch loop | 40 | CS_GRP_CALL in backward-branch loop body |
| 16-byte XOR with register | 30 | 4+ EOR or 1+ VEOR in loop body |
| MOV updates LDRB base register | 20 | MOV Rd, Rs where Rd appears as LDRB base |
| Pre-loop LDR into chaining reg | 10 | LDR Rx, [PC, #N] before loop; 16 non-null bytes at target |

Patterns scoring >= 50 are returned. Score 90-100 = high-confidence CBC.

```python
from ablation.analyzers.crypto_pattern_detector import CustomCBCDetector

det = CustomCBCDetector(open('/path/to/lib.so', 'rb').read(), load_addr=0)

# Scan a .text range for CBC patterns
patterns = det.scan_range(va=0xa000, size=0x2000)
for p in patterns:
    print(p.fmt())
# CBCPattern  conf=90  outer=0xa000  block_fn=0xa9a0  chain_reg=r5
#             iv_va=0x6f10  iv=b'7178265647164836'

# When function boundaries are known
pat = det.scan_function(va=0xa684, size=0xa0)
```

### Identification checklist

Look for this pattern when:

1. The binary does NOT import `mbedtls_aes_crypt_cbc` or `AES_cbc_encrypt` from the
   PLT but clearly does AES operations.
2. The binary has a BSS pointer that is overwritten at the start of each loop iteration
   (tracks the current ciphertext block position).
3. A `.rodata` string of 8-16 printable characters exists near the string pool -- it
   is almost certainly the hardcoded IV.
4. The single-block AES function starts by loading a round key at an offset of 0xa0
   from the key schedule BSS (= last round key = decryption direction).

### Limitation

The EOR-register detection works for byte-by-byte CBC implementations. If the
compiler vectorizes the XOR into NEON VEOR only, the chaining register cannot be
derived from LDRB bases; in that case signals 3 and 4 are not scored and maximum
confidence is 70.
