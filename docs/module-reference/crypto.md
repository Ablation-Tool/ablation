# Crypto Modules

Six independent tools: encrypted region detection, XOR key recovery, cryptographic posture auditing, BMP LSB steganography and Lagrange secret-sharing key extraction, hash algorithm identification from K-table constants, and hand-rolled AES-CBC detection in ARM32 Thumb2 binaries.

---

## EntropyMapper

**File:** `ablation/analyzers/entropy_mapper.py`

Sliding-window Shannon entropy scan. EntropyMapper maps a binary file into entropy regions to locate encrypted blobs, compressed sections, crypto key material, and packed payloads.

### Shannon entropy

For a sequence of bytes, Shannon entropy H measures information density:

```
  H = -Σ p(x) * log2(p(x))   for each distinct byte value x

  Maximum possible: H = 8.0 bits/byte
    when all 256 byte values appear with equal frequency (1/256)
    This is the expected distribution of random data (AES ciphertext, key material)

  Minimum possible: H = 0.0 bits/byte
    when only one byte value appears (e.g., a null region, 0x00 padding)
```

### Entropy scale

```
  H ~= 8.0         ENCRYPTED   AES ciphertext, XOR keystream, LZMA, squashfs
  H ~= 6.0 - 8.0   CODE/DATA   compiled code, mixed sections, crypto key material
  H ~= 4.0 - 6.0   CODE/DATA   x86-64/ARM64 .text sections, instruction and data mix
  H ~= 0.0 - 4.0   SPARSE      ASCII strings, null regions, padding
```

### Usage

```python
from ablation.analyzers.entropy_mapper import EntropyMapper

mapper = EntropyMapper('/path/to/firmware.raw')
regions = mapper.classify()

for r in regions:
    print(r.fmt())
    # 0x00000000  [ENCRYPTED 7.94]  ████████████████████████████████
    # 0x00020000  [CODE/DATA 5.21]  ████████████

# Find encrypted/plaintext transitions
transitions = result.find_transitions(threshold=0.5)
for t in transitions:
    print(f"0x{t.offset:x}: {t.from_class} -> {t.to_class}  delta={t.delta:.2f}")
```

---

## XorSolver

**File:** `ablation/analyzers/xor_solver.py`

Automated XOR decryption for firmware. Firmware XOR obfuscation almost always uses a static, repeating multi-byte key. XorSolver tries three attack modes in priority order.

### Attack modes

**Mode 1: Known-plaintext attack (KPA)**

When the plaintext at a fixed offset is known (ELF magic `\x7fELF` at offset 0, gzip magic `\x1f\x8b` at offset 0, etc.), XOR the ciphertext bytes against the known plaintext to derive the key bytes:

```
  ciphertext[i] = plaintext[i] XOR key[i % key_length]

  Derive key[0]: key[0] = ciphertext[0] XOR plaintext[0]
  Derive key[1]: key[1] = ciphertext[1] XOR plaintext[1]
  ...

  Verify: does the derived partial key repeat throughout ciphertext?
    period = key_length (typically 4, 8, or 64 bytes in firmware)
    check: ciphertext[key_length + i] XOR key[i] == plaintext[key_length + i] for known offsets
```

**Mode 2: Hamming distance key length guesser**

Normalized Hamming distance between adjacent ciphertext blocks is minimized when the guessed block size equals the true key length. At the correct key length L, XOR-ing adjacent blocks cancels out the key (since block[i] XOR key = ciphertext_segment and block[i+L] XOR key = next_segment; their XOR = plaintext XOR). Random data has Hamming distance 0.5 normalized; repeating-key XOR data dips below 0.5 at the correct period.

```
  for L in 1..max_len:
    d = hamming_distance(ciphertext[0:L], ciphertext[L:2L]) / L
    minimize d over all L values
    → L at minimum is the key length candidate
```

**Mode 3: Frequency analysis / transposition**

Once key length L is known, split the ciphertext into L byte streams (one per key position). Within each stream, every byte is XOR-ed with the same key byte. Score each candidate key byte (0-255) for each position against the expected opcode frequency distribution for x86-64/ARM code:

```
  for position p in 0..L-1:
    stream_p = ciphertext[p::L]   (every L-th byte starting at p)
    for k in 0..255:
      plaintext_candidate = bytes([b ^ k for b in stream_p])
      score[k] = frequency_match(plaintext_candidate, opcode_freq_table)
    key[p] = argmax(score)
```

### Usage

```python
from ablation.analyzers.xor_solver import XorSolver

solver = XorSolver('/path/to/encrypted_firmware.raw')
result = solver.solve()
if result.key:
    print(f"Key: {result.key.hex()}")
    decrypted = result.decrypt(open('/path/to/encrypted_firmware.raw', 'rb').read())

# KPA only (fastest — use when the plaintext magic is known)
result = solver.kpa_attack(max_probe=64)
```

### Known plaintext dictionary

| Magic | Format | File offset |
|---|---|---|
| `\x7fELF` | ELF binary | 0 |
| `hsqs` / `sqsh` | SquashFS | 0 |
| `\x1f\x8b` | gzip | 0 |
| `\xfd7zXZ\x00` | XZ | 0 |
| `\x02\x53\xef` | ext4 superblock | 0x438 |

---

## CryptoAudit

**File:** `ablation/analyzers/crypto_audit.py`

Post-access cryptographic posture auditor. Finds JWTs with weak secrets, SAML assertion wrapping risks, hardcoded key material, and TLS endpoint weaknesses.

### JWT structure and cracking

```
  JWT format: header.payload.signature
    header  = base64url({"alg":"HS256","typ":"JWT"})
    payload = base64url({"sub":"user","iat":...,"exp":...})
    sig     = HMAC-SHA256(secret, header + "." + payload)

  Weak secret crack:
    for secret in weak_secret_dictionary:
      candidate_sig = HMAC-SHA256(secret, header + "." + payload)
      if candidate_sig == provided_signature:
        cracked (secret found)

  If cracked: attacker can forge arbitrary claims.
```

```python
from ablation.analyzers.crypto_audit import CryptoAudit

auditor = CryptoAudit()
result = auditor.crack_jwt(token_string)
if result.cracked:
    print(f"Secret: '{result.secret}'")
    print(f"Claims: {result.claims}")

findings = auditor.scan_jwt_files('/path/to/app/config/')
```

---

## BmpKeyExtractor / LSBStegoReader / LagrangeKeyExtractor

**File:** `ablation/analyzers/lsb_stego_extractor.py`

Recovers key material hidden in BMP files using LSB steganography combined with a Lagrange polynomial secret-sharing scheme (Shamir-style). Found in stripped ARM32 Android `.so` binaries where multiple seeds index into separate polynomials stored in the LSB channel of a BMP asset.

### Lagrange secret sharing in brief

A Lagrange polynomial through N points uniquely determines a degree-(N-1) polynomial. In Shamir's scheme, the secret is the polynomial's value at x=0. Given N coordinate pairs (x_i, y_i), the secret is reconstructed:

```
  f(x) = Σ y_i * L_i(x)   where L_i(x) = Π (x - x_j)/(x_i - x_j)
                                               j≠i

  f(0) = Σ y_i * Π (-x_j) / (x_i - x_j)
               j≠i

  This is evaluated over rational arithmetic (imath mp_rat) to avoid
  floating-point error. The result is then serialized to bytes.
```

The BMP LSB channel stores the coordinate pairs: each pixel's least-significant bit contributes one bit of the point data. The seed string determines the pixel offset (via hash), and the layout describes how many type groups and coordinate pairs follow.

### Byte-order behavior

Output bytes are little-endian. Negative polynomial values receive a reverse two's complement transformation where carry propagates from MSByte toward LSByte (not the standard direction). Bit-aligned integers where `nbits % 8 == 0` get one extra trailing zero byte appended. These behaviors match the target binary's `imath mp_int_to_binary` path exactly.

### Usage

```python
from ablation.analyzers.lsb_stego_extractor import BmpKeyExtractor

ext = BmpKeyExtractor('/path/to/keys.bmp')
result = ext.extract('MySeed')
print(result.fmt())
# seed='MySeed'  type_count=2  n_groups=147  n_pts=73
# raw_key_hex (124B): f5d794352a4f64f2...
#   component[0] (62B): f5d794352a4f64f2...
#   component[1] (62B): 320b9aa4d6fbbb43...
```

### Identification checklist

Look for this scheme when:

1. A `.so` imports `read_keys_from_content` or a similarly named symbol.
2. The BMP is a small image with no obvious visual content.
3. `mp_rat_read_string` is called with radix 16 (coordinates are hex integers).
4. A Vandermonde matrix construction precedes Gaussian elimination over rationals.
5. Output strings are 60-70 bytes each, multiple per seed.

---

## HashAlgoDiscriminator

**File:** `ablation/analyzers/crypto_pattern_detector.py`

Identifies hash algorithms (MD5, SHA-1, SHA-256, SHA-512, CRC32) from K-table and round-constant signatures found in compiled ARM32 / Thumb2 code.

### How cryptographic constants appear in compiled code

Each hash algorithm uses unique round constants derived from mathematical functions (cube roots of primes for SHA-256, sine values for MD5). These constants are loaded as 32-bit immediates in compiled code. Two loading mechanisms exist in ARM32 Thumb2:

```
  MOVW/MOVT pair (Thumb2 large-immediate encoding):
    MOVW Rd, #lo16    ; load lower 16 bits
    MOVT Rd, #hi16    ; load upper 16 bits, merge
    result = (hi16 << 16) | lo16 = 32-bit constant

    Tracker maintains pending_movw[register] between instructions.
    When MOVT fires: full constant = pending_movw[Rd] | (MOVT_imm << 16)

  LDR Rx, [PC, #N] (literal pool load):
    constant is stored at (insn_va & ~3) + 4 + N in the binary
    read directly from binary bytes at that offset
```

### Algorithm signatures

| Algorithm | Discriminating constants | Notes |
|---|---|---|
| MD5 | K[0..7]: 0xd76aa478, 0xe8c7b756, 0x242070db, ... | K-table from `floor(abs(sin(i+1)) * 2^32)` |
| SHA-1 | Round constants: 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 | 4 constants cover all 80 rounds |
| SHA-256 | IV H[0..7] + K[0..7]: 0x6a09e667, 0x428a2f98, ... | Shared upper half with SHA-512 |
| SHA-512 | Unique K[0..3] lower halves: 0xd728ae22, 0xf3bcc908, ... | These do not appear in SHA-256 |
| CRC32 | Reflected polynomial: 0xedb88320 | |

The shared SHA-256/SHA-512 ambiguity (first eight K-table upper-half words are identical) is resolved by checking for SHA-512-unique lower-half constants.

```python
from ablation.analyzers.crypto_pattern_detector import HashAlgoDiscriminator

disc = HashAlgoDiscriminator(open('/path/to/lib.so', 'rb').read(), load_addr=0)
result = disc.scan_function(va=0xf978, size=0x200)
print(result.fmt())
# MD5  conf=100  [0xf9ba:MD5_K0, 0xf9da:MD5_K1, 0xf9fc:MD5_K2, ...]

result = HashAlgoDiscriminator.identify([0xd76aa478, 0xe8c7b756, 0x242070db])
# HashAlgoMatch(algo='MD5', confidence=37, matched=[...])
```

**Important:** MD5 and SHA-1 share the same four initialization constants (A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476). Scan the compress function (which uses the K-table), not the init function.

---

## CustomCBCDetector

**File:** `ablation/analyzers/crypto_pattern_detector.py`

Detects hand-rolled AES-128-CBC patterns in ARM32 Thumb2 binaries. Targets the structural fingerprint of vendor-implemented CBC where the developer calls a single-block AES function in a loop and manually handles the CBC XOR chaining, rather than calling `mbedtls_aes_crypt_cbc`.

### What CBC chaining looks like in assembly

```
  Standard CBC decrypt (D = AES block decrypt):
    plaintext[0] = D(ciphertext[0]) XOR IV
    plaintext[1] = D(ciphertext[1]) XOR ciphertext[0]
    plaintext[i] = D(ciphertext[i]) XOR ciphertext[i-1]

  Hand-rolled ARM32 Thumb2 implementation:
    ; pre-loop: IV pointer loaded into chaining register
    LDR  r5, [pc, #N]         ; r5 = ptr to IV in .rodata

    ; loop body (16-byte block iteration):
    loop:
      STR  r6, [bss1]         ; update block pointer in BSS
      BL   aes_block_fn       ; single-block AES decrypt (r6=input, r7=output)

      ; XOR 16 bytes of AES output with r5 (prev CT or IV)
      LDRB r2, [r5, #0]
      EOR  r2, r2, r8
      STRB r2, [r7, #0]       ; x16 iterations with incrementing offset

      MOV  r5, r4             ; advance chaining register to current CT block
      CMP  ...
      BLO  loop               ; backward branch
```

### Scoring heuristic (four signals)

| Signal | Points | How detected |
|---|---|---|
| BL inside a backward-branch loop | 40 | `CS_GRP_CALL` in backward-branch loop body |
| 16-byte XOR with register | 30 | 4+ EOR or 1+ VEOR in loop body |
| MOV updates LDRB base register | 20 | MOV Rd, Rs where Rd appears as LDRB base |
| Pre-loop LDR into chaining register | 10 | LDR Rx, [PC, #N] before loop; 16 non-null bytes at target |

Patterns scoring >= 50 are returned. Score 90-100 is high-confidence CBC.

```python
from ablation.analyzers.crypto_pattern_detector import CustomCBCDetector

det = CustomCBCDetector(open('/path/to/lib.so', 'rb').read(), load_addr=0)
patterns = det.scan_range(va=0xa000, size=0x2000)
for p in patterns:
    print(p.fmt())
# CBCPattern  conf=90  outer=0xa000  block_fn=0xa9a0  chain_reg=r5
#             iv_va=0x6f10  iv=b'7178265647164836'
```

The EOR-register detection works for byte-by-byte CBC implementations. If the compiler vectorizes the XOR into NEON VEOR only, the chaining register cannot be derived from LDRB bases and maximum confidence is 70.
