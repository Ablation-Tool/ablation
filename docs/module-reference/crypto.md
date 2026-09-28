# Crypto Modules

Four independent tools: encrypted region detection, XOR key recovery, cryptographic
posture auditing, and BMP LSB steganography / Lagrange secret-sharing key extraction.

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
