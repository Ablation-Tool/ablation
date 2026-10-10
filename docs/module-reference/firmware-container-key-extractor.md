# FirmwareContainerKeyExtractor

## Why this exists

Four things Ablation could not do before this module:

1. **Hardware FortiGate cert keys were inaccessible.** `FortiOSHardwareExtractor` removes the outer XOR layer from FortiOS hardware `.out` files and recovers key confidence above 0.80. The inner gzip partitions remain encrypted because they carry a second layer: a stream cipher whose key is embedded in the firmware container's RSA signature block. Without this extractor, all 99 hardware FortiGate model variants in the research collection have inaccessible cert keys.

2. **No PKCS#1 v1.5 padding block scanner.** The FGT7K-2 finding (fortigate_7kf_re.py) confirmed that Fortinet embeds a 32-byte RC4 key in the PKCS#1 v1.5 padding of the firmware container's signature. There was no module to locate those blocks in a decrypted binary and extract candidate key material from the non-0xFF padding bytes.

3. **No RC4 known-plaintext key tester.** Given candidate keys from PKCS#1 blocks, testing each one against the inner partitions required manual scripting. The gzip magic bytes at partition offsets (0x1f 0x8b 0x08) make a reliable crib for RC4 KPA. This module automates that loop.

4. **No manual key override path for partition decryption.** Hardware teardown or RSA key recovery can produce a known inner key. Without a standardised entry point to apply that key to all partitions at once, decryption was a one-off script, not a reusable pipeline.

---

**File:** `ablation/analyzers/firmware_container_key_extractor.py`

Recovers encryption keys from FortiOS hardware firmware containers and decrypts the inner partitions so downstream analysis can access cert keys and security libraries.

The module runs in three stages. First, it calls `FortiOSHardwareExtractor` to remove the outer XOR layer and locate inner partition offsets. Second, it scans the decrypted binary for PKCS#1 v1.5 signature blocks and extracts candidate key bytes from the padding string. Third, it tests each candidate with RC4 decryption against the known gzip magic at each partition start and confirms which key produces valid gzip output.

When decryption succeeds for a partition that contains `etc/fgt_512.key`, the result's `datafs_path` is set so the caller can extract cert keys the same way as `FortiGateCertKeyScanner`.

---

## Caller contract

All paths in `ExtractionResult` point into a working directory created by `from_path()`. That directory persists until the caller calls `result.cleanup()`. Without the cleanup call the working directory leaks.

```python
result = FirmwareContainerKeyExtractor.from_path('/path/to/firmware.out')
try:
    # use result.datafs_path, result.partitions, etc.
finally:
    result.cleanup()
```

To manage the output directory yourself, pass `output_dir=`. The module writes into that path and `result.cleanup()` becomes a no-op.

---

## Supported cipher types

| Cipher | Detection | Notes |
|---|---|---|
| RC4 stream | PKCS#1 v1.5 candidate tested against gzip magic | Primary path; FGT7K-2 class |
| XOR repeating | Outer key tested as fallback | Covers cases where both layers use the same key |
| Override (caller-specified cipher) | `override_key` + `override_cipher` parameter | For keys recovered by hardware teardown or RSA decrypt |

Not supported: gzip FENCRYPT (PKZIP DES-based) and AES-CBC. Both require additional firmware loader RE.

---

## Usage

```python
from ablation.analyzers.firmware_container_key_extractor import FirmwareContainerKeyExtractor

# Automatic key recovery
result = FirmwareContainerKeyExtractor.from_path(
    '/media/research/Fortinet/FortiGate/Firmware/Hardware/FGT_60F/'
    'FGT_60F-v7.2.13.M-build1762-FORTINET.out'
)
try:
    print(result.report())

    # If datafs was recovered, extract cert keys
    if result.datafs_path:
        import tarfile, hashlib
        with tarfile.open(result.datafs_path, 'r:gz') as tf:
            for name in ('etc/fgt_512.key', 'etc/fgt2.key', 'etc/fgt.key'):
                try:
                    data = tf.extractfile(tf.getmember(name)).read()
                    print(f'{name}: {hashlib.md5(data).hexdigest()}')
                except KeyError:
                    pass
finally:
    result.cleanup()

# XOR override key (from hardware teardown), caller-managed output directory
result = FirmwareContainerKeyExtractor.from_path(
    '/path/to/firmware.out',
    override_key=bytes.fromhex('0102030405...'),
    override_cipher='xor',
    output_dir='/tmp/my_analysis/'
)

# RC4 override key (key recovered via RSA private key decryption)
result = FirmwareContainerKeyExtractor.from_path(
    '/path/to/firmware.out',
    override_key=bytes.fromhex('deadbeef...'),
    override_cipher='rc4',
)
try:
    ...
finally:
    result.cleanup()
```

---

## PKCS#1 v1.5 block structure

Fortinet hardware firmware containers include an RSA-2048 signature block in PKCS#1 v1.5 format. The FGT7K-2 finding established that a 32-byte RC4 key is embedded in the padding string (PS) of that block rather than using the standard 0xFF fill.

```
[0x00][0x01][PS bytes — should be 0xFF, but Fortinet stores key material here][0x00][DigestInfo][Hash]
```

The scanner locates blocks where at least 80% of the PS bytes are 0xFF (real PKCS#1 padding). It extracts the non-0xFF bytes from the padding string as a candidate key. Requiring the 80% threshold prevents the 2-byte `0x00 0x01` pattern from generating false-positive candidates across the full binary.

After a candidate passes this check, key confirmation requires a full 10-byte gzip header match (magic + deflate method byte + FLG reserved-bit check) before the module streams the partition to disk.

---

## Key recovery process

```
hardware .out
  |
  v  FortiOSHardwareExtractor (outer XOR, IC >= 0.5 required)
  decrypted_full.bin  +  inner partition offsets
  |
  +- PKCS#1 block scan (>= 80% 0xFF required)  ->  candidate keys (list)
  |
  +- For each candidate key:
  |    RC4-decrypt first 32 bytes of partition[0]
  |    Check full 10-byte gzip header (magic + CM + FLG reserved bits)
  |    If confirmed: stream-decrypt full partition in 4 MiB chunks
  |
  +- Identify datafs partition (contains fgt_512.key in its tar listing)
       set result.datafs_path
```

---

## Output fields

`ExtractionResult` fields:

| Field | Type | Meaning |
|---|---|---|
| `outer_key` | bytes | 64-byte XOR key from outer layer |
| `outer_key_confidence` | float | IC from FortiOSHardwareExtractor (< 0.5 means wrong format) |
| `pkcs1_candidates` | list[bytes] | Candidate keys extracted from PKCS#1 blocks |
| `partitions` | list[PartitionResult] | One entry per inner partition; `valid_gzip=True` if decrypted |
| `datafs_path` | str or None | Path to decrypted datafs.tar.gz if the cert partition was recovered |
| `workdir` | str or None | Temp dir created by `from_path()`; None if `output_dir=` was passed |
| `error` | str or None | Set if outer extraction failed or a fatal exception occurred |

Call `result.cleanup()` to remove `workdir` when done. It is a no-op if `output_dir=` was passed or if cleanup already ran.

---

## Related modules

- `FortiOSHardwareExtractor` (`fortios_firmware_extractor.py`) -- outer XOR decryption; required dependency
- `FortiGateCertKeyScanner` (`fortigate_cert_key_scanner.py`) -- OVF/VMware cert key fingerprinting
- `FirmwareContainer` (`firmware_container.py`) -- partition-table firmware container parser
