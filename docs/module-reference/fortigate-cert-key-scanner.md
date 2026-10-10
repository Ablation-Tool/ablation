# FortiGateCertKeyScanner

## Why this exists

Four things Ablation could not do before this module:

1. **No batch key fingerprinting for FortiGate firmware.** Extracting cert keys from a FortiGate OVF package required five manual steps: unzip the outer archive, unzip the inner OVF archive, convert the VMDK to a raw image, extract the P1 partition, and read the tar archive. Running that manually across 20+ versions took over an hour.

2. **No unknown-key detection.** The Fortinet shared key corpus has five known MD5 fingerprints across CRITICAL and HIGH severity families. A new firmware release could introduce a rotated key or a new family. Without a comparison baseline, that change was invisible.

3. **No persistent scan cache.** VMDK conversion takes about 30 seconds per image. Repeated sweeps of the same directory re-ran the full pipeline every time. The scanner caches results by file size and modification time so a 20-image sweep runs in under a second on the second pass.

4. **No coverage for bare disk formats.** KVM QCOW2, Hyper-V VHD, and Hyper-V VHDX images arrive without an outer OVF ZIP wrapper. The OVF pipeline did not apply to them. `from_disk()` covers every FortiGate virtual deployment format in a single interface.

---

**File:** `ablation/analyzers/fortigate_cert_key_scanner.py`

Extracts and fingerprints `fgt_512.key`, `fgt2.key`, and `fgt.key` from FortiGate firmware packages. Compares each MD5 against the known Fortinet shared key family table and flags any unrecognised MD5 as a potential new finding. Each key also carries a SHA-256 fingerprint for cross-validation.

**Supported input formats:**

| Method | Input | qemu-img flag |
|---|---|---|
| `from_path()` | OVF ZIP (`.out.zip`) | vmdk (via inner ZIP) |
| `from_disk()` | KVM QCOW2 (`.qcow2`) | qcow2 |
| `from_disk()` | Hyper-V VHD (`.vhd`) | vpc |
| `from_disk()` | Hyper-V VHDX (`.vhdx`) | vhdx |
| `from_disk()` | Bare VMDK (`.vmdk`) | vmdk |

All FortiGate virtual disks place P1 at LBA 2048 (256 MiB ext4, contains `datafs.tar.gz`). FAZ and FMG KVM images use P1 at LBA 8193 and have no `datafs.tar.gz`; `from_disk()` returns an error result for those — this is correct behavior, not a scanner bug.

**Not supported:** Hardware `.out` files (inner partitions encrypted; use `FirmwareContainerKeyExtractor` for those).

**Requirements:** `qemu-img` and `debugfs` on PATH (install `qemu-utils` and `e2fsprogs`).

---

## Known key families

| MD5 | Key name | Severity | Notes |
|---|---|---|---|
| `1158fa1e43c915520a051fe4bebf90d6` | fgt_512.key Gen1 | CRITICAL | 512-bit RSA; shared FGT/FFW/FEXT/FWF from at least v6.4.15 |
| `12b045d81de1c16c531e2a43e17f0332` | fgt_512.key Gen2 | CRITICAL | 512-bit RSA; ARM64 v8.0.0 variant |
| `c8eaa255efceab1512356f46f90b57b5` | fgt2.key | CRITICAL | 2048-bit RSA; cross-platform; FortiRecorder MitM path |
| `4e447a814e6ea1e8b9ac8581ffd4c600` | fgt.key | HIGH | 2048-bit RSA; FGT VM64 + FortiWiFi JFFS2; FortiRecorder MitM path |
| `c0ab56309ab9647b28529d412d44b676` | fsw_512.key | CRITICAL | 512-bit RSA; FortiSwitch v7 |

MD5 is used for family identification only. Each `KeyEntry` also carries `sha256` for cross-validation. A result with `family == "UNKNOWN"` means the MD5 is not in this table and is an immediate finding candidate.

---

## Usage

```python
from ablation.analyzers.fortigate_cert_key_scanner import FortiGateCertKeyScanner

# OVF ZIP (VMware/ESXi)
result = FortiGateCertKeyScanner.from_path(
    '/media/research/Fortinet/FortiGate/Firmware/Virtual/FGT_VM64/'
    'FGT_VM64-v7.4.12.M-build2902-FORTINET.out.zip'
)
print(FortiGateCertKeyScanner.report([result]))

# Bare KVM QCOW2
result = FortiGateCertKeyScanner.from_disk(
    '/media/research/Fortinet/VM-KVM/FGT_VM64_KVM-v7.4.12.M-build2902-FORTINET.qcow2'
)

# Bare Hyper-V VHD
result = FortiGateCertKeyScanner.from_disk(
    '/media/research/Fortinet/VM-HV/FGT_VM64_HV-v7.4.12.M-build2902-FORTINET.vhd'
)

# Batch scan a directory (OVF ZIPs)
results = FortiGateCertKeyScanner.batch_scan(
    '/media/research/Fortinet/FortiGate/Firmware/Virtual/FGT_VM64/'
)
print(FortiGateCertKeyScanner.report(results))

# Find unknown key variants
unknowns = [r for r in results if r.has_unknown_keys()]
if unknowns:
    print(f"{len(unknowns)} images with unrecognised key material")

# Force re-scan after a transient failure (disk full, missing qemu-img)
result = FortiGateCertKeyScanner.from_path('/path/to/firmware.zip', force_rescan=True)
result = FortiGateCertKeyScanner.from_disk('/path/to/firmware.qcow2', force_rescan=True)
```

---

## Extraction pipeline

```
outer .zip
  +- inner .out.ovf.zip
       +- fortios.vmdk  (VMware4 streamOptimized)
            |
            v  qemu-img convert -f vmdk -O raw
            fortios.raw  (2 GiB sparse)
            |
            v  read P1 at LBA 2048 (256 MiB, ext4)
            p1.ext4
            |
            v  debugfs dump datafs.tar.gz
            datafs.tar.gz  (16-17 MiB)
            |
            +- etc/fgt_512.key  -> MD5 + SHA-256 -> family lookup
            +- etc/fgt2.key     -> MD5 + SHA-256 -> family lookup
            +- etc/fgt.key      -> MD5 + SHA-256 -> family lookup
```

Intermediate files live in a temporary directory and are removed before the result is returned.

---

## Cache

Results are cached in `~/.ablation/cache/fortigate_cert_key_scanner.json`. The cache key is the file path, size, and modification time in nanoseconds — any change to the file triggers a rescan. Cache reads and writes are protected by `fcntl.flock` so concurrent batch scans on overlapping directories do not corrupt the cache. Cache writes are atomic (write to `.tmp`, then `os.replace`).

Error results are never written to cache. If a scan fails (missing tool, disk full, corrupt firmware), the next run re-attempts the full pipeline. Use `force_rescan=True` to bypass a stale successful-but-wrong cache entry.

---

## KeyEntry fields

| Field | Type | Meaning |
|---|---|---|
| `name` | str | Key filename (e.g. `fgt_512.key`) |
| `md5` | str | MD5 hexdigest — family identification only |
| `sha256` | str | SHA-256 hexdigest — cross-validation |
| `family` | str | Family name from `KNOWN_KEY_FAMILIES`, or `"UNKNOWN"` |
| `severity` | str | `"CRITICAL"`, `"HIGH"`, or `"UNKNOWN"` |
| `description` | str | Human-readable note from the known-family table |

---

## Related modules

- `FortiOSHardwareExtractor` (`fortios_firmware_extractor.py`) -- outer XOR decryption for hardware `.out` files
- `FirmwareContainerKeyExtractor` (`firmware_container_key_extractor.py`) -- recovers keys from hardware firmware inner partitions
- `FirmwareContainer` (`firmware_container.py`) -- partition-table firmware container parser
