# Firmware Key Corpus

**File:** `ablation/analyzers/fortigate_cert_key_scanner.py`

Classifies recovered firmware keys against a cross-image family table and flags any unrecognized key variant as a potential finding. An anomalous key count, a version shipping more key files than its family table entry predicts: it surfaces before decryption begins.

Built from the Fortinet firmware RE corpus across 22+ engagement sessions. Covers every FortiGate virtual deployment format: OVF ZIP, KVM QCOW2, Hyper-V VHD/VHDX, and bare VMDK.

---

## Why this exists

Three things were not possible before this module:

1. **Batch key comparison was manual.** Confirming that a new firmware release ships the same shared key family as prior versions required extracting keys from each image individually and comparing MD5s by hand. A 20-version sweep took days.

2. **Unknown key variants had no automatic detection.** A new Fortinet firmware release that introduces a previously unseen key variant, representing a change in the shared-key corpus. It produced no alert. The module flags any `UNKNOWN` family entry immediately.

3. **Formats beyond OVF ZIP required separate tooling.** KVM QCOW2, Hyper-V VHD, and VHDX images each needed different extraction commands. `FortiGateCertKeyScanner` handles all four formats through a single `from_path()` or `from_disk()` call.

---

## Known key family table (`KNOWN_KEY_FAMILIES`)

The module maintains a corpus of known Fortinet key families keyed by MD5:

| Family | Severity | Description |
|---|---|---|
| `fgt_512.key Gen1` | CRITICAL | 512-bit RSA; shared across FGT/FFW/FEXT/FWF; factorable in under 1 second |
| `fgt_512.key Gen2` | HIGH | 512-bit RSA; second generation; still below 768-bit minimum |
| Additional families | varies | Extended corpus from sessions 1–22 |

An extracted key with MD5 matching a known entry gets classified with its family name and severity. An extracted key with no matching entry gets `family='UNKNOWN'`, a potential new finding.

---

## Supported input formats

| Format | Method | Notes |
|---|---|---|
| OVF ZIP (`.out.zip`) | `from_path()` | Outer ZIP → inner `.out.ovf.zip` → `fortios.vmdk` → VMDK → P1 |
| QCOW2 (`.qcow2`) | `from_disk()` | KVM FortiGate; `qemu-img convert -f qcow2` |
| VHD (`.vhd`) | `from_disk()` | Hyper-V dynamic; `qemu-img convert -f vpc` |
| VHDX (`.vhdx`) | `from_disk()` | Hyper-V v2; `qemu-img convert -f vhdx` |
| VMDK (`.vmdk`) | `from_path()` or `from_disk()` | Bare VMDK without outer ZIP wrapper |

All FortiGate virtual disk formats use P1 at LBA 2048 (256 MiB ext4 containing `datafs.tar.gz`). FAZ and FMG KVM images use P1 at LBA 8193 and contain no `datafs.tar.gz`; `from_disk()` returns an error result for these, that is correct behavior.

**Requirements:** `qemu-img` and `debugfs` e2fsprogs must be on PATH.

---

## Usage

```python
from ablation.analyzers.fortigate_cert_key_scanner import FortiGateCertKeyScanner

# Single OVF ZIP (VMware/ESXi)
result = FortiGateCertKeyScanner.from_path('/path/to/FGT_VM64-v7.4.12.M.out.zip')
print(FortiGateCertKeyScanner.report([result]))

# Bare disk image (KVM QCOW2, Hyper-V VHD/VHDX)
result = FortiGateCertKeyScanner.from_disk('/path/to/FGT_VM64_KVM-v7.4.12.qcow2')
print(FortiGateCertKeyScanner.report([result]))

# Batch sweep — all OVF ZIPs in a directory
results = FortiGateCertKeyScanner.batch_scan(
    '/media/research/Fortinet/FortiGate/Firmware/Virtual/FGT_VM64/'
)
print(FortiGateCertKeyScanner.report(results))

# Flag unknown key variants (potential new corpus finding)
unknowns = [r for r in results if any(k.family == 'UNKNOWN' for k in r.keys.values())]
if unknowns:
    print(f"{len(unknowns)} image(s) contain unrecognized key variants")

# Force re-scan of a previously cached image
result = FortiGateCertKeyScanner.from_path('/path/to/firmware.zip', force_rescan=True)
```

---

## Result fields (`KeyScanResult`)

| Field | Description |
|---|---|
| `firmware_path` | Path to the analyzed image |
| `version` | Firmware version string extracted from the image |
| `keys` | `dict[filename, KeyEntry]`: one entry per cert/key file found |
| `error` | Error message if extraction failed; `None` on success |

### `KeyEntry`

| Field | Description |
|---|---|
| `filename` | Key file name inside `datafs.tar.gz` (e.g. `fgt_512.key`) |
| `md5` | MD5 of the key file used for family lookup only, not integrity |
| `sha256` | SHA-256 for cross-validation |
| `family` | Family name from `KNOWN_KEY_FAMILIES`, or `'UNKNOWN'` |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `UNKNOWN` |
| `description` | Human-readable description of the key family |

---

## Caching

VMDK conversion takes approximately 30 seconds per image. `FortiGateCertKeyScanner` caches results by image path and file hash. A sweep of 20+ versions runs in seconds after the first pass. Pass `force_rescan=True` to bypass the cache when an image has been replaced at the same path.

---

## How it works

Loads the firmware image, maps entropy across the file using a sliding window, and classifies regions as encrypted, compressed, or plaintext. Known cryptographic constants and key derivation patterns are matched against the corpus. Partition boundaries are recovered from format signatures in the plaintext regions. Each finding includes the byte offset, the matched pattern, and the confidence level.

---

## Example output

```
[CRITICAL] HARDCODED_KEY   offset=0x1A40C0  len=32
  detail: AES-256 key matches family corpus entry FGT-SHARED-2022
  evidence: 8b3f...e1c4 (first 4 / last 4 bytes shown)

[HIGH] WEAK_ALGO   offset=0x3B200
  detail: MD5 constant detected in hash init sequence
```

---

## False positives

Version-mismatch findings appear when a known key or certificate is present in a build where it was intentionally removed. Cross-reference against the family table in `FirmwareKeyCorpus` and the product release notes before escalating. Development-only debug keys identifiable by subject CN matching vendor dev lab naming conventions are not production findings.

---

## Pipeline position

**Before this module:** Download the firmware image and confirm the file is complete (no `.aria2` sidecar). Read the product CLI Reference and Release Notes in `docs/` before analysis.

**After this module:** Feed extracted filesystems or ELF binaries to `SemanticSearcher`, `TaintTracker`, and `FirmwareAuthBypassDetector`.

---

## Reading output

`FortiGateCertKeyScanner(path).scan()` returns a `CertKeyScanResult`. See [fortigate-cert-key-scanner](fortigate-cert-key-scanner.md) for the full field reference (`path`, `version`, `keys`, `error`).

`FortiBuildTrackClassifier.classifyfilename` returns a `BuildTrackResult`. See [fortibuild-track-classifier](fortibuild-track-classifier.md) for the full field reference (`product`, `version`, `build_number`, `build_track`, `expected_keys`, `key_generation`).

---

## See also

- [FirmwareContainers](firmware-containers.md): partition extraction from container images
- [FirmwareContainerKeyExtractor](firmware-container-key-extractor.md): recover embedded key material
- [TaintAnalysis](taint-analysis.md): trace network input to sinks in extracted binaries
- [SemanticSearch](semantic-search.md): find vulnerability candidates in extracted ELFs
