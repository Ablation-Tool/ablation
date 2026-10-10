# FortiBuildTrackClassifier

## Why this exists

Two things Ablation could not do before this module:

1. **No way to predict a firmware image's key set without running the full extraction pipeline.** VMDK conversion and debugfs extraction take 30–90 seconds per image. The M/F build track appears in the filename and deterministically predicts whether the image ships one or three cert keys. Without a filename parser, the only way to know was to run FortiGateCertKeyScanner and wait. This module produces a prediction in microseconds that lets a batch sweep skip images before any disk I/O.

2. **No anomaly detection for unexpected key sets.** A M-build that ships only one key, or an F-build that ships three, would pass through FortiGateCertKeyScanner without any flag. FortiBuildTrackClassifier produces a structured prediction that callers can compare against scanner results using `discrepancy()` to surface these deviations as potential new findings.

---

**File:** `ablation/analyzers/fortibuild_track_classifier.py`

Parses Fortinet firmware filenames and returns the build track (M/F), expected cert key set, key generation, version, and product family. Pure Python — no disk I/O, no external tools.

The M vs F distinction is not documented in Fortinet's public materials. It was established through systematic corpus analysis across every virtual deployment format: VMware OVF, Hyper-V VHD/VHDX, KVM QCOW2, ARM64 KVM. The pattern is 100% consistent in the tested corpus.

---

## Build track rules

| Track | Version | Expected keys | Generation |
|---|---|---|---|
| M | v6.x, v7.x | fgt_512.key, fgt2.key, fgt.key | Gen1 |
| M | v8.0+ | fgt_512.key, fgt2.key | Gen2 |
| F | v6.x, v7.x | fgt_512.key | Gen1 |
| F | v8.0+ | fgt_512.key | Gen2 |

M = maintenance track. F = feature track. The product family and architecture (x86-64 vs ARM64) do not affect the key set.

---

## Usage

```python
from ablation.analyzers.fortibuild_track_classifier import FortiBuildTrackClassifier

# Single filename
result = FortiBuildTrackClassifier.classify(
    'FGT_VM64-v7.4.12.M-build2902-FORTINET.out.zip'
)
print(result.build_track)      # 'M'
print(result.expected_keys)    # ['fgt_512.key', 'fgt2.key', 'fgt.key']
print(result.key_generation)   # 'Gen1'
print(result.product)          # 'FGT_VM64'
print(result.version)          # '7.4.12'
print(result.build_number)     # 2902

# Batch classify a list
import os
filenames = os.listdir('/media/research/Fortinet/VM-KVM/')
results = FortiBuildTrackClassifier.batch_classify(filenames)
print(FortiBuildTrackClassifier.report(results))

# Cross-validate against FortiGateCertKeyScanner results
from ablation.analyzers.fortigate_cert_key_scanner import FortiGateCertKeyScanner

path = '/media/research/Fortinet/VM-KVM/FGT_VM64_KVM-v7.4.12.M-build2902-FORTINET.qcow2'
scan_result = FortiGateCertKeyScanner.from_disk(path)
track_result = FortiBuildTrackClassifier.classify(path)

if not scan_result.error:
    actual_keys = set(scan_result.keys.keys())
    diff = track_result.discrepancy(actual_keys)
    if diff:
        print(f"ANOMALY in {track_result.filename}: {diff}")
    else:
        print(f"Key set matches prediction ({track_result.build_track}-build)")
```

---

## Extraction pipeline

```
Fortinet firmware filename (no I/O)
  |
  +- os.path.basename()
  |
  +- _FILENAME_RE regex
  |    product, major, minor, patch, track (M/F), build number
  |
  +- _predict_keys(track, major_version)
       -> expected_keys list, key_generation string
```

---

## BuildTrackResult fields

| Field | Type | Meaning |
|---|---|---|
| `filename` | str | Input filename (basename only) |
| `product` | str | Product family, e.g. `FGT_VM64`, `FGT_VM64_HV`, `FOS_VM64_KVM` |
| `version` | str | Version string, e.g. `7.4.12` |
| `build_number` | int | Build number, e.g. `2902` |
| `build_track` | str | `"M"` (maintenance) or `"F"` (feature) |
| `expected_keys` | list[str] | Predicted cert key filenames for this image |
| `key_generation` | str | `"Gen1"` (v6/v7) or `"Gen2"` (v8+) |
| `error` | str or None | Set if filename does not match the Fortinet pattern |

`expected_keys` is a **prediction** from the filename, not disk-verified. Use `discrepancy()` to compare against `FortiGateCertKeyScanner` results before treating the prediction as confirmed.

---

## Related modules

- `FortiGateCertKeyScanner` (`fortigate_cert_key_scanner.py`) — extracts and fingerprints actual cert keys from disk images
- `FirmwareContainerKeyExtractor` (`firmware_container_key_extractor.py`) — hardware `.out` file key recovery
