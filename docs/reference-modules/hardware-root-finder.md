# HardwareRootFinder

**File:** `modules/hardware_root_finder.py`

## Why this exists

Identifies hardware-assisted security feature usage in stripped firmware: ARM TrustZone SMC calls, x86 SGX instructions, IOMMU/SMMU bypass patterns, secure boot chain verification stubs, and TPM command sequences. Used for determining whether a firmware image has any meaningful hardware security integration or is relying purely on software controls.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.
