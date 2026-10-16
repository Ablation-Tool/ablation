# VideoContainer

**File:** `modules/video_container.py`

## Why this exists

MP4/MOV/QuickTime container format parser for firmware images that embed video assets. Identifies container atom hierarchy, codec types, and embedded metadata — used when firmware analysis reveals bundled media that may contain steganographic payloads or embedded configuration.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_CONTAINER_BYTES` | 256 MB | Container file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `read_bytes()`; `_MAX_CONTAINER_BYTES=256MB`. Extended size atoms (first_size==1) handled correctly with 64-bit length read. No lief.parse(). No HTTP reads.
