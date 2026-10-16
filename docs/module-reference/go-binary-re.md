# Go Binary RE

**File:** `modules/go_binary_re.py`

## Why this exists

Go binary reverse engineering for Mach-O and ELF targets (Go 1.16+): pclntab function table parsing, command dispatch map reconstruction, message frame format inference from bufio.Reader call chains, and RIP-relative pointer resolution.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |
| `_MAX_RESP_BYTES` | 16 MB | HTTP response body cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. HTTP reads capped at `_MAX_RESP_BYTES=16MB`. No lief.parse().
