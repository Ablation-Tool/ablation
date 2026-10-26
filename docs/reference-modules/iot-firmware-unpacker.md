# IoTFirmwareUnpacker

Generic IoT firmware format detector and extraction pipeline: identifies the container format by magic bytes, strips wrapper headers, decompresses, extracts the inner filesystem, and walks the result to build a file inventory.

---

## Why this exists

1. **Every vendor uses a different container.** VIVOTEK wraps a gzip tar in a 49-byte proprietary header. D-Link uses `SHRS`. TP-Link uses `\x55\xAA\x55\xAA`. Before this module, identifying and stripping each wrapper required one-off shell incantations per vendor (`dd if=fw bs=1 skip=49 | zcat | tar x`).

2. **Encrypted images need early detection.** OpenSSL AES-encrypted images (`Salted__` magic) are unextractable without a key. Previously we'd attempt extraction and get confusing errors. The module detects the `Salted__` magic first and aborts with an actionable message pointing at the bootloader/upgrade script.

3. **uImage header stripping was manual.** U-Boot uImage headers (magic `0x27051956`) are 64 bytes and wrap the real payload. Without stripping them, `unsquashfs` reports "no valid filesystem". The module detects and strips them transparently.

---

## How it works

```
probe(path) — detection only, no extraction
  Read first 2048 bytes
  Walk _MAGICS table: [(offset, magic_bytes, format_name), ...]
    Checked in priority order (vivotek_pkg before gzip, uimage before gzip)
  Special cases:
    vivotek_pkg: check offset 49 for gzip magic \x1f\x8b — confirms inner gzip
    openssl_aes: Salted__ at offset 0 → encrypted=True, early exit
    ext2: magic \x53\xef at offset 1080
    uimage: >I magic 0x27051956 at offset 0 → inner_offset=64
  Returns: FirmwareInfo(path, size, format, encrypted, inner_offset, notes)

unpack(path, outdir, squashfs_tool) — extraction
  probe() to identify format
  _unwrap(): strip outer container → raw payload bytes or file
    vivotek_pkg: skip 49 bytes, write remainder to outdir/inner.tar.gz
    uimage:      skip 64 bytes, write remainder to outdir/inner.bin
    gzip:        decompress to outdir/inner.bin
    tar:         extract all members to outdir/
  _extract_layer(): extract filesystem from inner payload
    squashfs_*:  subprocess unsquashfs -d outdir/rootfs inner_payload
    cpio:        subprocess cpio --extract
    tar:         tarfile.extractall(filter='data')
  _build_inventory(): walk extracted rootfs, classify each file by magic
  Returns: UnpackResult(source_path, outdir, format_chain, rootfs_path, inventory, error)
```

---

## IoTFirmwareUnpacker

```python
from ablation.analyzers.iot_firmware_unpacker import IoTFirmwareUnpacker

# Probe without extracting — fast, no disk writes
info = IoTFirmwareUnpacker.probe('/path/to/firmware.flash.pkg')
print(info)
# FirmwareInfo: vivotek_pkg  size=5,242,880  inner_offset=49  NOT ENCRYPTED

# Full extraction
result = IoTFirmwareUnpacker.unpack(
    '/path/to/firmware.flash.pkg',
    outdir='/tmp/fw_extract',
    squashfs_tool='unsquashfs',   # default
)
if result.error:
    print(f"Extraction failed: {result.error}")
else:
    print(f"Format chain: {' → '.join(result.format_chain)}")
    print(f"Rootfs: {result.rootfs_path}")
    for f in result.inventory[:10]:
        print(f"  {f.ftype:<12} {f.path}")
```

### FirmwareInfo fields

| Field | Content |
|:---|:---|
| `path` | Source file path |
| `size` | File size in bytes |
| `format` | Detected format string (e.g. `vivotek_pkg`, `openssl_aes`) |
| `encrypted` | True if OpenSSL AES or other encryption detected |
| `inner_offset` | Byte offset where the real payload starts |
| `notes` | Human-readable notes (e.g. suggested decryption step) |

### UnpackResult fields

| Field | Content |
|:---|:---|
| `source_path` | Original firmware file |
| `outdir` | Extraction directory |
| `format_chain` | Ordered list of formats stripped, e.g. `['vivotek_pkg', 'gzip', 'tar', 'squashfs_le']` |
| `rootfs_path` | Path to extracted rootfs root, or None |
| `inventory` | List of `FirmwareFile(path, ftype, size)` from rootfs walk |
| `error` | Error string if extraction failed, else None |

---

## Detected formats

| Format | Magic / detection | Notes |
|:---|:---|:---|
| `vivotek_pkg` | offset 0: any 49 bytes + offset 49: `\x1f\x8b` | VIVOTEK .flash.pkg |
| `uimage` | offset 0: `\x27\x05\x19\x56` (big-endian) | U-Boot legacy image |
| `squashfs_le` | offset 0: `sqsh` | SquashFS little-endian |
| `squashfs_be` | offset 0: `hsqs` | SquashFS big-endian |
| `squashfs_v3` | offset 0: `qshs` or `shsq` | SquashFS v3 |
| `cramfs` | offset 0: `\x28\xCD\x3D\x45` | CramFS |
| `jffs2` | offset 0: `\x85\x19` | JFFS2 |
| `ext2` | offset 1080: `\x53\xEF` | ext2/3/4 |
| `gzip` | offset 0: `\x1f\x8b` | gzip |
| `xz` | offset 0: `\xfd7zXZ\x00` | xz |
| `bzip2` | offset 0: `BZh` | bzip2 |
| `zip` | offset 0: `PK\x03\x04` | ZIP |
| `tar` | offset 257: `ustar` | POSIX tar |
| `cpio` | offset 0: `070701` or `070702` | newc/crc cpio |
| `openssl_aes` | offset 0: `Salted__` | OpenSSL `enc -aes-256-cbc` |
| `elf` | offset 0: `\x7fELF` | ELF binary (not a container) |

---

## Usage

```python
# Identify an unknown firmware blob
info = IoTFirmwareUnpacker.probe('/media/research/ND9541/ND9541_fw.bin')
if info.encrypted:
    print(info.notes)  # "OpenSSL AES encrypted. Find key in bootloader upgrade script."
    # → grep the bootloader for openssl enc -d or AES key constants

# Full pipeline
result = IoTFirmwareUnpacker.unpack('/media/research/fw.bin', outdir='/tmp/extract')
if result.rootfs_path:
    from ablation.analyzers.cgi_surface_mapper import CGISurfaceMapper
    mapper = CGISurfaceMapper.from_rootfs(result.rootfs_path)
    surface = mapper.map()
    print(CGISurfaceMapper.report(surface))
```

---

## False positives

**Partial gzip inside uImage misidentified as plain gzip:** If the uImage wraps a gzip-compressed squashfs, `probe()` sees the uImage magic at offset 0 and returns `uimage`, not `gzip`. This is correct — `unpack()` will strip the 64-byte header and then process the gzip payload.

**VIVOTEK header heuristic on other 49-byte-padded containers:** The VIVOTEK detection checks only that offset 49 has gzip magic. A non-VIVOTEK container that happens to have `\x1f\x8b` at byte 49 will be misclassified. If extraction fails, re-probe at different offsets manually.

---

## Pipeline position

**Before this module:** none. Use at the start of any new firmware RE session.

**After this module:** `CGISurfaceMapper.from_rootfs(result.rootfs_path)` to enumerate the web attack surface. `BinaryContext.load_or_build()` on ELF files from `result.inventory`.

---

## FORGE findings

| ID | Severity | Finding |
|:---|:---|:---|
| IFU-F1 | MEDIUM | `gzip.decompress()` is unbounded — decompression bomb risk on crafted firmware |
| IFU-F2 | LOW | `tarfile.extractall(filter='data')` path traversal guard requires Python 3.12+ |
| IFU-F3 | LOW | Hardcoded 120s `unsquashfs` timeout; large images may exceed this |

---

## See also

- [CGISurfaceMapper](cgi-surface-mapper.md): uses extracted rootfs to map the HTTP attack surface
- [ShellSinkClassifier](shell-sink-classifier.md): classifies exec sinks in shell CGI handlers found after unpacking
