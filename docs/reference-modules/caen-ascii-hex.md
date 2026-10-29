# CAEN ASCII-Hex Firmware Containers

`CaenHexFirmware` decodes CAEN `#NuovoFirmware...#` update files with an ASCII-hex body, an end-of-text marker, and an additive checksum trailer. It has no third-party dependencies.

---

## Why this exists

1. Some CAEN firmware is neither Intel HEX nor a raw ELF. Treating the printable body as text or decoding it without its wrapper produces a shifted, corrupt payload.
2. The trailing value is not a CRC32 of the decoded binary. It is the 32-bit sum of all pre-EOT ASCII bytes except line feeds, encoded as eight uppercase hexadecimal digits.
3. A checksum is an integrity check, not authenticity. Parsing must not turn a valid update into a trusted-update claim.

---

## Format

```text
uppercase_hex("#NuovoFirmware" + board + "#" + payload) + optional_LFs
0x04
optional_LF + eight_uppercase_hex_digits + optional_LF
```

The checksum is:

```python
sum(byte for byte in body_before_eot if byte != 0x0A) & 0xFFFFFFFF
```

Board identifiers are restricted to ASCII letters, digits, underscore, dot, and hyphen. The decoded payload is not assumed to be an ELF or to use a particular processor.

---

## Usage

```python
from ablation.parsers.caen_hex import CaenHexFirmware

image = CaenHexFirmware.from_path('/path/to/firmware')
print(image.board)
print(image.metadata())
open('/tmp/caen-payload.bin', 'wb').write(image.payload)
```

Use `from_bytes()` for an in-memory container. `checksum` is the trailer value and `computed_checksum` is the independently calculated value; construction fails if they differ. `metadata()` reports the board, payload size, and verification status.

The default input limit is 16 MiB. `from_path()` checks file size before reading. Invalid hexadecimal, unexpected whitespace, missing headers or terminators, empty payloads, and checksum mismatches raise `CaenHexError`.

---

## Verification

```python
assert image.checksum == image.computed_checksum
assert image.metadata()['checksum_verified'] is True
```

For a new container family, independently compare the payload's ELF magic, program headers, and load segments. If using it with `BinaryContext`, verify that the resulting architecture and virtual addresses are coherent before disassembling.

---

## Limitations and false positives

- The additive checksum is easily forged and provides no signature or origin guarantee.
- A valid wrapper does not establish that the bootloader accepts the payload.
- This parser supports the observed uppercase CAEN format, not every CAEN update encoding. Intel HEX files belong in `IntelHexImage`.
- Empty lines are accepted within the body, but other whitespace and lowercase hexadecimal are rejected.
- No firmware update or target-device operation is performed.

---

## See also

- [Strict Intel HEX Parser](intel-hex.md)
- [bFLT v4 Executables](bflt.md)
- [JFFS2 Filesystem Reader](jffs2.md)
