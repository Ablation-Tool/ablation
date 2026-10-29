# CAEN ASCII-Hex Firmware Containers

`CaenHexFirmware` unwraps CAEN `#NuovoFirmware...#` update files, extracts the board identifier and payload, and checks the additive trailer. It turns an opaque vendor encoding into bytes that an executable loader can inspect.

---

## Start with the problem

A firmware file can look like a long stream of printable hexadecimal characters and still contain a machine-code program. Each original byte has been written as two hexadecimal characters. The update also has its own header, an end marker, and a checksum.

This creates a small but important step before reverse engineering: reverse the encoding without losing the payload's exact bytes. A mistaken offset or an incorrect checksum interpretation can hide an ELF header, corrupt instructions, or produce a false claim about update authentication.

`CaenHexFirmware` exists to make that step repeatable. It was added after the CAEN A1676 update was found to contain a 92,346-byte ARM32 ELF inside this wrapper. The parser does not assume that every CAEN update contains ARM or ELF.

For the larger workflow, see [Firmware Parsing: From Artifacts to Analysis](firmware-parsing.md).

---

## The format in plain terms

The outer file is text with three logical parts:

```text
uppercase_hex("#NuovoFirmware" + board + "#" + payload) + optional_LFs
0x04
optional_LF + eight_uppercase_hex_digits + optional_LF
```

The first part is the encoded envelope and contents. The `0x04` byte is an end-of-text marker, not a printable character. The final eight digits record the checksum.

After hexadecimal decoding, the payload begins with a structure such as:

```text
#NuovoFirmwareA1676#<payload bytes>
```

The model name is therefore metadata inside the decoded wrapper, not a filename guess.

---

## How the parser works

1. Check the file size before reading it. The default input limit is 16 MiB.
2. Split the input at the first end-of-text marker and validate the trailer shape.
3. Accept uppercase hexadecimal digits and line feeds in the body. Reject other whitespace and lowercase hexadecimal.
4. Decode the hexadecimal body and validate the `#NuovoFirmware` prefix, board terminator, and board characters.
5. Sum the encoded ASCII bytes before the end marker, excluding line feeds, and keep the low 32 bits.
6. Compare that result with the trailer. Return the board and payload only when the format and checksum agree.

The checksum calculation is:

```python
sum(byte for byte in body_before_eot if byte != 0x0A) & 0xFFFFFFFF
```

The line-feed rule matters. Adding or removing a line feed does not change this checksum, while changing a hexadecimal digit does. The calculation covers the encoded text, not a CRC32 of the decoded executable.

Board identifiers may contain ASCII letters, digits, underscore, dot, and hyphen. Invalid encodings, missing markers, empty payloads, and checksum mismatches raise `CaenHexError` rather than returning partially decoded firmware.

---

## Why this works

Hexadecimal encoding is reversible: two characters specify exactly one original byte. The wrapper markers provide explicit boundaries, and the trailer supplies an independently computable consistency check. Nothing in this step requires executing firmware or knowing its instruction set.

The checksum works as an error detector because the producer and parser can perform the same arithmetic over the same bytes. It does not work as an authenticator because it has no secret key. Anyone who can modify the file can recompute it.

---

## A complete small example

This example constructs a valid container, parses it, and checks both metadata and recovered bytes:

```python
from ablation.parsers.caen_hex import CaenHexFirmware

payload = b'\x7fELFdemo'
body = (b'#NuovoFirmwareA1676#' + payload).hex().upper().encode() + b'\n'
checksum = sum(value for value in body if value != 0x0A) & 0xFFFFFFFF
raw = body + b'\x04\n' + f'{checksum:08X}\n'.encode()

image = CaenHexFirmware.from_bytes(raw)
assert image.board == 'A1676'
assert image.payload == payload
assert image.checksum == image.computed_checksum
assert image.metadata()['checksum_verified'] is True
```

For a real update, use `CaenHexFirmware.from_path('/path/to/firmware')`. `metadata()` reports the board, payload size, trailer, and verification result. `from_bytes()` accepts payloads already recovered from another container.

If the payload starts with ELF magic, validate its ELF headers and load addresses before passing it to an ELF analysis pipeline. A valid wrapper does not validate those inner structures.

---

## What this adds for the user

This is a small ingestion component with a concrete payoff: one command replaces a manual hexadecimal conversion, a board-name extraction, and an easily mistyped checksum calculation. It preserves strict input rules and gives scripts a stable object to pass to later analysis.

Its narrow scope is intentional. A future firmware auto-detection layer could call it as one backend, but that layer is not part of this parser. It could also be extended for another observed CAEN encoding or replaced without changing instruction-level analyzers.

---

## Boundaries and common misreadings

- A valid additive checksum is not a signature, an origin guarantee, or proof of secure update enforcement.
- Successful decoding does not establish that a bootloader accepts or executes the payload.
- Only the observed uppercase CAEN format is accepted. Intel HEX files belong in `IntelHexImage`.
- Empty lines are accepted within the body. Other whitespace and lowercase hexadecimal are rejected.
- The parser performs no firmware update, device communication, or executable code execution.
- A plaintext password found in a decoded payload still needs a separate reachability and authorization analysis.

---

## See also

- [Firmware Parsing: From Artifacts to Analysis](firmware-parsing.md)
- [Strict Intel HEX Parser](intel-hex.md)
- [bFLT (Binary Flat Format)](bflt.md)
- [JFFS2 Filesystem Reader](jffs2.md)
