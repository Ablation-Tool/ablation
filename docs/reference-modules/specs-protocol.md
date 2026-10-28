# SPECS Protocol Codec and Vector Parser

`specs_protocol` encodes and validates SPECS serial frames and recovers headers from archived simulation transaction text. It makes the long-frame boundary and reported-count behavior explicit.

---

## Why this exists

1. SPECS uses I2C-like start and stop conditions but is not an ordinary byte-oriented I2C transaction. Generic I2C decoders cannot represent its final-payload marker bit.
2. The RTL comment and implementation disagree about long frames. The implemented rule is `read_count > 0x80`, not a special case for 255.
3. Archived vectors provide useful evidence, but manually reading transaction words is error-prone. The parser recovers their three-byte headers and computes the same count and checksum properties as the codec.

---

## How it works

A frame has three header bytes, one header-checksum byte, payload bytes, and one payload-checksum byte. Each byte is transmitted least-significant bit first. A ninth bit marks only the final payload byte.

```mermaid
flowchart LR
    A[Three header bytes] --> B[Header checksum]
    C[Payload] --> D[Final-byte marker]
    C --> E[Payload XOR checksum]
    B --> F[Strict decoder]
    D --> F
    E --> F
```

The header checksum is the XOR of the high and low nibbles of the first three bytes, combined with the high nibble of the fourth byte. The payload checksum is the XOR of all payload bytes. Header bytes and the trailer are excluded from the payload checksum. Frame and iterable materialization is limited to 65,536 words to reject accidental unbounded input.

The long-frame rules are:

| Read count | Long frame | Reported count |
|---|---|---|
| `0x7F` | No | 127 |
| `0x80` | No | 0 |
| `0x81` | Yes | 1 |
| `0xFF` | Yes | 127 |

---

## Usage

```python
from ablation.analyzers.specs_protocol import encode_frame, decode_frame

words = encode_frame([0x55, 0x02, 0x01], [0xDE, 0xAD, 0xBE, 0xEF])
print([f'{word.value:02X}' for word in words])
header, payload = decode_frame(words)
```

Output:

```
['55', '02', '01', '03', 'DE', 'AD', 'BE', 'EF', '22']
```

Parse archived simulation text:

```python
from ablation.analyzers.specs_protocol import parse_simulation_headers

headers = parse_simulation_headers(vector_text)
for item in headers:
    print(item.header, item.read_count, item.long_frame,
          item.reported_count, item.computed_header_checksum)
```

The parser removes `//` comments and reads transaction headers following `0x76543210` markers. Archived vectors with counts 129 and 130 are classified as long frames.

---

## False positives

A transaction-like value in arbitrary text is not necessarily a simulation header. The caller must select the correct vector format and artifact. The parser only interprets headers after the documented marker.

XOR checksums are integrity checks, not authentication. They detect single-bit corruption in the tested frame model, but some arbitrary byte substitutions preserve the checksum. A successful decode does not prove that a frame is authentic or semantically valid for a particular slave.

---

## Pipeline position

**Before this module:** Recover the SPECS transaction text or frame words and preserve the source artifact.

**After this module:** Compare decoded headers and count behavior against RTL, simulation evidence, or a focused hardware test. Dynamic HDL simulation remains separate from vector parsing.

---

## Reading findings

| Field | Content |
|:---|:---|
| `SpecsWord.value` | Transmitted byte value |
| `SpecsWord.last` | Final-payload marker bit |
| `header` | Three recovered header bytes |
| `read_count` | Second header byte |
| `long_frame` | Result of `read_count > 0x80` |
| `reported_count` | Result of `read_count & 0x7F` |
| `computed_header_checksum` | Model-generated four-bit header checksum |

---

## See also

- [VerilogSemantic](verilog-semantic.md)
- [LPGBT Protocol Decoders](lpgbt-decoder.md)
