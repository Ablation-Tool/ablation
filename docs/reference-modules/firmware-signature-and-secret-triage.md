<a id="lsb-steganographic-key-recovery"></a>
# Firmware Extraction & Triage

Scan raw firmware for embedded filesystems, compression formats, security-relevant strings, and entropy transitions, then extract partitions from supported fixed-record firmware containers.

**Files:** `ablation/core/firmware_analyzer.py` · `ablation/analyzers/firmware_container.py`

---

## Why these tools exist

An unknown firmware image can contain several embedded regions, but scanning it by eye offers no reliable starting point. Signature, string, and entropy checks provide three different kinds of leads: a possible container boundary, a possible credential or component, and a change in byte distribution. Each is useful because the others cannot answer its question.

The fixed-record container reader is separate from that broad triage. It performs actual partition extraction only for one validated layout instead of treating every magic match as a filesystem. Users therefore get a small first-pass workflow: locate candidates, inspect them structurally, then hand valid payloads to a format-specific parser. These components can grow with independently verified signatures or container layouts; they are not a universal unpacker, credential validator, or encryption detector.

## What these modules do

`firmware_analyzer.py` provides static, standard-library triage for an arbitrary byte image. It identifies likely extraction targets and security-review leads without executing firmware.

`firmware_container.py` parses one specific container layout: an 8-byte magic, firmware/vendor/product metadata, and 296-byte partition records beginning at file offset `0x54`. It is not a universal firmware unpacker and does not decrypt or decompress partition payloads.

## Signature scanning

`scan_firmware_signatures(data)` checks each byte offset against the registered magic table and returns at most 100 hits:

```python
from ablation.core.firmware_analyzer import scan_firmware_signatures

with open('/path/to/firmware.bin', 'rb') as f:
    data = f.read()

for hit in scan_firmware_signatures(data):
    print(hex(hit['offset']), hit['type'], hit['severity'])
```

Recognized families include SquashFS, JFFS2, UBI, CPIO, ZIP/APK, gzip, bzip2, xz, LZMA, LZ4, zstd, ELF, U-Boot, device-tree blobs, and Android boot images. `HIGH` marks a filesystem category considered extractable by this scanner; it does not mean a vulnerability.

A magic match identifies a possible embedded region, not a validated filesystem. Confirm the surrounding header and partition layout before extraction.

## String and credential triage

`extract_firmware_strings(data, min_length=8)` extracts printable strings and returns these categories:

| Field | Content |
|:---|:---|
| `passwords` | Text matching password-assignment patterns. |
| `private_keys` | PEM private-key markers and their offsets. |
| `api_tokens` | Token-like strings near key, secret, or API text. |
| `ips` / `urls` | IPv4 addresses and HTTP(S) URLs. |
| `passwd_entries` | Unix passwd-format entries. |
| `supply_chain` | BusyBox, OpenSSL, and Linux kernel version strings. |
| `debug_strings` | Telnet, bind-shell, backdoor, and netcat references. |

These are review leads, not verified credentials, vulnerable dependency versions, or backdoor proof. Handle any recovered secret as sensitive material and validate it only on systems you are authorized to test.

## Entropy transitions

`analyze_firmware_entropy(data, block_size=1024)` computes Shannon entropy per block and returns the first block, the last block, and blocks whose entropy differs from the previous block by more than `1.0`.

```python
from ablation.core.firmware_analyzer import analyze_firmware_entropy

for section in analyze_firmware_entropy(data):
    print(hex(section['offset']), section['entropy'], section['type'])
```

Types are `compressed/encrypted` above 7.0, `data` from 5.0 through 7.0, and `code/text` below 5.0. These thresholds are heuristics: compressed, encrypted, random, and densely encoded data can overlap. Entropy alone cannot establish encryption or locate a key.

## Complete file triage

`scan_firmware_file(path)` runs all three analyses and consolidates findings:

```python
from ablation.core.firmware_analyzer import scan_firmware_file

result = scan_firmware_file('/path/to/firmware.bin')
print(result['size'])
for finding in result['findings']:
    print(finding['severity'], finding['category'], finding['detail'])
```

The returned dictionary also contains `signatures`, `strings`, and `entropy_sections`. Consolidated findings include private-key markers, password assignments, extractable filesystems, non-root UID-0 passwd entries, component version strings, and debug indicators. Severity is a triage convention, not a CVSS score or confirmed exploit result.

For JSON output:

```bash
python ablation/core/firmware_analyzer.py /path/to/firmware.bin --json
```

## Parse and extract a supported container

```python
from ablation.analyzers.firmware_container import FirmwareContainer

firmware = FirmwareContainer.from_path('/path/to/firmware.BIN')
firmware.dump_partitions()

for partition in firmware.partitions:
    print(partition.name, hex(partition.offset), partition.size, partition.payload_type)

firmware.extract('bin', '/tmp/bin-partition.bin')
firmware.extract_all('/tmp/firmware-partitions')
```

`read_partition(name)` returns payload bytes and raises `KeyError` for an unknown name. `extract()` writes one partition; `extract_all()` writes numbered `.bin` files and returns their paths.

Payload detection recognizes gzip, xz, zstd, LZ4, LZO, CPIO, ELF, PE, and ext2/3/4 signatures. The payload remains in its original form after extraction; decompression, decryption, filesystem mounting, and safe path handling belong to subsequent tools.

## Limitations

- The signature scanner can report magic bytes inside unrelated data. Validate candidates structurally.
- String patterns produce false positives in documentation, test data, and compressed content. Do not treat a version string as proof of a CVE.
- The container parser accepts only the documented fixed-record layout. A zero-partition result can mean an unsupported format rather than an empty image.
- Container extraction does not validate payload contents or make them safe to mount, execute, or parse.
- Large images are processed in memory. Use an environment with adequate memory and avoid running untrusted extracted content.

## See also

- [Fortinet Firmware Analysis](firmware-extraction.md): FortiOS-specific key recovery and partition extraction.
- [Packed & Encrypted Region Detection](entropy-mapper.md): windowed entropy maps and region classification.
- [Binary Parsing & Hardening](binary-format-and-platform-identification.md): identify executable partitions after extraction.
