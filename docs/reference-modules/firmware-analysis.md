# Firmware Analysis

Decrypts and extracts proprietary firmware through a three-stage key recovery chain. Huawei VRP squashfs with ARM64 BCJ filter is also supported. Both tools target formats where standard extraction tools silently fail.

---

## Why this exists

Two things blocked firmware analysis before these modules:

**1. Proprietary firmware encryption was a dead end.**
Many vendor firmware images use a layered encryption scheme: an outer XOR key applied to the entire image, then an inner PKCS#1 v1.5 RSA-encrypted RC4 session key embedded in the partially-decrypted data, then the actual payload encrypted with RC4. Each layer requires a different recovery method. Without a reusable chain, each engagement re-discovered the same key recovery steps from scratch. `FirmwareContainerKeyExtractor` packages the full three-stage chain as one call.

**2. Huawei VRP squashfs used a non-standard XZ filter.**
Standard `unsquashfs` cannot extract Huawei VRP v600R024+ squashfs images because they use the ARM64 BCJ Branch Call Jump XZ filter (filter ID 0x0A) rather than the x86 BCJ filter (0x04) that most tools assume. The ARM64 BCJ filter transforms branch target offsets in ARM64 instructions to improve compression ratios. `HuaweiSquashfsExtractor` handles this filter without external tool dependencies.

---

## How the decryption chain works

```mermaid
flowchart TD
    A(["Raw encrypted firmware (.out / .zip)"]):::input --> Z{"ZIP wrapper?\n(PK\\x03\\x04 magic)"}:::neutral
    Z:::neutral -->|Yes: v8.0.0+| ZA["Unwrap: parse STORE-ZIP local header\nExtract .out from data offset\n30 + fname_len + extra_len"]:::primary
    Z:::neutral -->|No: v6.x / v7.x| B["B"]:::secondary
    ZA:::primary --> B:::secondary
    B:::secondary

    B:::secondary --> C["Partially decrypted binary"]:::tertiary

    C:::tertiary --> D["Stage 2 · PKCS#1 v1.5 block scan\nScan for 0x00 0x02 ... 0x00 padding\nExtract candidate RSA-encrypted\nRC4 session key (256 bytes, RSA-2048)"]:::tertiary

    D:::tertiary --> E["Stage 3 · RC4 known-plaintext attack\ngzip magic: 0x1f 0x8b 0x08 0x00\nkeystream[0:4] recovered via XOR\nFull session key recovered by\ninverting PRGA with KSA structure"]:::tertiary

    E:::tertiary --> F(["RC4 session key recovered\nDecrypt payload → result.datafs_path\n/etc/shadow · web service binary · SSH host keys"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#546e7a,stroke-width:2px
    linkStyle 1 stroke:#bf360c,stroke-width:2px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#00695c,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
```

### Stage 1: Outer XOR layer

FortiOS v8.0.0 hardware firmware ships as a STORE-compressed ZIP containing a single `.out` file. `from_path()` detects the `PK\x03\x04` magic and unwraps it before decompression, so the same call works on both bare `.out` and ZIP-wrapped `.out` inputs.

FortiWiFi/FortiGate appliances use NAND flash. Unprogrammed NAND cells read as 0xFF. The XOR key is derived by XOR-ing the encrypted bytes against the known plaintext: ELF magic `0x7f 0x45 0x4c 0x46` or gzip magic `0x1f 0x8b 0x08` at the payload start.

```
  key recovery:
    known_plain = b'\x7f\x45\x4c\x46'  (ELF magic)
    key[:4] = encrypted[:4] ^ known_plain
    key repeats at 64-byte period (NAND page boundary)
```

### Stage 2: PKCS#1 v1.5 block scan

PKCS#1 v1.5 encryption padding has a fixed structure: `0x00 0x02 [8+ non-zero random bytes] 0x00 [message]`. The scanner finds `0x00 0x02... 0x00` sequences in the partially-decrypted binary and extracts candidate RSA-encrypted RC4 session key blocks. The typical key block size is 256 bytes RSA-2048, positioned 128 bytes from the start of the cert partition.

### Stage 3: RC4 known-plaintext attack

RC4 is a stream cipher. The keystream XORs with plaintext to produce ciphertext: `ciphertext[i] = plaintext[i] XOR keystream[i]`. The payload is known to start with a gzip archive, so the first four bytes of keystream are recoverable:

```
  keystream[0] = ciphertext[0] XOR 0x1f
  keystream[1] = ciphertext[1] XOR 0x8b
  keystream[2] = ciphertext[2] XOR 0x08
  keystream[3] = ciphertext[3] XOR 0x00
```

The RC4 KSA Key Scheduling Algorithm initializes the permutation S from the 128-byte session key. Given the first four keystream bytes and the KSA structure, the full session key is recoverable by inverting the PRGA.

Override the key if already known: `override_key=bytes.fromhex('...')`.

---

## Firmware Key Corpus

`FortiGateCertKeyScanner` and `FortiBuildTrackClassifier` together maintain a cross-firmware key family corpus that identifies anomalous firmware builds before decryption begins.

```mermaid
flowchart TD
    A(["Firmware image or bare disk"]):::input --> B{"Input format"}:::neutral
    B:::neutral -->|"OVF ZIP"| C["Extract vmdk or qcow2 from ZIP\nLocate fgt_512.key / fgt2.key / fgt.key"]:::primary
    B:::neutral -->|"Bare disk (.qcow2 / .vhd / .vmdk)"| D["qemu-img convert to raw bytes\nRead P1 partition at LBA 2048\nLocate datafs.tar.gz\nExtract key files from archive"]:::secondary

    C:::primary --> E["Compute MD5 hash\nCompare against KNOWN_KEY_FAMILIES table"]:::tertiary
    D:::secondary --> E:::tertiary

    E:::tertiary --> F{"Family\nknown?"}:::neutral
    F:::neutral -->|Yes| G["Classify: Gen1 / Gen2 / maintenance / feature"]:::tertiary
    F:::neutral -->|No| H(["Flag family=UNKNOWN\nNew finding: possible novel key family"]):::output

    G:::tertiary --> I["FortiBuildTrackClassifier\nParse filename: FGT_XXXX-vY.Z.W-buildNNNN.out\nExtract build_track (M=maintenance / F=feature)\nExtract key_generation from build number"]:::tertiary

    I:::tertiary --> J{"result.discrepancy\n(actual_keys)?"}:::neutral
    J:::neutral -->|"Expected Gen1, found Gen2"| K(["Anomalous build\nPossible tampered image"]):::output
    J:::neutral -->|Consistent| L(["Normal: archive or deploy"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#546e7a,stroke-width:2px
    linkStyle 1 stroke:#bf360c,stroke-width:2px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#546e7a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
    linkStyle 8 stroke:#6a1b9a,stroke-width:2px
    linkStyle 9 stroke:#546e7a,stroke-width:2px
    linkStyle 10 stroke:#2e7d32,stroke-width:3px
    linkStyle 11 stroke:#2e7d32,stroke-width:3px
```

The KNOWN_KEY_FAMILIES table is a cross-firmware corpus of MD5 hashes accumulated across engagements. Each new engagement that identifies a new key family adds to the corpus. `batch_scan(dir)` scans a directory of firmware images and reports all family classifications in one pass, flagging unknown families for immediate investigation.

---

## Huawei VRP Squashfs

### Why standard unsquashfs fails

XZ compression supports optional branch-and-call transformation (BCJ) filters that improve compression by making instruction addresses relative before compression. The x86 BCJ filter (filter ID 0x04) is the default in most squashfs implementations. Huawei VRP v600R024+ uses the ARM64 BCJ filter (filter ID 0x0A), which transforms the target addresses in AArch64 `bl`, `blr`, and `b` instructions. No standard squashfs tool ships with ARM64 BCJ support.

### Extraction pipeline

```mermaid
flowchart TD
    A(["Huawei VRP squashfs filesystem"]):::input --> B["Validate squashfs v4 superblock\nmagic = 0x73717368\ns_major = 4\ncompression = XZ (comp_id = 4)"]:::primary

    B:::primary --> C["Try standard xz.decompress(data)"]:::secondary
    C:::secondary --> D{"Decompress\nsucceeded?"}:::neutral

    D:::neutral -->|Yes| E["Standard XZ decompression\n(x86 BCJ filter or no filter)"]:::tertiary
    D:::neutral -->|No: filter mismatch| F["Retry with lzma.decompress(data,\n  format=lzma.FORMAT_RAW,\n  filters=[{'id': 0x0A}])\nARM64 BCJ filter ID"]:::tertiary

    E:::tertiary --> G(["Filesystem extracted\next.list_files() → inner paths\next.extract(path) → bytes"]):::output
    F:::tertiary --> G:::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#546e7a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
```

Decompression limits: 8 MB per metadata block, 512 MB per file. Use as a context manager: `with HuaweiSquashfsExtractor(path) as ext:`. Not thread-safe.

---

## How it works

Loads the firmware image, maps entropy across the file using a sliding window, and classifies regions as encrypted, compressed, or plaintext. Known cryptographic constants and key derivation patterns are matched against the corpus. Partition boundaries are recovered from format signatures in the plaintext regions. Each finding includes the byte offset, the matched pattern, and the confidence level.

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/firmware.elf')
print(ctx.summary())
```

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

`FirmwareContainerKeyExtractor.from_path(path).extract()` returns an `ExtractionResult`. See [firmware-container-key-extractor](firmware-container-key-extractor.md) for the `ExtractionResult` / `PartitionResult` field reference.

`FirmwareAuthBypassDetector.from_path(path).scan()` returns a `FirmwareAuthBypassResult`. See [firmware-auth-bypass-detector](firmware-auth-bypass-detector.md) for the field reference `path`, `is_vulnerable`, `severity`, `summary`, and `arch`.
| `evidence` | Byte offset or string excerpt that triggered the finding |

---

## See also

- [FirmwareContainers](firmware-containers.md): partition extraction from container images
- [FirmwareContainerKeyExtractor](firmware-container-key-extractor.md): recover embedded key material
- [TaintAnalysis](taint-analysis.md): trace network input to sinks in extracted binaries
- [SemanticSearch](semantic-search.md): find vulnerability candidates in extracted ELFs
