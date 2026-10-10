# Firmware Analysis

Decrypts and extracts proprietary firmware through a three-stage key recovery chain. Huawei VRP squashfs with ARM64 BCJ filter is also supported. Both tools target formats where standard extraction tools silently fail.

---

## Why this exists

Two things blocked firmware analysis before these modules:

**1. Proprietary firmware encryption was a dead end.**
Many vendor firmware images use a layered encryption scheme: an outer XOR key applied to the entire image, then an inner PKCS#1 v1.5 RSA-encrypted RC4 session key embedded in the partially-decrypted data, then the actual payload encrypted with RC4. Each layer requires a different recovery method. Without a reusable chain, each engagement re-discovered the same key recovery steps from scratch. `FirmwareContainerKeyExtractor` packages the full three-stage chain as one call.

**2. Huawei VRP squashfs used a non-standard XZ filter.**
Standard `unsquashfs` cannot extract Huawei VRP v600R024+ squashfs images because they use the ARM64 BCJ (Branch Call Jump) XZ filter (filter ID 0x0A) rather than the x86 BCJ filter (0x04) that most tools assume. The ARM64 BCJ filter transforms branch target offsets in ARM64 instructions to improve compression ratios. `HuaweiSquashfsExtractor` handles this filter without external tool dependencies.

---

## How the decryption chain works

```mermaid
flowchart TD
    A[/"Raw encrypted firmware (.out / .bin)"/] --> B["Stage 1 · Outer XOR layer\nFortiOSHardwareExtractor\nKPA against ELF magic 0x7f454c46\nor gzip magic 0x1f8b0800\n64-byte repeating key (NAND page boundary)"]

    B --> C["Partially decrypted binary"]

    C --> D["Stage 2 · PKCS#1 v1.5 block scan\nScan for 0x00 0x02 ... 0x00 padding\nExtract candidate RSA-encrypted\nRC4 session key (256 bytes, RSA-2048)"]

    D --> E["Stage 3 · RC4 known-plaintext attack\ngzip magic: 0x1f 0x8b 0x08 0x00\nkeystream[0:4] recovered via XOR\nFull session key recovered by\ninverting PRGA with KSA structure"]

    E --> F[/"RC4 session key recovered\nDecrypt payload → result.datafs_path\n/etc/shadow · web service binary · SSH host keys"/]

    style A fill:#1e293b,stroke:#475569,color:#e2e8f0
    style F fill:#14532d,stroke:#166534,color:#dcfce7
```

### Stage 1: Outer XOR layer

FortiWiFi/FortiGate appliances use NAND flash. Unprogrammed NAND cells read as 0xFF. The XOR key is derived by XOR-ing the encrypted bytes against the known plaintext: ELF magic `0x7f 0x45 0x4c 0x46` or gzip magic `0x1f 0x8b 0x08` at the payload start.

```
  key recovery:
    known_plain = b'\x7f\x45\x4c\x46'  (ELF magic)
    key[:4] = encrypted[:4] ^ known_plain
    key repeats at 64-byte period (NAND page boundary)
```

### Stage 2: PKCS#1 v1.5 block scan

PKCS#1 v1.5 encryption padding has a fixed structure: `0x00 0x02 [8+ non-zero random bytes] 0x00 [message]`. The scanner finds `0x00 0x02 ... 0x00` sequences in the partially-decrypted binary and extracts candidate RSA-encrypted RC4 session key blocks. The typical key block size is 256 bytes (RSA-2048), positioned 128 bytes from the start of the cert partition.

### Stage 3: RC4 known-plaintext attack

RC4 is a stream cipher. The keystream XORs with plaintext to produce ciphertext: `ciphertext[i] = plaintext[i] XOR keystream[i]`. The payload is known to start with a gzip archive, so the first four bytes of keystream are recoverable:

```
  keystream[0] = ciphertext[0] XOR 0x1f
  keystream[1] = ciphertext[1] XOR 0x8b
  keystream[2] = ciphertext[2] XOR 0x08
  keystream[3] = ciphertext[3] XOR 0x00
```

The RC4 KSA (Key Scheduling Algorithm) initializes the permutation S from the 128-byte session key. Given the first four keystream bytes and the KSA structure, the full session key is recoverable by inverting the PRGA.

Override the key if already known: `override_key=bytes.fromhex('...')`.

---

## Firmware Key Corpus

`FortiGateCertKeyScanner` and `FortiBuildTrackClassifier` together maintain a cross-firmware key family corpus that identifies anomalous firmware builds before decryption begins.

```mermaid
flowchart TD
    A[/"Firmware image or bare disk"/] --> B{"Input format"}
    B -->|"OVF ZIP"| C["Extract vmdk or qcow2 from ZIP\nLocate fgt_512.key / fgt2.key / fgt.key"]
    B -->|"Bare disk (.qcow2 / .vhd / .vmdk)"| D["qemu-img convert to raw bytes\nRead P1 partition at LBA 2048\nLocate datafs.tar.gz\nExtract key files from archive"]

    C --> E["Compute MD5 hash\nCompare against KNOWN_KEY_FAMILIES table"]
    D --> E

    E --> F{"Family\nknown?"}
    F -->|Yes| G["Classify: Gen1 / Gen2 / maintenance / feature"]
    F -->|No| H[/"Flag family=UNKNOWN\nNew finding: possible novel key family"/]

    G --> I["FortiBuildTrackClassifier\nParse filename: FGT_XXXX-vY.Z.W-buildNNNN.out\nExtract build_track (M=maintenance / F=feature)\nExtract key_generation from build number"]

    I --> J{"result.discrepancy\n(actual_keys)?"}
    J -->|"Expected Gen1, found Gen2"| K[/"Anomalous build\nPossible tampered image"/]
    J -->|Consistent| L["Normal: archive or deploy"]

    style A fill:#1e293b,stroke:#475569,color:#e2e8f0
    style H fill:#7f1d1d,stroke:#991b1b,color:#fecaca
    style K fill:#7f1d1d,stroke:#991b1b,color:#fecaca
```

The KNOWN_KEY_FAMILIES table is a cross-firmware corpus of MD5 hashes accumulated across engagements. Each new engagement that identifies a new key family adds to the corpus. `batch_scan(dir)` scans a directory of firmware images and reports all family classifications in one pass, flagging unknown families for immediate investigation.

---

## Huawei VRP Squashfs

### Why standard unsquashfs fails

XZ compression supports optional branch-and-call transformation (BCJ) filters that improve compression by making instruction addresses relative before compression. The x86 BCJ filter (filter ID 0x04) is the default in most squashfs implementations. Huawei VRP v600R024+ uses the ARM64 BCJ filter (filter ID 0x0A), which transforms the target addresses in AArch64 `bl`, `blr`, and `b` instructions. No standard squashfs tool ships with ARM64 BCJ support.

### Extraction pipeline

```mermaid
flowchart TD
    A[/"Huawei VRP squashfs filesystem"/] --> B["Validate squashfs v4 superblock\nmagic = 0x73717368\ns_major = 4\ncompression = XZ (comp_id = 4)"]

    B --> C["Try standard xz.decompress(data)"]
    C --> D{"Decompress\nsucceeded?"}

    D -->|Yes| E["Standard XZ decompression\n(x86 BCJ filter or no filter)"]
    D -->|No: filter mismatch| F["Retry with lzma.decompress(data,\n  format=lzma.FORMAT_RAW,\n  filters=[{'id': 0x0A}])\nARM64 BCJ filter ID"]

    E --> G[/"Filesystem extracted\next.list_files() → inner paths\next.extract(path) → bytes"/]
    F --> G

    style A fill:#1e293b,stroke:#475569,color:#e2e8f0
    style G fill:#14532d,stroke:#166534,color:#dcfce7
```

Decompression limits: 8 MB per metadata block, 512 MB per file. Use as a context manager: `with HuaweiSquashfsExtractor(path) as ext:`. Not thread-safe.
