# Fortinet Firmware Analysis

Fortinet `.out` firmware files have two encryption layers. Most tools only get past the first one.

---

## Layer 1: The outer XOR cipher

Standard tools like binwalk, file, and 7z can detect the outer gzip wrapper on a `.out` file but fail at what is inside. The inner binary is XOR-encrypted with a 64-byte repeating key. Binwalk has no automated XOR key recovery, so it calls the inner data "data." Ablation's `XorSolver` exploits a property that generic tools don't know about: NAND flash memory erases to `0xFF`, so the plaintext is roughly 80 to 86 percent null bytes. That byte-frequency bias creates an Index of Coincidence spike at shift=64 that is 192 to 244 times above random baseline, which is unambiguous key-length signal from a 4KB sample. `FortiOSHardwareExtractor` wraps this into a single call that goes from raw `.out` to decrypted NAND image.

```python
from ablation.analyzers.fortios_firmware_extractor import FortiOSHardwareExtractor

ext = FortiOSHardwareExtractor.from_path('/path/to/FGT_60F-v7.2.13.out')
result = ext.recover_xor_key()
print(f'confidence={result.confidence:.3f}  key={result.key.hex()}')

ext.extract_to('/tmp/fgt60f_partitions/')
```

Hardware appliances have a second layer on top of that. The inner gzip partitions are RC4-encrypted. Fortinet marks RC4-encrypted partitions by setting reserved bits in the gzip FLG byte. That is not a corrupt header, it is a marker. `FirmwareContainerKeyExtractor` scans the decrypted outer image for PKCS#1 v1.5 blocks that carry the RC4 key and decrypts each partition with it. Generic tools see the gzip magic bytes, report invalid compression, and stop because they have no concept of a per-partition secondary cipher.

```python
from ablation.analyzers.firmware_container_key_extractor import FirmwareContainerKeyExtractor

result = FirmwareContainerKeyExtractor.from_path('/path/to/FGT_60F-v7.2.13.out')
print(result.report())
# Outer XOR key confidence: 0.981
# PKCS#1 candidate keys found: 1
# Inner partitions: 4
#   offset=0x... kind=gzip DECRYPTED cipher=rc4 valid_gzip=True
```

---

## Layer 2: The known-key corpus

Fortinet ships the same private key files unchanged across entire product families for years. `FortiGateCertKeyScanner` maintains a `KNOWN_KEY_FAMILIES` table of every confirmed MD5 fingerprint in the corpus. For any new Fortinet firmware, a single scan call returns an immediate verdict: known CRITICAL, known HIGH, or an unknown MD5 that is itself a finding candidate.

Without the table, you extract a key, compute an MD5, and have no context. With it, you know that `1158fa1e` is the same 512-bit RSA key present across FortiGate, FortiFirewall, FortiWiFi, and FortiExtender, and you know the severity of that finding before writing a single line of analysis.

```python
from ablation.analyzers.fortigate_cert_key_scanner import FortiGateCertKeyScanner

# OVF ZIP (VMware/ESXi)
result = FortiGateCertKeyScanner.from_path('/path/to/FGT_VM64-v7.4.12.out.zip')
print(FortiGateCertKeyScanner.report([result]))

# KVM QCOW2, Hyper-V VHD/VHDX, or bare VMDK
result = FortiGateCertKeyScanner.from_disk('/path/to/FGT_VM64_KVM-v7.4.12.qcow2')

# Batch sweep a directory
results = FortiGateCertKeyScanner.batch_scan('/path/to/FortiGate/Firmware/')
unknowns = [r for r in results if r.has_unknown_keys()]
```

`FortiBuildTrackClassifier` adds a check before you touch the image. It reads the M-build vs F-build suffix in the firmware filename and predicts how many keys the image should contain. An unexpected count is flagged as anomalous.

```python
from ablation.analyzers.fortibuild_track_classifier import FortiBuildTrackClassifier

info = FortiBuildTrackClassifier.from_filename('FGT_VM64-v7.4.12.M-build2902-FORTINET.out.zip')
print(info.expected_keys)   # ['fgt_512.key', 'fgt2.key', 'fgt.key']
print(info.track)           # 'M'
```

Known key families (current table):

| MD5 | Key | Severity |
|---|---|---|
| `1158fa1e` | fgt_512.key Gen1 | CRITICAL |
| `12b045d8` | fgt_512.key Gen2 | CRITICAL |
| `c8eaa255` | fgt2.key | CRITICAL |
| `c0ab5630` | fsw_512.key | CRITICAL |
| `4e447a81` | fgt.key | HIGH |
| `2f231375` | fgt.key (FortiAP MIPS) | HIGH |

Any image with a Gen1 or Gen2 `fgt_512.key` is immediately CRITICAL. The 2048-bit keys are HIGH severity because they are shared across a product family, not because they are factorable.

---

## Layer 3: Semantic sweep

Most vulnerability scanners grep for `system(` and `strcpy`, or they run a dynamic fuzzer. Neither approach works well on stripped Fortinet binaries. Ablation's semantic sweep lifts functions to an intermediate representation, traces taint from user-controlled inputs to dangerous sink call sites, and ranks candidates by a composite score built from opcode density, xref depth, argument structure, and known-bad patterns. An 885-function binary returns a ranked shortlist in 35 seconds.

```bash
python sweeps/fortinet_sweep.py ./httpsd
```

Fortinet binaries wrap many sink calls through PLT stubs, so a naive `call system@plt` scan misses most of the surface. `SinkArgClassifier` resolves PLT stubs to identify the true sink and classifies argument provenance as constant string, snprintf-formatted, caller-propagated, or unknown. ARM32 and ARM64 use different PLT calling conventions, so the same sink identification logic that works on x86-64 fails silently on ARM without architecture-aware resolvers. `CppVtableReconstructorAnalyzer` resolves virtual dispatch chains that would otherwise appear as opaque register-indirect calls in any static disassembler.

Ghidra and IDA give you an annotated disassembly of 885 functions with no prioritization. Ablation gives you 5 to 10 confirmed taint paths worth manual time. The FortiWeb `FWB-FABRIC-1` finding, a pre-auth SQL injection and path traversal through an unsanitized Bearer token, came from this ranking. The semantic sweep put the handler in the top candidates and a manual capstone trace confirmed it.

---

## Related modules

- [FortiOSHardwareExtractor](../module-reference/firmware-containers.md)
- [FirmwareContainerKeyExtractor](../module-reference/firmware-container-key-extractor.md)
- [FortiGateCertKeyScanner](../module-reference/fortigate-cert-key-scanner.md)
- [FortiBuildTrackClassifier](../module-reference/fortibuild-track-classifier.md)
- [SinkArgClassifier](../module-reference/sink-arg-classifier.md)
- [CppVtableReconstructorAnalyzer](../module-reference/cpp-vtable-reconstructor.md)
