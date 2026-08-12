# Ablation

**Autonomous Reverse Engineering Tool**

Deploy inside compromised systems to autonomously reverse engineer unknown platforms.

```
    ___    ____  __    ___  ______________  _   __
   /   |  / __ )/ /   /   |/_  __/  _/ __ \/ | / /
  / /| | / __  / /   / /| | / /  / // / / /  |/ / 
 / ___ |/ /_/ / /___/ ___ |/ / _/ // /_/ / /|  /  
/_/  |_/_____/_____/_/  |_/_/ /___/\____/_/ |_/   
                                                   
 Autonomous Reverse Engineering Tool v2.2.0
```
Know the system before you own the system.

---

<div>
  <img src="https://img.shields.io/badge/Language-Python_3-961490?style=flat-square" alt="Language">
  <img src="https://img.shields.io/badge/Build-PyInstaller-961490?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/License-Research_Only-961490?style=flat-square" alt="License">
</div>

---

## ⚡ Overview

**Ablation fingerprints unknown systems from the inside** — platform detection, binary analysis, process enumeration, network mapping, privilege escalation paths, and syscall tracing. All autonomous. Zero dependencies on target.

### macOS

macOS support is first-class. Ablation runs natively without modification or target environment setup — no third-party packages required, no Python environment setup on target.

- **`bv41` Decoder:** Decodes Apple's proprietary LZ4 container (bv41 framing, `Compression.framework`), targeting MacStadium Orka VM image layers and APFS snapshots without requiring an Apple runtime.
- **Orka RE Module:** Detects gRPC sockets (`/var/run/orka-engine.sock`, `run.sock`), extracts embedded credentials from binaries, maps cluster infrastructure from inside a macOS VM.

### 🍏 The "Special Sauce"

**`core/bv41_decoder.py` is the only publicly available offline decoder for Apple's framed LZ4 container format.** No other tool — standard LZ4 libraries, 7-Zip (including LZ4-enabled forks), Keka, or APFS forensic suites (BlackBag, Cellebrite) — implements this specific framing.

What makes it the only open implementation:

- **Full magic check.** Correctly identifies all three chunk types: `bv41` (LZ4-compressed), `bv4-` (passthrough), and `bv4$` (terminator). Generic LZ4 decoders open with a frame magic check (`0x184D2204`) and fail immediately.
- **Multi-chunk stream iteration.** Walks the complete chain of variable-length chunks until the `bv4$` terminator — stopping at the first block silently truncates output.
- **Passthrough handling.** The `bv4-` uncompressed case is decoded correctly without calling into lz4 at all. Most implementations that do partial bv41 support miss this branch.
- **Fully offline.** Requires only the open-source `lz4` block API — no Apple frameworks, no macOS runtime, no private APIs. Works cross-platform.

Additional capabilities:

- **Metadata probing.** `probe_bv41()` API returns chunk count, compression ratio, and uncompressed size without full decode.
- **Integrated.** Built into a post-exploitation autonomous RE tool with CLI one-liner and PyInstaller single-binary packaging.

#### Format internals

Apple's `Compression.framework` wraps raw LZ4 block data in its own chunked container — distinct from the standard LZ4 frame format (Yann Collet):

```
Offset  Size  Field
  0     4B    magic: b'bv41' (LZ4-compressed chunk)
                    b'bv4-' (passthrough/uncompressed chunk)
                    b'bv4$' (terminator — end of stream)
  4     4B    uncompressed_size (uint32 little-endian)
  8     4B    compressed_size (uint32 little-endian)
 12     N     raw LZ4 block payload — NOT an LZ4 frame
```

The stream is a chain of variable-length chunks ending at the `bv4$` terminator. A decoder must walk the chain, not just read a single block.

**Why standard decoders fail:** The standard LZ4 frame format starts with magic `0x184D2204`, a frame descriptor, and data blocks. The bv41 payload skips all of that — it is a raw LZ4 block, not a frame. Every decoder that opens with a magic check fails immediately. Correct decode requires `lz4.block.decompress(payload, uncompressed_size=N)` where `N` is read from the bv41 header, not from the LZ4 stream itself. Multi-chunk files require iterating all chunks; stopping at the first block silently truncates output.

**How Orka uses it:** Both `orka-engine` and `runvz` call `AppleArchive.ByteStream.decompressionStream(using: .lz4)` — Apple's private API — to decode VM image layers before handing them to `Virtualization.framework`. The bv41 container is the wire format for those layers on NFS mounts and OCI registries. Inspecting or auditing a layer without this decoder requires calling into a live macOS `Compression.framework` runtime.

---

## 🚀 Quick Start

```bash
git clone https://github.com/zellkernel/ablation.git
cd ablation
./build.sh

# Deploy to target
scp dist/ablation target:/tmp/scan

# Execute (full autonomous scan)
ssh target '/tmp/scan'

# Retrieve reports
scp target:/tmp/ablation-*.{json,txt} ./
```

Output in 60 seconds: platform fingerprint, 379 processes enumerated, 50 binaries analyzed, network map, privilege escalation paths, full JSON + text reports.

---

## Usage Modes

### 1. Autonomous (Default)

Full system analysis.

```bash
./ablation
```

Phases: platform detection → process enumeration → binary discovery → network analysis → container/platform enumeration (Docker, Kubernetes, Orka) → vulnerability analysis → privilege escalation enumeration → report generation.

### 2. Quick Fingerprint

```bash
./ablation --quick
```

Output:
```
OS: Linux 7.0.0-28-generic
Distribution: ubuntu 24.04
Architecture: x86_64 (64 bit)
Kernel: 7.0.0-28-generic
Security: ASLR full, AppArmor enabled
```

### 3. Process Analysis

```bash
./ablation --process 1234
```

Output (JSON): memory maps, loaded modules, open file descriptors, environment variables, writable+executable regions.

### 4. Binary Analysis

```bash
./ablation --binary /bin/ls
```

Output: format (ELF/PE/Mach-O), entry point, section headers, first 20 instructions disassembled.

### 5. Syscall Tracing

```bash
./ablation --syscalls 1234 --duration 10
```

Output: syscall frequency table, error counts, time percentages, top 20 syscalls by volume.

### 6. Privilege Escalation

```bash
./ablation --privesc
```

Detects: SUID/SGID binaries, writable PATH directories, sudo ALL + NOPASSWD, Docker group, writable cron jobs, dangerous capabilities (CAP_SETUID etc.), kernel exploits (DirtyPipe etc.).

### 7. Docker Enumeration

```bash
./ablation --docker
```

Output: container detection, containers/images/volumes/networks, capabilities (CapEff), escape vectors (socket mount, privileged, CAP_SYS_ADMIN).

### 8. Kubernetes Enumeration

```bash
./ablation --k8s
```

Output: service account + namespace, token extraction, pods/services/secrets/configmaps, RBAC permissions, escape vectors.

### 9. Orka Platform Enumeration

```bash
./ablation --orka
```

Output: VM metadata server enumeration (`169.254.169.254:80`), cluster info, VMs, images, gRPC socket enumeration, embedded credential detection, Sentry session stream detection (`:8969/stream`), security findings.

### 10. bv41 Decode

```bash
python3 core/bv41_decoder.py input.bv41 output.bin
```

Probe without decode:

```python
from core.bv41_decoder import probe_bv41, is_bv41
info = probe_bv41(data)
# → {'chunk_count': N, 'total_uncompressed_bytes': M, 'overall_ratio': X.Xx}
```

Optional dependency for compressed chunks: `pip install lz4`. Passthrough (`bv4-`) chunks decode without it.

### 11. Full Container Analysis

```bash
./ablation --containers
```

Runs Docker + Kubernetes + Orka enumerations together.

---

## Architecture

```
ablation/
├── core/
│   ├── platform_detect.py     # OS/arch/kernel detection
│   ├── binary_parser.py       # ELF/PE/Mach-O parser
│   ├── disasm_engine.py       # Capstone disassembly
│   ├── pe_analyzer.py         # Windows PE deep-dive
│   ├── macho_analyzer.py      # macOS Mach-O deep-dive
│   └── bv41_decoder.py        # decodes Apple's proprietary LZ4 container
├── modules/
│   ├── process_enum.py        # Process/memory analysis
│   ├── syscall_trace.py       # Syscall tracing
│   ├── privesc_enum.py        # Privilege escalation
│   ├── network_analyze.py     # Network enumeration
│   ├── docker_enum.py         # Docker environment detection
│   ├── k8s_enum.py            # Kubernetes pod enumeration
│   └── orka_enum.py           # Orka platform detection + RE
├── main.py                    # Orchestrator
└── build.sh                   # PyInstaller build script
```

~3,400 lines across 14 modules.

---

## Cross-Platform Support

| Platform | Detection | Binary Parse | Process Enum | Network | Privesc |
|----------|-----------|--------------|--------------|---------|---------|
| **Linux** | Yes | Yes (ELF) | Yes | Yes | Yes |
| **Windows** | Yes | Yes (PE) | Yes | Yes | Partial |
| **macOS** | Yes | Yes (Mach-O + bv41) | Yes | Yes | Partial |
| **BSD** | Yes | Yes (ELF) | Partial | Yes | Partial |

macOS: all modules run without third-party packages. `bv41_decoder.py` requires `lz4` only for compressed chunks; passthrough chunks need nothing.

---

## Build Requirements

**Development machine:** Python 3.8+, PyInstaller (`pip install pyinstaller`), Capstone (`pip install capstone`).

**Target machine:** None (self-contained binary).

**Optional (bv41 decode):** `pip install lz4`.

```bash
./build.sh
# → dist/ablation (~15MB standalone executable)
```

---

## Roadmap

**Phase 1–5 (complete):** Core platform detection, binary parsing, process enumeration, syscall tracing, privilege escalation, network analysis, Windows PE, macOS Mach-O, container/platform detection (Docker, Kubernetes, Orka), bv41 decoder, embedded credential detection, gRPC socket enumeration, stdlib-only macOS compat.

**Phase 6 (planned):** Full Windows support, macOS sandbox detection (SIP/Gatekeeper/TCC), cloud platform metadata servers (AWS/Azure/GCP), APFS volume enumeration, automated exploit suggestion.

---

## Security & Ethics

**Authorized use only.** Usage on systems you do not own or have explicit written authorization to test is illegal.

Intended use: red team engagements, CTF competitions, security research labs, bug bounty programs (within scope).

Ablation enumerates metadata and does not exfiltrate data. It reports vulnerabilities and does not exploit them.

---

**Ablation: Know the system before you own the system.**
