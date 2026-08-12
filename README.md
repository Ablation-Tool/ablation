# Ablation

**Autonomous Reverse Engineering Tool**

Deploy inside compromised systems to autonomously reverse engineer unknown platforms.

```
    ___    __    __    ___  ___________  ____  _  __
   / _ |  / /   / /   / _ |/_  __/  _/ |/ / | / /
  / __ | / _ \ / /__ / __ | / /  _/ //    /  |/ / 
 /_/ |_|/_.__//____//_/ |_|/_/ /___/_/|_/_/|___/  
                                                   
 Autonomous Reverse Engineering Tool v2.2.0
 Deploy INSIDE systems | Zero dependencies
```
Know the system before you own the system.
---

## What It Does

**Ablation fingerprints unknown systems from the inside** — platform detection, binary analysis, process enumeration, network mapping, privilege escalation paths, and syscall tracing. All autonomous. Zero dependencies on target.

**Think: "strace + lsof + netstat + LinPEAS + custom tools" in one self-contained binary.**

**macOS support is first-class.** Ablation runs natively on macOS without modification — no `requests` required (stdlib `urllib` fallback is built in), no Python environment setup on target. The bv41 decoder, Mach-O parser, and Orka RE module all run on macOS the same way they run on Linux.

New in v2.2.0:
- **bv41 decoder** — Apple `Compression.framework` proprietary LZ4 container (used by MacStadium Orka for VM image layers, APFS snapshots). Decodes chunked bv41 streams without any Apple runtime.
- **Orka RE module** — gRPC socket enumeration on `/var/run/orka-engine.sock` + `run.sock`, embedded credential detection, Sentry session stream detection, full cluster fingerprint from inside a macOS VM
- **macOS compatibility** — stdlib-only fallback (`urllib`) when `requests` is not installed; all modules load and run cleanly on macOS targets

---

## Quick Start

```bash
# Build standalone binary
./build.sh

# Deploy to target
scp dist/ablation target:/tmp/scan

# Execute (full autonomous scan)
ssh target '/tmp/scan'

# Retrieve reports
scp target:/tmp/ablation-*.{json,txt} ./
```

**Output in 60 seconds:**
- Platform fingerprint (OS, kernel, arch, security)
- 379 processes enumerated
- 50 binaries analyzed
- Network map (interfaces, listening ports, connections)
- Privilege escalation paths (SUID, sudo, docker, writable paths)
- Full JSON + text reports

---

## Usage Modes

### 1. Autonomous (Default)
Full system analysis. Run everything.

```bash
./ablation
```

**Phases:**
1. Platform detection
2. Process enumeration
3. Binary discovery
4. Network analysis
5. Container/platform enumeration (Docker, Kubernetes, Orka)
6. Vulnerability analysis
7. Privilege escalation enumeration
8. Report generation

### 2. Quick Fingerprint
Platform detection only.

```bash
./ablation --quick
```

**Output:**
```
OS: Linux 7.0.0-28-generic
Distribution: ubuntu 24.04
Architecture: x86_64 (64 bit)
Kernel: 7.0.0-28-generic
Security: ASLR full, AppArmor enabled
```

### 3. Process Analysis
Deep-dive on specific PID.

```bash
./ablation --process 1234
```

**Output (JSON):**
- Memory maps
- Loaded modules
- Open file descriptors
- Environment variables
- Writable+executable regions

### 4. Binary Analysis
Parse and disassemble specific binary.

```bash
./ablation --binary /bin/ls
```

**Output:**
- Format (ELF/PE/Mach-O)
- Entry point
- Section headers
- First 20 instructions disassembled

### 5. Syscall Tracing
Trace syscalls for running process.

```bash
./ablation --syscalls 1234 --duration 10
```

**Output:**
- Syscall frequency table
- Error counts
- Time percentages
- Top 20 syscalls by volume

### 6. Privilege Escalation
Enumerate privesc vectors.

```bash
./ablation --privesc
```

**Detects:**
- SUID/SGID binaries (52 found)
- Writable PATH directories
- Sudo access (ALL + NOPASSWD)
- Docker group membership
- Writable cron jobs
- Dangerous capabilities (CAP_SETUID, etc.)
- Kernel exploits (DirtyPipe, etc.)

### 7. Docker Enumeration
Docker environment detection and escape vector identification.

```bash
./ablation --docker
```

**Output:**
- Container detection (in_container, socket_access)
- Docker containers (ID, name, image, status)
- Images (repository, tag, size)
- Volumes and networks
- Capabilities (CapEff)
- Escape vectors (socket mount, privileged, CAP_SYS_ADMIN)

### 8. Kubernetes Enumeration
Kubernetes pod detection and RBAC analysis.

```bash
./ablation --k8s
```

**Output:**
- Service account + namespace
- Token extraction
- Pods, services, secrets, configmaps
- RBAC permissions (kubectl auth can-i)
- Escape vectors (privileged pod, hostPath mounts)

### 9. Orka Platform Enumeration
MacStadium Orka platform (K8s-based macOS virtualization).

```bash
./ablation --orka
```

**Output:**
- VM metadata server enumeration (169.254.169.254)
- Cluster info (API endpoints, certificates)
- VMs (name, namespace, status, IP, SSH/VNC ports)
- Images (base images, custom images)
- gRPC socket enumeration (`/var/run/orka-engine.sock`, `run.sock`)
- Embedded credential detection (API keys, shared secrets extracted from binaries)
- Sentry session stream detection (`:8969/stream`)
- Security findings (unauthenticated endpoints, default credentials, embedded keys)

### 10. bv41 Decode
Decode Apple Compression.framework bv41 streams (Orka VM image layers, APFS snapshots).

```bash
python3 core/bv41_decoder.py input.bv41 output.bin
```

**Format details:**
- 4B magic: `bv41` (LZ4-compressed chunk) | `bv4-` (passthrough chunk)
- 4B uncompressed size (uint32 LE)
- 4B compressed size (uint32 LE)
- N bytes raw LZ4 block payload (not lz4 frame format)
- Stream terminates at `bv4$`

**Probe without decode:**
```python
from core.bv41_decoder import probe_bv41, is_bv41
info = probe_bv41(data)
# → {'chunk_count': N, 'total_uncompressed_bytes': M, 'overall_ratio': X.Xx}
```

**Why this matters — the format is obscure by design:**

The exact `bv41` / `bv4-` / `bv4$` chunked container is an internal Apple format from `Compression.framework`. Public documentation is essentially nonexistent. General-purpose tools — standard lz4 libraries, 7-Zip, OCI layer unpackers, most APFS forensic suites — do not handle it. Standard `lz4` frame decoders reject the raw LZ4 block payload because it lacks the frame magic; standard APFS tools stop at the filesystem layer and don't descend into the compressed stream.

What makes `core/bv41_decoder.py` distinct:
- Standalone, dependency-light Python decoder — runs offline with no Apple runtime, no macOS required
- Explicit targeting of Orka VM image layers and APFS snapshots for RE and supply-chain inspection
- `probe_bv41()` API for metadata-only inspection (chunk count, compression ratio, uncompressed size) without full decode
- Integrated into a post-exploitation autonomous RE tool with CLI one-liner and PyInstaller single-binary packaging

**Format internals — why standard LZ4 decoders reject it:**

Standard LZ4 (Yann Collet) uses a frame format with magic `0x184D2204`, a frame descriptor, and data blocks. Apple did not use this. `bv41` wraps raw LZ4 *block* data with Apple's own framing, one chunk at a time:

```
Offset  Size  Field
  0     4B    magic: b'bv41' (compressed), b'bv4-' (uncompressed pass-through), b'bv4$' (terminator)
  4     4B    uncompressed_size (uint32 LE)
  8     4B    compressed_size (uint32 LE)
 12     N     raw LZ4 block payload — no LZ4 frame header, just the block data
```

The payload is a raw LZ4 block, not a frame. A call to `lz4.decompress()` or any frame-format decoder will fail immediately — the magic byte check rejects it. Correct decode requires `lz4.block.decompress(payload, uncompressed_size=N)` where the size comes from the bv41 header, not from within the LZ4 stream.

A stream can chain multiple `bv41` or `bv4-` chunks until a `bv4$` terminator. The decoder must walk the chain, accumulating output, and stop at the terminator — most LZ4 tools have no concept of this chunking.

**How Orka uses it:**

orka-engine and runvz both call `AppleArchive.ByteStream.decompressionStream(using: .lz4)` — Apple's private framework API — to decode VM image layers before handing them to `Virtualization.framework`. The bv41 container is the wire format for those layers on NFS and OCI registries. Inspecting a layer without this decoder means calling into a live macOS `Compression.framework` — not viable in offline RE.

**`core/bv41_decoder.py` is currently the only publicly available tool that decodes this format offline.** The format is lightly documented by Apple only as an implementation detail of `COMPRESSION_LZ4` and is used in a narrow enough context that no open-source or commercial tool has shipped a decoder. 7-Zip (including LZ4-enabled forks), Keka, and APFS/disk-image forensic suites (BlackBag, Cellebrite) all lack support for this specific chunked framing.

### 11. Full Container Analysis
Run all container/platform enumerations.

```bash
./ablation --containers
```

**Output:**
- Docker enumeration (if accessible)
- Kubernetes enumeration (if in pod)
- Orka enumeration (if in VM or API reachable)

---

## Capabilities

### Platform Intelligence
- OS/kernel/distribution detection
- Architecture (x86/x64/ARM/MIPS)
- Security features (ASLR, SELinux, AppArmor)
- Available tools inventory

### Binary Analysis
- Multi-format parsing (ELF, PE, Mach-O)
- Entry point location
- Section/segment enumeration
- Disassembly (Capstone, multi-arch)
- Windows PE deep-dive (imports, suspicious functions)
- macOS Mach-O deep-dive (load commands, dylibs, code signing)
- Apple bv41 container decode (LZ4 block, chunked)

### Runtime Analysis
- Process enumeration (all PIDs)
- Memory map analysis
- Loaded module tracking
- Syscall tracing (strace integration)
- Network enumeration (interfaces, listening ports, connections)

### Security Assessment
- Vulnerability detection (ASLR, ptrace, etc.)
- Privilege escalation paths (7 categories)
- SUID binary enumeration
- Writable+executable memory detection
- Docker group exploitation
- Sudo misconfiguration detection

### Container/Platform Detection
- Docker container detection (`/.dockerenv`, cgroup, hostname)
- Kubernetes pod detection (service account, env vars)
- Orka VM detection (metadata server, API reachability)
- Container escape vector enumeration
- Service account token extraction
- RBAC permission checking
- Default credential detection
- Embedded key detection (API keys, shared secrets, product UUIDs in binaries)
- gRPC control plane socket enumeration

---

## Architecture

```
ablation/
├── core/                      # Platform-agnostic analysis
│   ├── platform_detect.py     # OS/arch/kernel detection
│   ├── binary_parser.py       # ELF/PE/Mach-O parser
│   ├── disasm_engine.py       # Capstone disassembly
│   ├── pe_analyzer.py         # Windows PE deep-dive
│   ├── macho_analyzer.py      # macOS Mach-O deep-dive
│   └── bv41_decoder.py        # Apple Compression.framework bv41/LZ4 container
├── modules/                   # Specialized enumeration
│   ├── process_enum.py        # Process/memory analysis
│   ├── syscall_trace.py       # Syscall tracing
│   ├── privesc_enum.py        # Privilege escalation
│   ├── network_analyze.py     # Network enumeration
│   ├── docker_enum.py         # Docker environment detection
│   ├── k8s_enum.py            # Kubernetes pod enumeration
│   └── orka_enum.py           # Orka platform detection + RE (gRPC sockets, embedded creds, bv41)
├── main.py                    # Orchestrator
└── build.sh                   # PyInstaller build script
```

**Total:** ~3,400 lines across 14 modules

---

## Deployment Models

### 1. Standard Deploy
Copy binary, execute, retrieve reports.

```bash
scp dist/ablation target:/tmp/scan
ssh target '/tmp/scan'
scp target:/tmp/ablation-*.json ./
```

### 2. Memory-Only (Stealth)
Execute from /dev/shm, leave no disk artifacts.

```bash
scp dist/ablation target:/dev/shm/scan
ssh target '/dev/shm/scan && rm /dev/shm/scan'
```

**Advantages:**
- No disk writes (except final report)
- Survives reboot without persistence
- Minimal forensic footprint

### 3. One-Liner Remote Execute
Execute and retrieve in single SSH session.

```bash
ssh target 'cat > /tmp/s && chmod +x /tmp/s && /tmp/s && cat /tmp/ablation-summary.txt && rm /tmp/s /tmp/ablation-*' < dist/ablation
```

---

## Cross-Platform Support

| Platform | Detection | Binary Parse | Process Enum | Network | Privesc |
|----------|-----------|--------------|--------------|---------|---------|
| **Linux** | Yes | Yes (ELF) | Yes | Yes | Yes |
| **Windows** | Yes | Yes (PE) | Yes | Yes | Partial |
| **macOS** | Yes | Yes (Mach-O + bv41) | Yes | Yes | Partial |
| **BSD** | Yes | Yes (ELF) | Partial | Yes | Partial |

**Full Linux support. Windows/macOS binary analysis ready. Process/network enumeration adapts per platform.**

**macOS note:** All modules run without third-party packages installed (`requests` is optional; `urllib` fallback is built in). `bv41_decoder.py` requires `lz4` only if decoding compressed chunks.

---

## Build Requirements

**Development machine:**
- Python 3.8+
- PyInstaller (`pip install pyinstaller`)
- Capstone (`pip install capstone`)

**Target machine:**
- None (self-contained binary)

**Optional (for bv41 decode):**
- lz4 (`pip install lz4`)

**Build:**
```bash
./build.sh
```

**Output:**
- `dist/ablation` (~15MB standalone executable)

---

## Use Cases

### 1. Initial Reconnaissance
Just gained access to unknown Linux server. What is it?

```bash
./ablation --quick
# → Ubuntu 20.04, kernel 5.4.0, x86_64, ASLR enabled
```

### 2. Attack Surface Enumeration
Find listening services and network exposure.

```bash
./ablation  # full autonomous scan
# → 12 listening ports: SSH (22), MySQL (3306), Redis (6379)
# → 55 active connections
# → 8 network interfaces
```

### 3. Privilege Escalation
User shell → root path discovery.

```bash
./ablation --privesc
# → [CRITICAL] Sudo access (ALL + NOPASSWD)
# → [CRITICAL] Docker group membership
# → [HIGH] 8 writable PATH directories
# → [HIGH] Writable cron job: /var/spool/cron/crontabs/user
```

### 4. Binary Triage
Unknown ELF on disk. What is it?

```bash
./ablation --binary /opt/suspicious
# → ELF 64-bit, entry 0x401200
# → 7 sections (.text, .data, .rodata, etc.)
# → Disassembly: push rbp; mov rbp, rsp; sub rsp, 0x20...
```

### 5. Behavioral Analysis
What is this process doing?

```bash
./ablation --syscalls 5432 --duration 30
# → Top syscalls: read (47%), write (23%), poll (15%)
# → Network: socket, connect, send (outbound connections)
# → File: open, read, close (reading /etc/passwd)
```

### 6. Container Breakout
Inside Docker container. Find escape vectors.

```bash
./ablation --docker
# → [CRITICAL] Docker socket mounted (/var/run/docker.sock)
# → [CRITICAL] Running in privileged mode
# → [HIGH] CAP_SYS_ADMIN capability present
# → Escape vector: docker -H unix:///var/run/docker.sock run -v /:/host alpine chroot /host
```

### 7. Orka VM Enumeration
Inside MacStadium Orka macOS VM. Enumerate platform and probe for hardcoded credentials.

```bash
./ablation --orka
# → In Orka VM: TRUE
# → Metadata Server: 169.254.169.254 (accessible)
# → [CRITICAL] Embedded API key found in binary (shared secret)
# → [CRITICAL] Cluster info exposed (unauthenticated /api/v1/cluster-info)
# → [HIGH] gRPC socket accessible: /var/run/orka-engine.sock (39 RPCs, no auth)
# → [HIGH] Default credentials (admin:admin on :8822)
# → API Servers: 10.221.188.20, 10.221.188.100
```

### 8. Orka Image Layer Decode
Decode bv41-wrapped VM image layer to inspect contents.

```bash
python3 core/bv41_decoder.py layer.bv41 layer.raw
# → bv41 stream: 128 chunks, 512.00 MB uncompressed, ratio 2.8x
# → Decoded 536870912 bytes → layer.raw
```

---

## Comparison to Existing Tools

| Tool | Type | Where Runs | Dependencies | Output |
|------|------|------------|--------------|--------|
| **Ablation** | Autonomous RE | Target (post-access) | None | Platform fingerprint + vulns + network |
| Ghidra | Interactive RE | Analyst workstation | Java + GUI | Decompiled code, manual analysis |
| strace | Syscall tracer | Target | None | Raw syscall log |
| LinPEAS | Privesc enum | Target | Bash | Text report of privesc vectors |
| nmap | Network scanner | External | None | Open ports (from outside) |
| lsof | File descriptor list | Target | None | Open files for single process |

**Ablation combines the breadth of LinPEAS with the depth of Ghidra's binary parsing, the runtime visibility of strace, and the network view of netstat — all in one autonomous tool.**

---

## Security & Ethics

**Authorized use only.**

Ablation is a security research and penetration testing tool. Usage on systems you do not own or have explicit written authorization to test is **illegal**.

**Intended use:**
- Red team engagements (authorized)
- CTF competitions
- Security research labs
- Personal test environments
- Bug bounty programs (within scope)

**Not for:**
- Unauthorized system access
- Malicious reconnaissance
- Data exfiltration
- Persistence mechanisms

**Restraint built-in:**
- Enumerates metadata, does not exfiltrate data
- Minimal syscall footprint
- Reports vulnerabilities, does not exploit
- Names are the finding (samples minimal to confirm severity)

---

## Roadmap

**Phase 1 (complete):** Core platform detection, binary parsing, process enumeration
**Phase 2 (complete):** Syscall tracing, privilege escalation enumeration
**Phase 3 (complete):** Network analysis, Windows PE deep-dive, macOS Mach-O deep-dive
**Phase 4 (complete):** Container/platform detection (Docker, Kubernetes, Orka)
**Phase 5 (complete):** bv41 decoder, embedded credential detection, gRPC socket enumeration, stdlib-only macOS compat

**Phase 6 (planned):**
- Full Windows support (Win32 API hooking, registry enum, service analysis)
- macOS sandbox detection (SIP, Gatekeeper, TCC)
- Behavior-based malware detection
- Kernel module enumeration
- Automated exploit suggestion (map findings to Metasploit modules)
- Cloud platform detection (AWS, Azure, GCP metadata servers)
- APFS volume enumeration

---

## Development

**Language:** Python 3
**Deployment:** PyInstaller single-file executable
**License:** Research/Educational Use
**Version:** 2.2.0

---

## Example Output

```
    ___    __    __    ___  ___________  ____  _  __
   / _ |  / /   / /   / _ |/_  __/  _/ |/ / | / /
  / __ | / _ \ / /__ / __ | / /  _/ //    /  |/ / 
 /_/ |_|/_.__//____//_/ |_|/_/ /___/_/|_/_/|___/  

 Autonomous Reverse Engineering Tool v2.2.0
 Deploy INSIDE systems | Zero dependencies

[*] Ablation - Autonomous Mode
[*] Analyzing compromised system...

[1/8] Platform Detection
  OS: Linux 64bit
  Kernel: 7.0.0-28-generic

[2/8] Process Enumeration
  Found 379 running processes

[3/8] Binary Discovery
  Found 50 interesting binaries

[4/8] Network Analysis
  Interfaces: 8
  Listening: 12

[5/8] Container/Platform Enumeration
  Docker: In container=False, Socket=True
  Kubernetes: In K8s=False
  Orka: VM=False, API=False

[6/8] Vulnerability Analysis
  Identified 3 potential vulnerabilities

[7/8] Privilege Escalation Enumeration
  Found 6 potential paths

[8/8] Report Generation
  Report saved: /tmp/ablation-summary.txt

[+] Analysis complete!
[+] Full report: /tmp/ablation-report.json
[+] Summary: /tmp/ablation-summary.txt
```

---

**Ablation: Know the system before you own the system.**
