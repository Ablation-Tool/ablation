
<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="ablation">
</p>

## What is this?

**Ablation** is an autonomous reverse engineering and attack surface analysis tool. Drop it on a system and it maps what's running, how things are structured internally, and where security boundaries break down — without requiring a debugger, source code, or prior target knowledge.

## What does it do exactly?

Ablation has 60+ analysis modules across eight domains:

### Cisco ASA / Firepower

| Module | What it finds |
|--------|--------------|
| `cisco_asa_lina_re` | LINA binary RE — `gp_obj` struct layout, RADIUS overflow path (Class attr 25 → OU= injection), version-dispatch for gp_name offset (0x2b0 pre-9.22.2, 0x2b1 post). `RadiusOverflowProbe` class for live testing. |
| `cisco_asa_cred_audit` | Type 7 password decode, Type 5 hash detection, default/weak credential matching |
| `cisco_radius_ise_re` | RADIUS Class attribute 25 attack primitives, ISE CoA (RFC 5176), posture bypass, RADIUS packet construction with configurable attributes |
| `cisco_cstp_attack` | CSTP/AnyConnect tunnel RE, HostScan/CSD/DAP bypass chains, sdesktop cookie injection, SAML SP injection, username timing oracle, tunnel group enumeration, RADIUS CoA mid-session injection, CRL/OCSP bypass, cert-map tunnel-group bypass, ASA version fingerprinting |
| `cisco_webvpn_js_re` | WebVPN JavaScript bundle extraction, static secret scanning from `portal.js` / `svc.js`, session token patterns |
| `cisco_asdm_download_re` | Live ASDM JAR download from Cisco ASA (`/+CSCOU+/asa/asdm.jar`), JNLP resolution, authenticated JAR retrieval |
| `cisco_asdm_jar_re` | ASDM JAR → JVM constant pool parse, hardcoded auth bypass, X509TrustManager extraction, REST API endpoint map |
| `cisco_asdm_re` | JVM class file structure parsing, constant pool analysis |
| `cisco_rommon_re` | ROMMON config-register decode, boot-field bypass detection, password-recovery exposure |
| `cisco_config_re` | Running/startup config parsing — Type 7 decode, AAA chain map, access-list analysis, VPN profile extraction, weak auth detection |
| `cisco_ios_re` | IOS/IOS-XE ELF/packed image RE — MIPS/ARM64/x86 gadget extraction, hardcoded credential scanning, crash dump analysis with ADRP-based image-base recovery |
| `cisco_api_enum` | ASA REST API (`/api/...`) endpoint enumeration, unauthenticated surface mapping |

### Cisco NX-OS / ACI / Data Center

| Module | What it finds |
|--------|--------------|
| `cisco_nxos_guestshell_re` | NX-OS guestshell LXC rootfs analysis — credential extraction, shadow hash detection, SNMP community strings, JDBC URLs, private keys, security package inventory |
| `nxos_enum` | NX-OS / ACI / APIC REST API enumeration — fabric topology, tenant policy model, AAA config, VMM integration, L3Out connectivity, contract analysis |
| `nexus_dashboard_enum` | Nexus Dashboard / NDI / NDFC / NDO REST API — unauthenticated cluster info, Kafka export config, integration surface |
| `hyperflex_enum` | HyperFlex Connect REST API, iSCSI/NFS, UCSM XML API, APIC, Intersight claim-code extraction |

### Orka3 / MacStadium

| Module | What it finds |
|--------|--------------|
| `orka_oidc_re` | Orka3 OIDC auth flow RE — `fetchClusterInfo` → PKCE → JWT extraction; CVE-2020-26160 audience bypass; empty HS256 secret forge; internal host map (`10.221.188.x`) |
| `orka_vm_exec_re` | VM exec via K8s pod exec API (`/api/v1/namespaces/orka-default/pods/<vm>/exec?container=orka-vm`), SPDY executor, SA token creation, virsh command execution on hypervisor |
| `orka_api_surface_re` | Complete Orka REST API reconstruction (60+ routes) from Go binary RE — VM/image/ISO/SA/registry-credential/node management |
| `orka_jwt_dynamic_re` | In-vitro HS256 empty-key HMAC verification harness — replicates Go's `SigningMethodHMAC.Verify` with `b''` key; generates forged admin tokens |
| `orka_enum` | Live Orka API enumeration, token validation, image list, VM config extraction |

### Cross-Platform Binary RE

| Module | What it finds |
|--------|--------------|
| `swift_re` | Swift Mach-O binary RE — SwiftNIO service extraction, gRPC service/method discovery, Vapor route map, Objective-C runtime class enumeration |
| `java_re` | Java `.class`/`.jar` security audit — deserialization gadget chains (Ysoserial library detection), reflection abuse, framework fingerprinting (Spring/Jackson/Gson/Hibernate) |
| `java_decompiler` | Pure-Python JVM constant pool parser — UTF-8/String/Methodref/NameAndType decoding without external tools |
| `macos_malware_re` | macOS malware artifact analysis — LaunchAgent/Daemon persistence, XPC service exposure, dylib hijack surface, Mach-O code signature gaps |
| `windows_kernel_re` | Windows kernel/driver RE — IOCTL `CTL_CODE` decomposition, device type/access/function decode, dispatch table analysis |
| `forensics_enum` | Binary exploit pattern detection — SEH chain corruption (FS:[0] patterns), POPAD+JMP shellcode sequences, Windows x86 exploit artifacts |
| `regression` | Firmware version struct offset regression (OLS, logistic, symbolic) — tracks confirmed `gp_name` offset across ASA versions; `FirmwareVersionRegression` + `SymbolicOffsetRegression` classes |

### Cryptography / JWT

| Module | What it finds |
|--------|--------------|
| `jwt_crypto_analyzer` | Algorithm confusion (RS256→HS256), empty secret detection, known-weak secret brute-force, token forgery, `none` alg bypass |
| `crypto_audit` | Weak JWT secret list (production leak frequency), crypto implementation patterns |

### Container / Cloud / Kubernetes

| Module | What it finds |
|--------|--------------|
| `docker_enum` | Docker socket exposure, container escape surface (cap sets, namespace leaks, socket mounts), daemon API reachability |
| `k8s_enum` | K8s service account tokens, RBAC misconfiguration, secret exposure, ConfigMap credential hunting |
| `harbor_enum` | Harbor registry API — unauthenticated project listing, image manifest extraction, vulnerability report access |
| `privesc_enum` | SUID/SGID binaries, world-writable paths, cron job injection, sudo rule analysis |
| `lateral_movement` | AI/ML infra port sweep, MacStadium internal DNS discovery, environment/config secret regex patterns |

### Network / TLS / Infrastructure

| Module | What it finds |
|--------|--------------|
| `tls_enum` | TLS version probing (1.0/1.1 detection), weak cipher enumeration (RC4/3DES/NULL/EXPORT/anon-DH), cert chain validation |
| `net_sniffer` | Raw packet capture + cleartext credential extraction (post-compromise, elevated privileges) |
| `network_analyze` | Network interface map, routing table, listening services, established connection inventory |
| `nginx_enum` | Nginx alias traversal payloads, path confusion for LFI, NX-API frontend probing |
| `sip_enum` | SIP service enumeration — OPTIONS/REGISTER/INVITE probe, extension brute-force surface, media negotiation |
| `streaming_enum` | Kafka (9092/9093) raw protocol enumeration, Flink (8081) REST API, NiFi, Confluent Schema Registry |

### Live System

| Module | What it finds |
|--------|--------------|
| `process_enum` | Live process inventory with memory maps, open FDs, loaded libraries |
| `syscall_trace` | System call tracing (strace/dtrace) with pattern classification |
| `macos_sysadmin` | macOS keychain credential surface, Orka-related service names, sysadmin attack paths |
| `ios_enum` | iOS/Apple platform privilege level map, IOS Type 7/5/8/9 password decode |

### Core (support libraries)

| Module | What it does |
|--------|-------------|
| `core/elf_parser` | ELF section/symbol/dynamic table parsing |
| `core/macho_analyzer` | Mach-O load command, section, and symbol analysis |
| `core/pe_parser` / `pe_analyzer` | PE import/export table, section entropy, resource analysis |
| `core/binary_parser` | Format-agnostic binary parsing primitives |
| `core/disasm_engine` | Capstone-backed disassembler with gp_obj field annotation |
| `core/firmware_analyzer` | Firmware magic byte recognition (SquashFS/UBI/JFFS2/LZMA/etc), entropy classification, hardcoded credential extraction |
| `core/bv41_decoder` | Apple Compression.framework `bv41` (chunked LZ4) decoder — handles Orka VM image layers and APFS snapshots; pure Python, no native dependencies |
| `core/attck_tagger` | MITRE ATT&CK technique tagging for all findings |
| `core/yara_generator` | YARA rule generation from binary scan results |
| `core/shellcode_utils` | Shellcode templates (x86-64 + ARM64), bad-byte detection, XOR/ADD encoders, NOP sled |
| `core/tls_analyzer` | TLS cert chain analysis, CT anomaly detection (honeypot signal per Insight #97), quantum-vulnerability inventory (RSA/ECDSA → Shor; ML-KEM/ML-DSA → safe) |
| `core/swift_demangle` | Swift symbol demangling |
| `core/platform_detect` | Platform fingerprint — OS, arch, kernel, container runtime |

### Utilities

| File | Purpose |
|------|---------|
| `utils/poc_radius_ou_inject.py` | Standalone RADIUS Group Policy Injection PoC — fake RADIUS server mode (responds to every Access-Request with attacker-controlled OU=) or single-packet send mode. Demonstrates F1 (no Message-Authenticator enforcement) + F2 (256-byte OU= vs 64-byte CLI limit). |

## Why would I use this?

- You have a shell on a Cisco ASA, NX-OS box, or Orka cluster and want to recover struct layouts, credential material, and attack chains without source
- You're tracking struct field offsets across ASA firmware versions — the `regression.py` module maintains confirmed data points and fits boundary models
- You need to RE a stripped Go binary (Orka), Java JAR (ASDM), or Apple bv41-compressed layer offline
- You want JWT forgery primitives against Orka's HS256-empty-secret or CVE-2020-26160 audience bypass
- You need a RADIUS injection PoC against ASA's Class attribute 25 parsing layer

## Quick start

```bash
# Full autonomous analysis of the current system
./ablation

# Cisco ASA attack surface
./ablation --asa 192.168.1.1

# LINA binary RE with version-dispatch
./ablation --lina /path/to/lina --asa-version 9.22.2.32

# RADIUS overflow probe (test infrastructure only)
python3 -c "
from modules.cisco_asa_lina_re import RadiusOverflowProbe
p = RadiusOverflowProbe(version=(9, 22, 2, 32))
print(hex(p.GP_NAME_OFFSET))   # 0x2b1
print(hex(p.OVERFLOW_DELTA))   # 0x57
"

# JWT forgery against Orka3 (empty HS256 secret)
./ablation --orka-jwt /path/to/token.txt

# bv41 layer decode
./ablation --bv41 /path/to/layer.lz4

# Streaming infra
./ablation --kafka 10.0.0.1

# NX-OS guestshell analysis
./ablation --guestshell /path/to/rootfs
```

## Requirements

```
Python 3.8+
capstone      # binary disassembly (cisco_asa_lina_re, core/disasm_engine)
```

No root required for binary analysis. Live-process modes (net_sniffer, syscall_trace, process_enum) need elevated privileges where noted.

## Confirmed struct data

`modules/regression.py` carries version-confirmed struct offsets for Cisco ASA LINA:

| ASA Version | gp_name offset | Source |
|-------------|----------------|--------|
| 9.13.1 | 0x2b0 | ASAv virtioa.qcow2, binary confirmed |
| 9.14.1.1 | 0x2b0 | FTD 6.6.0 qcow2, binary confirmed |
| 9.15.1 | 0x2b0 | FTD 6.7.0-65 qcow2, binary confirmed |
| 9.20.3 | 0x2b0 | ASAv PLR-Licensed qcow2, binary confirmed |
| 9.22.1.1 | 0x2b0 | ASAv PLR qcow2, binary confirmed |
| 9.22.2.32 | 0x2b1 | inline-strcpy discriminator, binary confirmed |

Transition boundary: struct alignment shifts between 9.22.1.x and 9.22.2.x. Version dispatch is automatic via `RadiusOverflowProbe(version=(...))`.

Post-overflow field map (9.22.2.32, LEA frequency analysis):

| Offset | Size | Hits | Field |
|--------|------|------|-------|
| 0x2b1 | char* | — | gp_name (OVERFLOW SOURCE) |
| 0x2f0 | ptr | — | dns_ptr |
| 0x308 | ptr | — | wins_ptr (PRIMARY TARGET) |
| 0x310 | int32 | 59 | auth_state |
| 0x318 | int32 | 63 | primary_status |
| 0x328 | char* | 112 | secondary_string (HOTTEST — secondary target) |
| 0x367 | uint8 | 31 | state_enum (only compared to 0x83) |
| 0x368 | uint32 | 50 | auth_flags bitmask (37 test ops — auth bypass candidate) |
| 0x36c | uint16 | — | port/protocol |

---

For authorized security testing only.
