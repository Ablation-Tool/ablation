
<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="ablation">
</p>

## What is ablation?

Ablation is a modular reverse engineering and attack surface analysis tool built for post-access work. 
It runs on the target without a debugger, source code, or prior knowledge of what's installed. 
Give it a binary, a live process, a firmware image, or a running cluster and it figures out the structure, maps the security boundaries, and surfaces what's exploitable.

Supports Linux, macOS, Windows, Docker, Kubernetes, and Orka. The 60+ modules share a common disassembly engine (x86 / ARM64 / MIPS / PPC), a unified binary parser (ELF / Mach-O / PE / firmware), and an ATT&CK tagger that labels every finding.

## Platforms

| Platform | Coverage |
|----------|----------|
| Linux (ELF — x86-64, ARM64, MIPS) | Binary RE, live process, privesc, containers |
| **macOS / Apple Silicon** | **Mach-O, Swift ABI, Orka cluster RE, malware persistence, Keychain, MDM** |
| Windows (PE / PE32+) | Kernel driver RE, IOCTL dispatch, DKOM, SSDT, DSE bypass |
| Docker | Escape surface, socket mounts, capability audit |
| Kubernetes | SA token extraction, RBAC, secret read, etcd direct access |
| **Orka** | **K8s API, JWT forge (CVE-2020-26160 + empty-key), VM exec, gRPC service map** |
| Cisco ASA / Firepower | LINA struct RE, RADIUS overflow, ASDM JAR, WebVPN JS, ROMMON |
| Cisco NX-OS / ACI | APIC REST, fabric topology, guestshell rootfs, Nexus Dashboard |

## Quick start

```bash
# Autonomous analysis of the current system
./ablation

# Analyze a binary (ELF, Mach-O, PE, or firmware image)
./ablation --binary /path/to/target

# Cisco ASA attack surface (live host)
./ablation --asa 192.168.1.1

# LINA binary RE with version dispatch
./ablation --lina /path/to/lina --asa-version 9.22.2.32

# Orka cluster enumeration
./ablation --orka https://orka-api:443

# Container and K8s escape surface
./ablation --docker
./ablation --k8s

# RADIUS overflow probe (version-dispatched, test infrastructure only)
python3 -c "
from modules.cisco_asa_lina_re import RadiusOverflowProbe
p = RadiusOverflowProbe(version=(9, 22, 2, 32))
print(hex(p.GP_NAME_OFFSET), hex(p.OVERFLOW_DELTA))
# 0x2b1  0x57
p2 = RadiusOverflowProbe(version=(9, 20, 3, 0))
print(hex(p2.GP_NAME_OFFSET), hex(p2.OVERFLOW_DELTA))
# 0x2b0  0x58
"

# Orka JWT empty-key forge
./ablation --orka-jwt /path/to/captured-token.txt

# NX-OS guestshell rootfs analysis
./ablation --guestshell /path/to/rootfs

# Kafka / Flink / NiFi enumeration
./ablation --kafka 10.0.0.1:9092
```

## Requirements

```
Python 3.8+
capstone      # binary disassembly — pip install capstone
```

Root is not required for binary analysis. Live-process modes (`net_sniffer`, `syscall_trace`, `process_enum`) need elevated privileges where noted.

---

## Module reference

### Apple / macOS

macOS is a first-class platform. The Apple module group covers Swift binary RE, full Mach-O format analysis, macOS-specific malware persistence mechanisms, the sysadmin attack surface (Keychain, FileVault, MDM/DEP, Open Directory, ARD/VNC), and complete Orka cluster enumeration with JWT forgery, VM exec, and API surface reconstruction.

#### `swift_re` — Swift binary reverse engineering

Parses the Swift 5 ABI without requiring `swift-demangle` in PATH: reads `__swift5_types`, `__swift5_proto`, and `__swift5_reflstr` Mach-O sections directly to extract type metadata, protocol conformances, and reflection metadata.

Detects gRPC service descriptors embedded in Swift binaries — common in Orka components. Extracts service names, method names, request/response types, and streaming flags from the protobuf descriptor pool in `__DATA`. Finds SwiftNIO TCP/HTTP server setup call sites and Vapor route registrations (maps the full URL → handler table).

ARM64 async/await boundary detection: identifies `swift_async_let_start`, `swift_task_create`, actor hops (`_swift_task_switch`), and continuation resume points. Maps async functions that cross trust domains. Also detects LicenseSpring SDK license validation call sites for commercial macOS software RE.

#### `macos_malware_re` — macOS malware and persistence analysis

Maps all macOS persistence mechanisms: LaunchAgents (`~/Library/LaunchAgents/`), LaunchDaemons (`/Library/LaunchDaemons/`), Login Items, cron, periodic scripts, shell profile injection (`~/.zshrc`/`~/.bash_profile`), DYLD_INSERT_LIBRARIES hijacking, and kernel extension / System Extension loading.

TCC (Transparency Consent Control) database analysis: reads `~/Library/Application Support/com.apple.TCC/TCC.db` directly, maps which apps hold Full Disk Access, camera, microphone, and screen-recording grants. Detects TCC bypass indicators — UTType handler registrations, AppleScript grants, Accessibility permission abuse.

EvilQuest / ThiefQuest IOC detection: known LaunchAgent PList names, ransomware file extension list, C2 beacon patterns, and the characteristic `sysctl hw.model` VM-detection bypass.

dyld hijack surface: finds `@rpath`, `@loader_path`, `@executable_path` entries in Mach-O LC_RPATH load commands. Checks whether rpath directories are writable — a writable rpath allows dylib injection without a SIP bypass.

Keychain analysis: enumerates stored items by service/account label using `security` CLI, identifies items with `kSecAttrAccessibleAlways` (readable without user authentication). Orka-specific paths (`/Users/admin/orka/`, `/opt/orka/`, `/etc/orka/`) scanned for credential files and cluster tokens.

#### `macos_sysadmin` — macOS administrative attack surface

Keychain: full item enumeration — generic passwords, internet passwords, certificates, keys. Maps weak ACLs (any-application access) vs. per-application access controls.

FileVault: FDE status, recovery key exposure check, Institutional Recovery Key presence.

Open Directory: local user enumeration via LDAP to `127.0.0.1`, group membership, admin group members, shadow hash presence in `/var/db/dslocal/`.

MDM / DEP: enrollment status (`profiles status`), enrolled MDM server URL, DEP enrollment indicator. An enrolled device can receive arbitrary MDM commands from the enrolled server — MDM infrastructure compromise = silent OS-level control of the fleet.

ARD / VNC: Apple Remote Desktop service status, VNC password location in `/Library/Preferences/com.apple.RemoteManagement.plist`, screen-sharing enabled users.

Sudoers and PAM: `/etc/sudoers` NOPASSWD rules, PAM module stack, authentication bypass indicators.

Orka-specific service names: maps Orka-related launchd services, agent socket paths, and control plane tokens stored in macOS Keychain by Orka client tooling.

#### `orka_enum` — Orka live cluster enumeration

Live enumeration of an Orka API endpoint: validates tokens, lists VMs, extracts VM configuration (CPU, RAM, image, Orka node), maps image registry contents, and tests default credentials. Feeds `orka_oidc_re` and `orka_jwt_dynamic_re` with token material for forgery.

#### `orka_oidc_re` — Orka3 OIDC / PKCE flow RE + CVE-2020-26160

Reconstructs the Orka3 OIDC authorization flow from Go binary symbols: `fetchClusterInfo`, PKCE code challenge generation, authorization endpoint URL, token exchange, and JWT extraction. Maps internal host range (`10.221.188.x`) from cluster-info response.

CVE-2020-26160: `dgrijalva/jwt-go` v3.2.0 accepted an empty HMAC key — Orka's HS256 token validation was affected. Also implements the `aud` (audience) claim bypass path: tokens without a required `aud` claim were accepted when the parser's expected audience list was empty.

```python
from modules.orka_oidc_re import OrkaOIDCAnalyzer
a = OrkaOIDCAnalyzer('https://orka-api:443')
flow = a.extract_auth_flow()  # client_id, redirect_uri, PKCE method, token endpoint
```

#### `orka_jwt_dynamic_re` — Orka HS256 empty-key forge

In-vitro harness that replicates Go's `SigningMethodHMAC.Verify` with `b''` as the key. Takes a captured Orka JWT, extracts the header and claims, and produces a forged token signed with an empty HMAC-SHA256 key — gives any `sub` and `role` claim, including `orka-admin`.

```python
from modules.orka_jwt_dynamic_re import OrkaJWTForger
forged = OrkaJWTForger().forge(
    captured_token='eyJ...',
    target_sub='admin',
    target_role='orka-admin'
)
```

#### `orka_api_surface_re` — Orka REST API reconstruction from binary

Extracts the complete Orka REST API surface by scanning Go binary components for URL path strings and HTTP method references: 60+ routes across VM management, image management, ISO operations, service account operations, registry credential management, node management, and image cache. Cross-references with the Kubernetes API server to distinguish Orka-layer endpoints from K8s-native endpoints. Outputs a sorted endpoint table with observed authentication requirements.

#### `orka_vm_exec_re` — Orka VM exec path

Orka VMs are K8s pods. VM name == pod name with no transformation (confirmed from `getExecRequestURL` call chain in disassembly). This module traces the exec path: K8s pod exec API (`/api/v1/namespaces/orka-default/pods/<vm>/exec?container=orka-vm`), SPDY executor transport, SA token creation, and the resulting virsh command execution capability on the hypervisor node.

With `pods/exec` permission on `orka-default` namespace and a forged or stolen SA token: arbitrary command execution in any running Orka VM.

#### `core/macho_analyzer` — Mach-O binary parser

Universal binaries (fat), single-arch Mach-O 32/64. Extracts: all load commands (LC_ types), section/segment layout, import table (dylib deps + symbols), export trie, code signature (entitlements, team ID, signing identity), and Objective-C runtime metadata (class list, method list, ivar list, protocol list, category list). Entitlement extraction identifies hardened-runtime bypass entitlements: `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.private.security.clear-library-validation`.

#### `core/bv41_decoder` — Apple BV41 / Compression.framework LZ4 decoder

Pure Python. Decodes Apple's BV41 chunked LZ4 format used in `dyld_shared_cache` slices, APFS snapshots, and Orka VM image layers stored in Harbor. Finds `bv41` magic, decodes the block header, decompresses the payload. No native dependencies.

#### `core/swift_demangle` — Swift ABI name demangler

Handles `$s` prefix (Swift 5+ mangling): module qualifiers, generic specializations, protocol conformances, operator names, property accessors. Falls back to the `swift-demangle` binary if present in PATH.

---

### Cisco ASA / Firepower

#### `cisco_asa_lina_re` — LINA binary RE and RADIUS overflow

LINA is the monolithic x86-64 ELF process that implements Cisco ASA. This module recovers struct field layouts from stripped binaries and provides a live RADIUS overflow probe.

**Struct recovery methodology:** scans all `REX 8D /r disp32` (LEA with 32-bit displacement) instructions in the 0x200–0x500 displacement range. Classifies each site by follow-up instruction type: CALL sites (string/copy operations), CMP sites (enum comparators), TEST/AND sites (bitmask fields), and MOV-write sites (direct field writes). Frequency and instruction-class distributions identify field purpose without source code.

**Confirmed `gp_obj` layout — 9.22.2.32 (5633 LEA sites, 367 distinct offsets):**

| Offset | Type | Hits | Field | Notes |
|--------|------|------|-------|-------|
| `0x2b0/0x2b1` | `char*` | — | `gp_name` | Version-dependent offset |
| `0x2f0` | `ptr` | — | `dns_ptr` | DNS server string pointer |
| `0x308` | `ptr` | — | `wins_ptr` | **PRIMARY OVERFLOW TARGET** |
| `0x310` | `int32` | 59 | `auth_state` | |
| `0x318` | `int32` | 63 | `primary_status` | |
| `0x328` | `char*` | 112 | `secondary_string` | **HOTTEST post-overflow field** |
| `0x367` | `uint8` | 31 | `state_enum` | Only compared to `0x83` — single auth gate |
| `0x368` | `uint32` | 50 | `auth_flags` | 37 TEST ops — auth bypass candidate |
| `0x36c` | `uint16` | — | `port_proto` | Port/protocol field |

**`RadiusOverflowProbe`:** RFC 2865 RADIUS server that sends Class attribute (type 25) payloads of controlled length against the `wins_ptr` write path. Version dispatch is automatic at construction time:

```python
from modules.cisco_asa_lina_re import RadiusOverflowProbe

# 9.22.2+ layout: gp_name=0x2b1, OVERFLOW_DELTA=0x57
p = RadiusOverflowProbe(version=(9, 22, 2, 32), secret=b'cisco')
print(hex(p.GP_NAME_OFFSET))   # 0x2b1
print(hex(p.OVERFLOW_DELTA))   # 0x57 (wins_ptr - gp_name)

# Pre-9.22.2 layout: gp_name=0x2b0, OVERFLOW_DELTA=0x58
p2 = RadiusOverflowProbe(version=(9, 20, 3, 0))
print(hex(p2.OVERFLOW_DELTA))  # 0x58

p.run()  # listen on :1812, send overflow payload on each Access-Request
```

**Version-confirmed offset table** (`modules/regression.py`):

| ASA Version | `gp_name` offset | `OVERFLOW_DELTA` | Source |
|-------------|-----------------|------------------|--------|
| 9.13.1 | 0x2b0 | 0x58 | ASAv virtioa.qcow2 |
| 9.14.1.1 | 0x2b0 | 0x58 | FTD 6.6.0 qcow2 |
| 9.15.1 | 0x2b0 | 0x58 | FTD 6.7.0-65 qcow2 |
| 9.20.3 | 0x2b0 | 0x58 | ASAv PLR-Licensed qcow2 |
| 9.22.1.1 | 0x2b0 | 0x58 | ASAv PLR qcow2 |
| 9.22.2.32 | **0x2b1** | **0x57** | inline-strcpy discriminator |

9.21.x: presumed 0x2b0 (continuity from 9.20.3 + 9.22.1.1), not yet confirmed from firmware.

#### `cisco_radius_ise_re` — RADIUS Class attribute injection (ISE)

ISE-specific RADIUS analysis. Confirmed write site in 9.22.2.32: `LEA rdi,[obj+0x308]; MOV rsi,rbx; CALL 0x3cf0ee0` (bounded copy entry at `0x3cefb70`). Builds RFC 2865 Access-Accept packets with arbitrary Class attribute 25 content (OU= injection). Also covers ISE CoA (Change of Authorization, RFC 5176), posture bypass analysis, and ISE Vendor-Specific Attribute parser surface.

#### `cisco_cstp_attack` — AnyConnect / CSTP attack surface

CSTP (Cisco Secure Tunneling Protocol) is the AnyConnect VPN transport. Module covers: DAP (Dynamic Access Policy) bypass chains — maps the posture evaluation sequence and conditions where DAP rules are satisfied without meeting stated requirements. `sdesktop` cookie injection path. SAML SP injection (ACS URL manipulation). Username timing oracle (response-time delta distinguishes valid vs invalid usernames). Tunnel group enumeration from the WebVPN login page. RADIUS CoA mid-session injection (force re-auth or disconnect). CRL/OCSP bypass (certificate validation path). Certificate-map tunnel-group bypass. ASA version fingerprinting from HTTP response headers.

#### `cisco_webvpn_js_re` — WebVPN JavaScript RE

Downloads unauthenticated JS bundles from `/+CSCOU+/` and `/+CSCOE+/`. Extracts: tunnel group names, hidden API endpoints not visible in the UI, OS detection logic that changes portal behavior by client user-agent, CSRF token generation pattern, SAML SP metadata and ACS URL. Maps session state machine transitions — identifies states where re-authentication can be skipped.

#### `cisco_asdm_download_re` — ASDM JAR download

Handles the full ASDM JAR retrieval chain: `GET /admin/launch` → `302` → logon page → `POST /+webvpn+/index.html` → session cookie → JNLP XML parse → JAR URL resolution → JAR stream to disk. Supports both the standard path (`/+CSCOU+/asa/asdm.jar`) and version-specific paths.

#### `cisco_asdm_jar_re` — ASDM JAR / JVM constant pool RE

Parses CAFEBABE class files per the JVM specification: constant pool (all tag types — Utf8, Class, Methodref, Fieldref, InterfaceMethodref, String, Integer, Float, Long, Double, NameAndType, MethodHandle, MethodType, Dynamic, InvokeDynamic), field and method descriptors, attribute table. Stdlib only (`struct`, `zipfile`).

Extracts: the custom `X509TrustManager` that accepts any certificate (ASDM skips TLS validation against ASA — confirmed), REST API endpoint URLs from string constants, hardcoded credential candidates, and `ObjectInputStream.readObject()` call sites (deserialization surface).

#### `cisco_asdm_re` — ASDM class file structure

JVM class file structure parsing and constant pool analysis as a standalone module. Used upstream by `cisco_asdm_jar_re`.

#### `cisco_rommon_re` — ROMMON bypass

Maps the ROMMON boot environment: password recovery procedure (config-register `0x2142` modification to skip startup-config load), image authentication bypass paths in older IOS versions (load unsigned image from ROMMON), and ROMMON environment variable injection.

#### `cisco_config_re` — Configuration analysis

Parses IOS / ASA running and startup configs. Type 7 decode (Vigenere with known key — reversible). Extracts: enable secret hashes, local user password hashes, SNMP community strings, TACACS+/RADIUS shared secrets, BGP neighbor passwords, NTP authentication keys, crypto key material (certificate subject, key size), and AAA chain structure.

#### `cisco_ios_re` — IOS firmware RE

IOS firmware image analysis: image format identification (ELF, compressed ELF, monolithic), IFS (IOS File System) extraction, text/data segment map, IOSd process entry point. Crash dump analysis with ADRP-based image-base recovery for ARM64. MIPS/ARM64/x86 gadget extraction. Hardcoded credential scan.

#### `cisco_api_enum` — ASA REST API enumeration

ASA REST API (`/api/...`, available since ASA 9.3) endpoint enumeration. Unauthenticated surface mapping. Session cookie reuse from ASDM auth flow.

#### `cisco_asa_cred_audit` — ASA credential audit

Credential testing across all ASA management interfaces: web management, ASDM, REST API. Measures lockout behavior (threshold, window, applies uniformly across interfaces?). Maps the authentication stack — local vs RADIUS vs TACACS+ — so the right target for credential testing is clear.

---

### Cisco NX-OS / ACI / Data Center

#### `nxos_enum` — NX-OS / ACI / APIC enumeration

Full ACI fabric enumeration via APIC REST API. Unauthenticated endpoint: `GET /api/aaaListDomains.json` returns all AAA domain names without credentials. Full MIT (Management Information Tree) class queries (auth required for the rest): fabric nodes, tenants, EPGs, bridge domains, VRFs, L4 contracts, L3Outs, BGP peers. VMM integration objects expose vCenter controller IP (`vmmCtrlrP`) and vCenter username (`vmmUsrAccP`) — lateral movement path from ACI to vSphere. Default credential list: `admin/admin`, `admin/C1sco12345`, `admin/Cisco123`, and variants.

#### `nexus_dashboard_enum` — Nexus Dashboard / NDI / NDFC / NDO

Nexus Dashboard is the SSO convergence platform for NDI (Insights), NDFC (Fabric Controller), and NDO (Orchestrator). One credential set unlocks all three. Kafka anomaly export configuration (`/api/v1/event-services/exporters`) is often world-readable without authentication — exposes Kafka broker addresses, topics, and TLS certificates. Hashicorp Terraform and ServiceNow integration endpoints can expose cloud provider credentials and ITSM tokens.

#### `cisco_nxos_guestshell_re` — NX-OS guestshell rootfs analysis

NX-OS ships with a Guest Shell LXC container (CentOS). Analyzes extracted or mounted rootfs images: credential pattern scan (passwords, API tokens, shadow hashes, JDBC URLs, private keys, SNMP community strings), unexpected SUID binaries vs the known-safe set, world-writable cron directories, Python security packages that shouldn't be in production. Validates EXT4 magic (`0xEF53` at offset `0x438`) before analysis.

#### `hyperflex_enum` — Cisco HyperFlex

HyperFlex REST API (`/coreapi/v1/`) enumeration. SCVM (Storage Controller VM) SSH surface. Default credential testing. Cluster health data read, VM inventory extraction, Intersight claim-code extraction.

#### `ios_enum` — IOS / IOS-XE live enumeration

SSH and NETCONF-based enumeration of live Cisco IOS and IOS-XE devices: interface inventory, routing table, BGP neighbors, ACLs, user accounts, Syslog/SNMP configuration, CDP neighbor table, AAA server list. NETCONF/YANG support for IOS-XE 16.3+. Type 7/5/8/9 password decode.

---

### Binary Analysis Core

#### `core/binary_parser` — Universal format detection

ELF32/64, Mach-O 32/64, Mach-O fat (universal binary), PE32/PE32+, and raw firmware blob detection from magic bytes. Dispatches to the appropriate format-specific analyzer.

#### `core/elf_parser` — ELF analysis

Full ELF parsing: header, program headers, section headers, symbol tables (`.symtab` and `.dynsym`), dynamic section (needed libraries, RPATH, RUNPATH), relocation tables (REL/RELA), and GNU notes. Stripped binary symbol recovery: identifies function prologues (ENDBR64, PUSH RBP + MOV RBP RSP), estimates function boundaries, builds an approximate symbol map from cross-references.

#### `core/pe_parser` / `core/pe_analyzer` — PE analysis

PE32/PE32+ parsing: DOS header, NT headers, section table, import directory (all DLL + function names), export directory, TLS callbacks, load config (CFG, ASLR, DEP flags), debug directory (PDB path). Security feature detection: ASLR, DEP/NX, SafeSEH, CFG, Authenticode signature presence. Section entropy analysis for packed/encrypted sections.

#### `core/firmware_analyzer` — Firmware image analysis

Embedded filesystem magic detection: SquashFS, CramFS, ext2/3/4, JFFS2, YAFFS, UBI. Per-block entropy analysis to distinguish compressed regions, encrypted regions, and plaintext config areas. Extracts root filesystem to a temp directory for further analysis — credential scan, SUID binary check, web app RE.

#### `core/disasm_engine` — Multi-architecture disassembler

Capstone wrapper with gp_obj field annotation support. Architectures: x86 (16/32/64), ARM (ARM/Thumb/ARM64), MIPS (32/64), PowerPC. Provides: function boundary detection, call graph extraction, basic block decomposition, and cross-reference building. The annotation layer maps known Cisco ASA struct offsets to human-readable field names inline.

#### `core/yara_generator` — YARA rule generation

Generates YARA rules from binary analysis results: string constants, byte sequences around function prologues, import table combinations, and section layout signatures. Output rules are ready for hunting across firmware collections or malware corpora.

#### `core/attck_tagger` — MITRE ATT&CK tagging

Maps all ablation findings to ATT&CK technique IDs. Input: structured findings from any module. Output: ATT&CK technique list with tactic, technique ID, name, and the specific finding that triggered the tag.

#### `core/shellcode_utils` — Shellcode analysis and generation

x86-64 and ARM64 shellcode templates. Entropy calculation, null-byte density analysis, common shellcode sequence detection (GetProcAddress patterns, syscall stubs, XOR decode loops), NOP sled identification. XOR/ADD encoders for bad-byte avoidance.

#### `core/tls_analyzer` — TLS certificate and configuration analysis

Certificate chain parsing, CT log anomaly detection (I/N ≥ 0.30 = honeypot signal, per confirmed discriminator), cipher suite enumeration, protocol version detection. Flags: self-signed certificates, expired certificates, weak key sizes (RSA < 2048), deprecated ciphers (RC4, DES, 3DES, export-grade, null), TLS 1.0/1.1. Quantum-vulnerability inventory: RSA/ECDSA → vulnerable to Shor's algorithm; ML-KEM/ML-DSA → post-quantum safe.

#### `core/platform_detect` — Platform fingerprinting

OS, architecture, kernel version, container runtime detection. Identifies: bare metal vs VM vs Docker vs K8s Pod vs Orka VM. Used at startup to determine which module set applies.

---

### Java

#### `java_re` — Java class file RE

Parses CAFEBABE class files: complete constant pool (all tag types per JVM spec), method access flags, field descriptors, attribute table. Security extraction: `ObjectInputStream.readObject()` call sites (deserialization), `Runtime.exec()` / `ProcessBuilder` (command injection), reflection call sites (`Class.forName`, `Method.invoke`), JDBC URLs and connection strings in string constants. Framework fingerprinting: Spring, Jackson, Gson, Hibernate detection from import patterns.

#### `java_decompiler` — Java decompilation wrapper

Wraps Procyon, CFR, or Fernflower (whichever is in PATH) to produce readable source from class files. Falls back to `javap -c` bytecode output. Identifies the best available decompiler and uses it.

---

### Windows Kernel

#### `windows_kernel_re` — Windows kernel driver RE

**IOCTL dispatch:** finds `DriverEntry`, traces `IRP_MJ_DEVICE_CONTROL` handler registration, extracts the IOCTL dispatch table with full `CTL_CODE` decomposition (device type, access required, function code, transfer type), maps each IOCTL to its handler function. The dispatch table is the primary attack surface for kernel driver exploitation.

**DKOM:** identifies `PsGetCurrentProcess` / `PsLookupProcessByProcessId` call sites followed by `EPROCESS` field accesses — process token stealing and DKOM-based rootkit technique detection.

**SSDT hooks:** checks SSDT for entries pointing outside `ntoskrnl.exe` / `win32k.sys` (rootkit indicator). Enumerates shadow SSDT (`Win32k.sys`) hooks.

**Driver signing bypass:** detects `g_CiEnabled` / `g_CiOptions` patch patterns (DSE disable), `SeLoadDriverPrivilege` abuse, and test-signing mode indicators.

#### `forensics_enum` — Forensic artifact analysis

SEH chain corruption detection (FS:[0] pattern), POPAD+JMP shellcode sequence identification. Windows artifact map: event log locations and sizes, prefetch files, recently accessed files (MRU), shellbag entries, jump lists, browser history paths. Maps the forensic footprint for understanding attacker dwell time.

---

### Containers and Kubernetes

#### `docker_enum` — Docker escape surface

In-container checks: Docker socket at `/var/run/docker.sock` (writable = root via `docker run --privileged`), container capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`), namespace isolation (PID, mount, network, user), writable host paths via bind mounts. Daemon API checks (no socket needed): TCP 2375/2376 without TLS client auth. Image and container enumeration via daemon API.

#### `k8s_enum` — Kubernetes enumeration

Service account token extraction from `/var/run/secrets/kubernetes.io/serviceaccount/`. Direct API server enumeration using the SA token — no `kubectl` needed. RBAC self-check via `SelfSubjectAccessReview` — tests `get/list/create/delete` on pods, secrets, configmaps, and `exec` on pods. Reports exact permissions without cluster-admin.

Secret extraction with base64 decode. ConfigMap credential hunting (password/token/key pattern matching). Privilege escalation path detection: `pods/exec` → RCE on any pod; `secrets/get` on `kube-system` → credential harvest; `create pods` → privileged pod → host escape; `system:node` role → lateral to other nodes. etcd direct access (2379): key-space enumeration, secret extraction bypassing K8s RBAC. Kubelet API (10250): pod list, exec without auth on unprotected Kubelets.

#### `harbor_enum` — Harbor OCI registry + supply chain

Default credentials: `admin:Harbor12345` (common on Orka and self-hosted K8s deployments). Project and repository enumeration, image manifest pull, layer extraction. BV41 / Apple Compression metadata decode (`bv41_decoder`). Vulnerability scan results (Trivy integration) — attacker gets CVE inventory without running a scanner. Robot account enumeration (often broad access, longer-lived tokens). Supply chain mapping: identifies images with `FROM` referencing external registries.

#### `privesc_enum` — Privilege escalation enumeration

SUID/SGID binaries (vs known-safe set), world-writable paths, cron job injection (writable scripts referenced by root cron), sudo NOPASSWD rules, Linux capabilities on binaries and processes, Docker group membership, `/etc/passwd` writability, readable shadow or backup files, package manager attack surface (`pip install` to root PATH, `npm install -g` writable prefix). Cross-platform: macOS vs Linux checks.

---

### Network and Protocol

#### `tls_enum` — TLS service enumeration

Active TLS handshake probes: supported cipher suites, protocol versions (TLS 1.0/1.1 detection), certificate chain, OCSP stapling, session resumption (session ID and session ticket), HSTS/HPKP header presence, JA3 server fingerprint.

#### `net_sniffer` — Raw packet capture and credential extraction

Raw socket capture with protocol parsers: HTTP basic auth, FTP, Telnet, SMTP AUTH, POP3, IMAP, SNMP community strings, SIP Digest authentication, clear-text LDAP bind requests. Output is structured credential tuples.

#### `network_analyze` — Network topology analysis

Network interface map, routing table, listening services, established connection inventory. From captured traffic or pcap: ARP table reconstruction, VLAN tag enumeration (802.1Q), routing protocol identification (OSPF/EIGRP/BGP hello detection), DHCP server and internal DNS server identification.

#### `nginx_enum` — nginx configuration and CVE surface

Config file parsing: server blocks, location blocks, `proxy_pass` targets, `auth_basic` / `auth_request` directives, include chains. Alias traversal: detects `location /path/ { alias /dir; }` without trailing slash on the location — path confusion allows `GET /path../etc/passwd`. Version fingerprinting mapped to known CVEs (CVE-2017-7529 range filter overflow, HTTP/2 off-by-one). `proxy_pass` misconfiguration: path appended to upstream URL enables SSRF amplification.

#### `sip_enum` — SIP / VoIP enumeration

SIP OPTIONS sweep for extension discovery, REGISTER scan, Digest auth capture, RTP stream identification. Maps voicemail extensions, conference bridge numbers, SIP trunk authentication credentials from REGISTER messages.

#### `streaming_enum` — Data streaming platform enumeration

**Kafka:** broker enumeration via Metadata API (no auth required if ACLs aren't enforced), topic list, partition/leader map, consumer group offsets, sensitive topic detection by name pattern, produce access test (data injection surface). **Flink:** REST API (`/jobs`, `/taskmanagers`, `/jars`) — job submission allows arbitrary JAR execution without auth by default. **NiFi:** processor configuration reads (passwords in clear text for many processor types), template download (full pipeline definition including credentials), sensitive property key extraction. **Confluent Schema Registry:** unauthenticated subject and schema enumeration.

#### `llm_enum` — LLM inference server enumeration

Ollama (`/api/tags`, `/api/generate`), LM Studio, LocalAI, and generic OpenAI-compatible endpoints. Checks: unauthenticated model listing, unfiltered text generation, model file path exposure, system prompt leakage via `/api/show`.

---

### Cryptography and Authentication

#### `jwt_crypto_analyzer` — JWT attack suite

`alg: none` bypass: strips signature, sets algorithm to `none`. RS256 → HS256 confusion: re-signs with the RS256 public key as HMAC-SHA256 secret — valid if the library reads only the `alg` header. Weak HMAC key brute-force (wordlist of production-leaked common secrets). `kid` header injection: SQL injection when server queries a DB for the key by ID, SSRF via URL-valued `kid`, directory traversal to a predictable file path.

```python
from modules.jwt_crypto_analyzer import JWTAttackSuite
suite = JWTAttackSuite(target_url='https://target/api/')
suite.run_all(token='eyJhbGc...')
```

#### `crypto_audit` — Binary cryptographic implementation audit

Hardcoded key material detection (high-entropy byte sequences near crypto function call sites), weak RNG usage (`rand()` / `random()` in security-sensitive contexts), ECB mode indicators (identical ciphertext block pairs), MD5/SHA1 import detection, custom cryptographic implementations (re-implementation of AES/DES/RSA rather than system crypto).

---

### Post-Compromise

#### `process_enum` — Process and memory analysis

All running processes (PID, PPID, name, command line) — `/proc` on Linux, `ps` on macOS. For a target PID: `/proc/PID/maps` (heap/stack/mmap layout, loaded DSOs), `/proc/PID/fd` (open database connections, sockets, sensitive files held open), `/proc/PID/environ` (environment variables, often contains credentials). macOS: `vmmap` and `lsof` equivalents.

#### `lateral_movement` — Lateral movement surface

TCP scan using stdlib socket — no nmap dependency. Cloud metadata: `169.254.169.254` (AWS/GCP/Azure IMDS), ECS task metadata endpoint. Extracts IAM role ARN, temporary credentials, instance identity document, user data. Credential harvest from common locations: `~/.aws/credentials`, `~/.kube/config`, `~/.ssh/id_*`, `~/.docker/config.json`, `.env` files in web roots, `/etc/kubernetes/admin.conf`. Orka internal DNS discovery (`10.221.188.x`).

#### `syscall_trace` — System call tracing

Wraps `strace` (Linux) / `dtruss` / `dtrace` (macOS). Filters and structures output: `open`/`openat` (file access), `connect` (network), `execve` (process launch), `write` to network FDs. Identifies credential access patterns and data exfiltration paths.

---

### Regression

#### `regression` — Struct offset version registry

Version-confirmed struct field offset database for Cisco ASA LINA. `SymbolicOffsetRegression` stores confirmed offsets from real firmware images indexed by version tuple. `FirmwareVersionRegression` fits a boundary model across the confirmed data points. `OLS`, `LogisticRegression`, `DescriptiveStats`, `CorrelationMatrix` for offset trend analysis.

```python
from modules.regression import SymbolicOffsetRegression

offset = SymbolicOffsetRegression.gp_name_offset((9, 20, 3, 0))
# -> 0x2b0

for ver, entry in SymbolicOffsetRegression.CONFIRMED.items():
    print(ver, hex(entry['gp_name_offset']), entry['source'])
```

---

### Utilities

#### `utils/poc_radius_ou_inject.py` — RADIUS Group Policy Injection PoC

Standalone PoC for F1 (no Message-Authenticator enforcement) + F2 (256-byte OU= vs 64-byte CLI limit) on Cisco ASA. Two modes: fake RADIUS server (responds to every Access-Request with attacker-controlled OU= in Class attribute 25), and single-packet send mode (fires one crafted Access-Accept at the ASA). Demonstrates the overflow delta computed by `RadiusOverflowProbe`.

---

## Architecture

```
ablation/
├── main.py
├── modules/
│   ├── core/
│   │   ├── binary_parser.py
│   │   ├── elf_parser.py
│   │   ├── macho_analyzer.py       ← Apple Mach-O
│   │   ├── pe_parser.py
│   │   ├── pe_analyzer.py
│   │   ├── firmware_analyzer.py
│   │   ├── disasm_engine.py        ← x86/ARM/MIPS/PPC capstone wrapper
│   │   ├── platform_detect.py
│   │   ├── bv41_decoder.py         ← Apple BV41 / chunked LZ4
│   │   ├── swift_demangle.py       ← Swift 5 ABI demangler
│   │   ├── tls_analyzer.py
│   │   ├── yara_generator.py
│   │   ├── attck_tagger.py
│   │   └── shellcode_utils.py
│   ├── swift_re.py                 ← Swift binary RE, gRPC, async/await
│   ├── macos_malware_re.py         ← Persistence, TCC, EvilQuest IOCs, dylib hijack
│   ├── macos_sysadmin.py           ← Keychain, FileVault, MDM/DEP, ARD/VNC, OD
│   ├── orka_enum.py                ← Live Orka cluster enumeration
│   ├── orka_api_surface_re.py      ← REST API reconstruction from Go binary
│   ├── orka_jwt_dynamic_re.py      ← Empty-key HS256 JWT forge
│   ├── orka_oidc_re.py             ← CVE-2020-26160 + PKCE flow RE
│   ├── orka_vm_exec_re.py          ← VM exec via K8s pod exec API
│   ├── cisco_asa_lina_re.py        ← LINA struct RE + RadiusOverflowProbe
│   ├── cisco_radius_ise_re.py
│   ├── cisco_asdm_re.py
│   ├── cisco_asdm_download_re.py
│   ├── cisco_asdm_jar_re.py
│   ├── cisco_webvpn_js_re.py
│   ├── cisco_cstp_attack.py
│   ├── cisco_rommon_re.py
│   ├── cisco_config_re.py
│   ├── cisco_ios_re.py
│   ├── cisco_nxos_guestshell_re.py
│   ├── cisco_api_enum.py
│   ├── cisco_asa_cred_audit.py
│   ├── nxos_enum.py
│   ├── nexus_dashboard_enum.py
│   ├── ios_enum.py
│   ├── hyperflex_enum.py
│   ├── docker_enum.py
│   ├── k8s_enum.py
│   ├── harbor_enum.py
│   ├── nginx_enum.py
│   ├── java_re.py
│   ├── java_decompiler.py
│   ├── windows_kernel_re.py
│   ├── forensics_enum.py
│   ├── tls_enum.py
│   ├── net_sniffer.py
│   ├── network_analyze.py
│   ├── sip_enum.py
│   ├── streaming_enum.py
│   ├── llm_enum.py
│   ├── jwt_crypto_analyzer.py
│   ├── crypto_audit.py
│   ├── privesc_enum.py
│   ├── process_enum.py
│   ├── lateral_movement.py
│   ├── syscall_trace.py
│   └── regression.py
└── utils/
    └── poc_radius_ou_inject.py
```

---

For authorized security testing only.
