
<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="ablation">
</p>

## What is ablation?

Ablation is a custom-built modular reverse engineering and attack surface analysis tool. 
Every module is written from scratch for the specific target. 
It runs on the target without a debugger, source code, or prior knowledge of what's installed. Give it a binary, a live process, a firmware image, or a running cluster and it figures out the structure, maps the security boundaries, and surfaces what's exploitable.

Supports Linux, macOS, Windows, Docker, Kubernetes, and Orka. The 120+ modules share a custom disassembly engine (x86 / ARM64 / MIPS / PPC), a custom binary parser (ELF / Mach-O / PE / firmware), and an ATT&CK tagger that labels every finding.

## Platforms

| Platform | Coverage |
|----------|----------|
| Linux (ELF — x86-64, ARM64, MIPS) | Binary RE, live process, privesc, containers, garble-obfuscated Go |
| **macOS / Apple Silicon** | **Mach-O, Swift ABI, Orka cluster RE, malware persistence, Keychain, MDM** |
| Windows (PE / PE32+) | Kernel driver RE, IOCTL dispatch, DKOM, SSDT, DSE bypass |
| Docker | Escape surface, socket mounts, capability audit |
| Kubernetes | SA token extraction, RBAC, secret read, etcd direct access |
| **Orka** | **K8s API, JWT forge (CVE-2020-26160 + empty-key), VM exec, gRPC service map** |
| **Cisco ASA** | **LINA struct RE, RADIUS class-attr overflow (F1/F2), ASDM JAR, WebVPN JS, ROMMON, CSTP** |
| **Cisco FTD / FDM** | **40+ modules: JWT forgery, Neo4j key decrypt, TAR slip RCE, ZMQ NULL auth, AJP bypass, hardcoded AES key, 83 total findings** |
| **Cisco ISE** | **RADIUS OU injection, LDAP chain, credential audit — 46 findings (CRIT:11)** |
| **Cisco CUCM** | **Static AES key, OAuth JWT forgery chain, ITL signing key, HAProxy mode 666, SAML always-true — 482 findings** |
| **Cisco AnyConnect** | **NetworkExtension IKEv2 RE, acsockext TOCTOU, DTLS/CSTP attack surface** |
| Cisco IOS / IOS-XE | Firmware RE, crashdump analysis, hardcoded credential scan, ROMMON bypass |
| Cisco NX-OS / ACI | APIC REST, fabric topology, guestshell rootfs, Nexus Dashboard |
| **WeChat Android** | **MMTLS protocol RE, PSK extraction, DB key derivation, ptrace key extraction** |

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

# Go binary obfuscated with garble (GoReSym fails → use this)
python3 modules/go_garble_re.py /path/to/binary

# CUCM 15.0.1 — full static findings summary (482 findings)
python3 -c "from modules.cisco_cucm_re import full_findings_summary; print(full_findings_summary())"

# FTD fleet-wide Python AES-256 key (F-FTD-110)
python3 -c "from modules.ftd_hardcoded_aes_key import AES256_KEY; print(AES256_KEY.hex())"
```

## Requirements

```
Python 3.8+
capstone        # binary disassembly — pip install capstone
```

**Cisco RE Engine additional dependencies (optional — only needed for `cisco_re_engine.py`):**

```
flare-floss     # stack/tight-loop string deobfuscation — pip install flare-floss
flare-capa      # capability identification — pip install flare-capa
ropper          # ROP chain generation — pip install ropper
keystone-engine # shellcode assembly — pip install keystone-engine
rzpipe          # radare2 Python API — pip install rzpipe
frida           # dynamic instrumentation — pip install frida-tools
scapy           # protocol fuzzing — pip install scapy
```

External binaries: `r2` (radare2), `bindiff` (BinDiff v8), `frida` CLI. capa rule set must be cloned separately:
```bash
git clone https://github.com/mandiant/capa-rules.git /tmp/capa-rules
```

Root is not required for binary analysis. Live-process modes (`net_sniffer`, `syscall_trace`, `process_enum`) and Frida attach (`cisco_re_engine.py --mode frida`) need elevated privileges where noted.

---

## Module reference

---

### Apple / macOS

macOS is a first-class platform. Covers Swift binary RE, Mach-O format analysis, malware persistence, sysadmin attack surface, and full Orka cluster enumeration.

#### `swift_re` — Swift binary RE

Reads `__swift5_types`, `__swift5_proto`, `__swift5_reflstr` Mach-O sections directly — no `swift-demangle` in PATH required.

- **gRPC** — extracts service names, methods, request/response types, streaming flags from the protobuf descriptor pool in `__DATA`
- **SwiftNIO / Vapor** — finds TCP/HTTP server setup call sites, maps full URL → handler table
- **async/await** — detects `swift_async_let_start`, `swift_task_create`, actor hops (`_swift_task_switch`), continuation resume points; maps functions that cross trust boundaries
- **LicenseSpring** — locates license validation call sites in commercial macOS binaries

#### `macos_malware_re` — macOS malware and persistence

- **Persistence** — LaunchAgents, LaunchDaemons, Login Items, cron, periodic scripts, shell profile injection, DYLD_INSERT_LIBRARIES, kernel extensions / System Extensions
- **TCC** — reads `TCC.db` directly; maps FDA, camera, mic, screen-recording grants; flags UTType handler / AppleScript / Accessibility bypass indicators
- **EvilQuest / ThiefQuest** — known PList names, ransomware extension list, C2 beacon patterns, `sysctl hw.model` VM-detection bypass
- **dyld hijack** — finds writable `@rpath` entries in LC_RPATH load commands (writable rpath = dylib injection without SIP bypass)
- **Keychain** — enumerates items by service/account label, flags `kSecAttrAccessibleAlways`; scans `/Users/admin/orka/`, `/opt/orka/`, `/etc/orka/` for credential files

#### `macos_sysadmin` — macOS administrative attack surface

- **Keychain** — generic passwords, internet passwords, certificates, keys; maps any-app ACLs vs per-app ACLs
- **FileVault** — FDE status, recovery key exposure, Institutional Recovery Key presence
- **Open Directory** — local user enumeration via LDAP to `127.0.0.1`, admin group members, shadow hash presence in `/var/db/dslocal/`
- **MDM / DEP** — enrolled MDM server URL, DEP indicator; enrolled devices accept arbitrary MDM commands from the enrolled server
- **ARD / VNC** — service status, VNC password plist location, screen-sharing enabled users
- **Sudoers / PAM** — NOPASSWD rules, PAM module stack, auth bypass indicators
- **Orka** — launchd services, agent socket paths, control plane tokens stored in macOS Keychain by Orka client tooling

#### `orka_enum` — Orka live cluster enumeration

Validates tokens, lists VMs, extracts VM configuration (CPU, RAM, image, node), maps image registry contents, tests default credentials. Feeds `orka_oidc_re` and `orka_jwt_dynamic_re` with token material.

#### `orka_oidc_re` — Orka OIDC / PKCE flow RE + CVE-2020-26160

Reconstructs the OIDC auth flow from Go binary symbols: `fetchClusterInfo`, PKCE code challenge, token exchange, JWT extraction. Maps internal host range (`10.221.188.x`) from cluster-info.

- **CVE-2020-26160** — `dgrijalva/jwt-go` v3.2.0 accepted an empty HMAC key; Orka's HS256 validation was affected
- **`aud` bypass** — tokens without a required audience claim accepted when the parser's expected audience list was empty

```python
from modules.orka_oidc_re import OrkaOIDCAnalyzer
flow = OrkaOIDCAnalyzer('https://orka-api:443').extract_auth_flow()
# -> {client_id, redirect_uri, pkce_method, token_endpoint}
```

#### `orka_jwt_dynamic_re` — Orka HS256 empty-key forge

Replicates Go's `SigningMethodHMAC.Verify` with `b''` as the key. Forges a token with any `sub` and `role` claim.

```python
from modules.orka_jwt_dynamic_re import OrkaJWTForger
forged = OrkaJWTForger().forge(
    captured_token='eyJ...',
    target_sub='admin',
    target_role='orka-admin'
)
```

#### `orka_api_surface_re` — Orka REST API reconstruction from binary

Scans Go binary components for URL path strings and HTTP method references. Outputs 60+ sorted routes across VM, image, ISO, service account, registry credential, node, and image cache operations — with observed authentication requirements per endpoint.

#### `orka_vm_exec_re` — Orka VM exec path

VM name == pod name (confirmed from `getExecRequestURL` disassembly — no transformation). Traces the exec path to `/api/v1/namespaces/orka-default/pods/<vm>/exec?container=orka-vm` via SPDY executor. With `pods/exec` permission and a forged SA token: arbitrary command execution in any running Orka VM, virsh access on the hypervisor node.

#### `core/macho_analyzer` — Mach-O binary parser

Universal fat binaries, single-arch 32/64. Extracts: all LC_ load commands, section/segment layout, import table, export trie, code signature (entitlements, team ID), ObjC runtime metadata (class/method/ivar/protocol lists). Flags hardened-runtime bypass entitlements: `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.private.security.clear-library-validation`.

#### `core/bv41_decoder` — Apple BV41 / Compression.framework LZ4 decoder

Pure Python, no native dependencies. Decodes Apple's BV41 chunked LZ4 format from `dyld_shared_cache` slices, APFS snapshots, and Orka VM image layers in Harbor.

#### `core/swift_demangle` — Swift ABI name demangler

Handles `$s` prefix (Swift 5+ mangling): module qualifiers, generic specializations, protocol conformances, operator names, property accessors. Falls back to the `swift-demangle` binary if present.

---

### Cisco

#### `cisco_asa_lina_re` — LINA binary RE + RADIUS overflow

LINA is the monolithic x86-64 ELF that implements Cisco ASA. Recovers struct field layouts from stripped binaries via LEA frequency analysis and provides a live RADIUS overflow probe.

**Struct recovery:** scans all `REX 8D /r disp32` LEA instructions in the 0x200–0x500 displacement range. Follow-up instruction type (CALL / CMP / TEST / MOV-write) reveals field purpose: CALL = string/copy target, CMP = enum comparator, TEST = bitmask, MOV = direct write.

**Confirmed `gp_obj` layout — 9.22.2.32 (5633 LEA sites, 367 offsets):**

| Offset | Type | Hits | Field | Notes |
|--------|------|------|-------|-------|
| `0x2b0/0x2b1` | `char*` | — | `gp_name` | Version-dependent |
| `0x2f0` | `ptr` | — | `dns_ptr` | |
| `0x308` | `ptr` | — | `wins_ptr` | **PRIMARY OVERFLOW TARGET** |
| `0x310` | `int32` | 59 | `auth_state` | |
| `0x318` | `int32` | 63 | `primary_status` | |
| `0x328` | `char*` | 112 | `secondary_string` | **HOTTEST post-overflow field** |
| `0x367` | `uint8` | 31 | `state_enum` | Only compared to `0x83` |
| `0x368` | `uint32` | 50 | `auth_flags` | 37 TEST ops — auth bypass candidate |
| `0x36c` | `uint16` | — | `port_proto` | |

**`RadiusOverflowProbe`** — RFC 2865 RADIUS server, sends Class attribute (type 25) payloads of controlled length against `wins_ptr`. Version dispatch is automatic:

```python
from modules.cisco_asa_lina_re import RadiusOverflowProbe

p = RadiusOverflowProbe(version=(9, 22, 2, 32), secret=b'cisco')
print(hex(p.GP_NAME_OFFSET))   # 0x2b1
print(hex(p.OVERFLOW_DELTA))   # 0x57

p2 = RadiusOverflowProbe(version=(9, 20, 3, 0))
print(hex(p2.OVERFLOW_DELTA))  # 0x58

p.run()   # listens :1812, fires overflow payload on each Access-Request
```

**Version-confirmed offsets** (`regression.py`):

| ASA Version | `gp_name` | `OVERFLOW_DELTA` | Source |
|-------------|-----------|------------------|--------|
| 9.13.1 | 0x2b0 | 0x58 | ASAv virtioa.qcow2 |
| 9.14.1.1 | 0x2b0 | 0x58 | FTD 6.6.0 qcow2 |
| 9.15.1 | 0x2b0 | 0x58 | FTD 6.7.0-65 qcow2 |
| 9.20.3 | 0x2b0 | 0x58 | ASAv PLR-Licensed qcow2 |
| 9.22.1.1 | 0x2b0 | 0x58 | ASAv PLR qcow2 |
| 9.22.2.32 | **0x2b1** | **0x57** | inline-strcpy discriminator |

9.21.x: presumed 0x2b0 — not yet confirmed from firmware.

#### `cisco_radius_ise_re` — RADIUS Class attribute injection

Confirmed write site in 9.22.2.32: `LEA rdi,[obj+0x308]; MOV rsi,rbx; CALL 0x3cf0ee0` (copy body at `0x3cefb70`). Builds RFC 2865 Access-Accept packets with arbitrary Class attribute 25 / OU= content. Covers ISE CoA (RFC 5176), posture bypass, and VSA parser surface.

#### `cisco_cstp_attack` — AnyConnect / CSTP

- DAP (Dynamic Access Policy) bypass — posture evaluation sequence, conditions where rules pass without meeting requirements
- `sdesktop` cookie injection, SAML SP ACS URL manipulation
- Username timing oracle — response-time delta distinguishes valid vs invalid usernames
- Tunnel group enumeration from the WebVPN login page
- RADIUS CoA mid-session injection (force re-auth / disconnect)
- CRL/OCSP bypass, certificate-map tunnel-group bypass
- ASA version fingerprinting from HTTP response headers

#### `cisco_webvpn_js_re` — WebVPN JavaScript RE

Downloads unauthenticated JS bundles from `/+CSCOU+/` and `/+CSCOE+/`. Extracts: tunnel group names, hidden API endpoints, OS detection logic, CSRF token generation pattern, SAML SP metadata and ACS URL. Maps session state machine — identifies states where re-auth can be skipped.

#### `cisco_asdm_download_re` — ASDM JAR download

Full retrieval chain: `GET /admin/launch` → `302` → logon → `POST /+webvpn+/index.html` → session cookie → JNLP XML parse → JAR URL resolution → stream to disk.

#### `cisco_asdm_jar_re` — ASDM JAR / JVM constant pool RE

Parses CAFEBABE class files per JVM spec (all constant pool tag types). Stdlib only (`struct`, `zipfile`).

- Custom `X509TrustManager` that accepts any certificate — ASDM skips TLS validation against ASA (confirmed)
- REST API endpoint URLs from string constants
- Hardcoded credential candidates
- `ObjectInputStream.readObject()` call sites (deserialization surface)

#### `cisco_rommon_re` — ROMMON bypass

Config-register `0x2142` modification to skip startup-config load, image authentication bypass paths (load unsigned image from ROMMON in older IOS), ROMMON environment variable injection.

#### `cisco_config_re` — Configuration analysis

Type 7 decode (Vigenere, reversible). Extracts: enable secret / local user hashes, SNMP community strings, TACACS+/RADIUS shared secrets, BGP neighbor passwords, NTP auth keys, crypto key material, AAA chain structure.

#### `cisco_ios_re` — IOS firmware RE

Image format identification (ELF / compressed ELF / monolithic), IFS extraction, IOSd entry point. Crash dump analysis with ADRP-based image-base recovery (ARM64). MIPS/ARM64/x86 gadget extraction. Hardcoded credential scan.

#### `cisco_api_enum` — ASA REST API enumeration

ASA REST API (`/api/...`, 9.3+) endpoint enumeration. Unauthenticated surface mapping. Session cookie reuse from ASDM auth flow.

#### `cisco_asa_cred_audit` — ASA credential audit

Credential testing across web management, ASDM, and REST API. Measures lockout behavior per-interface. Maps auth stack (local vs RADIUS vs TACACS+).

#### `anyconnect_re` — AnyConnect / NetworkExtension RE

LIEF + capstone x86_64 RE of Apple's `NetworkExtension.framework` (1095.140.2) and Cisco's `acsockext` System Extension (5.1.16.194) on macOS 10.15.7. Exposes callable address tables for IKEv2 tunnel setup, auth bypass intercept, and DNS injection TOCTOU.

**`AnyConnectNEAnalyzer`** — NE framework (x86_64, Catalina)

Key address tables:
- `NE_PHASE1_SELREFS` — phase-1 selrefs (IKE_SA_INIT → IKE_AUTH); `NEIKEv2ProviderAuthenticate:` @ `0x2ca770`
- `NE_TUNNEL_START_SELREFS` — 8 ordered selrefs in tunnel-start: `protocolConfiguration` → `tunnelKind` → `setOptions:` (0x2ca758, pre-auth intercept) → `NEIKEv2ProviderAuthenticate:` (0x2ca770)

Bypass targets:
- `0xd8f60` — patch `call [rip+0x188a32]` (objc_msgSend → `NEIKEv2ProviderAuthenticate:`) → force rax=1; skips Cisco auth on tunnel start
- `0x2ca758` — hook point before auth callback; full tunnelOptions access

```python
from modules.anyconnect_re import AnyConnectNEAnalyzer, ACSockExtAnalyzer

a = AnyConnectNEAnalyzer('/path/to/NetworkExtension')
print(a.tunnel_start_selrefs())
insns = a.start_ikev2_tunnel(count=200)

ac = ACSockExtAnalyzer('/path/to/acsockext_x86_64')
print(ac.inject_block_callback())   # double-fetch TOCTOU @ 0x100082f38
```

**`ACSockExtAnalyzer`** — `com.cisco.anyconnect.macos.acsockext` 5.1.16.194 (x86_64)

AppProxy / NetworkFilter / DNS proxy via `NEAppProxyProvider` / `NEFilterDataProvider` / `NEDNSProxyProvider`. TOCTOU in `injectDelayedResponseIntoUDPFlow:` — async block re-fetches flow via `findUDPFlowWithDelayedReponse:` @ `0x100082f5e`; race window allows null or replaced flow on second fetch.

#### Cisco FTD / FDM — 43 modules

Static RE of Cisco Firepower Threat Defense 6.7.0-65 through 7.0.0-94 and FDM (Firepower Device Manager). Covers the FDM Java/Tomcat REST layer, Python management plane (`cisco_sf_common_base`), lina binary, and daemon attack surfaces.

**Key chains:**

- **F-FTD-102 → F-FTD-106: JWT forgery** — `ftd_neo4j_password_decrypt` extracts AES key from Neo4j Python bindings → decrypts admin password → `ftd_jwt_forge` forges HS256 tokens → cluster admin on any FDM instance
- **F-FTD-105: Spring Security bypass** — `ftd_fdm_local_auth_bypass`: FDM whitelist passes `127.0.0.1` behind a reverse proxy forwarding a client-controlled `X-Forwarded-For` header — pre-auth admin API access
- **F-FTD-107: TAR slip RCE** — `ftd_backup_tarslip`: backup restore decompresses a user-controlled tar without canonical path validation — arbitrary file write as root
- **F-FTD-109: cli_shadow root** — `ftd_clishadow_root`: `cli_shadow` NOPASSWD in sudoers on FTD 7.0.0-94 — root from any local account
- **F-FTD-110: Python AES key** — `ftd_hardcoded_aes_key`: SHA-256 of hardcoded passphrase → AES-256-CBC; static across all FTD/FMC deployments; decrypts Python management plane ciphertext fleet-wide without device access
- **F-FTD-66: SRU zip-slip** — `ftd_sru_zipslip`: `NGFWFileUtils.extractTarArchive` no canonical path check; three vulnerable call sites in the SRU unpack path
- **F-FTD-67: Config zip-slip** — `ftd_config_import_zipslip`: zip4j 1.3.3 (CVE-2018-1002202) in config import — no signature check on zip contents; admin credentials → arbitrary file write as www
- **F-FTD-79: DevAuth** — `ftd_devauth_hardcoded_creds`: development auth bypass; all 7 SHA-256 hashes cracked
- **ZMQ NULL auth** — `ftd_sfdc_zmq_rep`: SFDataCorrelator ZMQ REP socket — NULL auth, data injection
- **eStreamer unauth** — `ftd_estreamer_unauth`: unauthenticated network event streaming
- **AJP GhostCat** — `ftd_ajp_ghostcat`: AJP connector on FDM management interface (CVE-2020-1938 surface)
- **Snort plugin injection** — `ftd_snort3_plugin_injection`: detection engine Lua plugin write path — www → sfsnort pivot

```python
# Fleet-wide FTD/FMC Python-layer AES-256 key
from modules.ftd_hardcoded_aes_key import AES256_KEY
print(AES256_KEY.hex())

# JWT forgery chain (F-FTD-102 → F-FTD-106) — CONTROLLED ENVIRONMENT ONLY
from modules.ftd_jwt_forge import FDMJWTForger
token = FDMJWTForger('192.168.1.1').forge(neo4j_key='<hex-from-ftd_neo4j_password_decrypt>')
```

#### `cisco_re_engine` — Unified Cisco RE platform (8 modules)

**CONTROLLED ENVIRONMENT ONLY**

Cisco-specialized RE suite integrating FLOSS, capa, radare2, BinDiff/Diaphora, Frida, ropper, keystone, and Scapy into a single ablation-native module. Purpose-built heuristics for lina, FTD, ASA, and AnyConnect.

```bash
# Static analysis: FLOSS + capa + r2 on a Cisco ELF
python3 modules/cisco_re_engine.py /tmp/ftd-p6/usr/local/asa/bin/lina --mode static

# Full static chain
python3 modules/cisco_re_engine.py /path/to/lina --mode full

# Semantic firmware diff (two versions)
python3 modules/cisco_re_engine.py /path/to/lina-old --mode diff --binary-b /path/to/lina-new

# Frida attach to running process
python3 modules/cisco_re_engine.py /path/to/lina --mode frida --process lina

# ROP gadget discovery + shellcode assembly
python3 modules/cisco_re_engine.py /path/to/lina --mode exploit

# Protocol fuzzer (cstp | dtls | fdm_api | ikev2)
python3 modules/cisco_re_engine.py /dev/null --mode fuzz --fuzz-host 192.168.45.45 --fuzz-port 443 --fuzz-protocol fdm_api

# All modules in sequence
python3 modules/cisco_re_engine.py /path/to/lina --mode all
```

**Module breakdown:**

| Module | Tools | What it surfaces |
|--------|-------|-----------------|
| `static_analysis` | FLOSS, capa, r2 | Deobfuscated strings, capability fingerprints, function map |
| `string_correlate` | FLOSS + capa xref | Maps strings to capa hits and code xrefs — context for each credential/config string |
| `auth_hunt` | r2 string scan | Auth/credential/crypto patterns: hardcoded hashes, DevAuth markers, RADIUS/TACACS+/SAML strings, debug interface indicators |
| `firmware_diff` | BinDiff / Diaphora | Semantic diff between firmware versions; classifies changes (auth check, bug fix, crypto update); highlights attack surface delta |
| `frida_trace` | Frida | Real-time strcmp/SHA256/setuid hook with backtrace; maps auth flow at runtime |
| `exploit_surface` | ropper + keystone | ROP gadget chain suggestion, shellcode assembly skeleton, ASLR/DEP mitigation notes |
| `protocol_fuzz` | Scapy | CSTP, DTLS, FDM REST API (including Log4Shell probe), IKEv2 template fuzzing |
| `report` | CVE map | Unified findings JSON/text with CISCO_CVE_MAP auto-attribution (F-FTD-60, F-FTD-79, Log4Shell, etc.) |

**Built-in heuristics:** DevAuth SHA-256 hashes (F-FTD-79, all 7 cracked), sftunnel HMAC markers, FDM provision/token endpoint strings, lina struct field names (`gp_name`, `wins_ptr`, `auth_flags`), proprietary Cisco DES/3DES key schedule constants, debug interface markers (`gdbserver`, `SYS_ptrace`, `/dev/cisco0`).

#### `cisco_ise_re` — Cisco ISE 3.5 static RE (46 findings, CRIT:11)

Static analysis of Cisco Identity Services Engine 3.5.0.527. Key findings:

- **RADIUS Class attribute OU= overflow** — 256-byte RADIUS Class attribute vs 64-byte CLI GP name buffer; pre-auth memory corruption in LINA auth path (chains from `cisco_radius_ise_re`)
- **Hardcoded credentials** — dev/service accounts with weak or default passwords
- **LDAP chain** — bind password decrypt via static key → AD enumeration
- **SSRF and XXE surfaces** in ISE REST API and posture assessment endpoints
- **Unauthenticated REST endpoints** in the monitoring/reporting API

```python
from modules.cisco_ise_re import ISEAttackSurface
ise = ISEAttackSurface('192.168.1.100')
ise.probe_unauth_endpoints()
ise.probe_radius_overflow()
```

#### `cisco_cucm_re` — Cisco CUCM 15.0.1 static RE (482 findings)

Static analysis of Cisco Unified Communications Manager 15.0.1.11901-2 ISO. AlmaLinux 8, Tomcat, Informix DB, OpenSAML SSO SP.

**Critical chains:**

- **Static AES-128 key** (`smetsysocsiccni\x00`) — decrypts all credentials fleet-wide: CAPF CA key, Informix password, LDAP bind password, SAF inter-cluster creds
- **OAuth JWT forgery** — `ccmuser:ccmuser` DB → `SELECT keyvalue FROM authzkeys WHERE tkpurpose=2` → static key decrypt → PKCS8 RSA → forge RS256 JWT → cluster-wide SSO
- **ITL Recovery signing key** — DER private key at `/usr/local/platform/.security/ITLRecovery/keys/ITLRecovery_priv.der` → forge ITL trust list → all phones re-key to attacker CM → SRTP interception
- **HAProxy admin socket** — `/var/run/haproxy.sock mode 666 level admin` — world-writable; any local process issues `disable server`, `shutdown sessions all`, backend redirect
- **SAMLAuthValve always-true** + OpenSAML 2.6.5 XSW → pre-auth admin session
- **TAPS pre-auth RCE** — Java 1.4 skeleton, no JEP 290, CommonsCollections → ysoserial chain
- **Informix default creds** — `informix/informix` on port 9088

```python
from modules.cisco_cucm_re import full_findings_summary, probe_axis2_admin
print(full_findings_summary())           # all 482 findings
probe_axis2_admin('cucm.internal')       # F1: Axis2 admin:axis2 hot-deploy probe
```

---

### Cisco NX-OS / ACI / Data Center

#### `nxos_enum` — NX-OS / ACI / APIC

- Unauthenticated: `GET /api/aaaListDomains.json` returns all AAA domain names
- Full MIT queries: fabric nodes, tenants, EPGs, bridge domains, VRFs, L4 contracts, L3Outs, BGP peers
- VMM objects expose vCenter controller IP (`vmmCtrlrP`) and username (`vmmUsrAccP`) — lateral movement to vSphere
- Default creds: `admin/admin`, `admin/C1sco12345`, `admin/Cisco123`, variants

#### `nexus_dashboard_enum` — Nexus Dashboard / NDI / NDFC / NDO

SSO platform — one credential set unlocks NDI, NDFC, and NDO. Kafka export config (`/api/v1/event-services/exporters`) is often world-readable without auth: broker addresses, topics, TLS certs. Terraform and ServiceNow integration endpoints can expose cloud provider credentials and ITSM tokens.

#### `cisco_nxos_guestshell_re` — NX-OS guestshell rootfs analysis

Analyzes extracted/mounted CentOS LXC rootfs. Validates EXT4 magic (`0xEF53` at `0x438`).

- Credential scan: passwords, API tokens, shadow hashes, JDBC URLs, private keys, SNMP community strings
- SUID binaries vs known-safe set
- World-writable cron directories
- Python security packages that shouldn't be in production

#### `hyperflex_enum` — Cisco HyperFlex

HyperFlex REST API (`/coreapi/v1/`), SCVM SSH surface, default credential testing, VM inventory, Intersight claim-code extraction.

#### `ios_enum` — IOS / IOS-XE live enumeration

SSH + NETCONF enumeration: interface inventory, routing table, BGP neighbors, ACLs, user accounts, Syslog/SNMP config, CDP neighbors, AAA server list. NETCONF/YANG for IOS-XE 16.3+. Type 7/5/8/9 password decode.

---

### Binary Analysis Core

#### `core/binary_parser` — Format detection

ELF32/64, Mach-O 32/64 / fat, PE32/PE32+, and raw firmware blobs from magic bytes. Dispatches to the appropriate analyzer.

#### `core/elf_parser` — ELF analysis

Header, program headers, section headers, `.symtab` / `.dynsym`, dynamic section (RPATH, RUNPATH, needed libs), REL/RELA relocations, GNU notes. Stripped binary recovery: prologue detection (ENDBR64, PUSH RBP + MOV RBP RSP) → approximate symbol map from cross-references.

#### `core/pe_parser` / `core/pe_analyzer` — PE analysis

NT headers, section table, import/export directories, TLS callbacks, load config (CFG, ASLR, DEP flags), PDB path. Security feature flags: ASLR, DEP/NX, SafeSEH, CFG, Authenticode. Section entropy for packed/encrypted regions.

#### `core/firmware_analyzer` — Firmware image analysis

Magic detection: SquashFS, CramFS, ext2/3/4, JFFS2, YAFFS, UBI. Per-block entropy to distinguish compressed vs encrypted vs plaintext regions. Extracts root filesystem to temp directory for downstream analysis.

#### `core/disasm_engine` — Multi-architecture disassembler

Capstone wrapper. Architectures: x86 (16/32/64), ARM/Thumb/ARM64, MIPS 32/64, PowerPC. Function boundary detection, call graph, basic block decomposition, cross-reference building. Annotation layer maps Cisco ASA struct offsets to field names inline.

#### `core/yara_generator` — YARA rule generation

String constants, byte sequences around prologues, import combinations, section layout signatures → ready-to-use YARA rules for firmware or malware hunting.

#### `core/attck_tagger` — MITRE ATT&CK tagging

Structured findings → ATT&CK technique list with tactic, technique ID, name, and triggering finding.

#### `core/shellcode_utils` — Shellcode analysis and templates

x86-64 / ARM64 shellcode templates. Entropy, null-byte density, common sequence detection (GetProcAddress, syscall stubs, XOR decode loops), NOP sled identification. XOR/ADD encoders for bad-byte avoidance.

#### `core/tls_analyzer` — TLS analysis

Certificate chain parsing, CT anomaly detection (I/N ≥ 0.30 = honeypot signal), cipher enumeration, protocol version detection. Flags: self-signed, expired, RSA < 2048, RC4/DES/3DES/export-grade/null ciphers, TLS 1.0/1.1. Quantum inventory: RSA/ECDSA → Shor-vulnerable; ML-KEM/ML-DSA → post-quantum safe.

#### `core/platform_detect` — Platform fingerprinting

OS, architecture, kernel version, container runtime. Bare metal vs VM vs Docker vs K8s Pod vs Orka VM. Used at startup to select the applicable module set.

---

### Java

#### `java_re` — Java class file RE

Full constant pool parse (all JVM tag types). Security extraction:

- `ObjectInputStream.readObject()` call sites — deserialization surface
- `Runtime.exec()` / `ProcessBuilder` — command injection chains
- `Class.forName` / `Method.invoke` — reflection abuse
- JDBC URLs and connection strings from string constants
- Framework fingerprinting: Spring, Jackson, Gson, Hibernate

#### `java_decompiler` — Decompilation wrapper

Uses Procyon, CFR, or Fernflower (whichever is in PATH). Falls back to `javap -c` bytecode output.

---

### Windows Kernel

#### `windows_kernel_re` — Kernel driver RE

- **IOCTL dispatch** — `DriverEntry` → `IRP_MJ_DEVICE_CONTROL` handler → full `CTL_CODE` decomposition (device type, access, function, transfer type) → per-IOCTL handler map
- **DKOM** — `PsGetCurrentProcess` / `PsLookupProcessByProcessId` call sites followed by `EPROCESS` field access; process token stealing detection
- **SSDT hooks** — entries pointing outside `ntoskrnl.exe` / `win32k.sys`; shadow SSDT enumeration
- **DSE bypass** — `g_CiEnabled` / `g_CiOptions` patch patterns, `SeLoadDriverPrivilege` abuse, test-signing mode indicators

#### `forensics_enum` — Forensic artifact analysis

SEH chain corruption (FS:[0] pattern), POPAD+JMP shellcode sequences. Windows artifact map: event logs, prefetch, MRU, shellbags, jump lists, browser history. Maps attacker dwell time indicators.

---

### Containers and Kubernetes

#### `vmnetd_re` — Docker vmnetd socket protocol RE

RE module for `com.docker.vmnetd`, the macOS privileged helper that runs as root and handles Docker networking.

**What it maps:**
- Handler dispatch table — locates `handlePing`, `handleBindIpv4`, `handleInstallSymlinks`, `handleUninstall`, `handleDiagnose` and surrounding byte context to recover command IDs
- VMN3T handshake magic — finds all occurrences in the binary, extracts surrounding frame structure, locates `handshake.go` source path reference
- Path strings — extracts all `/usr/local/`, `/usr/bin/`, `/var/run/`, `/etc/`, `/Library/`, `/private/` paths from binary; maps what `symlinkBinary` / `symlinkDockerSock` can create/target
- `UserWritablePaths` struct fields — context dump from binary for boundary validation logic
- Live socket probe — sends structured binary probes against `/var/run/com.docker.vmnetd.sock` to confirm command ID → response mapping

```bash
VMNETD_BINARY=/path/to/com.docker.vmnetd python3 modules/vmnetd_re.py
```

```python
from modules.vmnetd_re import run
run(binary='/path/to/com.docker.vmnetd', socket_path='/var/run/com.docker.vmnetd.sock')
```

Goal: craft `SymlinkMessage` as root via the privileged socket.

#### `docker_enum` — Docker escape surface

- `/var/run/docker.sock` writable → root via `docker run --privileged`
- Capabilities: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`
- Namespace isolation: PID, mount, network, user
- Writable host paths via bind mounts
- Daemon API on TCP 2375/2376 without TLS client auth

#### `k8s_enum` — Kubernetes enumeration

SA token from `/var/run/secrets/kubernetes.io/serviceaccount/`. Direct API server enumeration — no `kubectl` needed. RBAC self-check via `SelfSubjectAccessReview` (exact permissions, no cluster-admin required).

- Secret extraction with base64 decode
- ConfigMap credential hunting
- Privesc paths: `pods/exec` → RCE; `secrets/get` on `kube-system` → cred harvest; `create pods` → privileged pod → host escape; `system:node` → lateral to other nodes
- etcd direct access (2379): key-space enumeration, secret extraction bypassing RBAC
- Kubelet API (10250): pod list, exec on unprotected Kubelets

#### `harbor_enum` — Harbor OCI registry + supply chain

Default creds: `admin:Harbor12345`. Project/repo enumeration, image manifest pull, layer extraction, BV41 metadata decode. Trivy vulnerability scan results (attacker gets CVE inventory without running a scanner). Robot account enumeration. Supply chain map: images with external `FROM` references.

#### `privesc_enum` — Privilege escalation

SUID/SGID vs known-safe set, world-writable paths, cron job injection, sudo NOPASSWD rules, Linux capabilities on binaries/processes, Docker group membership, `/etc/passwd` writability, readable shadow files, package manager PATH attack surface. Cross-platform: macOS + Linux.

---

### Network and Protocol

#### `tls_enum` — TLS service enumeration

Supported cipher suites, protocol versions (TLS 1.0/1.1 detection), certificate chain, OCSP stapling, session resumption (ID + ticket), HSTS/HPKP, JA3 server fingerprint.

#### `net_sniffer` — Raw packet capture + credential extraction

Protocol parsers: HTTP basic auth, FTP, Telnet, SMTP AUTH, POP3, IMAP, SNMP community strings, SIP Digest, clear-text LDAP bind requests. Output is structured credential tuples.

#### `network_analyze` — Network topology

Interface map, routing table, listening services, established connections. From pcap: ARP table, VLAN tags (802.1Q), routing protocol detection (OSPF/EIGRP/BGP hellos), DHCP and DNS server identification.

#### `nginx_enum` — nginx configuration + CVE surface

Config parsing: server blocks, location blocks, `proxy_pass` targets, auth directives, include chains. Alias traversal: `location /path/ { alias /dir; }` without trailing slash → `GET /path../etc/passwd`. Version → CVE mapping (CVE-2017-7529, HTTP/2 off-by-one). `proxy_pass` path-append SSRF amplification.

#### `sip_enum` — SIP / VoIP

OPTIONS sweep for extension discovery, REGISTER scan, Digest auth capture, RTP stream identification. Maps voicemail extensions, conference bridges, SIP trunk credentials.

#### `streaming_enum` — Kafka / Flink / NiFi

- **Kafka** — Metadata API broker enumeration (no auth if ACLs unenforced), topic list, partition/leader map, consumer group offsets, sensitive topic detection, produce access test
- **Flink** — REST API at `:8081`; job submission allows arbitrary JAR execution without auth by default
- **NiFi** — processor config reads (cleartext passwords in many processor types), template download with embedded credentials
- **Schema Registry** — unauthenticated subject and schema enumeration

#### `llm_enum` — LLM inference server enumeration

Ollama, LM Studio, LocalAI, OpenAI-compatible. Checks: unauthenticated model listing, unfiltered generation, model file path exposure, system prompt leakage via `/api/show`.

#### `qwen3_tts_re` — Qwen3-TTS / MLX-TTS WebAPI RE

Assessment module for `mlx-community/Qwen3-TTS` and compatible FastAPI/uvicorn TTS services (default port 2023).

**Modules:**
- **M1 `module_health`** — `/health` endpoint: model IDs, instance UUID, process start time, MLX active memory in GB — full system state without auth
- **M2 `module_unauth_synthesis`** — confirms unauthenticated compute access; logs WAV size + Content-Disposition
- **M3 `module_path_enum`** — 30-path sweep: `/docs`, `/openapi.json`, `/models`, `/voices`, `/admin`, `/metrics`, `/config`, `/reload`, `/stream`, `/ws`, and more
- **M4 `module_ssml_injection`** — SSML basic, SSML `<audio src>` SSRF (IMDS + loopback), prosody injection, XXE, script injection, path traversal in text field, null bytes, 10k-char resource exhaustion, Unicode homoglyphs; baselines against normal synthesis for size-delta anomaly detection
- **M5 `module_param_discovery`** — probes 30+ undocumented parameters (`voice`, `speaker_id`, `model`, `seed`, `callback_url`, `webhook`, `ssml`, `emotion`, etc.) via error reflection
- **M6 `module_race_condition`** — 5 concurrent synthesis threads; surfaces missing rate limiting
- **M7 `module_file_enum`** — predictable-filename IDOR sweep for generated audio files across `/files/`, `/audio/`, `/static/`, `/output/`

```bash
QWEN3_TTS_TARGET=http://<host>:2023 python3 modules/qwen3_tts_re.py
```

```python
import os; os.environ["QWEN3_TTS_TARGET"] = "http://<host>:2023"
from modules.qwen3_tts_re import run_all
result = run_all()
```

---

### Cryptography and Authentication

#### `jwt_crypto_analyzer` — JWT attack suite

- `alg: none` bypass
- RS256 → HS256 confusion (re-sign with public key as HMAC secret)
- Weak HMAC key brute-force (production-leaked wordlist)
- `kid` injection: SQL injection (DB key lookup), SSRF (URL-valued kid), directory traversal

```python
from modules.jwt_crypto_analyzer import JWTAttackSuite
JWTAttackSuite(target_url='https://target/api/').run_all(token='eyJhbGc...')
```

#### `crypto_audit` — Binary cryptographic audit

Hardcoded key material (high-entropy bytes near crypto call sites), weak RNG (`rand()` / `random()` in security-sensitive paths), ECB mode indicators, MD5/SHA1 imports, custom crypto re-implementations.

---

### Post-Compromise

#### `process_enum` — Process and memory analysis

All processes (PID, PPID, name, cmdline) — `/proc` on Linux, `ps` on macOS. Per-PID: `/proc/PID/maps` (heap/stack/mmap/DSO layout), `/proc/PID/fd` (open DB connections, sockets, sensitive files held open), `/proc/PID/environ` (environment variables). macOS: `vmmap` + `lsof` equivalents.

#### `lateral_movement` — Lateral movement surface

TCP scan (stdlib socket, no nmap). Cloud metadata: `169.254.169.254` (AWS/GCP/Azure IMDS), ECS task metadata endpoint — IAM role ARN, temporary credentials, user data. Credential harvest: `~/.aws/credentials`, `~/.kube/config`, `~/.ssh/id_*`, `~/.docker/config.json`, `.env` files, `/etc/kubernetes/admin.conf`. Orka internal DNS discovery (`10.221.188.x`).

#### `syscall_trace` — System call tracing

Wraps `strace` (Linux) / `dtruss` / `dtrace` (macOS). Structured output: `open`/`openat`, `connect`, `execve`, `write` to network FDs. Flags credential access patterns and data exfiltration paths.

---

### Regression

#### `regression` — Struct offset version registry

Version-confirmed struct offsets for Cisco ASA LINA, indexed by version tuple. `FirmwareVersionRegression` fits a boundary model. Includes `OLS`, `LogisticRegression`, `DescriptiveStats`, `CorrelationMatrix`.

```python
from modules.regression import SymbolicOffsetRegression

offset = SymbolicOffsetRegression.gp_name_offset((9, 20, 3, 0))
# -> 0x2b0

for ver, entry in SymbolicOffsetRegression.CONFIRMED.items():
    print(ver, hex(entry['gp_name_offset']), entry['source'])
```

---

### WeChat Android

WeChat 8.0.56 arm64 static RE. Covers the MMTLS transport protocol, DB encryption key derivation, and runtime key extraction via ptrace — no Frida. Synthesized from symbol tables, embedded source paths, and log strings in `libwechatnetwork.so` and `libMMProtocalJni.so`.

Native ARM64 tooling lives in [mmtls-lab](https://github.com/sshpie/mmtls-lab). `wechat_re.py` drives it via adb.

#### `wechat_re` — MMTLS + DB key + ptrace key extraction

**MMTLS protocol** (WeChat's custom TLS replacement, private `mars-wechat` repo):
- Two-tier key architecture: `HybridEcdh` (static+ephemeral) → `AxEcdh` (double ratchet / Signal-style forward secrecy)
- Cipher suites: AES-GCM (primary), SM4-GCM (Chinese national standard GB/T 32907)
- KDF: HKDF-SHA384 (TLS 1.3 style), handshake format in `mmtls_handshake_messages.cpp` (private)
- PSK 0-RTT session resumption: `HS_MODE_ZERO_RTT_PSK`, tickets stored in `ClientCredStorage`

**Key offsets (libwechatnetwork.so 8.0.56 arm64):**

| Symbol | VA | Notes |
|--------|----|-------|
| `gILinkKey` | `0x3d4648` | 72-byte live session key (BSS) |
| HKDF call | `0x1ce28c` | BL `0x1dc424`; return site `0x1ce290` |
| key-insert orchestrator | `0x303fb0` | hlist splice at `0x304074` |

**Findings encoded:**
| ID | Severity | Finding |
|----|----------|---------|
| WX-F1 | INFO | MMTLS two-tier crypto: HybridEcdh + AxEcdh double ratchet |
| WX-F2 | MEDIUM | `ALERT_FALLBACK_NO_MMTLS` — network-level downgrade to HTTPS |
| WX-F3 | HIGH | PSK 0-RTT session resumption — extracted PSK enables replay |
| WX-F4 | HIGH | `gILinkKey` (72B, BSS, `0x3d4648`) — live MMTLS session key; extractable via ptrace probe |
| WX-F5 | HIGH | DB key: `computerKeyWithAllStr(IMEI, UIN)` → 7-char hex → SQLite SEE |
| WX-F6 | INFO | Pack format reconstructed: header (clientVer/type/flag/seq) + body (uin/func/encryptAlgo) |

```bash
# Full static RE (APK + libs)
./ablation --wechat \
  --wechat-apk /path/to/wechat-arm64.apk \
  --wechat-libs /path/to/native-libs/lib

# Compute EnMicroMsg.db decryption key offline
./ablation --wechat-db-key 123456789012345 987654321
# [+] WeChat DB key (MD5(IMEI+UIN)[:7]): a3f9e2c
```

```python
from modules.wechat_re import WeChatRE
wx = WeChatRE()

# Discover gILinkKey write site (single-steps from HKDF return until key changes)
result = wx.probe_discover()
# {'writer_pc': 0x1cad30, 'key': 'a3f9...', 'steps': 317}

# Continuous key capture at write site
wx.probe_hook(writer_pc=0x1cad30)
# streams JSON per key-write event

# One-shot key snapshot
wx.probe_dump()
```

**ptrace intercept points (mmtls_probe):**
- `probe_discover`: plants `BRK #0` at HKDF return (`0x1ce290`), single-steps until `gILinkKey` changes — resolves write site dynamically
- `probe_hook`: persistent `BRK #0` at `writer_pc`, re-armed after each hit; captures 72-byte key on every MMTLS session establishment
- `probe_dump`: polls `/proc/pid/mem` at `gILinkKey` until non-zero + stable (200ms verify)

**Injector (mmtls_inject):** PLT/GOT patcher with FULL_RELRO bypass. Android linker marks `.got.plt` `PROT_READ` after relocations — bypassed by injecting `mprotect()` into the target process via ptrace register manipulation (no shellcode). Patches `connect`/`send`/`recv`/`sendto`/`recvfrom` GOT entries to redirect through `libhook.so` globals.

**DB encryption:** SQLCipher (`libWCDB.so`) — not SQLite SEE. Key is 7 hex chars derived from MD5(IMEI+UIN).

---

### Go Binary RE

#### `go_garble_re` — garble-obfuscated Go ELF static analysis

Handles Go binaries compiled with `mvdan/garble` — the standard Go RE toolchain (GoReSym, `strings`, pclntab parsers) fails completely on these because garble encrypts all string constants at compile time, scrambles the pclntab function table, and renames every package and symbol. This module works around all three.

```bash
python3 modules/go_garble_re.py /path/to/binary
```

**What it does:**

- **Correct VA→file-offset mapping** — parses ELF LOAD program headers directly. Stock ablation `--binary` and `--go-re` modes treat the entry-point VA as a file offset (wrong for any non-PIE Go binary with a high base like `0x400000`). This module converts every virtual address correctly via `va - p_vaddr + p_offset`.
- **pclntab detection + garble diagnosis** — locates the Go function table by magic bytes (supports Go 1.12/1.16/1.18/1.20+ formats). Reports whether garble has scrambled the header (invalid `quantum`/`ptrsize` fields signal obfuscation; GoReSym will fail on these).
- **Bootstrap chain tracer** — Capstone disassembly that follows the Go runtime call chain from the entry point (`_rt0_amd64_linux` → `_rt0_amd64` → `runtime.rt0_go` → ...) using correct VA-aware addressing, not raw file offset iteration.
- **String anchor xref scanner** — given a known string's file offset (e.g. a port number found by `strings`), converts it to VA and scans all executable segments for RIP-relative LEA instructions that load that exact address. Finds every site that references the string — the surrounding function is the string's user.
- **Garble decrypt stub finder** — garble inserts a per-string XOR decrypt stub called from every use site. Scans all CALLs to find the most frequently called short functions and flags those with XOR instructions — these are the decrypt stubs. Reversing one stub + its call sites maps a full string decryption chain.

```python
from modules.go_garble_re import analyze_go_garble_binary

result = analyze_go_garble_binary('/path/to/linkease')
print(result['pclntab'])          # garble diagnosis
print(result['bootstrap'])        # entry → rt0 call chain with VA + file offsets
print(result['string_xrefs'])     # LEA sites referencing string anchors
print(result['decrypt_stubs'])    # top XOR-stub candidates by call frequency
```

**Findings structure:**

| Key | Contents |
|-----|----------|
| `elf` | Entry VA, file offset, LOAD segment map |
| `pclntab` | Magic, quantum, ptrsize, nfunc (or garble-scrambled values) |
| `bootstrap` | Per-stage VA + file offset + first 8 instructions |
| `string_xrefs` | Per-anchor: xref count + list of LEA instruction VAs |
| `decrypt_stubs` | Top candidates: VA, call count, XOR flag, instruction preview |
| `findings` | Human-readable summary line per finding |

**When to reach for it:** Any Go binary where GoReSym returns `"failed to locate pclntab"` or `"failed to read pclntab"` — that's the garble signature. Also useful for stripped Go binaries with no section headers (pclntab found by magic scan, not section lookup).

---

### Utilities

#### `utils/poc_radius_ou_inject.py` — RADIUS Group Policy Injection PoC

Standalone PoC for F1 (no Message-Authenticator enforcement) + F2 (256-byte OU= vs 64-byte CLI limit). Two modes: fake RADIUS server (every Access-Request gets an attacker-controlled OU= response), and single-packet send. Demonstrates the overflow delta from `RadiusOverflowProbe`.

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
│   ├── cisco_re_engine.py          ← Unified Cisco RE: FLOSS+capa+r2+BinDiff+Frida+ropper+keystone+Scapy
│   ├── cisco_asa_lina_re.py        ← LINA struct RE + RadiusOverflowProbe
│   ├── cisco_asa_cred_audit.py
│   ├── cisco_asdm_re.py
│   ├── cisco_asdm_download_re.py
│   ├── cisco_asdm_jar_re.py
│   ├── cisco_webvpn_js_re.py
│   ├── cisco_cstp_attack.py
│   ├── cisco_rommon_re.py
│   ├── cisco_config_re.py
│   ├── cisco_api_enum.py
│   ├── cisco_ise_re.py             ← ISE 3.5.0.527 static RE, 46 findings
│   ├── cisco_radius_ise_re.py      ← RADIUS Class attr injection + ISE CoA
│   ├── cisco_cucm_re.py            ← CUCM 15.0.1 static RE, 482 findings
│   ├── cisco_fmc_re.py             ← FMC RE (in progress)
│   ├── cisco_ftd_re.py             ← FTD RE engine
│   ├── cisco_ftd_jwt_escalation.py
│   ├── cisco_ftd_jwt_key_extraction.py
│   ├── cisco_ftd_tarslip.py
│   ├── ftd_jwt_forge.py            ← FDM JWT forgery (F-FTD-106)
│   ├── ftd_jwt_key_extraction.py
│   ├── ftd_neo4j_password_decrypt.py ← Neo4j AES key → admin password
│   ├── ftd_backup_tarslip.py       ← TAR slip RCE (F-FTD-107)
│   ├── ftd_fdm_local_auth_bypass.py ← 127.0.0.1 Spring Security bypass
│   ├── ftd_eventing_api_unauth.py
│   ├── ftd_sfdc_zmq_rep.py         ← SFDataCorrelator ZMQ NULL auth
│   ├── ftd_hardcoded_aes_key.py    ← Python-layer AES-256 static key
│   ├── ftd_clishadow_root.py       ← cli_shadow NOPASSWD → root
│   ├── ftd_telegraf_metrics_unauth.py
│   ├── ftd_admin_shadow_root.py
│   ├── ftd_ajp_ghostcat.py
│   ├── ftd_amp_stunnel_ssrf.py
│   ├── ftd_apache_cve_2019_0211.py
│   ├── ftd_azure_imds_access.py
│   ├── ftd_backup_restore_rootexec.py
│   ├── ftd_ciscossl_cve_2022_0778.py
│   ├── ftd_clamav_network_trigger.py
│   ├── ftd_config_import_zipslip.py ← zip4j 1.3.3 zip-slip (F-FTD-67)
│   ├── ftd_dbaccess_creds.py
│   ├── ftd_devauth_hardcoded_creds.py ← DevAuth bypass (F-FTD-79)
│   ├── ftd_estreamer_unauth.py
│   ├── ftd_fdm_config_export_key.py
│   ├── ftd_fdm_easysetup_takeover.py
│   ├── ftd_fdm_user_mgmt_bypass.py
│   ├── ftd_firmware_dl_ssrf.py
│   ├── ftd_ha_standby_preauth_bypass.py
│   ├── ftd_installpkg_root.py
│   ├── ftd_ldap_cred_exfil.py
│   ├── ftd_ldap_mitm.py
│   ├── ftd_lina_lua_inject.py
│   ├── ftd_log4shell_fdm.py
│   ├── ftd_mgmt_ip_reconfig.py
│   ├── ftd_neo4j_backup_exfil.py
│   ├── ftd_openssl_file_rw.py
│   ├── ftd_pjb_sqli.py
│   ├── ftd_platform_api_token_impersonate.py
│   ├── ftd_rabbitmq_bonfire_inject.py
│   ├── ftd_sfmb_static_creds.py
│   ├── ftd_snort3_plugin_injection.py
│   ├── ftd_sru_zipslip.py          ← NGFWFileUtils tar-slip (F-FTD-66)
│   ├── ftd_vault_proxy_cred_exfil.py
│   ├── ftd_www_root_escalation.py
│   ├── anyconnect_re.py            ← AnyConnect NE IKEv2 + acsockext RE
│   ├── cisco_ios_re.py
│   ├── cisco_nxos_guestshell_re.py
│   ├── nxos_enum.py
│   ├── nexus_dashboard_enum.py
│   ├── ios_enum.py
│   ├── hyperflex_enum.py
│   ├── go_garble_re.py             ← garble-obfuscated Go ELF RE
│   ├── wechat_re.py
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
│   ├── qwen3_tts_re.py             ← Qwen3-TTS / MLX-TTS WebAPI RE
│   ├── vmnetd_re.py                ← Docker vmnetd privileged socket RE
│   ├── jwt_crypto_analyzer.py
│   ├── crypto_audit.py
│   ├── privesc_enum.py
│   ├── process_enum.py
│   ├── lateral_movement.py
│   ├── syscall_trace.py
│   └── regression.py
├── docs/
│   ├── CONTAINER-PLATFORMS.md
│   └── DEPLOY.md
└── utils/
    └── poc_radius_ou_inject.py
```

---

For authorized security testing only.
