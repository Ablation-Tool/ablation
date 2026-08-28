# Cisco Module Reference

Covers ASA, FTD/FDM, ISE, CUCM, AnyConnect, IOS, and NX-OS. All modules purpose-built from firmware extraction.

---

## Cisco ASA

### `cisco_asa_lina_re` — LINA binary RE + RADIUS overflow

LINA is the monolithic x86-64 ELF that implements Cisco ASA. Recovers struct field layouts from stripped binaries via LEA frequency analysis and provides a live RADIUS overflow probe.

**Struct recovery:** scans all `REX 8D /r disp32` LEA instructions in the 0x200–0x500 displacement range. Follow-up instruction type (CALL / CMP / TEST / MOV-write) reveals field purpose.

**Confirmed `gp_obj` layout — 9.22.2.32 (5633 LEA sites, 367 offsets):**

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| `0x2b0/0x2b1` | `char*` | `gp_name` | Version-dependent |
| `0x2f0` | `ptr` | `dns_ptr` | |
| `0x308` | `ptr` | `wins_ptr` | PRIMARY OVERFLOW TARGET |
| `0x310` | `int32` | `auth_state` | |
| `0x318` | `int32` | `primary_status` | |
| `0x328` | `char*` | `secondary_string` | Hottest post-overflow field |
| `0x367` | `uint8` | `state_enum` | Only compared to `0x83` |
| `0x368` | `uint32` | `auth_flags` | 37 TEST ops — auth bypass candidate |

**`RadiusOverflowProbe`** — RFC 2865 RADIUS server, sends Class attribute (type 25) payloads against `wins_ptr`. Version dispatch automatic:

```python
from modules.cisco_asa_lina_re import RadiusOverflowProbe

p = RadiusOverflowProbe(version=(9, 22, 2, 32), secret=b'cisco')
print(hex(p.GP_NAME_OFFSET))   # 0x2b1
print(hex(p.OVERFLOW_DELTA))   # 0x57
p.run()   # listens :1812
```

**Version-confirmed offsets:**

| ASA Version | `gp_name` | `OVERFLOW_DELTA` |
|-------------|-----------|------------------|
| 9.13.1 | 0x2b0 | 0x58 |
| 9.14.1.1 | 0x2b0 | 0x58 |
| 9.15.1 | 0x2b0 | 0x58 |
| 9.20.3 | 0x2b0 | 0x58 |
| 9.22.1.1 | 0x2b0 | 0x58 |
| 9.22.2.32 | **0x2b1** | **0x57** |

### `cisco_radius_ise_re` — RADIUS Class attribute injection

Confirmed write site in 9.22.2.32: `LEA rdi,[obj+0x308]; MOV rsi,rbx; CALL 0x3cf0ee0`. Builds RFC 2865 Access-Accept packets with arbitrary Class attribute 25 / OU= content. Covers ISE CoA (RFC 5176), posture bypass, and VSA parser surface.

### `cisco_cstp_attack` — AnyConnect / CSTP

- DAP bypass — posture evaluation sequence, conditions where rules pass without meeting requirements
- `sdesktop` cookie injection, SAML SP ACS URL manipulation
- Username timing oracle — response-time delta distinguishes valid vs invalid usernames
- Tunnel group enumeration from the WebVPN login page
- RADIUS CoA mid-session injection (force re-auth / disconnect)
- CRL/OCSP bypass, certificate-map tunnel-group bypass
- ASA version fingerprinting from HTTP response headers

### `cisco_webvpn_js_re` — WebVPN JavaScript RE

Downloads unauthenticated JS bundles from `/+CSCOU+/` and `/+CSCOE+/`. Extracts: tunnel group names, hidden API endpoints, OS detection logic, CSRF token generation pattern, SAML SP metadata and ACS URL. Maps session state machine — identifies states where re-auth can be skipped.

### `cisco_asdm_download_re` — ASDM JAR download

Full retrieval chain: `GET /admin/launch` → `302` → logon → `POST /+webvpn+/index.html` → session cookie → JNLP XML parse → JAR URL resolution → stream to disk.

### `cisco_asdm_jar_re` — ASDM JAR / JVM constant pool RE

Parses CAFEBABE class files per JVM spec. Stdlib only (`struct`, `zipfile`).

- Custom `X509TrustManager` that accepts any certificate — ASDM skips TLS validation against ASA
- REST API endpoint URLs from string constants
- Hardcoded credential candidates
- `ObjectInputStream.readObject()` call sites

### `cisco_rommon_re` — ROMMON bypass

Config-register `0x2142` modification, image authentication bypass paths, ROMMON environment variable injection.

### `cisco_config_re` — Configuration analysis

Type 7 decode (Vigenere, reversible). Extracts: enable secret / local user hashes, SNMP community strings, TACACS+/RADIUS shared secrets, BGP neighbor passwords, NTP auth keys, crypto key material, AAA chain structure.

### `cisco_ios_re` — IOS firmware RE

Image format identification (ELF / compressed ELF / monolithic), IFS extraction, IOSd entry point. Crash dump analysis with ADRP-based image-base recovery (ARM64). MIPS/ARM64/x86 gadget extraction. Hardcoded credential scan.

### `cisco_api_enum` — ASA REST API enumeration

ASA REST API (`/api/...`, 9.3+) endpoint enumeration. Unauthenticated surface mapping. Session cookie reuse from ASDM auth flow.

### `cisco_asa_cred_audit` — ASA credential audit

Credential testing across web management, ASDM, and REST API. Measures lockout behavior per-interface. Maps auth stack (local vs RADIUS vs TACACS+).

---

## Cisco AnyConnect

### `anyconnect_re` — AnyConnect / NetworkExtension RE

LIEF + capstone x86_64 RE of Apple's `NetworkExtension.framework` (1095.140.2) and Cisco's `acsockext` System Extension (5.1.16.194) on macOS 10.15.7.

**`AnyConnectNEAnalyzer`** — NE framework (x86_64, Catalina)

Key address tables:
- `NE_PHASE1_SELREFS` — phase-1 selrefs (IKE_SA_INIT → IKE_AUTH); `NEIKEv2ProviderAuthenticate:` @ `0x2ca770`
- `NE_TUNNEL_START_SELREFS` — 8 ordered selrefs: `protocolConfiguration` → `tunnelKind` → `setOptions:` (0x2ca758) → `NEIKEv2ProviderAuthenticate:` (0x2ca770)

Key methods:
- `start_ikev2_tunnel(count=200)` — disasm `NEIKEv2PacketTunnelProvider.startIKEv2TunnelWithOptions:` @ `0xd878b`
- `provider_auth_callsite(count=30)` — 15 insns around `0xd8f3f`; objc_msgSend site at `0xd8f60`
- `skeyseed_derivation()` — SKEYSEED PRF derivation in IKE_SA_INIT response handler
- `prf_plus()` — PRF+ key material expansion (KEYMAT/SK_*)

Bypass targets:
- `0xd8f60` — patch `call [rip+0x188a32]` → force rax=1; skips Cisco auth on tunnel start
- `0x2ca758` — setOptions: selref; pre-auth intercept point with full tunnelOptions access

```python
from modules.anyconnect_re import AnyConnectNEAnalyzer, ACSockExtAnalyzer

a = AnyConnectNEAnalyzer('/path/to/NetworkExtension')
print(a.tunnel_start_selrefs())
insns = a.start_ikev2_tunnel(count=200)
auth = a.provider_auth_callsite()
```

**`ACSockExtAnalyzer`** — `com.cisco.anyconnect.macos.acsockext` 5.1.16.194

AppProxy / NetworkFilter / DNS proxy via `NEAppProxyProvider` / `NEFilterDataProvider` / `NEDNSProxyProvider`.

Key methods:
- `inject_path(count=100)` — `injectDelayedResponseIntoUDPFlow:` @ `0x100082ad4`
- `inject_block_callback(count=120)` — block @ `0x100082f38`; double-fetch TOCTOU confirmed
  - block struct: `[0x20]=self`, `[0x28]=packet_data`, `[0x30]=peer_addr(28B)`, `[0x48]=local_addr_byte`
  - write at `0x10005da06` (`_writeUDPDatagramToFlow`) called from `0x1000830c3`
- `reuse_toctou(count=50)` — `isConnectionReusableForDestination:` @ `0x10004b393`

TOCTOU race: between `injectDelayedResponseIntoUDPFlow:` dispatching and block executing `findUDPFlowWithDelayedReponse:` @ `0x100082f5e` — flow can be destroyed/replaced by concurrent DNS response.

```python
ac = ACSockExtAnalyzer('/path/to/acsockext_x86_64')
print(ac.inject_block_callback())
```

---

## Cisco FTD / FDM — 43 modules

Static RE of Cisco Firepower Threat Defense 6.7.0-65 through 7.0.0-94 and FDM (Firepower Device Manager). Covers the FDM Java/Tomcat REST layer, Python management plane (`cisco_sf_common_base`), lina binary, and daemon attack surfaces.

**Key chains:**

- **F-FTD-102 → F-FTD-106: JWT forgery** — `ftd_neo4j_password_decrypt` extracts AES key from Neo4j Python bindings → decrypts admin password → `ftd_jwt_forge` forges HS256 tokens → cluster admin on any FDM instance
- **F-FTD-105: Spring Security bypass** — `ftd_fdm_local_auth_bypass`: FDM whitelist passes `127.0.0.1` behind a reverse proxy forwarding a client-controlled `X-Forwarded-For` header — pre-auth admin API access
- **F-FTD-107: TAR slip RCE** — `ftd_backup_tarslip`: backup restore decompresses a user-controlled tar without canonical path validation — arbitrary file write as root
- **F-FTD-109: cli_shadow root** — `ftd_clishadow_root`: `cli_shadow` NOPASSWD in sudoers on FTD 7.0.0-94 — root from any local account
- **F-FTD-110: Python AES key** — `ftd_hardcoded_aes_key`: SHA-256 of hardcoded passphrase (`r4onxh8364&Jh^%P)Kqf65d6ev#^%#(&(;kuwtUTR-WQp%^#86`) → AES-256-CBC; static across all FTD/FMC deployments; decrypts Python management plane ciphertext fleet-wide
- **F-FTD-66: SRU zip-slip** — `ftd_sru_zipslip`: `NGFWFileUtils.extractTarArchive` no canonical path check; three vulnerable call sites in SRU unpack path
- **F-FTD-67: Config zip-slip** — `ftd_config_import_zipslip`: zip4j 1.3.3 (CVE-2018-1002202) — no signature check on zip contents; admin → arbitrary file write as www
- **F-FTD-79: DevAuth** — `ftd_devauth_hardcoded_creds`: development auth bypass; all 7 SHA-256 hashes cracked
- **ZMQ NULL auth** — `ftd_sfdc_zmq_rep`: SFDataCorrelator ZMQ REP socket — NULL auth, data injection
- **eStreamer unauth** — `ftd_estreamer_unauth`: unauthenticated network event streaming
- **AJP GhostCat** — `ftd_ajp_ghostcat`: AJP connector on FDM management interface (CVE-2020-1938 surface)
- **Snort plugin injection** — `ftd_snort3_plugin_injection`: detection engine Lua plugin write path — www → sfsnort pivot

```python
# Fleet-wide FTD/FMC AES-256 key
from modules.ftd_hardcoded_aes_key import AES256_KEY
print(AES256_KEY.hex())

# JWT forgery chain — CONTROLLED ENVIRONMENT ONLY
from modules.ftd_jwt_forge import FDMJWTForger
token = FDMJWTForger('192.168.1.1').forge(neo4j_key='<hex>')
```

---

## `cisco_re_engine` — Unified Cisco RE platform

**CONTROLLED ENVIRONMENT ONLY**

Integrates FLOSS, capa, radare2, BinDiff/Diaphora, Frida, ropper, keystone, and Scapy into a single ablation-native module.

```bash
python3 modules/cisco_re_engine.py /path/to/lina --mode static
python3 modules/cisco_re_engine.py /path/to/lina --mode full
python3 modules/cisco_re_engine.py /path/to/lina-old --mode diff --binary-b /path/to/lina-new
python3 modules/cisco_re_engine.py /path/to/lina --mode frida --process lina
python3 modules/cisco_re_engine.py /path/to/lina --mode exploit
python3 modules/cisco_re_engine.py /dev/null --mode fuzz --fuzz-host 192.168.45.45 --fuzz-port 443 --fuzz-protocol fdm_api
```

| Module | Tools | Output |
|--------|-------|--------|
| `static_analysis` | FLOSS, capa, r2 | Deobfuscated strings, capability fingerprints, function map |
| `string_correlate` | FLOSS + capa | Maps strings to capa hits and code xrefs |
| `auth_hunt` | r2 | Auth/credential/crypto patterns, DevAuth markers, debug interface indicators |
| `firmware_diff` | BinDiff / Diaphora | Semantic diff, attack surface delta |
| `frida_trace` | Frida | Real-time strcmp/SHA256/setuid hook with backtrace |
| `exploit_surface` | ropper + keystone | ROP gadget chain, shellcode skeleton, ASLR/DEP notes |
| `protocol_fuzz` | Scapy | CSTP, DTLS, FDM REST API, IKEv2 |
| `report` | CVE map | Unified findings JSON with CISCO_CVE_MAP auto-attribution |

---

## Cisco ISE

### `cisco_ise_re` — Cisco ISE 3.5 static RE (46 findings, CRIT:11)

Static analysis of Cisco Identity Services Engine 3.5.0.527.

- **RADIUS Class attribute OU= overflow** — 256-byte RADIUS Class attribute vs 64-byte CLI GP name buffer; pre-auth memory corruption in LINA auth path
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

---

## Cisco CUCM

### `cisco_cucm_re` — Cisco CUCM 15.0.1 static RE (482 findings)

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
print(full_findings_summary())
probe_axis2_admin('cucm.internal')
```

---

## Cisco NX-OS / ACI / Data Center

### `nxos_enum` — NX-OS / ACI / APIC

- Unauthenticated: `GET /api/aaaListDomains.json` returns all AAA domain names
- Full MIT queries: fabric nodes, tenants, EPGs, bridge domains, VRFs, L4 contracts, L3Outs, BGP peers
- VMM objects expose vCenter controller IP and username — lateral to vSphere
- Default creds: `admin/admin`, `admin/C1sco12345`, `admin/Cisco123`

### `nexus_dashboard_enum` — Nexus Dashboard / NDI / NDFC / NDO

SSO platform. Kafka export config (`/api/v1/event-services/exporters`) often world-readable: broker addresses, topics, TLS certs. Terraform and ServiceNow endpoints can expose cloud credentials and ITSM tokens.

### `cisco_nxos_guestshell_re` — NX-OS guestshell rootfs

CentOS LXC rootfs analysis. Validates EXT4 magic (`0xEF53` at `0x438`).

- Credential scan: passwords, API tokens, shadow hashes, JDBC URLs, private keys, SNMP community strings
- SUID binaries vs known-safe set
- World-writable cron directories

### `hyperflex_enum` — Cisco HyperFlex

HyperFlex REST API (`/coreapi/v1/`), SCVM SSH surface, default credential testing, VM inventory, Intersight claim-code extraction.

### `ios_enum` — IOS / IOS-XE live enumeration

SSH + NETCONF enumeration: interface inventory, routing table, BGP neighbors, ACLs, user accounts, Syslog/SNMP config, CDP neighbors, AAA server list. Type 7/5/8/9 password decode.
