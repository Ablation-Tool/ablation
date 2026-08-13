
<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="It's in the sauce">
</p>

# ablation

Autonomous reverse engineering tool. Deploy inside a compromised system or run against a remote target. Stdlib-only — no third-party dependencies.

## Usage

```
python3 main.py [MODE] [OPTIONS]
```

No arguments — full autonomous analysis of the local system.

---

## Modes

### Local system RE

| Flag | Description |
|---|---|
| `--quick` | Platform fingerprint only |
| `--process PID` | Analyze a specific process |
| `--binary FILE` | Analyze a binary |
| `--syscalls PID` | Trace syscalls for a process |
| `--privesc` | Enumerate privilege escalation paths |
| `--lateral` | Lateral movement: creds, SSH keys, API tokens, cloud metadata, subnet scan |
| `--macos` | macOS malware IOC scan, persistence, TCC audit, DYLD hijack |
| `--ebpf [PID]` | eBPF capability audit and tracing script generation |

### Container / orchestration

| Flag | Description |
|---|---|
| `--docker` | Docker environment enumeration |
| `--k8s` | Kubernetes environment enumeration |
| `--orka` | Orka platform enumeration |
| `--containers` | Full container/platform analysis (Docker + K8s + Orka) |
| `--podman [SOCKET]` | Podman socket enumeration — containers, secrets, privileged mounts |

### Binary RE (static analysis)

| Flag | Description |
|---|---|
| `--swift BINARY` | Swift Mach-O binary RE |
| `--java PATH` | Java `.class`/`.jar` security audit |
| `--cisco-ios-re FILE` | RE a Cisco IOS firmware image, crash dump, or running-config |
| `--cisco-asdm FILE` | RE a Cisco ASDM JAR or `.class` file — constant pool walk, credential extraction |
| `--cisco-guestshell PATH` | RE a NX-OS guest shell rootfs directory or ext4 image |
| `--cisco-config FILE` | RE a Cisco config — type-7 decode, credentials, weak-config scan, topology map |
| `--cisco-rommon FILE\|0xCONFREG` | ROMMON bypass analysis — confreg decode, platform-specific bypass procedure |

### Network RE (remote targets)

| Flag | Description |
|---|---|
| `--cisco-re HOST [--cisco-re-port PORT]` | Full Cisco RE probe suite — 38 probes across ASA / IOS / NX-OS / ISE / API |
| `--cisco-asdm-live HOST [--cisco-asdm-live-port PORT]` | Download ASDM JAR live from a Cisco ASA, RE constant pool |
| `--cisco-webvpn HOST [--cisco-webvpn-port PORT]` | RE WebVPN JS portal (win.js, logon HTML), SAML surface |
| `--asa` | Cisco ASA WebVPN enumeration (MacStadium targets) |
| `--ios [HOST]` | Cisco IOS/IOS-XE enumeration — SNMP/TFTP/RESTCONF/Telnet |
| `--nxos` | Cisco NX-OS / ACI / APIC enumeration |
| `--ise [HOST]` | Cisco ISE 3.1 enumeration |
| `--ise-iso PATH` | Analyze ISE ISO — extract root hash, Oracle config, TACACS+ creds |
| `--cisco-api HOST [...]` | Cisco platform API sweep — APIC / DNA-C / UCS-M / vManage / RESTCONF / NSO |
| `--nexus-dash HOST [...]` | Nexus Dashboard SSO pivot — APIC+NDFC+NDO creds, Kafka export |
| `--nginx [HOST]` | nginx enumeration — version, config/location disclosure, LFI |
| `--tls [HOST[:PORT] ...]` | TLS cipher suite audit |
| `--winprobe HOST` | Windows protocol surface — SMB null session, WMI/RPC, WinRM, RDP, MS17-010 |
| `--hyperflex HOST [...]` | HyperFlex Connect enum — REST brute, Intersight claim code, iSCSI/NFS |
| `--streaming HOST [...]` | Streaming pipeline — Kafka, Flink, NiFi, Schema Registry |
| `--vergeio HOST` | VergeOS HCI enumeration |
| `--sniff [DURATION]` | Raw packet capture — credential extraction (needs root) |

### Cryptographic

| Flag | Description |
|---|---|
| `--crypto` | Cryptographic audit — JWTs, keys, TLS |
| `--jwt TOKEN` | Analyze a JWT token for weaknesses |

---

## Cisco RE modules

### Binary / static analysis

**`cisco_ios_re.py`** — Cisco IOS firmware image, crash dump, and config RE
- `CiscoIOSImage` — ELF parser (ARM64/MIPS/x86), PT_LOAD segment walk, image base recovery, string extraction, ARM64 ROP gadget scanner (`ret`, `br xN`, `blr xN`, `ldp x29,x30`), credential pattern hunter
- `IOSCrashDumpRE` — PC/LR/SP/CPSR and register extraction from crash dump text; image base recovery via ADRP page offset math; backtrace frame decoder (GDB, Cisco native, inline formats)
- `CiscoConfigRE` — weak-config scanner, full network topology mapper
- CLI: `python3 cisco_ios_re.py <firmware.bin|crash.txt|running-config.txt>`

**`cisco_asdm_re.py`** — ASDM JAR and JVM bytecode RE
- `JVMConstantPool` — full spec-correct parser for all 20 JVM tag types; correct Long/Double two-slot consumption; 12 credential patterns matched against every Utf8 entry
- `ASDMJarRE` — ZIP/JAR walker; class prioritization by name keywords; JKS/DER/PEM/base64 crypto material hunter
- `CiscoClassFileRE` — single `.class` file analysis; CAFEBABE verification; Java version mapping
- CLI: `python3 cisco_asdm_re.py <jar_or_class_file>`

**`cisco_asdm_download_re.py`** — Live ASDM JAR fetch and RE
- `ASDMDownloader` — JNLP discovery across 5 paths; XML-validated jar href extraction; ZIP-magic verification on downloaded bytes
- `ASDMJarRE` — constant pool RE with 15 credential patterns
- CLI: `python3 cisco_asdm_download_re.py <host> [port]`

**`cisco_nxos_guestshell_re.py`** — NX-OS guest shell LXC container RE
- `GuestShellRE` — rootfs credential hunt (7 pattern families across passwd/shadow/config/history/isan/opt); script enumeration with shebang detection; Python package inventory; NX-API config extraction; world-writable path and SUID binary enumeration; cron job extraction
- `NXOSRootfsExtractor` — ext4 image extraction via `debugfs`; raw strings fallback (credential scan direct from data blocks without mount)
- CLI: `python3 cisco_nxos_guestshell_re.py <rootfs_dir_or_ext4_image>`

**`cisco_config_re.py`** — Cisco running/startup config RE
- Platform detection: IOS, NX-OS, ASA, IOS-XR
- `extract_credentials()` — 12 credential families: enable secret/password, local users, SNMP community/v3, TACACS key, RADIUS key, AAA server key, IPSec PSK, IKEv2 PSK, BGP MD5, OSPF md5-key, NTP auth-key; automatic type-7 Vigenere decode
- `find_weak_config()` — 14 weakness checks: no password-encryption, type-7 in use, no AAA, default SNMP community strings, SNMP RW, telnet on VTY, SSH v1, HTTP server, exec-timeout 0 0, config-register 0x2142 (ROMMON bypass), no SIEM, NTP unauthenticated, enable password without secret, priv-15 + type-7
- `map_network_topology()` — interfaces + IPs, VRFs, VLANs, BGP peers, OSPF areas, EIGRP, ACLs, management servers
- CLI: `python3 cisco_config_re.py <config_file>` or `-` for stdin

**`cisco_rommon_re.py`** — ROMMON bypass and Secure Boot RE
- `ROMMONBypassRE` — full config-register bit decode (boot field, NVRAM-skip bit 6, break-disable bit 8, diagnostic bit 13); platform-specific bypass step generator (IOS/IOS-XE, IOS-XR, ASA, NX-OS)
- `SecureBootRE` — PCR register extraction (SHA256), boot loader hash, OS image hash, TAm GUID extraction
- CLI: `python3 cisco_rommon_re.py <config_file|0xCONFREG>`

### Network / live target RE

**`cisco_webvpn_js_re.py`** — WebVPN portal JavaScript and SAML RE
- `WebVPNJSRE` — downloads `win.js`, logon HTML, portal HTML; extracts a0 state machine codes, tunnel groups, URL endpoints, OS detection matrix, CSRF cookie logic, hardcoded values and internal IPs
- `WebVPNSAMLRE` — SP metadata probe, ACS payload testing (empty/malformed/XML/XML-wrapping skeleton), per-group SAML routing map
- CLI: `python3 cisco_webvpn_js_re.py <host> [port]`

**`asa_enum.py`** — 59 functions including 8 standalone probes:
`probe_asa_mpf_policy_exposure`, `probe_asa_botnet_url_filter_exposure`, `probe_asa_asdm_jar_exposure`, `probe_cisco_java_deserialization_surface`, `probe_asa_anyconnect_profile_download`, `probe_asa_mobile_vpn_surface`, `probe_asa_ios_client_redirect_surface`, `probe_asa_webvpn_session_exposure`

**`ios_enum.py`** — 46 functions including 6 standalone probes:
`probe_ios_arm_debug_interface_exposure`, `probe_ios_rommon_variable_exposure`, `probe_ios_crash_artifact_exposure`, `probe_ios_exception_level_disclosure`, `probe_ios_cef_fib_exposure`, `probe_ios_bgp_rib_tree_exposure`

**`nxos_enum.py`** — 66 functions including 8 standalone probes:
`probe_nxos_bgp_evpn_control_plane`, `probe_nxos_vxlan_multisite_exposure`, `probe_nxos_vdc_isolation_exposure`, `probe_nxos_fcoe_vsan_exposure`, `probe_nxos_management_proxy_exposure`, `probe_nxos_nexus_dashboard_exposure`, `probe_nxos_mac_arp_table_exposure`, `probe_nxos_ecmp_hash_exposure`

**`ise_enum.py`** — 33 functions including 8 standalone probes:
`probe_ise_jmx_monitoring_exposure`, `probe_ise_heap_dump_exposure`, `probe_ise_legacy_api_endpoint_exposure`, `probe_ise_spring_framework_exposure`, `probe_ise_nginx_auth_bypass`, `probe_ise_nginx_upstream_config`, `probe_ise_concurrent_auth_race_surface`, `probe_ise_typed_error_fingerprint`

**`cisco_api_enum.py`** — 37 functions including 8 standalone probes:
`probe_aci_microsegmentation_exposure`, `probe_aci_tenant_network_topology`, `probe_cisco_nginx_proxy_exposure`, `probe_cisco_api_gateway_bypass`, `probe_cisco_crosswork_telemetry_exposure`, `probe_cisco_tetration_analytics_exposure`, `probe_cisco_catalyst_center_mobile_api`, `probe_cisco_umbrella_api_exposure`

---

## Other modules

### Infrastructure enumeration
`docker_enum.py`, `k8s_enum.py`, `orka_enum.py`, `podman_enum.py`, `harbor_enum.py`, `vergeio_enum.py`, `hyperflex_enum.py`, `nexus_dashboard_enum.py`, `streaming_enum.py`, `nginx_enum.py`, `lateral_movement.py`, `net_sniffer.py`

### Platform / OS
`process_enum.py`, `privesc_enum.py`, `network_analyze.py`, `macos_malware_re.py`, `macos_sysadmin.py`, `syscall_trace.py`, `windows_kernel_re.py`, `sip_enum.py`, `llm_enum.py`

### Crypto / auth
`jwt_crypto_analyzer.py`, `crypto_audit.py`, `tls_enum.py`

### Core RE engine
`binary_parser.py`, `disasm_engine.py`, `platform_detect.py`, `arm64_analyzer.py`, `elf_parser.py`, `pe_parser.py`, `macho_analyzer.py`, `firmware_analyzer.py`, `swift_re.py`, `java_re.py`, `java_decompiler.py`, `swift_demangle.py`, `ebpf_analyzer.py`, `shellcode_utils.py`, `tcg_lifter.py`, `yara_generator.py`, `attck_tagger.py`

---

## Requirements

Python 3.8+. No third-party packages. All modules use stdlib only: `ssl`, `socket`, `struct`, `urllib.request`, `json`, `os`, `re`, `base64`, `zipfile`, `hashlib`, `subprocess`.

Optional system tools used when present: `debugfs` (NX-OS rootfs extraction), `openssl` (TLS fingerprinting).
