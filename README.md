
<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="ablation">
</p>

<p align="center">
  Reverse engineering tool.
</p>

---

## Platforms

| Platform | Coverage |
|----------|----------|
| Linux (ELF — x86-64, ARM64, MIPS) | Binary RE, live process, privesc, containers, garble-obfuscated Go |
| macOS / Apple Silicon | Mach-O, Swift ABI, Orka cluster RE, malware persistence, Keychain, MDM |
| Windows (PE / PE32+) | Kernel driver RE, IOCTL dispatch, DKOM, SSDT, DSE bypass |
| Docker / Kubernetes | Escape surface, socket mounts, capability audit, SA token, etcd |
| Orka | K8s API, JWT forge (CVE-2020-26160 + empty-key), VM exec, gRPC |
| Cisco ASA | LINA struct RE, RADIUS class-attr overflow, ASDM JAR, WebVPN JS, ROMMON |
| Cisco FTD / FDM | 43 modules: JWT forgery, Neo4j key, TAR slip RCE, ZMQ NULL auth, hardcoded AES key |
| Cisco ISE | RADIUS OU injection, LDAP chain, credential audit — 46 findings (CRIT:11) |
| Cisco CUCM | Static AES key, OAuth JWT forgery, ITL signing key, HAProxy 666 — 482 findings |
| Cisco FMC | 44 findings: PAM code injection (root at login), backup/health module/report RCE chain, PERL5LIB root escalation, hardcoded DB creds, Vault root token plaintext on disk |
| Cisco AnyConnect | NetworkExtension IKEv2 RE, acsockext TOCTOU |
| Cisco IOS / IOS-XE | Firmware RE, crashdump analysis, hardcoded credential scan |
| Cisco NX-OS / ACI | APIC REST, guestshell rootfs, Nexus Dashboard, Kafka/TF cred exfil |
| WeChat Android | MMTLS protocol RE, PSK extraction, DB key derivation, ptrace key extraction |

## Quick start

```bash
# API RE (30 phases)
python3 modules/api_re.py http://target:8080
python3 modules/api_re.py http://target:8080 --depth deep --output out.json

# Binary / firmware
./ablation --binary /path/to/target
./ablation --lina /path/to/lina --asa-version 9.22.2.32

# Live targets
./ablation --asa 192.168.1.1
./ablation --orka https://orka-api:443
./ablation --docker && ./ablation --k8s

# CUCM static findings (482)
python3 -c "from modules.cisco_cucm_re import full_findings_summary; print(full_findings_summary())"

# FTD fleet-wide AES-256 key (F-FTD-110, all deployments)
python3 -c "from modules.ftd_hardcoded_aes_key import AES256_KEY; print(AES256_KEY.hex())"

# Go binary obfuscated with garble
python3 modules/go_garble_re.py /path/to/binary
```

## Modules

| Module | Platform | Summary |
|--------|----------|---------|
| `swift_re` | macOS | Swift ABI, gRPC service map, async/await, LicenseSpring |
| `macos_malware_re` | macOS | Persistence, TCC, EvilQuest IOCs, dylib hijack, Keychain |
| `macos_sysadmin` | macOS | Keychain, FileVault, MDM/DEP, ARD/VNC, Open Directory |
| `orka_enum` | Orka | Live cluster enum, image registry, default creds |
| `orka_oidc_re` | Orka | OIDC PKCE flow RE, CVE-2020-26160 |
| `orka_jwt_dynamic_re` | Orka | HS256 empty-key JWT forge |
| `orka_api_surface_re` | Orka | REST API reconstruction from Go binary (60+ routes) |
| `orka_vm_exec_re` | Orka | VM exec via K8s pods/exec API, SA token forge |
| `cisco_asa_lina_re` | Cisco ASA | LINA struct RE (gp_obj layout), version-dispatched RADIUS overflow probe |
| `cisco_radius_ise_re` | Cisco ASA/ISE | RADIUS Class attr injection, OU= overflow, ISE CoA |
| `cisco_cstp_attack` | Cisco ASA | DAP bypass, SAML, timing oracle, RADIUS CoA mid-session |
| `cisco_webvpn_js_re` | Cisco ASA | WebVPN JS bundle RE, tunnel group enum, CSRF pattern |
| `cisco_asdm_download_re` | Cisco ASA | ASDM JAR retrieval chain |
| `cisco_asdm_jar_re` | Cisco ASA | JVM constant pool RE, trust manager bypass, deserialization |
| `cisco_rommon_re` | Cisco ASA | ROMMON bypass, config-register, image auth bypass |
| `cisco_config_re` | Cisco ASA | Type 7 decode, SNMP/TACACS+/BGP credential extraction |
| `cisco_ios_re` | Cisco IOS | Firmware format, IFS extraction, crash dump ARM64 recovery |
| `cisco_api_enum` | Cisco ASA | REST API endpoint enum, unauthenticated surface |
| `cisco_asa_cred_audit` | Cisco ASA | Credential testing, lockout behavior, auth stack map |
| `anyconnect_re` | Cisco AnyConnect | NE IKEv2 address tables, auth bypass target, acsockext TOCTOU |
| `ftd_*` (43 modules) | Cisco FTD/FDM | JWT forgery chain, Neo4j key, TAR slip, cli_shadow root, static AES key, zip-slip, ZMQ NULL — see [docs/cisco.md](docs/cisco.md) |
| `cisco_ise_re` | Cisco ISE | 46 findings: RADIUS overflow, hardcoded creds, LDAP chain, unauth REST |
| `cisco_cucm_re` | Cisco CUCM | 482 findings: static AES, JWT forge, ITL key, HAProxy 666, TAPS RCE |
| `cisco_fmc_re` | Cisco FMC | 44 findings: PAM $PAM_USER Perl injection (root), backup name shell injection, health module XML injection, report name injection, PERL5LIB root escalation via SETENV sudoers, hardcoded DB/SMTP/RabbitMQ creds, Vault root token plaintext + hardcoded JKS password |
| `cisco_re_engine` | Cisco | FLOSS, capa, r2, BinDiff, Frida, ropper, keystone, Scapy |
| `nxos_enum` | Cisco NX-OS | APIC unauth surface, MIT queries, vCenter lateral |
| `nexus_dashboard_enum` | Cisco NX-OS | SSO pivot, Kafka export, Terraform/ServiceNow creds |
| `cisco_nxos_guestshell_re` | Cisco NX-OS | CentOS LXC rootfs, credential scan, SUID, cron |
| `ios_enum` | Cisco IOS-XE | SSH + NETCONF, BGP/ACL/AAA enum, type 7/5/8/9 decode |
| `hyperflex_enum` | Cisco HyperFlex | REST API, SCVM, default creds, Intersight claim-code |
| `wechat_re` | WeChat Android | MMTLS two-tier crypto, gILinkKey ptrace extraction, DB key |
| `go_garble_re` | Go (garble) | pclntab detection, bootstrap trace, XOR stub finder, string xref |
| `windows_kernel_re` | Windows | IOCTL map, DKOM, SSDT hooks, DSE bypass |
| `forensics_enum` | Windows | SEH corruption, prefetch, shellbag, browser history |
| `java_re` | Java | JVM constant pool, ObjectInputStream, JDBC, reflection abuse |
| `java_decompiler` | Java | Procyon/CFR/Fernflower wrapper |
| `vmnetd_re` | Docker macOS | vmnetd protocol RE, privileged socket, SymlinkMessage |
| `docker_enum` | Docker | Socket escape, CAP_SYS_ADMIN, bind mounts, TCP daemon |
| `k8s_enum` | Kubernetes | SA token, RBAC self-check, etcd bypass, Kubelet unauth |
| `harbor_enum` | Harbor | Default creds, image manifest, BV41, supply chain map |
| `privesc_enum` | Linux/macOS | SUID/SGID, sudo NOPASSWD, capabilities, cron injection |
| `tls_enum` | Network | Cipher suite, JA3, HSTS, session resumption |
| `net_sniffer` | Network | HTTP/FTP/Telnet/SMTP/SNMP/SIP/LDAP credential capture |
| `nginx_enum` | Network | Alias traversal, proxy SSRF, CVE map |
| `sip_enum` | Network | OPTIONS sweep, REGISTER, Digest auth, RTP stream |
| `streaming_enum` | Kafka/Flink/NiFi | Unauth broker enum, JAR execution, schema registry |
| `llm_enum` | LLM servers | Ollama/LM Studio model list, system prompt leak |
| `qwen3_tts_re` | TTS (Qwen3) | Unauth synthesis, SSML injection, IDOR, race condition |
| `network_analyze` | Network | Interface map, routing, VLAN, DHCP, OSPF/EIGRP/BGP |
| `api_re` | API | 30-phase RE: schema harvest, BOLA/BFLA, JWT alg confusion, NoSQL inject, CORS, PII scan, OAuth dynamic reg, WebSocket, shadow versions, timing oracle |
| `jwt_crypto_analyzer` | Auth | alg:none, RS256→HS256 confusion, kid SQLi/SSRF/traversal |
| `crypto_audit` | Binary | Hardcoded key material, weak RNG, ECB mode, custom crypto |
| `process_enum` | Linux/macOS | /proc maps, open FDs, environ |
| `lateral_movement` | Cloud | IMDS (AWS/GCP/Azure), ~/.aws, kubeconfig, SSH keys |
| `syscall_trace` | Linux/macOS | strace/dtruss wrapper, structured credential access output |
| `regression` | Cisco ASA | Version-confirmed LINA struct offsets, boundary model |
| `core/*` | All | ELF/Mach-O/PE/firmware parsers, x86/ARM64/MIPS/PPC disasm, ATT&CK tagger |

## Requirements

```
Python 3.8+
capstone        # pip install capstone
```

`cisco_re_engine` optional:
```
flare-floss  flare-capa  ropper  keystone-engine  rzpipe  frida  scapy
r2 (radare2)  bindiff (BinDiff v8)
```

## Documentation

- [docs/cisco.md](docs/cisco.md) — ASA, FTD/FDM, ISE, CUCM, AnyConnect, IOS, NX-OS
- [docs/apple.md](docs/apple.md) — Swift RE, Orka, malware persistence, sysadmin
- [docs/wechat.md](docs/wechat.md) — MMTLS protocol, DB key derivation, ptrace extraction
- [docs/core.md](docs/core.md) — binary analysis, Java, Windows kernel, containers, network, crypto

---

For authorized security testing only.
