# Core Module Reference

Binary analysis, Java, Windows kernel, containers, network, crypto, post-compromise, and Go RE.

---

## Binary Analysis Core

### `core/binary_parser` — Format detection

ELF32/64, Mach-O 32/64 / fat, PE32/PE32+, and raw firmware blobs from magic bytes. Dispatches to the appropriate analyzer.

### `core/elf_parser` — ELF analysis

Header, program headers, section headers, `.symtab` / `.dynsym`, dynamic section (RPATH, RUNPATH, needed libs), REL/RELA relocations, GNU notes. Stripped binary recovery: prologue detection (ENDBR64, PUSH RBP + MOV RBP RSP) → approximate symbol map from cross-references.

### `core/pe_parser` / `core/pe_analyzer` — PE analysis

NT headers, section table, import/export directories, TLS callbacks, load config (CFG, ASLR, DEP flags), PDB path. Security feature flags: ASLR, DEP/NX, SafeSEH, CFG, Authenticode. Section entropy for packed/encrypted regions.

### `core/firmware_analyzer` — Firmware image analysis

Magic detection: SquashFS, CramFS, ext2/3/4, JFFS2, YAFFS, UBI. Per-block entropy to distinguish compressed vs encrypted vs plaintext regions. Extracts root filesystem to temp directory for downstream analysis.

### `core/disasm_engine` — Multi-architecture disassembler

Capstone wrapper. Architectures: x86 (16/32/64), ARM/Thumb/ARM64, MIPS 32/64, PowerPC. Function boundary detection, call graph, basic block decomposition, cross-reference building. Annotation layer maps Cisco ASA struct offsets to field names inline.

### `core/yara_generator` — YARA rule generation

String constants, byte sequences around prologues, import combinations, section layout signatures → ready-to-use YARA rules for firmware or malware hunting.

### `core/attck_tagger` — MITRE ATT&CK tagging

Structured findings → ATT&CK technique list with tactic, technique ID, name, and triggering finding.

### `core/shellcode_utils` — Shellcode analysis and templates

x86-64 / ARM64 shellcode templates. Entropy, null-byte density, common sequence detection (GetProcAddress, syscall stubs, XOR decode loops), NOP sled identification. XOR/ADD encoders for bad-byte avoidance.

### `core/tls_analyzer` — TLS analysis

Certificate chain parsing, CT anomaly detection (I/N >= 0.30 = honeypot signal), cipher enumeration, protocol version detection. Flags: self-signed, expired, RSA < 2048, RC4/DES/3DES/export-grade/null ciphers, TLS 1.0/1.1.

### `core/platform_detect` — Platform fingerprinting

OS, architecture, kernel version, container runtime. Bare metal vs VM vs Docker vs K8s Pod vs Orka VM. Used at startup to select the applicable module set.

---

## Java

### `java_re` — Java class file RE

Full constant pool parse (all JVM tag types):

- `ObjectInputStream.readObject()` call sites — deserialization surface
- `Runtime.exec()` / `ProcessBuilder` — command injection chains
- `Class.forName` / `Method.invoke` — reflection abuse
- JDBC URLs and connection strings from string constants
- Framework fingerprinting: Spring, Jackson, Gson, Hibernate

### `java_decompiler` — Decompilation wrapper

Uses Procyon, CFR, or Fernflower (whichever is in PATH). Falls back to `javap -c` bytecode output.

---

## Windows Kernel

### `windows_kernel_re` — Kernel driver RE

- **IOCTL dispatch** — `DriverEntry` → `IRP_MJ_DEVICE_CONTROL` handler → full `CTL_CODE` decomposition (device type, access, function, transfer type) → per-IOCTL handler map
- **DKOM** — `PsGetCurrentProcess` / `PsLookupProcessByProcessId` call sites followed by `EPROCESS` field access; process token stealing detection
- **SSDT hooks** — entries pointing outside `ntoskrnl.exe` / `win32k.sys`; shadow SSDT enumeration
- **DSE bypass** — `g_CiEnabled` / `g_CiOptions` patch patterns, `SeLoadDriverPrivilege` abuse, test-signing mode indicators

### `forensics_enum` — Forensic artifact analysis

SEH chain corruption (FS:[0] pattern), POPAD+JMP shellcode sequences. Windows artifact map: event logs, prefetch, MRU, shellbags, jump lists, browser history. Maps attacker dwell time indicators.

---

## Containers and Kubernetes

### `vmnetd_re` — Docker vmnetd socket protocol RE

RE module for `com.docker.vmnetd`, the macOS privileged helper that runs as root.

- Handler dispatch table — `handlePing`, `handleBindIpv4`, `handleInstallSymlinks`, `handleUninstall`, `handleDiagnose` and surrounding byte context
- VMN3T handshake magic — all occurrences in binary, surrounding frame structure
- Path strings — extracts all `/usr/local/`, `/usr/bin/`, `/var/run/`, `/etc/`, `/Library/` paths
- Live socket probe — structured binary probes against `/var/run/com.docker.vmnetd.sock`

Goal: craft `SymlinkMessage` as root via the privileged socket.

```bash
VMNETD_BINARY=/path/to/com.docker.vmnetd python3 modules/vmnetd_re.py
```

### `docker_enum` — Docker escape surface

- `/var/run/docker.sock` writable → root via `docker run --privileged`
- Capabilities: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`
- Namespace isolation: PID, mount, network, user
- Daemon API on TCP 2375/2376 without TLS client auth

### `k8s_enum` — Kubernetes enumeration

SA token from `/var/run/secrets/kubernetes.io/serviceaccount/`. Direct API server enumeration — no `kubectl` needed. RBAC self-check via `SelfSubjectAccessReview`.

- Secret extraction with base64 decode
- Privesc paths: `pods/exec` → RCE; `secrets/get` on `kube-system` → cred harvest; `create pods` → privileged pod → host escape
- etcd direct access (2379): key-space enumeration, secret extraction bypassing RBAC
- Kubelet API (10250): pod list, exec on unprotected Kubelets

### `harbor_enum` — Harbor OCI registry + supply chain

Default creds: `admin:Harbor12345`. Project/repo enumeration, image manifest pull, layer extraction, BV41 metadata decode. Trivy vulnerability scan results. Robot account enumeration. Supply chain map: images with external `FROM` references.

### `privesc_enum` — Privilege escalation

SUID/SGID vs known-safe set, world-writable paths, cron job injection, sudo NOPASSWD rules, Linux capabilities on binaries/processes, Docker group membership, `/etc/passwd` writability, readable shadow files. Cross-platform: macOS + Linux.

---

## Network and Protocol

### `tls_enum` — TLS service enumeration

Supported cipher suites, protocol versions (TLS 1.0/1.1 detection), certificate chain, OCSP stapling, session resumption (ID + ticket), HSTS/HPKP, JA3 server fingerprint.

### `net_sniffer` — Raw packet capture + credential extraction

Protocol parsers: HTTP basic auth, FTP, Telnet, SMTP AUTH, POP3, IMAP, SNMP community strings, SIP Digest, clear-text LDAP bind requests. Output is structured credential tuples.

### `network_analyze` — Network topology

Interface map, routing table, listening services, established connections. From pcap: ARP table, VLAN tags (802.1Q), routing protocol detection (OSPF/EIGRP/BGP hellos), DHCP and DNS server identification.

### `nginx_enum` — nginx configuration + CVE surface

Config parsing: server blocks, location blocks, `proxy_pass` targets, auth directives, include chains. Alias traversal: `location /path/ { alias /dir; }` without trailing slash → `GET /path../etc/passwd`. Version → CVE mapping (CVE-2017-7529). `proxy_pass` path-append SSRF amplification.

### `sip_enum` — SIP / VoIP

OPTIONS sweep for extension discovery, REGISTER scan, Digest auth capture, RTP stream identification. Maps voicemail extensions, conference bridges, SIP trunk credentials.

### `streaming_enum` — Kafka / Flink / NiFi

- **Kafka** — Metadata API broker enumeration (no auth if ACLs unenforced), topic list, partition/leader map, consumer group offsets, sensitive topic detection, produce access test
- **Flink** — REST API at `:8081`; job submission allows arbitrary JAR execution without auth by default
- **NiFi** — processor config reads (cleartext passwords in many processor types), template download with embedded credentials
- **Schema Registry** — unauthenticated subject and schema enumeration

### `llm_enum` — LLM inference server enumeration

Ollama, LM Studio, LocalAI, OpenAI-compatible. Checks: unauthenticated model listing, unfiltered generation, model file path exposure, system prompt leakage via `/api/show`.

### `qwen3_tts_re` — Qwen3-TTS / MLX-TTS WebAPI RE

Assessment module for `mlx-community/Qwen3-TTS` and compatible FastAPI/uvicorn TTS services (default port 2023).

- **M1 `module_health`** — `/health` endpoint: model IDs, instance UUID, process start time, MLX active memory — full system state without auth
- **M2 `module_unauth_synthesis`** — confirms unauthenticated compute access
- **M3 `module_path_enum`** — 30-path sweep: `/docs`, `/openapi.json`, `/models`, `/voices`, `/admin`, `/metrics`, `/config`, `/reload`, `/stream`, `/ws`
- **M4 `module_ssml_injection`** — SSML basic, `<audio src>` SSRF (IMDS + loopback), prosody injection, XXE, path traversal, null bytes, 10k-char resource exhaustion
- **M5 `module_param_discovery`** — probes 30+ undocumented parameters via error reflection
- **M6 `module_race_condition`** — 5 concurrent synthesis threads; surfaces missing rate limiting
- **M7 `module_file_enum`** — predictable-filename IDOR sweep for generated audio files

```bash
QWEN3_TTS_TARGET=http://<host>:2023 python3 modules/qwen3_tts_re.py
```

---

## Cryptography and Authentication

### `jwt_crypto_analyzer` — JWT attack suite

- `alg: none` bypass
- RS256 → HS256 confusion (re-sign with public key as HMAC secret)
- Weak HMAC key brute-force
- `kid` injection: SQL injection (DB key lookup), SSRF (URL-valued kid), directory traversal

```python
from modules.jwt_crypto_analyzer import JWTAttackSuite
JWTAttackSuite(target_url='https://target/api/').run_all(token='eyJhbGc...')
```

### `crypto_audit` — Binary cryptographic audit

Hardcoded key material (high-entropy bytes near crypto call sites), weak RNG (`rand()` / `random()` in security-sensitive paths), ECB mode indicators, MD5/SHA1 imports, custom crypto re-implementations.

---

## Post-Compromise

### `process_enum` — Process and memory analysis

All processes (PID, PPID, name, cmdline) — `/proc` on Linux, `ps` on macOS. Per-PID: `/proc/PID/maps`, `/proc/PID/fd` (open DB connections, sockets), `/proc/PID/environ`.

### `lateral_movement` — Lateral movement surface

TCP scan (stdlib socket, no nmap). Cloud metadata: `169.254.169.254` (AWS/GCP/Azure IMDS), ECS task metadata. Credential harvest: `~/.aws/credentials`, `~/.kube/config`, `~/.ssh/id_*`, `~/.docker/config.json`, `.env` files.

### `syscall_trace` — System call tracing

Wraps `strace` (Linux) / `dtruss` / `dtrace` (macOS). Structured output: `open`/`openat`, `connect`, `execve`, `write` to network FDs. Flags credential access patterns and exfiltration paths.

---

## Regression

### `regression` — Struct offset version registry

Version-confirmed struct offsets for Cisco ASA LINA, indexed by version tuple. `FirmwareVersionRegression` fits a boundary model. Includes `OLS`, `LogisticRegression`, `DescriptiveStats`, `CorrelationMatrix`.

```python
from modules.regression import SymbolicOffsetRegression

offset = SymbolicOffsetRegression.gp_name_offset((9, 20, 3, 0))
# -> 0x2b0

for ver, entry in SymbolicOffsetRegression.CONFIRMED.items():
    print(ver, hex(entry['gp_name_offset']), entry['source'])
```

---

## Go Binary RE

### `go_garble_re` — garble-obfuscated Go ELF static analysis

Handles Go binaries compiled with `mvdan/garble` — the standard Go RE toolchain (GoReSym, `strings`, pclntab parsers) fails completely because garble encrypts all string constants, scrambles the pclntab, and renames every symbol.

```bash
python3 modules/go_garble_re.py /path/to/binary
```

- **Correct VA→file-offset mapping** — parses ELF LOAD program headers directly; stock ablation modes treat VA as file offset (wrong for any non-PIE Go binary with a high base like `0x400000`)
- **pclntab detection + garble diagnosis** — locates function table by magic bytes (Go 1.12/1.16/1.18/1.20+); reports whether garble has scrambled the header
- **Bootstrap chain tracer** — follows Go runtime call chain from entry point (`_rt0_amd64_linux` → `_rt0_amd64` → `runtime.rt0_go`) using correct VA-aware addressing
- **String anchor xref scanner** — given a known string's file offset, converts to VA and scans all executable segments for RIP-relative LEA instructions that load that exact address
- **Garble decrypt stub finder** — scans all CALLs to find the most frequently called short functions with XOR instructions — these are the per-string decrypt stubs

```python
from modules.go_garble_re import analyze_go_garble_binary

result = analyze_go_garble_binary('/path/to/binary')
print(result['pclntab'])       # garble diagnosis
print(result['bootstrap'])     # entry → rt0 call chain
print(result['decrypt_stubs']) # top XOR-stub candidates by call frequency
```

**When to use:** any Go binary where GoReSym returns `"failed to locate pclntab"` — that's the garble signature.

---

## Utilities

### `utils/poc_radius_ou_inject.py` — RADIUS Group Policy Injection PoC

Standalone PoC for F1 (no Message-Authenticator enforcement) + F2 (256-byte OU= vs 64-byte CLI limit). Two modes: fake RADIUS server (every Access-Request gets an attacker-controlled OU= response), and single-packet send.
