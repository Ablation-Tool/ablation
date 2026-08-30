<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="ablation">
</p>

<p align="center">
</p>

---

Tracks functions across binary versions using behavior, not location — no symbols, no source, no CVE number required.

Every other approach breaks when the address moves or the code changes slightly. Signature scanners need exact byte matches. IDA and Ghidra need a human to manually correlate functions across versions. BinDiff works on full binary pairs but has no semantic understanding — it matches structure, not meaning. None of them tell you *when* a function was patched.

Ablation matches on three signals simultaneously — structure, instruction overlap, and what the function actually does — and uses the result to produce a **forensic patch attribution timeline from firmware alone**.

---

## How it works

```
Binary  →  Prologue scan  →  FuncFeatures[]
                                    │
                          ┌─────────▼──────────┐
                          │  1. Block filter    │  ±2 basic blocks       (coarse)
                          │  2. 4-gram Jaccard  │  mnemonic n-grams      (precise)
                          │  3. MPNet embedding │  semantic meaning       (cross-arch)
                          └─────────┬──────────┘
                                    │
                              HomologMatch
                            (va, jaccard, semantic_score, confidence, delta)
```

**Stage 1** prunes the search space. **Stage 2** is the load-bearing signal: mnemonic 4-gram Jaccard is build-invariant — the same function compiled with different optimization flags, address layouts, or minor code tweaks produces nearly the same Jaccard. **Stage 3** bridges ISA boundaries where Jaccard fails (x86-64 seed vs. ARM64 target).

---

## The novel part: Jaccard as a patch epoch classifier

Jaccard isn't used as binary match/no-match. It's a continuous implementation era signal:

| Jaccard | Interpretation |
|---------|---------------|
| ~0.97 | Bytecode nearly identical — same implementation era, almost certainly unpatched |
| ~0.21 | Structural rewrite — function was significantly changed, patched |
| ~0.11–0.19 | Different implementation era — pre-dates the current codeline |

No existing tool does this. BinDiff and Diaphora give you "X% similar." Ablation gives you "this function has been in the same implementation era since version 9.8, changed once at 9.15, and every version after that is a structural rewrite of the original" — derived entirely from firmware, with no CVE, no advisory, no source code.

**Example — Cisco ASA `attr_list_add_impl` sweep across 33 firmware versions:**

```
Era 1  (jac ~0.11–0.19)   ASA 9.1.7 → 9.6.4        old implementation
Era 2  (jac ~0.96–0.97)   ASA 9.8.x → 9.14.4.24    UNPATCHED  (~3.5 years, no CVE)
──────────────────── patch boundary: ASA 9.15.x ─────────────────────────────────
Era 3  (jac ~0.21)        ASA 9.15.x → 9.22+        PATCHED
Era 4  (jac ~0.19)        ASA 10.1.x                 separate codeline, patched
```

The boundary was identified by sweeping FTD 6.6.0 (ASA 9.14 base, Era 2) vs. FTD 6.7.0 (ASA 9.15 base, Era 3) — no source code, no debug symbols, no prior knowledge of the patch. Cross-architecture coverage extends the same timeline to ARM64 (FTD 10.0.0, FTD 1200) and i386 (ASA 9.1.x, 9.2.x) via the semantic layer.

This runs in under two minutes on a 94MB stripped binary.

---

## Architecture

```
modules/
├── func_id_db.py        SQLite function identity store (WAL, FK-indexed, schema v2)
├── llm_analyst/         Claude ReAct loop — active RE participant
│   ├── agent_loop.py    tool-calling loop, budget governor, loop detection
│   ├── tool_registry.py get_disassembly / get_cfg / get_xrefs / get_strings / query_func_db
│   ├── context_builder.py hierarchical prompt: prior findings → callees → strings → CFG → asm
│   ├── rag_retriever.py  SQL-backed prior-findings recall (VA match → callee overlap → role)
│   └── tasks/           function_namer / vuln_hypothesis / struct_reconstructor
├── semantic_search.py   BERT function similarity (MiniLM-L6-v2, 384-dim)
├── version_delta.py     cross-version homolog matching + patch localization
└── bare_adapter.py      ablation findings → BARE binary → ranked Metasploit modules
```

### llm_analyst

Claude runs as an active RE participant via a tool-calling ReAct loop. Given an unknown function VA, it issues disassembly, CFG, xref, and string queries against the binary, then calls `query_func_db` to pull prior findings, and terminates with a structured `done()` result: function name, role, confidence, vuln notes.

- 7 tools: `get_disassembly`, `get_cfg`, `get_xrefs`, `get_strings`, `get_imports`, `query_func_db`, `done`
- Role taxonomy: `RADIUS_ATTR_HANDLER`, `RADIUS_DISPATCH`, `CRYPTO_HPKE`, `CRYPTO_STRAP`, `SAML_HANDLER`, `CSTP_HANDLER`, `DTLS_HANDLER`, and 12 others
- Budget governor: hard stop at `max_tool_calls` (default 10), partial result on budget exhaust
- Results with `confidence ≥ 0.5` persist to `func_id_db` as `ANGR_INFERRED`

### semantic_search

BERT-based function similarity seeded from `func_id_db` CONFIRMED/ANGR_INFERRED functions.

- Opcode categorization follows BinFuse (TrustCom 2025): 11 semantic categories (`DATA_TRANSFER_OP`, `ARITHMETIC_OP`, `COMPARISON_OP`, ...) — cross-architecture invariant, x86 `mov` and ARM64 `ldr` collapse to `DATA_TRANSFER_OP`
- Markov transition text: top-5 adjacent-category transitions (`COMPARISON_OP->CONDITIONAL_OP(2)`) encode behavioral structure invariant to optimization level
- Corpus cached as numpy array keyed on db hash; repeated queries cost one dot-product (~1ms)

### version_delta

Tracks a seed function across binary versions via a three-stage pipeline.

```
Stage 1  Structural pre-filter     basic block count ±2, edge ratio ±35%
Stage 2  Mnemonic 4-gram Jaccard   build-invariant sequence similarity, top-10 candidates
Stage 3  Semantic tiebreaker       SemanticSearcher when top-2 within 0.05 Jaccard
```

Patch localization via `difflib.SequenceMatcher` on normalized instruction lines surfaces the exact changed instructions. Primary use case: track the RADIUS Class attribute overflow patch (CVE-2022-0778) across 17 lina versions.

### func_id_db

SQLite store for function identity across binary versions. Schema v2 (WAL, FK-indexed, 1NF).

- Tables: `binaries`, `functions`, `struct_fields`, `call_chains`, `call_chain_steps`
- Seeded: 23 CONFIRMED lina functions (RADIUS/AAA, HPKE, STRAP, SAML), 7 AnyConnect functions, 52 lina offsets, 1 call chain (6 steps)
- Matching: byte-pattern signature, callee-set overlap, struct field offset, string xrefs

### bare_adapter

Converts `llm_analyst.AnalysisResult` vuln findings to BARE `findings.json` and ranks against 3,904 Metasploit modules via the BARE binary (offline, air-gap safe, no Python at inference).

- AI/ML-specific findings (HPKE, STRAP, custom RADIUS) trigger `no_high_confidence_match` — expected, no MSF coverage exists for these
- Classic overflow/memcpy primitives surface usable MSF modules

---

## Target coverage

| Platform | Coverage |
|----------|---------|
| Cisco ASA (lina) | struct RE (gp_obj layout), RADIUS class-attr overflow, ASDM JAR, WebVPN JS, ROMMON, 17+ versions tracked |
| Cisco FTD / FDM | 43 modules: JWT forgery, Neo4j key, TAR slip RCE, ZMQ NULL auth, hardcoded AES-256 key, zip-slip |
| Cisco ISE | RADIUS OU injection, LDAP chain, credential audit — 46 findings (CRIT:11) |
| Cisco CUCM | Static AES key, OAuth JWT forgery, ITL signing key, HAProxy 666 — 482 findings |
| Cisco FMC | 44 findings: PAM code injection (root), backup/health module/report RCE chain, PERL5LIB root escalation, hardcoded DB creds, Vault root token |
| Cisco AnyConnect | HPKE/STRAP/IPC RE, acsockext TOCTOU, DTLS handler, SAML forging |
| Cisco IOS / IOS-XE | Firmware RE, crashdump, hardcoded credential scan |
| Cisco NX-OS / ACI | APIC REST, guestshell rootfs, Nexus Dashboard, Kafka/TF cred exfil |
| Orka | K8s API, JWT forge (CVE-2020-26160 + empty-key), VM exec, gRPC |
| WeChat Android | MMTLS two-tier crypto, PSK extraction, DB key derivation, ptrace key extraction |
| macOS / Apple Silicon | Mach-O, Swift ABI, Orka cluster RE, malware persistence, Keychain, MDM |
| Windows (PE / PE32+) | Kernel driver RE, IOCTL dispatch, DKOM, SSDT, DSE bypass |
| Docker / Kubernetes | Escape surface, socket mounts, capability audit, SA token, etcd |
| Linux (ELF x86-64/ARM64/MIPS) | Binary RE, live process, privesc, containers, garble-obfuscated Go |

---

## Quick start

```bash
# Binary / firmware
./ablation --binary /path/to/target
./ablation --lina /path/to/lina --asa-version 9.22.2.32

# Live targets
./ablation --asa 192.168.1.1
./ablation --orka https://orka-api:443

# LLM-assisted function analysis (requires ANTHROPIC_API_KEY)
python3 -c "
from modules.llm_analyst import AgentLoop
from modules.llm_analyst.tasks.vuln_hypothesis import VulnHypothesisTask
loop = AgentLoop('/path/to/lina')
result = loop.run(0x4a1234, task=VulnHypothesisTask())
print(result.name, result.role, result.confidence)
print(result.vuln_notes)
"

# Semantic function search
python3 -c "
from modules.semantic_search import SemanticSearcher
s = SemanticSearcher('~/.ablation/func_id.db')
s.build_corpus()
for r in s.query_function('sub_unknown', 'RADIUS_ATTR_HANDLER', ['strcpy', 'radius_decode'], ['RADIUS-Class']):
    print(f'{r.score:.3f}  {r.name}  ({r.role})')
"

# Cross-version patch tracking
python3 -c "
from modules.version_delta import VersionTracker
tracker = VersionTracker({
    '9.14': '/path/to/lina-9.14',
    '9.16': '/path/to/lina-9.16',
    '9.18': '/path/to/lina-9.18',
})
for report in tracker.track(seed_binary='9.14', seed_va=0x4a1234):
    print(report.summary())
"

# Quick function diff (no angr required)
python3 -c "
from modules.version_delta import diff_functions, jaccard_similarity
delta = diff_functions(asm_914, 'func_v914', asm_916, 'func_v916', callees_914, callees_916)
print(delta.unified_diff('9.14', '9.16'))
"

# Rank Metasploit modules against vuln findings
python3 -c "
from modules.bare_adapter import rank_modules, format_bare_output
output = rank_modules(results, binary_path='/path/to/lina')
print(format_bare_output(output))
"

# API RE (30 phases)
python3 modules/api_re.py http://target:8080
python3 modules/api_re.py http://target:8080 --depth deep --output out.json

# Platform-specific
python3 -c "from modules.cisco_cucm_re import full_findings_summary; print(full_findings_summary())"
python3 -c "from modules.ftd_hardcoded_aes_key import AES256_KEY; print(AES256_KEY.hex())"
python3 modules/go_garble_re.py /path/to/binary
```

---

## Modules

### RE infrastructure

| Module | Summary |
|--------|---------|
| `func_id_db` | SQLite function identity store — byte-pattern + callee + struct + string matching across binary versions |
| `llm_analyst/` | Claude ReAct loop — active RE participant; names functions, hypothesizes vulns, reconstructs structs |
| `semantic_search` | BERT-based function similarity (MPNet, BinFuse opcode categories, Markov transitions) |
| `version_delta` | Cross-version homolog matching (structural → 4-gram Jaccard → semantic) + SequenceMatcher patch diff |
| `bare_adapter` | Ablation findings → BARE binary → ranked Metasploit modules (3,904 modules, offline) |
| `regression` | Version-confirmed LINA struct offsets, angr Veritesting boundary model |
| `cisco_re_engine` | FLOSS, capa, r2, BinDiff, Frida, ropper, keystone, Scapy |
| `crypto_audit` | Hardcoded key material, weak RNG, ECB mode, custom crypto detection |
| `vtable_resolver` | C++ vtable layout recovery, virtual dispatch mapping |
| `interproc_field_writer` | Inter-procedural struct field write tracking |

### Cisco ASA / lina

| Module | Summary |
|--------|---------|
| `cisco_asa_lina_re` | LINA struct RE (gp_obj layout), RADIUS class-attr overflow probe |
| `cisco_radius_ise_re` | RADIUS Class attr injection, OU= overflow, ISE CoA |
| `cisco_cstp_attack` | DAP bypass, SAML, timing oracle, RADIUS CoA mid-session |
| `cisco_webvpn_js_re` | WebVPN JS bundle RE, tunnel group enum, CSRF pattern |
| `cisco_asdm_download_re` | ASDM JAR retrieval chain |
| `cisco_asdm_jar_re` | JVM constant pool RE, trust manager bypass, deserialization |
| `cisco_rommon_re` | ROMMON bypass, config-register, image auth bypass |
| `cisco_config_re` | Type 7 decode, SNMP/TACACS+/BGP credential extraction |
| `cisco_api_enum` | REST API endpoint enum, unauthenticated surface |
| `cisco_asa_cred_audit` | Credential testing, lockout behavior, auth stack map |
| `anyconnect_re` | NE IKEv2 address tables, HPKE/STRAP RE, acsockext TOCTOU |

### Cisco FTD / FDM (43 modules)

| Module | Summary |
|--------|---------|
| `ftd_jwt_forge` | JWT forgery chain — RS256→HS256 confusion |
| `ftd_jwt_key_extraction` | JWT signing key extraction |
| `ftd_neo4j_password_decrypt` | Neo4j key recovery |
| `ftd_backup_tarslip` | TAR slip RCE via backup restore |
| `ftd_config_import_zipslip` | Zip-slip RCE via config import |
| `ftd_hardcoded_aes_key` | Fleet-wide AES-256 key (F-FTD-110) |
| `ftd_sfmb_static_creds` | ZMQ NULL auth + static creds |
| `ftd_clishadow_root` | cli_shadow root escalation |
| `ftd_www_root_escalation` | www root escalation |
| `ftd_snort3_plugin_injection` | Snort3 plugin injection |
| *32 more* | See [docs/cisco.md](docs/cisco.md) |

### Cisco ISE / CUCM / FMC / IOS / NX-OS

| Module | Summary |
|--------|---------|
| `cisco_ise_re` | 46 findings: RADIUS overflow, hardcoded creds, LDAP chain |
| `cisco_cucm_re` | 482 findings: static AES, JWT forge, ITL key, HAProxy 666 |
| `cisco_fmc_re` | 44 findings: PAM $PAM_USER injection (root), PERL5LIB escalation, Vault token plaintext |
| `cisco_ios_re` | Firmware format, IFS extraction, crash dump ARM64 recovery |
| `cisco_nxos_guestshell_re` | CentOS LXC rootfs, credential scan, SUID, cron |
| `nxos_enum` | APIC unauth surface, MIT queries, vCenter lateral |
| `nexus_dashboard_enum` | SSO pivot, Kafka export, Terraform/ServiceNow creds |
| `ios_enum` | SSH + NETCONF, BGP/ACL/AAA enum, type 7/5/8/9 decode |
| `hyperflex_enum` | REST API, SCVM, default creds, Intersight claim-code |

### Orka / Apple

| Module | Summary |
|--------|---------|
| `orka_enum` | Live cluster enum, image registry, default creds |
| `orka_oidc_re` | OIDC PKCE flow RE, CVE-2020-26160 |
| `orka_jwt_dynamic_re` | HS256 empty-key JWT forge |
| `orka_api_surface_re` | REST API reconstruction from Go binary (60+ routes) |
| `orka_vm_exec_re` | VM exec via K8s pods/exec API, SA token forge |
| `swift_re` | Swift ABI, gRPC service map, async/await, LicenseSpring |
| `macos_malware_re` | Persistence, TCC, EvilQuest IOCs, dylib hijack, Keychain |
| `macos_sysadmin` | Keychain, FileVault, MDM/DEP, ARD/VNC, Open Directory |
| `macos_decompiler` | Mach-O binary decompilation, symbol recovery |
| `macos_mach_o_re` | Mach-O segment/section RE, ObjC class layout |

### WeChat / Mobile

| Module | Summary |
|--------|---------|
| `wechat_re` | MMTLS two-tier crypto, gILinkKey ptrace extraction, DB key derivation |
| `arm64_global_tracker` | ARM64 global variable tracking across function calls |
| `arm_symbolic` | ARM symbolic execution, constraint extraction |
| `arm_disasm` | ARM32/AArch64 disassembly with role annotation |

### Network / API / Infrastructure

| Module | Summary |
|--------|---------|
| `api_re` | 30-phase API RE: schema harvest, BOLA/BFLA, JWT confusion, NoSQL inject, WebSocket, shadow versions |
| `jwt_crypto_analyzer` | alg:none, RS256→HS256 confusion, kid SQLi/SSRF/traversal |
| `tls_enum` | Cipher suite, JA3, HSTS, session resumption |
| `net_sniffer` | HTTP/FTP/Telnet/SMTP/SNMP/SIP/LDAP credential capture |
| `nginx_enum` | Alias traversal, proxy SSRF, CVE map |
| `sip_enum` | OPTIONS sweep, REGISTER, Digest auth, RTP stream |
| `streaming_enum` | Kafka/Flink/NiFi: unauth broker, JAR execution, schema registry |
| `network_analyze` | Interface map, routing, VLAN, DHCP, OSPF/EIGRP/BGP |
| `lateral_movement` | Cloud IMDS (AWS/GCP/Azure), ~/.aws, kubeconfig, SSH keys |

### Containers / Windows / Java

| Module | Summary |
|--------|---------|
| `docker_enum` | Socket escape, CAP_SYS_ADMIN, bind mounts, TCP daemon |
| `k8s_enum` | SA token, RBAC self-check, etcd bypass, Kubelet unauth |
| `harbor_enum` | Default creds, image manifest, BV41, supply chain map |
| `windows_kernel_re` | IOCTL map, DKOM, SSDT hooks, DSE bypass |
| `forensics_enum` | SEH corruption, prefetch, shellbag, browser history |
| `java_re` | JVM constant pool, ObjectInputStream, JDBC, reflection abuse |
| `java_decompiler` | Procyon/CFR/Fernflower wrapper |
| `go_garble_re` | pclntab detection, bootstrap trace, XOR stub finder, string xref |
| `privesc_enum` | SUID/SGID, sudo NOPASSWD, capabilities, cron injection |

---

## Requirements

**Core:**
```
Python 3.10+
capstone          pip install capstone
```

**llm_analyst / semantic_search / version_delta:**
```
angr              pip install angr
anthropic         pip install anthropic
sentence-transformers  pip install sentence-transformers
numpy             pip install numpy
```

**cisco_re_engine (optional):**
```
flare-floss  flare-capa  ropper  keystone-engine  rzpipe  frida  scapy
r2 (radare2)  bindiff (BinDiff v8)
```

**bare_adapter:**
```
BARE binary       github.com/sshpie/BARE  (install to ~/.local/bin/bare)
```

---

## Documentation

- [docs/cisco.md](docs/cisco.md) — ASA, FTD/FDM, ISE, CUCM, AnyConnect, IOS, NX-OS
- [docs/apple.md](docs/apple.md) — Swift RE, Orka, malware persistence, sysadmin
- [docs/wechat.md](docs/wechat.md) — MMTLS protocol, DB key derivation, ptrace extraction
- [docs/core.md](docs/core.md) — binary analysis, Java, Windows kernel, containers, network, crypto

---

For authorized security testing only.
