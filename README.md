<div align="center">

<h1>Ablation</h1>

<p><strong>Semantic function matching for stripped firmware. No symbols. No source. No setup.</strong></p>

<p>BERT-encoded behavioral fingerprints locate vulnerability homologs across architectures,<br>
compiler variants, and firmware generations in under two minutes per binary.</p>

<p>
<a href="#how-it-works">How It Works</a> &nbsp;|&nbsp;
<a href="#the-ablation-difference">What Makes It Different</a> &nbsp;|&nbsp;
<a href="#use-cases">Use Cases</a> &nbsp;|&nbsp;
<a href="#claude-code-integration">Claude Code</a> &nbsp;|&nbsp;
<a href="#quick-start">Quick Start</a> &nbsp;|&nbsp;
<a href="#architecture">Architecture</a> &nbsp;|&nbsp;
<a href="#target-coverage">Coverage</a>
</p>

</div>

---

## How It Works

<img src="assets/sauce.jpg" width="480" alt="ablation">

Ablation operates at **stage 2.5** — after disassembly, before CFG analysis. It encodes what each function does semantically (opcode category sequences + Markov transitions + call targets + strings) into a BERT vector, then answers two questions: **which functions match a given vulnerability pattern** and **when was this function patched**.

Opcode categorization follows BinFuse (TrustCom 2025): 11 semantic categories (`DATA_TRANSFER_OP`, `ARITHMETIC_OP`, `COMPARISON_OP`, ...) that are cross-architecture invariant — x86-64 `mov` and ARM64 `ldr` both normalize to `DATA_TRANSFER_OP`. Markov transition text encodes behavioral structure invariant to optimization level. The result: a function can be recompiled, renamed, and moved 28 MB in address space — the behavioral fingerprint stays stable.

**Validated:** Cisco ASA `lina` 9.14 to 9.22 — RADIUS parser moved 28 MB, renamed, recompiled. Homolog similarity: 0.82. Unrelated function (TLS handler): 0.14. Separation: 5.9x.

<table>
<tr>
<td width="33%" valign="top">
<strong>Semantic Sweep</strong><br><br>
Describe dangerous code in plain English. Ablation encodes every function in the binary and returns the closest behavioral matches — no symbols, no database, no prior knowledge of the binary required.
</td>
<td width="33%" valign="top">
<strong>Patch Epoch Tracking</strong><br><br>
Mnemonic 4-gram Jaccard is a continuous implementation era signal, not binary match/no-match. Jaccard ~0.97 means unpatched; ~0.21 means structural rewrite. Derives patch timeline from firmware alone, no CVE or source required.
</td>
<td width="33%" valign="top">
<strong>Cross-Architecture Bridging</strong><br><br>
x86-64 seed finds its ARM64 counterpart in a different build via the semantic layer. Same query locates the same vulnerability class across Cisco ASA x86-64, FTD ARM64, and legacy i386 images.
</td>
</tr>
</table>

**Proven on production firmware:** `attr_list_add_impl` sweep across 33 Cisco ASA firmware versions identified a 3.5-year unpatched window with no CVE, no advisory, and no source — derived entirely from stripped binaries.

```
Era 1  (jac ~0.11–0.19)   ASA 9.1.7 → 9.6.4        old implementation
Era 2  (jac ~0.96–0.97)   ASA 9.8.x → 9.14.4.24    UNPATCHED  (~3.5 years, no CVE)
──────────────────── patch boundary: ASA 9.15.x ─────────────────────────────────
Era 3  (jac ~0.21)        ASA 9.15.x → 9.22+        PATCHED
Era 4  (jac ~0.19)        ASA 10.1.x                 separate codeline, patched
```

---

## The Ablation Difference

<img src="assets/accent.svg">

<table>
<tr>
<td width="25%" align="center" valign="top">
<br>
<strong>No Symbol Dependency &raquo;</strong>
<br><br>
Matches on behavioral semantics, not names or addresses. Stripped enterprise firmware is the default case, not an edge case.
<br><br>

- x86-64, ARM64, ARM32, MIPS32 all supported
- Same query finds the same function across ISA boundaries
- No FLIRT signatures, no debug info, no symbol table

</td>
<td width="25%" align="center" valign="top">
<br>
<strong>Semantic Matching &raquo;</strong>
<br><br>
BinDiff matches structure. Ablation matches meaning. Recompiled at -O3 instead of -O2, function swapped instructions — Ablation still finds it.
<br><br>

- BinFuse 11-category opcode normalization
- Markov transition text preserves behavioral structure
- `sentence-transformers/all-MiniLM-L6-v2`, 384-dim embeddings

</td>
<td width="25%" align="center" valign="top">
<br>
<strong>Catalog Coverage &raquo;</strong>
<br><br>
A single seed becomes a behavioral signature that sweeps every firmware variant sharing the functional logic — not just matching version strings.
<br><br>

- 33+ Cisco ASA lina versions tracked
- Fleet-wide patch timeline from firmware alone
- OEM derivative and legacy build coverage

</td>
<td width="25%" align="center" valign="top">
<br>
<strong>Disclosure-Aligned Output &raquo;</strong>
<br><br>
Structured findings with VA offsets, confidence scores, and version attribution feed directly into disclosure reports and CVE submissions.
<br><br>

- `func_id_db` stores confirmed function identities across binary versions
- Claude ReAct loop names functions and hypothesizes vulns
- BARE adapter ranks Metasploit modules against findings

</td>
</tr>
</table>

---

## Use Cases

<img src="assets/accent.svg">

Stripped firmware. No symbols. Production-scale vulnerability research.

<table>
<tr>
<td width="33%" align="center" valign="top">
<br>
<strong>VULNERABILITY SWEEP</strong>
<br><br>
Sweep a firmware image for a vulnerability class before reading a single line of assembly. 885 functions, 5 candidates per class, 35 seconds on CPU. Start every engagement here.
<br><br>
</td>
<td width="33%" align="center" valign="top">
<br>
<strong>PATCH TIMELINE RECONSTRUCTION</strong>
<br><br>
Track a function across every firmware version and identify the exact patch epoch. No CVE, no advisory, no source code — derives the timeline from Jaccard continuity across builds.
<br><br>
</td>
<td width="33%" align="center" valign="top">
<br>
<strong>N-DAY SYNDICATION</strong>
<br><br>
A single patch becomes a behavioral signature. Sweep thousands of firmware images across different product lines, OEM derivatives, and legacy builds for every unpatched variant.
<br><br>
</td>
</tr>
<tr>
<td width="33%" align="center" valign="top">
<br>
<strong>CROSS-ARCHITECTURE RE</strong>
<br><br>
x86-64 seed finds its ARM64 counterpart via the semantic layer. Same vulnerability class located across Cisco ASA x86-64, FTD ARM64, and i386 legacy images in one query.
<br><br>
</td>
<td width="33%" align="center" valign="top">
<br>
<strong>LLM-ASSISTED ANALYSIS</strong>
<br><br>
Claude ReAct loop runs against unknown function VAs: issues disassembly, CFG, xref, and string queries; names functions; hypothesizes vulns; persists results to func_id_db.
<br><br>
</td>
<td width="33%" align="center" valign="top">
<br>
<strong>EXPLOIT MODULE RANKING</strong>
<br><br>
BARE adapter converts findings to semantic queries against 3,904 Metasploit modules. Offline, air-gap safe. Classic overflow/memcpy primitives surface usable MSF modules immediately.
<br><br>
</td>
</tr>
</table>

**Real-world evidence:** [Ablation-Case-Studies](https://github.com/francis-rancid/Ablation-Case-Studies) — 8 production RE engagements across Cisco, Fujitsu, MikroTik, AXIS, MacStadium Orka, Enigma2, Skydio UAV, and WeChat.

---

## Claude Code Integration

<img src="assets/accent.svg">

`llm_analyst` runs Claude as an active RE participant via a tool-calling ReAct loop. Given an unknown function VA, it issues disassembly, CFG, xref, and string queries against the binary, then calls `query_func_db` to pull prior findings, and terminates with a structured result: function name, role, confidence, vuln notes.

```python
from modules.llm_analyst import AgentLoop
from modules.llm_analyst.tasks.vuln_hypothesis import VulnHypothesisTask

loop = AgentLoop('/path/to/lina')
result = loop.run(0x4a1234, task=VulnHypothesisTask())
print(result.name, result.role, result.confidence)
print(result.vuln_notes)
```

7 tools: `get_disassembly`, `get_cfg`, `get_xrefs`, `get_strings`, `get_imports`, `query_func_db`, `done`. Results with `confidence >= 0.5` persist to `func_id_db` as `ANGR_INFERRED`.

Role taxonomy includes: `RADIUS_ATTR_HANDLER`, `RADIUS_DISPATCH`, `CRYPTO_HPKE`, `CRYPTO_STRAP`, `SAML_HANDLER`, `CSTP_HANDLER`, `DTLS_HANDLER`, and 12 others.

---

## Quick Start

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

# Quick function diff
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
```

### Semantic Vulnerability Sweep

Describe what dangerous code looks like in plain English. Ablation encodes every function and returns the closest matches — no symbols, no database, no setup.

```python
import struct, capstone, numpy as np
from modules.semantic_search import describe_function
from sentence_transformers import SentenceTransformer

BINARY = '/path/to/target'          # any stripped ELF — no symbols needed
SCAN_START = 0x200000
SCAN_END   = 0x400000

PLT = {
    0x7a8e0: 'strcpy',   0x785f0: 'sprintf',  0x7a9b0: 'snprintf',
    0x79650: 'memcpy',   0x79710: 'free',      0x7bda8: 'malloc',
    0x7b710: 'recvfrom', 0x787e0: 'recvmsg',   0x7b3f0: 'recv',
}

with open(BINARY, 'rb') as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def find_starts(data, start, end):
    return [i for i in range(start, end - 4)
            if data[i] == 0x55 and data[i+1:i+4] == b'\x48\x89\xe5']

def extract(va, max_bytes=2048):
    lines, calls = [], []
    for insn in md.disasm(data[va:va + max_bytes], va):
        lines.append(f'{insn.mnemonic} {insn.op_str}'.strip())
        if insn.mnemonic == 'call':
            try:
                calls.append(PLT.get(int(insn.op_str, 16), insn.op_str))
            except ValueError:
                calls.append(insn.op_str)
        if insn.mnemonic in ('ret', 'retq'):
            break
    return lines, calls

funcs = []
for va in find_starts(data, SCAN_START, SCAN_END):
    lines, calls = extract(va)
    if len(lines) >= 5:
        funcs.append({'va': va, 'desc': describe_function(
            name=f'func_{va:07x}', role='TARGET',
            call_targets=calls, strings=[], asm_lines=lines,
        ), 'calls': calls})

model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')
corpus = model.encode([f['desc'] for f in funcs], normalize_embeddings=True,
                      batch_size=128, show_progress_bar=True).astype(np.float32)

queries = {
    'unsafe_memcpy':   'TARGET | calls: memcpy | vuln: memcpy called with length from packet without bounds check',
    'strcpy_overflow': 'TARGET | calls: strcpy | vuln: strcpy on user-controlled string into fixed buffer',
    'int_overflow':    'TARGET | calls: malloc calloc | vuln: integer overflow in size arithmetic before allocation',
    'double_free':     'TARGET | calls: free | vuln: double free use after free same pointer freed twice',
    'recv_overflow':   'TARGET | calls: recvfrom recv | vuln: recv into stack buffer no size validation',
}

for name, query in queries.items():
    qvec = model.encode(query, normalize_embeddings=True).astype(np.float32)
    scores = corpus @ qvec
    top = np.argsort(scores)[::-1][:5]
    print(f'\n--- {name} ---')
    for i in top:
        print(f'  {funcs[i]["va"]:#x}  score={scores[i]:.4f}  calls={funcs[i]["calls"][:4]}')
```

```
# Output — 885 functions, 11MB binary, 35 seconds on CPU
--- unsafe_memcpy ---
  0x2b8ed0  score=0.7238  calls=['memcpy', 'memset']
  0x294ef0  score=0.6621  calls=['strcpy', 'sprintf', 'malloc']

--- double_free ---
  0x2c0215  score=0.6325  calls=['free', 'free', 'free']
  0x294f30  score=0.6102  calls=['free', 'malloc', 'memcpy']
```

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

### semantic_search

BERT-based function similarity seeded from `func_id_db` CONFIRMED/ANGR_INFERRED functions.

- Opcode categorization follows BinFuse (TrustCom 2025): 11 semantic categories (`DATA_TRANSFER_OP`, `ARITHMETIC_OP`, `COMPARISON_OP`, ...) — cross-architecture invariant
- Markov transition text: top-5 adjacent-category transitions (`COMPARISON_OP->CONDITIONAL_OP(2)`) encode behavioral structure invariant to optimization level
- Corpus cached as numpy array keyed on db hash; repeated queries cost one dot-product (~1ms)

### version_delta

Three-stage pipeline for cross-version homolog tracking.

```
Stage 1  Structural pre-filter     basic block count ±2, edge ratio ±35%
Stage 2  Mnemonic 4-gram Jaccard   build-invariant sequence similarity, top-10 candidates
Stage 3  Semantic tiebreaker       SemanticSearcher when top-2 within 0.05 Jaccard
```

Jaccard as patch epoch classifier — not binary match/no-match but a continuous implementation era signal:

| Jaccard | Interpretation |
|---------|---------------|
| ~0.97 | Bytecode nearly identical — same implementation era, almost certainly unpatched |
| ~0.21 | Structural rewrite — function was significantly changed, patched |
| ~0.11–0.19 | Different implementation era — pre-dates the current codeline |

Patch localization via `difflib.SequenceMatcher` surfaces the exact changed instructions.

### func_id_db

SQLite store for function identity across binary versions. Schema v2 (WAL, FK-indexed, 1NF).

- Tables: `binaries`, `functions`, `struct_fields`, `call_chains`, `call_chain_steps`
- Seeded: 23 CONFIRMED lina functions (RADIUS/AAA, HPKE, STRAP, SAML), 7 AnyConnect functions, 52 lina offsets, 1 call chain (6 steps)
- Matching: byte-pattern signature, callee-set overlap, struct field offset, string xrefs

### bare_adapter

Converts `llm_analyst.AnalysisResult` vuln findings to BARE `findings.json` and ranks against 3,904 Metasploit modules via the BARE binary (offline, air-gap safe, no Python at inference).

---

## Modules

### RE Infrastructure

| Module | Summary |
|--------|---------|
| `func_id_db` | SQLite function identity store — byte-pattern + callee + struct + string matching across binary versions |
| `llm_analyst/` | Claude ReAct loop — active RE participant; names functions, hypothesizes vulns, reconstructs structs |
| `semantic_search` | BERT-based function similarity (MiniLM-L6-v2, BinFuse opcode categories, Markov transitions) |
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
| `ftd_jwt_forge` | JWT forgery chain — RS256 to HS256 confusion |
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
| `jwt_crypto_analyzer` | alg:none, RS256 to HS256 confusion, kid SQLi/SSRF/traversal |
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

## Target Coverage

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
BARE binary       github.com/francis-rancid/BARE  (install to ~/.local/bin/bare)
```

---

## Documentation

- [docs/cisco.md](docs/cisco.md) — ASA, FTD/FDM, ISE, CUCM, AnyConnect, IOS, NX-OS
- [docs/apple.md](docs/apple.md) — Swift RE, Orka, malware persistence, sysadmin
- [docs/wechat.md](docs/wechat.md) — MMTLS protocol, DB key derivation, ptrace extraction
- [docs/core.md](docs/core.md) — binary analysis, Java, Windows kernel, containers, network, crypto

**Case studies:** [Ablation-Case-Studies](https://github.com/francis-rancid/Ablation-Case-Studies) — 8 production RE engagements.

---

## Credits

- **[@francis-rancid](https://github.com/francis-rancid)** — research and development
- **Claude Code** ([claude.ai/code](https://claude.ai/code)) — assisted analysis

---

For authorized security testing only.
