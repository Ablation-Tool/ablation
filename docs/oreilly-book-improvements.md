# Ablation Improvements — O'Reilly Book Reading

Five books read and synthesized for Ablation improvement opportunities.
Sources: *The Art of Software Security Assessment* (Dowd et al.), *Designing Secure Software* (Kohnfelder),
*Malware Analysis Techniques*, *Securing AI Systems* (Borges & Campbell), *Software Supply Chain Security*.

---

## New Scanner Modules

### Vulnerability Scanners

**`signed_length_arg_scanner.py`** (source: AoSA Ch6)
A call-site classifier for length arguments where the type signature is `signed int` rather than `size_t`
at `read()`, `recvfrom()`, `memcpy()`, `memset()`, `malloc()`, `snprintf()` sinks. Negative values passed
to these become large positive sizes. Extends `SinkArgClassifier` with sign-at-call-site classification.

**`truncation_at_sink_scanner.py`** (source: AoSA Ch6, DSS Ch9)
Detects wide-to-narrow type truncation before allocation or index use: `uint32_t` length → `uint16_t`
before `malloc()`, or network-received 32-bit value truncated to 8-bit for comparison. Distinct from
`length_underflow.py` (arithmetic underflow) — this is a narrowing at assignment, not a computation error.

**`sizeof_ptr_detector.py`** (source: AoSA Ch6)
Finds `sizeof(ptr)` returning 4 or 8 instead of buffer size, producing false-safe length calculations
feeding `memcpy()`/`memset()`. Pattern: `mov` of immediate 4 or 8 into size argument of copy/fill sink
where destination is a heap or stack buffer larger than a pointer.

**`toctou_scanner.py`** (source: AoSA Ch9)
Detects `access@plt` followed by `open@plt` / `fopen@plt` on the same path argument within the same
function or short call chain — the classic TOCTOU race window. Clean new module on top of PLT import
scanning, similar to `ProcessInjectionComboScanner` approach.

**`signal_handler_race_scanner.py`** (source: AoSA Ch13)
Finds `signal()`/`sigaction()` registrations where the handler function calls non-async-signal-safe PLT
functions: `malloc`, `free`, `printf`, `syslog`, `fprintf`, `fflush`. Uses `BinaryContext` PLT imports +
call graph from registered handler VA.

**`metachar_filter_bypass_scanner.py`** (source: AoSA Ch8)
Identifies sanitizer functions (from `SanitizerDetector`) that iterate byte-by-byte but lack multi-byte
boundary checks — these are bypassable by embedding a filtered character inside a multi-byte sequence.
Flag sanitizers that use a byte loop without a check for continuation bytes (0x80–0xBF for UTF-8).

**`dead_security_check_scanner.py`** (source: DSS Ch8 — GotoFail pattern)
Uses `CFGBuilder` to flag functions where an unconditional `jmp`/`b`/`bl` appears mid-sequence in a
series of `cmp`+conditional-branch checks that gate a privileged operation — producing unreachable
security validation code. The GotoFail bug is the canonical example.

**`non_constant_time_comparator_scanner.py`** (source: DSS Ch8)
Identifies byte-by-byte comparison loops over fixed-length buffers with an early `bne`/`jne` exit before
loop completion, where one operand comes from a tainted source. These are timing oracle candidates for
secret comparison (MAC verify, password check, token compare).

**`weak_prng_at_security_sink_scanner.py`** (source: DSS Ch8)
Patterns for `srand(time())` / `rand()` / `random()` calls within the call graph leading to session-ID
generation, nonce creation, or token output. Distinct from taint-flow analysis — weak entropy is a
finding independent of how the value propagates.

**`uninitialized_var_path_scanner.py`** (source: AoSA Ch7)
Per-function def/use tracking over `CFGBuilder` output: flags variables read before write on error-path
CFG edges (cleanup epilogues jumped to from multiple locations). Particularly common in error-handling
paths in stripped firmware where cleanup jumps bypass initialization.

**`process_injection_combo_scanner.py`** (source: MAT Ch6/7)
Flags binaries that import `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` (or
`NtCreateThreadEx`) — the canonical process-injection triad. Uses `BinaryContext` PLT imports; full
co-occurrence in same binary is sufficient; within-function check via `SinkPropagator` for stronger signal.

**`deprecated_crypto_scanner.py`** (source: DSS Ch13)
SemanticSearcher patterns for MD5/SHA1 key-schedule byte constants, DES S-box constants, and RC4's
256-byte permutation init loop in `.rodata` or `.text`. Flags deprecated crypto in stripped binaries
without requiring taint analysis — a standalone finding class.

### Anti-Analysis Detection

**`entropy_analyzer.py`** (source: MAT Ch4/7)
Computes per-section Shannon entropy for ELF firmware; flags sections with entropy > 7.0 as likely
packed or encrypted. Alerts analyst before `SemanticSearcher` runs on data that cannot yet be analyzed
meaningfully. Pairs with import-table sparsity check (see `BinaryContext` enhancement below).

**`anti_analysis_string_detector.py`** (source: MAT Ch6/7)
Scans rodata for arrays of analysis-tool executable names (`regshot.exe`, `wireshark.exe`, `procmon.exe`,
`ollydbg.exe`, `x64dbg.exe`, etc.) — the Qakbot-style sandbox-detection checklist. Confirmed hit is a
defense-evasion finding independent of execution.

**`elf_anomaly_scanner.py`** (source: MAT Ch2)
Flags ELF images with section header/program header mismatches, section sizes inconsistent with file
size, and magic-byte mismatches between header and actual content. Runs at `BinaryContext.load_or_build()`
time and warns before analysis of potentially repacked firmware.

### Supply Chain / Firmware Integrity

**`build_integrity_analyzer.py`** (source: SSC Ch5)
Extracts embedded SHA256/SHA1/MD5 checksums from binary strings and compares them against the bytes
they reference where locatable. Hash mismatch between embedded self-verification value and actual bytes
is a strong implant indicator (the Codecov attack was detected this way).

**`build_provenance_extractor.py`** (source: SSC Ch5 — SolarWinds pattern)
Harvests build-path strings, compile-time macros (`__FILE__`, `__DATE__`), CI system identifiers
(`GITHUB_SHA`, `JENKINS_BUILD_ID`), and version strings from rodata. Flags anomalous or conflicting
provenance (two build hosts, mismatched timestamps) as a tampered-build indicator.

**`hardcoded_credential_scanner.py`** (source: SSC Ch5)
Dedicated rodata scanner for API keys, JWT secrets, AWS access key patterns (`AKIA[A-Z0-9]{16}`),
private key PEM headers, and bearer token patterns. Faster than taint analysis for red-team triage;
addresses SCBD-06 (secrets scanning) directly.

**`third_party_library_identifier.py`** (source: SSC Ch5)
Matches known OSS library version strings in rodata (`zlib 1.2.11`, `openssl 1.0.2k`) against a local
CVE stub list. Flags EOL or known-critical-CVE components embedded in firmware. More reliable than
symbol-based SCA for stripped binaries.

**`sbom_extractor.py`** (source: SSC Ch3/10)
Harvests CPE strings, package names/versions, and NTIA minimum-elements fields from binary rodata and
debug sections. Many firmware builders embed SBOM as JSON/XML blobs; extracting and diffing across
versions surfaces quietly dropped or version-pinned vulnerable components.

**`firmware_pki_checker.py`** (source: SSC Ch10)
Scans firmware images for absence of expected signature blocks: U-Boot FIT image signatures, UEFI Secure
Boot headers, TrustZone attestation blobs. Flags images where the update/boot path expects signing but
no signature structure is present.

### AI/Agent Security

**`prompt_injection_sink_classifier.py`** (source: SAI Ch1)
Extends `SinkArgClassifier` with a new sink class `PROMPT_INJECTION_SINK`: where a binary contains an
embedded LLM system prompt (multi-sentence instruction string in `.rodata`) and user-controlled input
flows into the prompt-assembly buffer. Taint currently stops at `system()`/`execv()`; extend to LLM
API call sites.

**`agent_authority_audit.py`** (source: SAI Ch2)
Extracts system prompt strings, parses permission-denying clauses ("do not access", "never execute"),
then cross-references against the binary's actual PLT imports and syscall surface. Mismatches between
claimed restrictions and actual capability surface are high-confidence misalignment findings.

**`agent_tool_surface_enumerator.py`** (source: SAI Ch3)
Extracts tool definitions an embedded agent exposes (from JSON schema strings, function registry tables,
MCP `tools` arrays in `.rodata`), classifies each tool by atomic privilege tier (read-only / reversible
write / destructive / external-comms), and reports the effective capability surface. Complements
`InferenceEndpointEnumeration`.

**`policy_engine_absence_detector.py`** (source: SAI Ch3)
Given a binary with LLM API call sites and tool-dispatch logic, checks whether an authorization check
exists between the LLM's tool-selection output and actual tool execution. Direct model-output-to-execution
flow with no intermediate AuthZ gate is `MISSING_AUTHZ_BOUNDARY` — a high-severity agentic design flaw.

**`agent_observability_audit.py`** (source: SAI Ch3)
Checks whether a binary's agentic loop emits structured audit events for tool calls and auth decisions.
If LLM tool dispatch paths exist but no logging call follows the dispatch, flag as `MISSING_AUDIT_TRAIL`.
Pairs with existing `AIControlIndicators`.

**`lethal_trifecta_scanner.py`** (source: SAI Ch1)
Checks an AI agent binary for simultaneous presence of: private data access (credential strings, DB
connection strings in reachable memory), untrusted input paths (network-sourced buffers to LLM call
sites), and external communication channels (outbound API endpoints). All three together = critical.

---

## Enhancements to Existing Modules

### BinaryContext

- **Import-table sparsity heuristic**: Flag binaries with fewer than a configurable threshold of PLT
  imports as potentially packed (canonical packer footprint: only `VirtualAlloc`, `LoadLibrary`,
  `GetProcAddress`). Pairs with `EntropyAnalyzer` to trigger a pre-analysis packing warning.

- **CPUID opcode scanner**: Add capstone sweep for `CPUID` opcode followed by conditional branch logic
  — anti-VM detection without any API call. Add to the anti-analysis detection set.

- **PUSHAD-at-entry packer signature**: For x86 ELF firmware, scan for PUSHAD within the first 32 bytes
  of `.text` entry point; combined with IAT sparsity this is a reliable packer signature.

- **ADS reference detection**: Scan for `CreateFileA`/`NtCreateFile` calls where the filename string
  argument contains `:` (NTFS Alternate Data Stream path) — flags stealthy Windows-targeting persistence.

### SemanticSearcher

- **`anti_analysis_apis` pattern set**: Add a vuln class covering `IsDebuggerPresent`, `GetAdaptersInfo`
  (MAC OUI VM check), `SetWindowsHookEx` (mouse monitoring), `CreateToolhelp32Snapshot` (process
  enumeration for tool detection). Confirmed PLT import = defense-evasion finding.

- **Sign extension in packet decoders**: Pattern for signed `char`/`short` field from a packet buffer
  being widened to `int` before a size calculation or comparison — surfaces without a new module.

- **Hallucinated-dependency injection**: Patterns for known AI-hallucinated package names appearing in
  `dlopen()` or import-equivalent call sites. New vuln class distinct from typosquatting.

- **Float-to-int narrowing**: Pattern for `VCVT`/`CVTTSS2SI`/`CVTTSD2SI` instructions whose destination
  register feeds an allocation or index expression (Ariane 5 pattern, DSS Ch9/13).

- **Authorization bypass through benign framing**: Flag system prompts containing
  "I am on the blue team"/"authorized security researcher" — baked-in refusal-bypass
  pre-conditions (SAI Ch1).

### PathSolver

- **Chain depth weighting**: Compute `chain_depth` — count of MEDIUM/LOW findings co-occurring on the
  same path from input to critical sink — and auto-elevate severity when `chain_depth >= 2`. Chained
  minor bugs routinely yield exploitability that individual scores miss (DSS Ch10).

### FindingRegistry

- **STRIDE category auto-population**: Auto-populate a `stride_category` field from sink class at
  registration: exec sinks → EoP, info-leak sinks → InfoDisclosure, CMDB write sinks → Tampering.
  Makes findings directly consumable by threat model reports.

- **DREAD auto-score**: Auto-compute DREAD score at registration from existing metadata: sink class →
  Damage, pre-auth flag → Exploitability, path length → Reproducibility (DSS Ch12/13).

### PatternLibrary

- **ssdeep / TLSH fuzzy similarity scoring**: Add a fuzzy similarity scorer on confirmed function byte
  sequences to find variants across firmware versions where identical logic was recompiled with minor
  padding changes — currently impossible with exact byte matching (MAT Ch2).

### ATTACKLabeler

- **ATT&CK technique ID auto-assignment**: Auto-assign T-IDs from confirmed finding types: T1055.003
  for Thread Execution Hijacking, T1027 for obfuscated files/information, T1552 for hardcoded
  credentials. Improves SKILLS report quality without manual tagging (MAT Ch10).

### AIControlIndicators

- **AI-generated code patterns**: Detect `/* Generated by GitHub Copilot */` strings and characteristic
  license header permutations from AI code generators. Copilot-generated code has ~40% vulnerability
  rate per Cornell research; presence flags elevated review priority (SSC Ch5).

### LLMBehaviorSecurityProbes

- **HITL enforcement probe**: Test whether a deployed agent enforces its stated Human-in-the-Loop tier:
  if system prompt claims "human approval required for destructive actions," attempt a destructive tool
  call and verify approval-gate response rather than direct execution (SAI Ch3).

- **LLM_CONTEXT_CREDENTIAL taint source**: Add taint source class for API keys/tokens retrieved via
  tool call that persist in heap buffer across multiple LLM round-trips — credential-leak-to-context
  patterns specific to agentic loops (SAI Ch2).

### CFGBuilder

- **Complete Mediation bypass detector**: Identify handler functions with auth/ACL `cmp`+branch on
  entry but alternative CFG edges (loop re-entry, indirect call targets) that reach the privileged
  operation without traversing the auth check node (DSS Ch4).

- **Error-path security state gap analysis**: Flag functions where a security-critical write (session
  key store, ACL update, audit log) appears on all success-path CFG nodes but is absent from all
  error-path nodes — security-state corruption under error conditions (DSS Ch13).

- **Auth-bypass via error path**: Identify functions where a zero/success return is reachable without
  passing through the auth check — early branch out before the check (DSS Ch3 "Fail Securely").

### ObfuscatedStringDecoder (extend existing)

- **Multi-layer decoding**: Systematically attempt Base64, hex, and ASCII-ordinal decoding on
  high-entropy string literals in `.rodata`. Many firmware droppers use Base64 → deflate → XOR chains;
  current IOC extractor handles some but not multi-layer (MAT Ch8).

---

## Dependency Confusion / Supply Chain Patterns

**`dependency_confusion_scanner.py`** (source: SSC Ch5)
Detect linked-in package manager paths (`site-packages/`, `.npm/`, `gems/`) in binary rodata pointing
to external or anomalous registry origins — embedded build-path strings survive stripping and reveal
whether a binary was built against a poisoned internal package.

---

## Priority Ordering (highest impact first)

1. `hardcoded_credential_scanner.py` — immediate red-team value, no arch dependency
2. `entropy_analyzer.py` + BinaryContext packing heuristic — improves all downstream analysis
3. `signed_length_arg_scanner.py` — closes the most common missed class from AoSA
4. `toctou_scanner.py` — clean new module, PLT-level, low false-positive rate
5. `deprecated_crypto_scanner.py` — standalone, no taint needed, rodata pattern match
6. `dead_security_check_scanner.py` (GotoFail) — high-severity class, CFGBuilder already exists
7. `signal_handler_race_scanner.py` — clean PLT + call-graph module
8. `third_party_library_identifier.py` + `sbom_extractor.py` — version string matching
9. `process_injection_combo_scanner.py` — PLT co-occurrence, low effort
10. `policy_engine_absence_detector.py` — AI agent gap, complements existing AI modules
11. `agent_authority_audit.py` — system prompt vs capability surface analysis
12. `build_integrity_analyzer.py` + `build_provenance_extractor.py` — supply chain
13. FindingRegistry STRIDE/DREAD auto-scoring — enriches all existing findings
14. PathSolver chain depth weighting — elevates chained findings automatically
15. `non_constant_time_comparator_scanner.py` — timing oracle detection
