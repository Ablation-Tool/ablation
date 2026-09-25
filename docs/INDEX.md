# Ablation Document Library

Semantic firmware analysis for vulnerability researchers.

---

## Getting Started

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Install, first binary, first sweep -- 15 minutes |
| [Pitch / Overview](../PITCH.md) | What Ablation is and why it exists |

---

## Workflows

Step-by-step guides for common research tasks.

| Document | Description |
|---|---|
| [Vulnerability Hunting](workflows/vuln-hunting.md) | Full loop: sweep to confirmed finding to disclosure |
| [Cross-Version Diffing](workflows/cross-version.md) | Track a function across firmware patch releases |
| [Go Binary RE](workflows/go-binaries.md) | Stripped Go binaries: pclntab recovery, garbled builds |
| [Crypto Analysis](workflows/crypto.md) | Encrypted firmware, XOR key recovery, JWT cracking |

---

## Module Reference

| Document | Covers |
|---|---|
| [Core Analyzers](module-reference/core.md) | BinaryContext, XRefGraph, CFGBuilder, TaintTracker, PathSolver |
| [Semantic Search](module-reference/semantic-search.md) | SemanticSearcher, CorpusBuilder, PatternLibrary |
| [Signature Matching](module-reference/sig-library.md) | SigLibrary, auto-naming fn_0x* functions |
| [Export Formats](module-reference/export.md) | SARIF 2.1.0, JSON, GitHub Code Scanning |
| [Registry](module-reference/registry.md) | NameRegistry, FindingRegistry |
| [Crypto](module-reference/crypto.md) | CryptoAudit, XorSolver, EntropyMapper |
| [Structural](module-reference/structural.md) | VtableResolver, VersionDelta, StructuralSim |
| [LLM Analyst](module-reference/llm.md) | LlmAnalyst ReAct agent loop |

---

## Integrations

| Document | |
|---|---|
| [Claude Code](integrations/claude-code.md) | Using Ablation inside a Claude Code session |
| [Binary Ninja](integrations/binja.md) | Plugin installation and commands |

---

## Target Notes

Vendor-specific RE knowledge: binary layout, known structures, confirmed patterns.

| Document | Vendors |
|---|---|
| [Axis](targets/axis.md) | AXIS OS, camera firmware, ACAP applications |
| [Tencent](targets/tencent.md) | TencentOS, WeChat, Qwen3 |
| [MikroTik](targets/routeros.md) | RouterOS |

---

## Release Notes

See [CHANGELOG.md](../CHANGELOG.md) for full version history.

| Version | Summary |
|---|---|
| v2.5.0 | FormatStringScanner fortify variants, IoctlAttackSurfaceGenerator, CrossBinaryTaintTracker, BYOVDDetector PDB fingerprints |
| v2.4.0 | MIPS32TaintTracker, HeapVulnScanner (INT_OVERFLOW/UAF/double-free/off-by-one) |
| v2.3.0 | BYOVDDetector 8-path scoring, SSDT/CR0/CR4/token-steal/APC primitives |
| v2.0.0 | KernelDriverAnalyzer: IRP/IOCTL dispatch, 40+ API risk classes, SMEP/CR0 scan |
| v1.8.0 | NameRegistry overlay, FindingRegistry, PatternLibrary self-improvement loop |
| v1.7.0 | LlmAnalyst ReAct agent, TaintTracker x86-64, PathSolver |
| v1.6.0 | VtableResolver ARM64, VersionDelta CFG shape diffing |
| v1.5.0 | BERT semantic search (SemanticSearcher), CorpusBuilder |
| v1.4.0 | XRefGraph, vectorized RIP-relative xref index in BinaryContext |
| v1.3.0 | Installable package (ablation.analyzers.*), BinaryContext SHA256 cache |
