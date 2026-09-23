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
| [Registry](module-reference/registry.md) | NameRegistry, FindingRegistry |
| [Crypto](module-reference/crypto.md) | CryptoAudit, XorSolver, EntropyMapper |
| [Structural](module-reference/structural.md) | VtableResolver, VersionDelta, StructuralSim |
| [LLM Analyst](module-reference/llm.md) | LlmAnalyst ReAct agent loop |

---

## Target Notes

Vendor-specific RE knowledge: binary layout, known structures, confirmed patterns.

| Document | Vendors |
|---|---|
| [Fortinet](targets/fortinet.md) | FortiGate, FortiManager -- IPS engine, flatui, FortiOS binary layout |
| [Cisco](targets/cisco.md) | ASA, FTD, ISE, CUCM, AnyConnect, IOS, NX-OS |
| [Axis](targets/axis.md) | AXIS OS, camera firmware, ACAP applications |
| [Tencent](targets/tencent.md) | TencentOS, WeChat, Qwen3 |
| [MikroTik](targets/routeros.md) | RouterOS |

---

## Release Notes

See [CHANGELOG.md](../CHANGELOG.md) for full version history.

| Version | Summary |
|---|---|
| v1.8.0 | NameRegistry overlay, FindingRegistry, PatternLibrary self-improvement loop |
| v1.7.0 | LlmAnalyst ReAct agent, TaintTracker x86-64, PathSolver |
| v1.6.0 | VtableResolver ARM64, VersionDelta CFG shape diffing |
| v1.5.0 | BERT semantic search (SemanticSearcher), CorpusBuilder |
| v1.4.0 | XRefGraph, vectorized RIP-relative xref index in BinaryContext |
| v1.3.0 | Installable package (ablation.analyzers.*), BinaryContext SHA256 cache |
