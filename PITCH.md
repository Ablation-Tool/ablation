# Ablation

**Find vulnerable functions in stripped firmware in seconds. No symbols. No source.**

---

## The problem with existing tools

IDA Pro and Ghidra are mapmakers. They build an exhaustive disassembly database before a
researcher can search for a single string. On a 50 MB network appliance image, that
initialization takes one to four hours. On an 18 MB stripped IPS engine with 19,000 functions
and no symbols, it crashes.

Vulnerability researchers are not mapmakers. They are hunters. A tool that forces a hunter to
wait hours before the hunt starts is the wrong tool.

---

## What Ablation does

Ablation is a Python framework for rapid vulnerability research on stripped binary firmware.

**It loads an 18 MB ELF in 0.5 seconds. On the second run, 110 milliseconds.**

Instead of a full disassembly database, Ablation runs three analysis tracks in parallel:

**1. Vectorized call graph and xref scan**
Treats `.text` as a NumPy array. Scans for CALL rel32 opcode bytes with `np.where`, extracts
every displacement field in one broadcast operation, and resolves every string cross-reference
in an O(N) pass over the binary. No sequential disassembly.

**2. BERT semantic search**
Encodes every function as a behavioral fingerprint: what it calls, what strings it references,
what its call-graph neighbors look like. Researchers query in plain English:

```
"TLV parser that advances a pointer without checking minimum field length"
"memcpy called with length from untrusted packet field"
"integer overflow before malloc without bounds check"
```

Results arrive in roughly 35 seconds across 19,000 functions. No symbols required.

**3. Self-improving pattern library**
Every confirmed vulnerability registers as a semantic pattern. On the next binary, those patterns replay automatically, across vendors and firmware versions. The tool improves with every finding.

---

## Real results

Ablation confirmed CVE-class vulnerabilities in production enterprise firmware before any
manual disassembly. In each case the semantic sweep identified the exact function; manual
disassembly only began after Ablation narrowed 19,000 functions to five candidates.

---

## Architecture

```
ablation/analyzers/
  binary_context.py       BinaryContext -- PLT/exports/strings/call graph/xref index
                          Cached at ~/.ablation/cache/ keyed by SHA256.
                          Build once in 0.5s. Reload in 110ms every subsequent session.

  semantic_search.py      SemanticSearcher -- BERT embeddings over 19k+ functions
  corpus_builder.py       CorpusBuilder -- func_id.db: behavioral descriptions per function
  pattern_library.py      PatternLibrary -- self-improving confirmed pattern corpus

  name_registry.py        NameRegistry -- persistent VA -> name overlay, cross-session
  finding_registry.py     FindingRegistry -- cross-target confirmed finding store

  xref_graph.py           XRefGraph -- full call graph with indirect resolution
  cfg_builder.py          CFGBuilder -- basic block decomposition + branch analysis
  taint_tracker_x86.py    TaintTracker -- x86-64 data flow from source to sink
  path_solver.py          PathSolver -- constraint-based path feasibility

  crypto_audit.py         CryptoAudit -- JWT, TLS, key material analysis
  xor_solver.py           XorSolver -- XOR key recovery from known plaintext
  entropy_mapper.py       EntropyMapper -- encrypted and packed section detection

  vtable_resolver.py      VtableResolver -- ARM64 C++ vtable reconstruction
  version_delta.py        VersionDelta -- cross-version function diffing by CFG shape

  llm_analyst/            LlmAnalyst -- ReAct agent loop for automated function naming
```

**50+ analyzers. One install.**

---

## Install

```bash
pip install ablation
```

From source:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Optional LLM features (automated naming via Claude):

```bash
pip install ablation[llm]
```

---

## Who it is for

**Vulnerability researchers** hunting in stripped enterprise firmware (network appliances,
embedded Linux, ICS/OT) who spend more time waiting on IDA Pro than finding bugs.

**Security teams** that analyze vendor advisories via patch diff. Load both firmware versions,
run VersionDelta, get a ranked list of changed functions in seconds.

**Bug bounty researchers** targeting appliance firmware under CVE programs (Fortinet, Cisco,
Axis, MikroTik) who triage dozens of binaries in a single engagement.

---

## What it is not

Ablation does not decompile. It does not generate C pseudocode. It does not replace IDA Pro
for deep manual analysis. It is the tool you run before opening a disassembler to find the
one function worth an hour of manual work.

---

## License

Commercial license required for commercial use. Non-commercial research use permitted.
Source at [github.com/Ablation-Tool/ablation](https://github.com/Ablation-Tool/ablation).
See [LICENSE](LICENSE) for full terms.
