# Ablation Documentation

Semantic firmware analysis for vulnerability researchers.

---

## Core Guides

- [Overview](./overview.md) — What Ablation is, how the analysis model works, and what each tool does.
- [Getting Started](./getting-started.md) — Install Ablation and run your first sweep in 15 minutes.
- [User Guide](./user-guide.md) — Session setup, tool ordering, CLI usage, and worked examples.
- [Decompiler Concepts](./concepts-decompiler.md) — IR lifter vs. decompiler, the three-stage pipeline, and the full `arch=` reference for every backend.
- [Tool and Mode Selection](./guide-tool-selection.md) — Task → tool lookup table for every analysis job.
- [Reverse Engineering Workflow](./guide-re-workflow.md) — End-to-end engagement workflow.

## Reference

- [Module Reference](./reference-modules/) — Per-module constructor patterns, key methods, and output formats for every Ablation analyzer.
- [Known Anomalies](./reference-anomalies/) — Per-ISA taint tracker false-negative conditions and workarounds.
- [Full Module Index](./INDEX.md) — Searchable catalog of all modules with descriptions.
- [Workflows](./workflows/) — Task-focused step-by-step walkthroughs.

## Architecture & Development

- [Architecture & Design](./architecture.md) — Data flow, design decisions, ISA backend tiers.
- [Development & Contributing](./development.md) — Project structure, custom scanner workflow, FORGE gate, build and test.

## Reliability & Safety

- [Safety Manual](./safety-manual.md) — Intended use, prerequisites for reliable results, known false negative categories.
- [Ablation Standards](./standards-ablation.md) — NIST SP 800-218, CISA Secure by Design, MIL-HDBK-115C compliance matrix.
- [Audit Transparency](./audit-transparency.md) — What is disclosed, what is not, and how limitations are communicated.

## Release Notes

- [Changelog](./CHANGELOG.md) — Full version history.
- [v2.5.0](./updates/v2.5.0.md) · [v2.4.0](./updates/v2.4.0.md) · [v2.0.0](./updates/v2.0.0.md)

## Other

- [FAQ](./faq.md)
