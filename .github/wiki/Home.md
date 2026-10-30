<p align="center">
  <img src="https://raw.githubusercontent.com/Ablation-Tool/ablation/main/assets/branding/ablation-1b-riveted-plate-header-1280.png" width="760" alt="Ablation">
</p>

# Ablation Documentation

**AI-assisted reverse engineering for stripped binaries, firmware, and application artifacts.**

Use Ablation for authorized security research. Start with your goal, then check the relevant limitations before relying on a result.

## Start with your goal

| I want to… | Start here |
| --- | --- |
| Install Ablation and complete my first analysis | **[Getting Started](Getting-Started)** |
| Analyze a particular artifact or research target | **[Choose a Workflow](Workflows)** |
| Find the right analyzer for a task | **[Tool Selection](Guide-Tool-Selection)** |
| Explore what Ablation can do by analysis domain | **[Capabilities](Capabilities)** |
| Look up a module, API, or output format | **[Module Reference](Module-Reference)** |
| Understand unsupported cases and false negatives | **[Known Limitations](Known-Limitations)** |

## Follow the guided learning path

1. **[Getting Started](Getting-Started)** — install, load a binary, and triage candidates.
2. **[CLI & User Guide](User-Guide)** — learn sessions, commands, configuration, and examples.
3. **[Vulnerability Hunting](Workflows-Vuln-Hunting)** — move from candidates to confirmed findings.
4. **[Finding Validation](Reference-Modules-Finding-Validation)** — validate paths and preserve evidence.

## Explore the library

- **[Reference](Reference)** — detailed guides, indexes, integrations, and supporting material.
- **[Architecture](Architecture-Guide)** — analysis pipeline, intermediate representation, and design decisions.
- **[Development](Development-Guide)** — contributing, testing, documentation, and engineering standards.
- **[Releases](Releases)** — changelog, support matrix, and release-specific notes.
- **[Languages](Languages)** — translated guides and documentation.

> [!IMPORTANT]
> A candidate or taint path is not automatically a confirmed vulnerability. Review [Known Limitations](Known-Limitations) and the [Safety Manual](Safety-Manual), then validate findings independently.

---

Generated from {{DOCUMENT_COUNT}} source documents in [`docs/`](https://github.com/Ablation-Tool/ablation/tree/main/docs). Edit documentation in the repository, not in the Wiki. Updates publish automatically after they reach `main`.
