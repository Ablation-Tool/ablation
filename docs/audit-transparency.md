# Audit Transparency Statement

**Version:** 1.0.0 — 2026-10-10  
**Standard:** CISA Secure by Design — Principle 2: Embrace Radical Transparency and Accountability  
**Scope:** All modules in `ablation/analyzers/`; all taint trackers; FORGE gate

This document satisfies CISA-SBD2 (Transparency) in the Ablation compliance matrix. It records how Ablation's limitations, quality gates, and audit results are disclosed to users and maintainers.

---

## 1. What Is Disclosed

### 1.1 Module Limitations

Every taint tracker and CRITICAL-producing scanner has a corresponding file at `docs/known-anomalies/<module>.md`. Each file documents:
- All known false negative conditions with triggering inputs
- All known false positive conditions
- Workarounds for each anomaly
- Open/resolved status per Ablation version

These files are committed to the public repository and are visible in every release.

### 1.2 FORGE Audit Results

Every module committed to Ablation has passed the SAFE CODE 10-section audit and FORGE gate (`gate_passed=True`). The FORGE cache is stored at `~/.ablation/forge_cache/`. The following is committed per module:
- `docs/module-reference/<module>.md` — public-facing module reference including "Why this exists" gap list and usage constraints
- SAFE CODE residual risk section — documents any findings that were ACCEPTED rather than fixed, with justification

When a module has an ACCEPTED risk, that risk appears in the module's `docs/known-anomalies/` file.

### 1.3 Version History

All changes are in the public git log at `Ablation-Tool/ablation`. Each commit carries:
- Version bump in `ablation/__init__.py`
- Co-Authored-By attribution line
- Description of what changed

Silent changes to shipped behavior are not permitted.

### 1.4 Qualification Status

The compliance matrix in `docs/ABLATION-STANDARDS.md` §10 is the single authoritative record of Ablation's qualification status against eight external standards frameworks. It is updated in every release that changes the qualification posture.

---

## 2. What Is Not Disclosed

The following are intentionally excluded from the public repository:

| Excluded | Reason |
|---|---|
| `re/<vendor>/<target>_re.py` | Contains target-identifying information; gitignored per OPSEC rule |
| `re/<vendor>/SESSION_<target>.md` | Per-engagement session state; local only |
| `~/.ablation/findings.db` | Cross-engagement finding database; contains target names |
| `~/.ablation/forge_cache/` | FORGE audit cache; may contain target-specific context |

Exclusion of findings and session state is a deliberate OPSEC decision, not a transparency gap. The *methodology* for all analysis is public; only target-identifying data is excluded.

---

## 3. How Limitations Are Communicated

When Ablation is used to produce findings for a PSIRT disclosure or safety case:
1. The analyst consults `docs/known-anomalies/<tracker>.md` for the architecture used
2. Any anomaly whose triggering condition matches the target is noted in the finding report
3. Manual verification supplements the tracker for any function whose analysis falls within a known anomaly
4. The word "Ablation" is not cited as the sole evidence for any CONFIRMED finding; the finding always includes byte-verified evidence

---

## 4. Change Log

| Date | Version | Change |
|---|---|---|
| 2026-10-10 | 1.0.0 | Initial committed artifact; closes CISA-SBD2 |
