# RE Session Planning Template

**Standard:** MIL-HDBK-115C Section 4 (Planning and Preparation)  
**Usage:** Copy to `re/<vendor>/SESSION_<target>.md` at the start of every engagement

---

## How to Use This Template

Copy this file to `re/<vendor>/SESSION_<target>.md`. Fill in all fields before running any tool. The session file is the RE plan per MIL-HDBK-115C §4. Update it at the end of each session. Write the retrospective at project close.

---

# RE Session: `<TARGET>`

**Vendor:** `<vendor>`  
**Product:** `<product>`  
**Version:** `<version>`  
**Session start:** `YYYY-MM-DD`  
**Last updated:** `YYYY-MM-DD`  

---

## 1. Target Identification (MIL-HDBK-115C §4.1)

| Field | Value |
|---|---|
| Binary name | |
| Binary format | ELF / PE / flat ROM / other |
| Architecture | |
| Endianness | big / little |
| Size | |
| SHA256 | `sha256sum <binary>` |
| Source | (firmware image, installer, download URL) |
| Download verified | YES / NO (check README.md Download Status if Fortinet) |

**Artifact collection:**

- [ ] Binary downloaded and hash verified
- [ ] PDF documentation read (`<product>/docs/` — CLI Reference first, then Release Notes)
- [ ] README.md Download Status checked (no `.aria2` present)
- [ ] Binary copied to working directory

---

## 2. Scope and Purpose (MIL-HDBK-115C §4.2)

**Purpose of this RE effort:**  
(e.g., PSIRT vulnerability research; safety case support; curriculum material)

**Scope:**  
(e.g., all exported functions in `<binary>`; network-facing functions only; security-access handler only)

**Out of scope:**  
(e.g., calibration data; bootloader; DRM)

---

## 3. Tool Selection Rationale (MIL-HDBK-115C §4.3)

| Tool | Reason for selection |
|---|---|
| `BinaryContext` | Always first: builds function index and string xrefs |
| `SemanticSearcher` | Always second: semantic sweep before any manual disasm |
| *(add tools as selected)* | |

**Taint tracker selected:** (e.g., `RH850TaintTracker`) — **why:** (e.g., GHS CC-RH ABI, `double_is_32bit=True` default matches firmware compiler)

**Known anomalies consulted:** `docs/known-anomalies/<tracker>.md` — **relevant anomalies:** (list any whose triggering conditions match this target)

---

## 4. Documentation Plan (MIL-HDBK-115C §4.4)

- All findings go in `re/<vendor>/<target>_re.py`
- This session file is the RE plan per MIL-HDBK-115C §4
- Retrospective will be written at project close (per `feedback-re-project-retrospective` rule)
- Disclosure: PSIRT / not applicable / TBD

---

## 5. Active Sessions Log

| Session | Date | Summary | Next |
|---|---|---|---|
| Session 1 | YYYY-MM-DD | | |

---

## 6. Confirmed Function Names

*(populated as `ctx.set_name()` calls are made)*

| VA | Name | Source |
|---|---|---|
| `0x...` | | confirmed |

---

## 7. Confirmed Findings

*(populated from `re/<vendor>/<target>_re.py`)*

| ID | Title | Severity | CWE | Status |
|---|---|---|---|---|
| `<TARGET>-001` | | | | CONFIRMED |

---

## 8. Eliminated Candidates

| ID | Description | Reason eliminated |
|---|---|---|
| | | |

---

## 9. Tool Improvements Identified

*(gaps found in Ablation during this engagement that should become new modules)*

| Gap | Proposed module | Priority |
|---|---|---|
| | | |

---

## 10. Retrospective

*(filled at project close)*

**Total sessions:** N  
**Total findings:** N CONFIRMED (N CRITICAL, N HIGH, N MEDIUM)  
**Won't-do-again:** (what would you skip next time)  
**Reusable patterns:** (patterns that should go into `PatternLibrary`)  
**Ablation gaps found:** (became which modules)
