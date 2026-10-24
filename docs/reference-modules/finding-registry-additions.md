# FindingRegistry: STRIDE and DREAD Additions

## Why these additions exist

Two gaps motivated this addition:

1. SKILLS reports required manual STRIDE categorization for every finding. The mapping from CWE class to STRIDE letter is deterministic and should be automated.
2. Finding triage order required analyst judgment on severity alone. A DREAD approximation derived from severity and CWE class provides a consistent numeric priority signal without a full qualitative assessment.

## stride_category(cwe_class)

Returns the STRIDE letter for a CWE class string. Returns an empty string for unmapped CWEs.

STRIDE letters: S = Spoofing, T = Tampering, R = Repudiation, I = Information Disclosure, D = Denial of Service, E = Elevation of Privilege.

```python
from ablation.analyzers.finding_registry import FindingRegistry

letter = FindingRegistry.stride_category('CWE-78')
# 'T' (Tampering)

letter = FindingRegistry.stride_category('CWE-200')
# 'I' (Information Disclosure)

letter = FindingRegistry.stride_category('CWE-999')
# '' (not mapped)
```

**CWE categories covered:** Spoofing (7 CWEs), Tampering (20 CWEs), Repudiation (3 CWEs), Information Disclosure (14 CWEs), Denial of Service (6 CWEs), Elevation of Privilege (7 CWEs).

## dread_score

Returns an integer DREAD score from 0 to 10. Based on severity base score plus a CWE bonus for high-exploitability classes.

This is a heuristic approximation, not a formal DREAD assessment. Use as a triage priority signal.

```python
score = FindingRegistry.dread_score('HIGH', 'CWE-78')
# 8  (base 7 + bonus 1 for command injection)

score = FindingRegistry.dread_score('MEDIUM', 'CWE-200')
# 5  (base 5 + no bonus)

score = FindingRegistry.dread_score('CRITICAL', 'CWE-787')
# 10  (base 9 + bonus 1, clamped to 10)
```

**Severity base scores:** CRITICAL = 9, HIGH = 7, MEDIUM = 5, LOW = 3, INFO = 1. Unknown severity defaults to 5.

**CWE bonus of 1** applies to command injection classes such as CWE-78, memory corruption classes such as CWE-119 and CWE-787, and use-after-free classes such as CWE-416.

## Usage in SKILLS reports

```python
for finding in registry.export():
    stride = FindingRegistry.stride_category(finding.cwe_class)
    dread  = FindingRegistry.dread_score(finding.severity, finding.cwe_class)
    print(f"{finding.title}  STRIDE={stride}  DREAD={dread}")
```
