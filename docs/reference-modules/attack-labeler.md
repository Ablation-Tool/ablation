# ATTACKLabeler

## Why this exists

Three gaps motivated this module:

1. SKILLS reports required manual ATT&CK T-ID lookup for every finding, which introduced inconsistency and delay.
2. CWE classes and scanner names provide a deterministic mapping to ATT&CK technique IDs that can be automated.
3. Missing T-IDs in reports reduces utility for blue team consumers who correlate findings against detection coverage.

## What it does

`ATTACKLabeler` maps confirmed Ablation finding types to MITRE ATT&CK Enterprise technique IDs. It covers two mapping routes:

- **CWE class**: 26 mappings from CWE IDs to T-IDs across execution, injection, credential, and evasion classes
- **Scanner name**: 16 mappings from Ablation scanner class names to T-IDs

CWE lookup takes precedence when both are provided.

## Constructor

```python
from modules.attack_labeler import ATTACKLabeler

label = ATTACKLabeler.label(cwe_class='CWE-78')
# ATTACKLabel(technique_id='T1059.004', technique_name='Unix Shell', source='cwe')

label = ATTACKLabeler.label(scanner_name='AntiAnalysisStringDetector')
# ATTACKLabel(technique_id='T1497', technique_name='Virtualization/Sandbox Evasion', source='scanner')

label = ATTACKLabeler.label(cwe_class='CWE-78', scanner_name='MetacharFilterBypassScanner')
# CWE takes precedence: T1059.004
```

## Methods

| Method | Returns | Notes |
| ------ | ------- | ----- |
| `ATTACKLabeler.label(cwe_class, scanner_name)` | `ATTACKLabel or None` | CWE preferred over scanner |
| `ATTACKLabeler.label_cwe(cwe_class)` | `ATTACKLabel or None` | CWE lookup only |
| `ATTACKLabeler.label_scanner(scanner_name)` | `ATTACKLabel or None` | Scanner lookup only |
| `ATTACKLabeler.all_mappings()` | `dict` | All CWE and scanner mappings |

## ATTACKLabel dataclass

```python
@dataclass
class ATTACKLabel:
    technique_id:   str    # e.g. 'T1059.004'
    technique_name: str    # e.g. 'Unix Shell'
    source:         str    # 'cwe' or 'scanner'
```

## Coverage

**CWE categories covered:**

- Execution: CWE-78, CWE-88, CWE-77, CWE-94
- Process injection: CWE-119, CWE-120, CWE-121, CWE-122, CWE-416, CWE-415, CWE-787
- Credential access: CWE-256, CWE-257, CWE-259, CWE-321, CWE-312, CWE-798
- Defense evasion: CWE-116, CWE-327, CWE-326
- Discovery: CWE-200, CWE-209
- Privilege escalation: CWE-250, CWE-269, CWE-284
- Exfiltration: CWE-319

**Scanners covered:** ProcessInjectionComboScanner, AntiAnalysisStringDetector, HardcodedCredentialScanner, SignalHandlerRaceScanner, DeadSecurityCheckScanner, NonConstantTimeComparatorScanner, WeakPRNGAtSecuritySinkScanner, SizeofPtrDetector, TruncationAtSinkScanner, SignedLengthArgScanner, LethalTrifectaScanner, PromptInjectionSinkClassifier, ELFAnomalyScanner, FirmwarePKIChecker, MetacharFilterBypassScanner, DependencyConfusionScanner.

## Severity and triage

`ATTACKLabeler` does not compute severity itself. Use it after `FindingRegistry.register()` to annotate existing findings. Unmapped CWE classes or scanner names return `None`; callers should handle gracefully.
