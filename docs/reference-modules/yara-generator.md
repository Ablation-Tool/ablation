# YARA Rule Generation

Generate deployment-ready YARA detection rules from Ablation scan findings: IOC strings, CRITICAL-severity malware API imports, anti-debug byte patterns, and confirmed vulnerability signatures: with auto-generated metadata including the source binary's SHA256.

---

## Why this exists

1. **Findings without detection rules have limited operational value.** An analyst who identifies a backdoor or malware sample in a firmware image needs to answer: "can I detect this at scale: across my environment, across ingested samples, across new firmware versions?" A YARA rule answers that question universally. Without automatic rule generation, analysts must manually translate findings into detection signatures: a step they skip under time pressure.

2. **IOC strings, malware API imports, and byte patterns have different detection properties.** A domain name in a C2 callback requires case-insensitive ASCII/wide matching. A `VirtualAllocEx` import requires a simple string match against the IAT. An anti-debug byte sequence (`EB 04 74 02`) requires a hex pattern match. A single YARA rule format can represent all three, but the generation logic must be type-aware. This module handles each category with the appropriate YARA string type and modifier.

3. **YARA condition logic must balance sensitivity and specificity.** A rule that fires on any single matching string produces too many false positives in large malware corpora. The generator uses `2 of ($s_*)` for IOC strings requiring two independent matches and `any of ($api_*)` for CRITICAL API imports (a single CRITICAL import like `NtCreateThreadEx` is a strong signal on its own). This calibration reflects the different false-positive rates of string vs. API indicators.

---

## How it works

```mermaid
flowchart TD
    A[findings dict or raw strings list] --> B{Generation path}
    B -->|PE scan findings| C["generate_from_pe_findings(findings, filepath)"]
    B -->|raw strings| D["generate_from_strings(strings, name)"]
    B -->|process injection| E["generate_process_injection_rule()"]
    C --> F[rule name: mal_{basename}_{sha256_16}]
    F --> G[meta: description, author_type, date, sha256]
    G --> H["Process IOC strings:\nfor each ioc in findings['ioc_strings']\nescape and add with 'ascii wide nocase'\ndedup by value"]
    H --> I["Process CRITICAL malware APIs:\nfor each api where severity=='CRITICAL'\nadd import name with 'ascii wide'\ndedup"]
    I --> J["Process anti_debug byte patterns:\nhex-format bytes or parse hex strings\nadd as { XX XX XX } byte pattern"]
    J --> K["Assemble condition:\n2 of ($s_*) for strings\nany of ($api_*) for APIs\nany of ($b_*) for bytes\nOR combination"]
    K --> L[YARARule.to_text(): serialize to YARA syntax]
    D --> M["Sanitize identifiers: _IDENT_RE strips non-alphanumeric\nDedup by string value\n'any of them' condition"]
    M --> L
    E --> N["Hardcoded API triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread\nAdditional: QueueUserAPC, RtlCreateUserThread, NtCreateThreadEx\nCondition: 3 of ($write_*) and ($create_remote or $queue_apc)"]
    N --> L
```

### Rule naming

Rule names are automatically sanitized to YARA-safe identifiers. For PE file-based rules:
```
rule_name = mal_{basename}_{sha256[:16]}
```
The SHA256 prefix ensures uniqueness across renamed malware samples. Non-alphanumeric characters in the filename are replaced with `_`.

### String types and modifiers

| Source | YARA String Type | Modifiers |
|---|---|---|
| IOC strings IP, domain, path, key | `"quoted string"` | `ascii wide nocase` |
| CRITICAL malware API names | `"quoted string"` | `ascii wide` |
| Anti-debug byte patterns | `{ HH HH HH }` hex | (none) |

### Condition assembly

The condition combines the three string categories with `OR`:
- If IOC strings present: `2 of ($s_*)`
- If CRITICAL APIs present: `any of ($api_*)`
- If byte patterns present: `any of ($b_*)`
- If only one category: just that condition
- If nothing: `false` empty rule that never matches

---

## Usage

```python
from ablation.core.yara_generator import (
    generate_from_pe_findings,
    generate_from_strings,
    generate_process_injection_rule,
    YARARule,
)

# From a PE scan findings dict
findings = {
    'ioc_strings': [
        {'type': 'domain', 'value': 'c2.evil.com'},
        {'type': 'ip', 'value': '10.13.37.1'},
    ],
    'malware_apis': [
        {'api': 'VirtualAllocEx', 'severity': 'CRITICAL'},
        {'api': 'WriteProcessMemory', 'severity': 'CRITICAL'},
    ],
    'anti_debug': [],
}
rule = generate_from_pe_findings(findings, '/samples/malware.exe')
print(rule.to_text())

# From a raw list of IOC strings
strings = ['evil.example.com', 'cmd.exe /c', 'HTTP/1.1 200 OK']
rule = generate_from_strings(strings, name='suspicious_agent')
print(rule.to_text())

# Pre-built process injection detection rule
rule = generate_process_injection_rule()
print(rule.to_text())
```

### Building a rule manually

```python
from ablation.core.yara_generator import YARARule

rule = YARARule(
    name="custom_backdoor_detection",
    meta={
        "description": "Confirmed backdoor: recv_handler at 0x22ccc0",
        "author": "ablation",
        "date": "2026-10-16",
    },
    strings=[
        ("$str_0", '"admin_backdoor_key"', "ascii wide nocase"),
        ("$api_0", '"NtCreateThreadEx"', "ascii wide"),
        ("$bytes_0", "{ E8 ?? ?? ?? ?? 48 85 C0 74 }", ""),
    ],
    condition="($str_0 and $api_0) or $bytes_0",
)
print(rule.to_text())
```

---

## Example output

```yara
rule mal_malware_exe_3a4f8c1d2b9e7f5a
{
    meta:
        description = "Auto-generated rule for malware.exe"
        author_type = "automated"
        date = "2026-10-16"
        sha256 = "3a4f8c1d2b9e7f5aabcdef1234567890..."

    strings:
        $s_0_c2_evil_com = "c2.evil.com" ascii wide nocase
        $s_1_10_13_37_1 = "10.13.37.1" ascii wide nocase
        $api_0_VirtualAllocEx = "VirtualAllocEx" ascii wide
        $api_1_WriteProcessMemory = "WriteProcessMemory" ascii wide

    condition:
        (2 of ($s_*)) or (any of ($api_*))
}
```

---

## False positives

**Shared IOC strings with common values.** If an IOC string is a common domain or IP address for example `127.0.0.1`, `example.com`, the `2 of ($s_*)` condition does not filter it out. Only one instance of a widely shared string could still match alongside another one. Remove obviously common values from the IOC strings input before calling the generator.

**API names in security utilities.** Anti-malware, EDR agents, and debugging tools legitimately import `NtCreateThreadEx`, `VirtualAllocEx`, and other CRITICAL APIs for monitoring purposes. The CRITICAL threshold in the generator is calibrated for untrusted samples: applying generated rules to enterprise endpoint binaries will produce false positives.

**Empty rules (`condition: false`).** When the findings dict is empty no IOC strings, no CRITICAL APIs, no byte patterns, the generator emits a rule with `condition: false`. This is a syntactically valid YARA rule that never matches. Validate that the findings input is populated before generating rules for deployment.

---

## Pipeline position

**Before this module:** Any Ablation scanner that produces findings with `type`/`description`/`severity` fields. PE scan findings from the PE analyzer; string extractions from `BinaryContext.strings`; byte patterns from confirmed vulnerability findings.

**After this module:** YARA rules are ready for deployment to YARA scanners, threat intelligence platforms, or host-based detection systems. Rules should be tested against a known-positive sample before deployment.

---

## Reading the output

| Field | Content |
|:---|:---|
| `rule.name` | YARA rule identifier alphanumeric + underscore, unique per binary SHA256 |
| `rule.meta` | Dict of metadata fields: description, author_type, date, sha256 |
| `rule.strings` | List of `identifier, value, modifiers` tuples |
| `rule.condition` | YARA condition expression |
| `rule.to_text()` | Full YARA rule in YARA syntax, ready for deployment |

---

## See also

- [ATT&CK Labeling](attandck-labeling.md): enrich findings with technique IDs before generating rules
- [Binary Context](binary-context.md): provides string extractions for rule generation
- [Finding Registry](finding-registry.md): source of confirmed findings for high-confidence rule generation
- [IOC Candidate Extraction](ioc-candidate-extraction.md): extract IP/domain/key candidates for `ioc_strings` input
