# Ablation -- Active Session Index

## Active target

**FortiGate 7000F** (FortiOS 8.0.0 build 0167)

Session state: `targets/fortinet/SESSION_fgt7kf.md`
Findings file: `targets/fortinet/fortinet_fortigate_7000f_re.py`

## Other targets (suspended)

| Target | Session file | Status |
|---|---|---|
| FortiManager 8.0.0 | `targets/fortinet/SESSION_fmg800.md` | 54 binary RE + 43 platform RE findings; source recovered 2026-09-24 from pyc; 15 findings pending final status; disclosure merge pending |
| Google Chrome 154.0.8037.57 | `targets/google/SESSION_chrome154.md` | Module scaffolded; sweep pending; chrome-sandbox SUID is priority target |

## How to resume any target

Read the target's session file first -- it has the binary paths, named function table,
confirmed findings, and exact next steps.

```python
# FortiGate 7000F
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/tmp/fgt7kf_libs/lib/libips.so.new')
print(ctx.names_table())  # 20 named functions
```
