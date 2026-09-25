# Ablation -- Active Session Index

## Active target

**FortiExplorer OnlineInstaller v2.6.1083** (PE32 Windows installer)

Session state: `targets/fortinet/SESSION_fortiexplorer_installer.md`
Findings file: `targets/fortinet/fortiexplorer_installer_re.py`

## Other targets (suspended)

| Target | Session file | Status |
|---|---|---|
| FortiGate 7000F | `targets/fortinet/SESSION_fgt7kf.md` | FXE-1 CRIT HTTP MITM→RCE; FXE-2 OpenSSL 1.0.1j; C17 CONFIRMED HIGH; FGT7K-4 HIGH; C14 CANDIDATE pending caller trace |
| FortiManager 8.0.0 | `targets/fortinet/SESSION_fmg800.md` | 54 binary RE + 43 platform RE findings; source recovered 2026-09-24 from pyc; 15 findings pending final status; disclosure merge pending |
| Google Chrome 154.0.8037.57 | `targets/google/SESSION_chrome154.md` | Module scaffolded; sweep pending; chrome-sandbox SUID is priority target |

## How to resume any target

Read the target's session file first -- it has the binary paths, named function table,
confirmed findings, and exact next steps.

```python
# FortiExplorer installer -- PE32, use lief + capstone directly (no BinaryContext)
import lief, capstone
from ablation.targets.fortinet.fortiexplorer_installer_re import (
    BINARY_PATH, disasm_window, print_findings
)
print_findings()
disasm_window(0x40c30c)  # ShellExecuteA call site

# FortiGate 7000F (suspended)
# from ablation.analyzers.binary_context import BinaryContext
# ctx = BinaryContext.load_or_build('/tmp/fgt7kf_libs/lib/libips.so.new')
# print(ctx.names_table())
```
