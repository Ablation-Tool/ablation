# Ablation -- Active Session Index

## Active target

**FortiSOAR Connector Repository Survey** (https://repo.fortisoar.fortinet.com/connectors/x86_64/)

Surveying available RPMs for next audit target.

## Other targets (suspended)

| Target | Session file | Status |
|---|---|---|
| FSR Agent Bridge v1.3.0 | `targets/fortinet/SESSION_fsr_agent_bridge.md` | ACB-1 HIGH (open redirect+JWT leak); ACB-2 HIGH (XSS); ACB-3/4/5 CONFIRMED; pending: PoC, scheme.so key source |
| Cisco ThreatGrid v1.3.0 | `targets/fortinet/SESSION_threatgrid.md` | COMPLETE -- 7 findings (TG-1/2 HIGH: api_key logged+persisted in DB) |
| Cisco Talos TI v1.0.0 | targets/fortinet/SESSION_talos_ti.md | publisher=SpryIQ.co cs_approved=false; CT-1/2/4 CONFIRMED; COMPLETE |
| FortiExplorer OnlineInstaller v2.6.1083 | `targets/fortinet/SESSION_fortiexplorer_installer.md` | FXE-1 CRIT HTTP MITM→RCE; FXE-2 OpenSSL 1.0.1j; pending: port confirm + PoC |
| FortiGate 7000F | `targets/fortinet/SESSION_fgt7kf.md` | C17 CONFIRMED HIGH; FGT7K-4 HIGH; C14 CANDIDATE pending caller trace |
| FortiManager 8.0.0 | `targets/fortinet/SESSION_fmg800.md` | 54 binary RE + 43 platform RE findings; source recovered 2026-09-24 from pyc; 15 findings pending final status; disclosure merge pending |
| Google Chrome 154.0.8037.57 | `targets/google/SESSION_chrome154.md` | Module scaffolded; sweep pending; chrome-sandbox SUID is priority target |

## How to resume any target

Read the target's session file first -- it has the binary paths, named function table,
confirmed findings, and exact next steps.

```python
# FSR Agent Bridge -- Python source + Cython .so
from ablation.targets.fortinet.fsr_agent_bridge_re import print_findings, scheme_so_disasm
print_findings()
scheme_so_disasm(0x8340)  # validate_token entry

# FortiExplorer installer (suspended) -- PE32, lief + capstone
# from ablation.targets.fortinet.fortiexplorer_installer_re import disasm_window, print_findings
# disasm_window(0x40c30c)  # ShellExecuteA call site

# FortiGate 7000F (suspended)
# from ablation.analyzers.binary_context import BinaryContext
# ctx = BinaryContext.load_or_build('/tmp/fgt7kf_libs/lib/libips.so.new')
# print(ctx.names_table())
```
