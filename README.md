
<p align="center">
  <img src="assets/sauce.jpg" width="480" alt="ablation">
</p>

## What is this?

**Ablation** is an autonomous reverse engineering tool that runs on a compromised or test system and maps its attack surface without requiring a debugger, source code, or prior knowledge of the target.

Drop it on a box. It figures out what's running, how things are structured, and where the security boundaries are weak.

## What does it do exactly?

Ablation covers several RE domains through a unified CLI:

| Mode | What it finds |
|------|--------------|
| `--quick` | Platform fingerprint — OS, arch, kernel, container runtime |
| `--process PID` | Live process memory maps, open FDs, loaded libs, heap layout |
| `--binary FILE` | ELF/Mach-O section map, stripped symbol recovery, unsafe call sites |
| `--privesc` | SUID binaries, world-writable paths, cron jobs, sudo rules |
| `--docker` | Container escape surface — socket mounts, cap sets, namespace leaks |
| `--k8s` | Service account tokens, RBAC misconfig, secret exposure |
| `--asa [HOST]` | Cisco ASA WebVPN attack surface, ASDM jar RE, RADIUS overflow path |
| `--jwt FILE` | JWT algorithm confusion, weak key detection, forgeability check |
| `--arm64 FILE` | ARM64 Mach-O deep analysis — Objective-C runtime, Swift type metadata |
| `--java PATH` | Java class/jar security audit — deserialization gadgets, reflection abuse |

Full autonomous mode (`./ablation`) runs all applicable modules and writes a structured findings report.

## Why would I use this?

- You have shell on a box and want a fast map of what's exploitable — faster than running a dozen tools manually
- You're RE-ing a stripped binary (Cisco ASA lina, NX-OS, macOS system daemons) and need to recover struct layouts without source
- You want regression data across firmware versions — the `regression.py` module tracks confirmed struct field offsets across version ranges
- You need a platform-agnostic tool that runs the same way on Linux, macOS, Docker, and Kubernetes environments

## Quick start

```bash
# Full autonomous analysis of the current system
./ablation

# Analyze a specific stripped binary
./ablation --binary /path/to/binary

# Cisco ASA-specific RE (requires lina ELF extraction)
./ablation --asa 192.168.1.1

# RADIUS overflow probe against a test ASA
python3 -c "
from modules.cisco_asa_lina_re import RadiusOverflowProbe
p = RadiusOverflowProbe(version=(9, 20, 3, 0))
print(hex(p.GP_NAME_OFFSET), hex(p.OVERFLOW_DELTA))
"
```

## Requirements

```
Python 3.8+
capstone      # binary disassembly
requests      # optional, falls back to urllib
```

No root required for binary analysis. Some live-process modes need elevated privileges.

## Confirmed data

The `modules/regression.py` module carries version-confirmed struct offsets for Cisco ASA LINA binaries extracted from real firmware images:

| ASA Version | gp_name offset | Source |
|-------------|----------------|--------|
| 9.13.1 | 0x2b0 | ASAv virtioa.qcow2, confirmed |
| 9.14.1.1 | 0x2b0 | FTD 6.6.0 qcow2, confirmed |
| 9.15.1 | 0x2b0 | FTD 6.7.0-65 qcow2, confirmed |
| 9.20.3 | 0x2b0 | ASAv PLR-Licensed qcow2, confirmed |
| 9.22.1.1 | 0x2b0 | ASAv PLR qcow2, confirmed |
| 9.22.2.32 | 0x2b1 | inline-strcpy discriminator, confirmed |

**Transition boundary:** struct layout shifts between 9.22.1.x and 9.22.2.x. Version dispatch is automatic.

---

For authorized security testing only.
