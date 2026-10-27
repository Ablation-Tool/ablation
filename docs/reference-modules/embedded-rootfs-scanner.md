# EmbeddedRootfsScanner

**Module**: `ablation/analyzers/embedded_rootfs_scanner.py`

---

## Why this exists

1. Every embedded Linux firmware image (PetaLinux, OpenWRT, Yocto, Buildroot) requires the same manual security checks: empty/weak credentials, inetd dangerous services, systemd autostart units, SSH config, SUID binaries. These were repeated manually on every new image.
2. The PetaLinux GEP analysis session for facility ATLAS confirmed the pattern: the same 8-step enumeration applied to every rootfs from every board variant.
3. Wrapping this into a structured scanner produces machine-readable findings rather than prose notes, enabling programmatic triage across multiple image variants (e.g., all 10 GCM415/GCM4 images).

---

## Inputs

Two constructor paths:

```python
# From an extracted rootfs directory tree
scanner = EmbeddedRootfsScanner.from_dir('/tmp/rootfs_extract/')

# From a raw WIC/img disk image (delegates to DiskImageExtractor)
scanner = EmbeddedRootfsScanner.from_image('/path/to/image.wic', partition_index=1)
```

---

## Checks performed

| Check | Files read | Key signal |
|-------|-----------|------------|
| `_check_shadow` | `/etc/shadow` | Empty password field (`root::`) |
| `_check_passwd` | `/etc/passwd` | Inline plaintext password |
| `_check_inetd` | `/etc/inetd.conf` | Dangerous services (telnet, ftp, rsh, rlogin, rexec, tftp) running as root |
| `_check_ssh_config` | `/etc/ssh/sshd_config` | `PermitRootLogin yes`, password auth with PAM |
| `_check_systemd_autostart` | `multi-user.target.wants/` in `/etc/`, `/usr/lib/`, `/lib/` | TCF agent (HIGH), inetd, NFS services |
| `_check_ipbus_shim` | `/usr/bin/runGepIpbusShim.sh`, `/usr/bin/runIpbusShim.sh` | Ports and /dev/mem base addresses of TCP-to-register bridges |
| `_check_suid` | `find -perm -4000` | SUID binaries (capped at 50 results) |

---

## RootfsFinding dataclass

```python
@dataclass
class RootfsFinding:
    severity: str   # HIGH | MEDIUM | LOW | INFO
    category: str   # CREDENTIAL | SERVICE | INETD | SSH | NFS | DEBUG | SUID
    title:    str
    detail:   str   # evidence (file content snippet, path)
```

Findings are sorted by severity (HIGH → INFO) in the returned list.

---

## Constructor patterns

```python
from ablation.analyzers.embedded_rootfs_scanner import EmbeddedRootfsScanner

# Directory tree
scanner = EmbeddedRootfsScanner.from_dir('/tmp/rootfs/')
findings = scanner.scan()
print(scanner.report(findings))

# Filter to HIGH only
high = [f for f in findings if f.severity == 'HIGH']

# Batch across multiple images
from ablation.analyzers.disk_image_extractor import DiskImageExtractor
for wic in Path('/media/cowboy/research/facility/fw/gep/').glob('*.wic.gz'):
    # Decompress first, then:
    scanner = EmbeddedRootfsScanner.from_image(str(wic_decompressed))
    findings = scanner.scan()
    high_count = sum(1 for f in findings if f.severity == 'HIGH')
    print(f'{wic.name}: {high_count} HIGH findings')
```

---

## Known limitations

- SUID enumeration via `find -perm -4000` only works on extracted directory trees. For image-mode, `find_suid()` on the extractor checks mode bits via `istat`, which is slow (capped at 2000 files).
- `/etc/init.d` SysV init scripts are not checked (systemd only).
- Does not analyze the actual service binaries — use `SinkArgClassifier` on binaries found via `_check_systemd_autostart` for the next RE step.

[↑ Back to INDEX](../INDEX.md)
