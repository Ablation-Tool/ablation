# KernelModuleSubsystemClassifier

## Why this exists

2 things that weren't possible before in Ablation:

1. **Every kernel module finding required manual attack surface annotation.** When `LA64MaxNotMinScanner` ran across 1096 `.ko` files and found 35 modules with findings, the output gave only `pattern_va` and `sink_name`. Nothing indicated whether `mac80211.ko` is PROXIMITY (any nearby WiFi AP) or LOCAL. In S35 every finding's `attack_surface` field was filled in by hand, one module at a time, by mentally navigating the kernel source tree. For a systematic 1096-module sweep this is the bottleneck.

2. **A MEDIUM finding in `mac80211.ko` and a MEDIUM finding in `mptbase.ko` looked identical in scanner output.** The first is reachable by any attacker in WiFi range. The second requires a specific LSI HBA installed in the machine. Without attack surface, the researcher has no way to sort findings by actual reach without looking up each module's subsystem separately.

`KernelModuleSubsystemClassifier` takes a `.ko` file path and returns the attack surface, subsystem label, network reachability, and confidence by matching the path after `.../kernel/` against a rule table. The rule table covers the standard Linux kernel source layout and is correct for `lib/modules/<version>/kernel/` paths from standard distribution packages.

## Usage

```python
from ablation.analyzers.kernel_module_subsystem_classifier import (
    KernelModuleSubsystemClassifier,
    KernelModuleClassification,
)

clf = KernelModuleSubsystemClassifier()

r = clf.classify('/lib/modules/6.6.119/kernel/net/mac80211/mac80211.ko')
print(r.attack_surface)     # "PROXIMITY"
print(r.subsystem)          # "net/mac80211"
print(r.network_reachable)  # True
print(r.confidence)         # "HIGH"
print(r.rule_matched)       # "net/mac80211/"

# Batch with report.
ko_files = list(Path('/lib/modules/.../kernel/').rglob('*.ko'))
results = clf.classify_batch([str(p) for p in ko_files])
print(KernelModuleSubsystemClassifier.report(results))
```

## Integration with LA64MaxNotMinScanner

```python
from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner
from ablation.analyzers.kernel_module_subsystem_classifier import KernelModuleSubsystemClassifier
from ablation.analyzers.scan_result_version_cache import ScanResultVersionCache
from pathlib import Path

cache = ScanResultVersionCache.for_scanner(LA64MaxNotMinScanner)
clf = KernelModuleSubsystemClassifier()

for ko_path in ko_files:
    findings = cache.get_or_scan(ko_path)
    if not findings:
        continue
    cls = clf.classify(ko_path)
    for f in findings:
        print(
            f"{Path(ko_path).name:<30}  "
            f"pattern@0x{f['pattern_va']:x}  "
            f"{cls.attack_surface:<22}  "
            f"net={cls.network_reachable}"
        )

cache.save()
```

## Rule table

Rules match most-specific first. First match wins.

| Prefix | Attack surface | Network-reachable | Confidence |
|--------|---------------|-------------------|------------|
| `net/mac80211/` | PROXIMITY | Yes | HIGH |
| `net/wireless/` | PROXIMITY | Yes | HIGH |
| `drivers/net/wireless/` | PROXIMITY | Yes | HIGH |
| `net/bluetooth/` | PROXIMITY-BT | Yes | HIGH |
| `drivers/bluetooth/` | PROXIMITY-BT | Yes | HIGH |
| `fs/dlm/` | NETWORK-cluster | Yes | HIGH |
| `fs/nfsd/` | NETWORK | Yes | HIGH |
| `net/sunrpc/` | NETWORK | Yes | HIGH |
| `net/` | NETWORK | Yes | MEDIUM |
| `drivers/usb/serial/` | LOCAL-USB | No | HIGH |
| `drivers/usb/storage/` | LOCAL-USB | No | HIGH |
| `drivers/usb/atm/` | LOCAL-USB | No | HIGH |
| `drivers/usb/gadget/` | LOCAL-USB | No | HIGH |
| `drivers/usb/` | LOCAL-USB | No | MEDIUM |
| `drivers/isdn/` | LOCAL-HARDWARE-ISDN | No | HIGH |
| `drivers/media/` | LOCAL-HARDWARE-MEDIA | No | HIGH |
| `drivers/message/fusion/` | LOCAL-HARDWARE-SAS | No | HIGH |
| `drivers/scsi/` | LOCAL-HARDWARE-SCSI | No | HIGH |
| `sound/` | LOCAL-DEV-ACCESS | No | HIGH |
| `drivers/gpu/drm/` | LOCAL-DRM | No | HIGH |
| `drivers/block/` | LOCAL-HARDWARE-BLOCK | No | MEDIUM |
| `drivers/nvme/` | LOCAL-HARDWARE-NVME | No | HIGH |
| `drivers/` | LOCAL-HARDWARE | No | MEDIUM |
| `fs/` | LOCAL | No | MEDIUM |
| `kernel/`, `mm/`, `crypto/`, `lib/`, `security/` | LOCAL | No | MEDIUM |
| *(fallback)* | LOCAL | No | LOW |

## Adding rules

Add entries to `_SUBSYSTEM_RULES` in the module. Put more-specific prefixes before broader ones. Each entry is:

```python
("subsystem/prefix/", "canonical-label", "ATTACK_SURFACE", network_reachable_bool, "CONFIDENCE")
```

Use HIGH confidence for unambiguous subsystems, MEDIUM for broad prefixes where individual modules may behave differently.

## Limitation

`_extract_subsystem_path` finds the first directory component named exactly `kernel` in the path. Standard Linux package paths have exactly one such component (`lib/modules/<version>/kernel/`). Paths with multiple components named `kernel` would match the first one, which may be wrong.
