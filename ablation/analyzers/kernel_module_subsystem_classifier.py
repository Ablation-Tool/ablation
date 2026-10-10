"""
kernel_module_subsystem_classifier.py: infers attack surface from a Linux kernel
module's path in the kernel source tree.

Linux kernel modules follow a well-structured source layout.  Given a .ko file path
like:
    .../kernel/net/mac80211/mac80211.ko
    .../kernel/fs/dlm/dlm.ko
    .../kernel/drivers/usb/serial/cyberjack.ko

the subsystem (the path component after .../kernel/) deterministically maps to a
standard attack surface classification:

    net/mac80211/         → PROXIMITY  (any WiFi-capable device nearby)
    net/wireless/         → PROXIMITY
    net/bluetooth/        → PROXIMITY-BT
    fs/dlm/               → NETWORK-cluster  (GFS2/OCFS2 DLM over TCP)
    net/                  → NETWORK
    drivers/net/wireless/ → PROXIMITY
    drivers/usb/          → LOCAL-USB
    drivers/isdn/         → LOCAL-HARDWARE-ISDN
    drivers/media/        → LOCAL-HARDWARE-MEDIA
    drivers/message/      → LOCAL-HARDWARE-SAS
    sound/                → LOCAL-DEV-ACCESS
    drivers/              → LOCAL-HARDWARE
    fs/                   → LOCAL
    ...                   → LOCAL (fallback)

Usage:
    from ablation.analyzers.kernel_module_subsystem_classifier import (
        KernelModuleSubsystemClassifier, KernelModuleClassification,
    )

    clf = KernelModuleSubsystemClassifier()
    result = clf.classify('/path/to/kernel_modules/kernel/net/mac80211/mac80211.ko')
    print(result.attack_surface)    # "PROXIMITY"
    print(result.subsystem)         # "net/mac80211"
    print(result.network_reachable) # True
    print(result.confidence)        # "HIGH"

    # Classify a batch:
    rows = clf.classify_batch([path1, path2, ...])
    print(KernelModuleSubsystemClassifier.report(rows))
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class KernelModuleClassification:
    ko_path: str
    subsystem: str          # e.g. "net/mac80211", "fs/dlm", "drivers/usb/serial"
    attack_surface: str     # e.g. "PROXIMITY", "NETWORK-cluster", "LOCAL-USB"
    network_reachable: bool # True = reachable without physical access
    confidence: str         # "HIGH" (exact rule) / "MEDIUM" (broad rule) / "LOW" (fallback)
    rule_matched: str       # the prefix rule that matched, for auditability

    def as_dict(self) -> dict:
        return {
            "ko_path": self.ko_path,
            "subsystem": self.subsystem,
            "attack_surface": self.attack_surface,
            "network_reachable": self.network_reachable,
            "confidence": self.confidence,
            "rule_matched": self.rule_matched,
        }


# Each rule: (subsystem_prefix, canonical_subsystem_label, attack_surface, network_reachable, confidence)
# Order matters: most-specific first; first match wins.
_SUBSYSTEM_RULES = [
    # 802.11 WiFi — all drivers share the mac80211 stack; any nearby AP can trigger
    ("net/mac80211/",               "net/mac80211",               "PROXIMITY",          True,  "HIGH"),
    ("net/wireless/",               "net/wireless",               "PROXIMITY",          True,  "HIGH"),
    ("drivers/net/wireless/",       "drivers/net/wireless",       "PROXIMITY",          True,  "HIGH"),

    # Bluetooth — proximity RF
    ("net/bluetooth/",              "net/bluetooth",              "PROXIMITY-BT",       True,  "HIGH"),
    ("drivers/bluetooth/",          "drivers/bluetooth",          "PROXIMITY-BT",       True,  "HIGH"),

    # DLM cluster filesystem distributed lock manager — TCP cluster network
    ("fs/dlm/",                     "fs/dlm",                     "NETWORK-cluster",    True,  "HIGH"),

    # NFS server receives network frames
    ("fs/nfsd/",                    "fs/nfsd",                    "NETWORK",            True,  "HIGH"),
    ("net/sunrpc/",                 "net/sunrpc",                 "NETWORK",            True,  "HIGH"),

    # Broad network subsystem
    ("net/",                        "net",                        "NETWORK",            True,  "MEDIUM"),

    # USB serial adapters (smart cards, GPS, modems) — physical USB device required
    ("drivers/usb/serial/",         "drivers/usb/serial",         "LOCAL-USB",          False, "HIGH"),
    ("drivers/usb/storage/",        "drivers/usb/storage",        "LOCAL-USB",          False, "HIGH"),
    ("drivers/usb/atm/",            "drivers/usb/atm",            "LOCAL-USB",          False, "HIGH"),
    ("drivers/usb/gadget/",         "drivers/usb/gadget",         "LOCAL-USB",          False, "HIGH"),
    ("drivers/usb/",                "drivers/usb",                "LOCAL-USB",          False, "MEDIUM"),

    # ISDN hardware
    ("drivers/isdn/",               "drivers/isdn",               "LOCAL-HARDWARE-ISDN",False, "HIGH"),

    # Media (DVB, cameras, tuners) — USB/PCIe hardware device
    ("drivers/media/",              "drivers/media",              "LOCAL-HARDWARE-MEDIA",False,"HIGH"),

    # LSI MPT SAS/FC HBA
    ("drivers/message/fusion/",     "drivers/message/fusion",     "LOCAL-HARDWARE-SAS", False, "HIGH"),

    # SCSI stack
    ("drivers/scsi/",               "drivers/scsi",               "LOCAL-HARDWARE-SCSI",False, "HIGH"),

    # Sound / ALSA — /dev/midi*, /dev/dsp*, audio group access
    ("sound/",                      "sound",                      "LOCAL-DEV-ACCESS",   False, "HIGH"),

    # DRM GPU
    ("drivers/gpu/drm/",            "drivers/gpu/drm",            "LOCAL-DRM",          False, "HIGH"),

    # Block devices
    ("drivers/block/",              "drivers/block",              "LOCAL-HARDWARE-BLOCK",False,"MEDIUM"),
    ("drivers/nvme/",               "drivers/nvme",               "LOCAL-HARDWARE-NVME",False, "HIGH"),

    # Broad drivers fallback
    ("drivers/",                    "drivers",                    "LOCAL-HARDWARE",     False, "MEDIUM"),

    # Filesystems — userspace mounts, usually needs CAP_SYS_ADMIN
    ("fs/",                         "fs",                         "LOCAL",              False, "MEDIUM"),

    # Core kernel
    ("kernel/",                     "kernel",                     "LOCAL",              False, "MEDIUM"),
    ("mm/",                         "mm",                         "LOCAL",              False, "MEDIUM"),
    ("crypto/",                     "crypto",                     "LOCAL",              False, "MEDIUM"),
    ("lib/",                        "lib",                        "LOCAL",              False, "MEDIUM"),
    ("security/",                   "security",                   "LOCAL",              False, "MEDIUM"),
]


def _check_rule_order() -> None:
    for i, (prefix_i, *_) in enumerate(_SUBSYSTEM_RULES):
        for j in range(i + 1, len(_SUBSYSTEM_RULES)):
            prefix_j = _SUBSYSTEM_RULES[j][0]
            if prefix_j.startswith(prefix_i) and prefix_j != prefix_i:
                raise AssertionError(
                    f"_SUBSYSTEM_RULES ordering error: rule {j} ({prefix_j!r}) is more "
                    f"specific than rule {i} ({prefix_i!r}) but comes after it. "
                    "More-specific rules must appear first."
                )


_check_rule_order()


def _extract_subsystem_path(ko_path: str) -> Optional[str]:
    """Return the path component after '.../kernel/' in a standard kernel module path.

    e.g. '/lib/modules/.../kernel/net/mac80211/mac80211.ko' → 'net/mac80211/mac80211.ko'
    Returns None if the path doesn't contain a '/kernel/' component.
    """
    parts = Path(ko_path).parts
    indices = [i for i, p in enumerate(parts) if p == "kernel"]
    if not indices:
        return None
    idx = indices[-1]
    # Join everything after 'kernel/'
    return "/".join(parts[idx + 1:])


class KernelModuleSubsystemClassifier:
    """Classify Linux kernel .ko files by attack surface based on source tree path."""

    def classify(self, ko_path: str) -> KernelModuleClassification:
        """Return a KernelModuleClassification for the given .ko path."""
        ko_path = str(ko_path)
        rel = _extract_subsystem_path(ko_path)

        if rel is None:
            # Path doesn't contain /kernel/ component — try basename heuristics
            return KernelModuleClassification(
                ko_path=ko_path,
                subsystem="unknown",
                attack_surface="LOCAL",
                network_reachable=False,
                confidence="LOW",
                rule_matched="(no /kernel/ component in path)",
            )

        for prefix, label, surface, net_reach, conf in _SUBSYSTEM_RULES:
            if rel.startswith(prefix):
                return KernelModuleClassification(
                    ko_path=ko_path,
                    subsystem=label,
                    attack_surface=surface,
                    network_reachable=net_reach,
                    confidence=conf,
                    rule_matched=prefix,
                )

        # Fallback
        # Use the top-level directory as the subsystem label
        top = rel.split("/")[0] if "/" in rel else rel
        return KernelModuleClassification(
            ko_path=ko_path,
            subsystem=top,
            attack_surface="LOCAL",
            network_reachable=False,
            confidence="LOW",
            rule_matched="(fallback)",
        )

    def classify_batch(self, ko_paths: List[str]) -> List[KernelModuleClassification]:
        return [self.classify(p) for p in ko_paths]

    @staticmethod
    def report(results: List[KernelModuleClassification]) -> str:
        if not results:
            return "(no results)"
        lines = [
            f"{'Module':<40} {'Subsystem':<30} {'Surface':<22} {'Net':^3} {'Conf':^6}",
            "-" * 108,
        ]
        for r in results:
            name = os.path.basename(r.ko_path)
            lines.append(
                f"{name:<40} {r.subsystem:<30} {r.attack_surface:<22}"
                f" {'Y' if r.network_reachable else 'N':^3} {r.confidence:^6}"
            )
        net_reach = sum(1 for r in results if r.network_reachable)
        lines.append(f"\n{len(results)} modules classified; {net_reach} network-reachable")
        return "\n".join(lines)
