"""
TencentOS Server 4.0 Minimal Container Image RE Module
Source: /media/cowboy/research/tencentos/4.0/tencentos-server-4.0-minimal-x86_64.tar (229MB)
  Repo tag: tencentos/tencentos_server40_mini:latest
  Layer: 2a50f168f0eab0596f87af37df795295e501e74f7deaa74e080b07eab05633ee/layer.tar
  RPM database: usr/lib/sysimage/rpm/rpmdb.sqlite (5,992,448 bytes)
  Created: 2024-03-22T07:56:13.840046479Z (same day as standard 4.0 container)
Method: layer.tar extraction; RPM blob header parse (no-magic format; il/dl header)
Analysis date: 2026-09-04

The minimal container strips down to 131 packages vs the standard TOS 4.0 container's
full install set. Key difference: openssh-server and openssh-clients are NOT present
in the minimal image. libssh IS present (git-over-SSH dependency).

This analysis confirms: the Terrapin-unpatched libssh 0.10.5-3 ships even in the
minimal base container, establishing it as a base image dependency for all TOS 4.x
containerized workloads that build on the mini base.
"""

COMPONENT_VERSIONS_TOS40_MINIMAL = {
    "libssh":       "0.10.5-3.tl4",
    "openssl-libs": "3.0.12-3.tl4",
    "glibc":        "2.38-5.tl4",
    "pam":          "1.5.3-4.tl4",
    "python3":      "3.11.6-2.tl4",
    "bash":         "5.2.15-2.tl4",
    "curl":         "8.4.0-4.tl4",
    "libcurl":      "8.4.0-4.tl4",
    "expat":        "2.5.0-2.tl4",
    "krb5-libs":    "1.21.2-1.tl4",
    "rpm":          "4.18.2-1.tl4",
    "dnf":          "4.16.2-2.tl4",
    "coreutils":    "9.4-2.tl4",
    "xz":           "5.4.4-1.tl4",
}

ABSENT_FROM_MINIMAL = [
    "openssh",
    "openssh-server",
    "openssh-clients",
    "openssh-askpass",
    "kernel",
    "kernel-headers",
    "kernel-core",
    "sudo",
    "polkit",
    "polkit-libs",
    "bind-libs",
    "nss",
    "systemd",
    "NetworkManager",
]

COMPARISON_WITH_STANDARD = {
    "total_packages": {"minimal": 131, "standard": "~200+"},
    "libssh":       {"minimal": "0.10.5-3.tl4", "standard": "0.10.5-3.tl4", "delta": "identical"},
    "openssl-libs": {"minimal": "3.0.12-3.tl4", "standard": "3.0.12-3.tl4", "delta": "identical"},
    "glibc":        {"minimal": "2.38-5.tl4",   "standard": "2.38-5.tl4",   "delta": "identical"},
    "rpm":          {"minimal": "4.18.2-1.tl4", "standard": "4.18.2-4.tl4", "delta": "standard has +3 releases"},
    "dnf":          {"minimal": "4.16.2-2.tl4", "standard": "4.16.2-5.tl4", "delta": "standard has +3 releases"},
    "pam":          {"minimal": "1.5.3-4.tl4",  "standard": "1.5.3-4.tl4",  "delta": "identical"},
    "note": (
        "Both containers were built on 2024-03-22. Package version differences are minor "
        "(rpm and dnf release counters differ). Security-relevant packages (libssh, openssl, "
        "glibc) are identical between minimal and standard. "
        "The minimal image is the intended base layer for containerized TOS 4.0 applications."
    ),
}

FINDINGS = {
    "TOS40M-F01": {
        "title": (
            "libssh 0.10.5-3 Present in TOS 4.0 Minimal Base Container; "
            "Confirms Terrapin-Unpatched libssh Is Baked Into All TOS 4.x Container Base Images; "
            "Any Container Layered on Top Inherits the Unfixed Dependency"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "libssh-0.10.5-3.tl4 (TOS 4.0 minimal base container)",
        "description": (
            "The TOS 4.0 minimal base container (tencentos_server40_mini) contains libssh 0.10.5-3, "
            "the same Terrapin-unpatched version as the standard TOS 4.0 container and "
            "all subsequent TOS 4.x releases. "
            "\n"
            "Significance of this finding: the minimal image is the base layer Tencent provides "
            "for containerized workloads. Any Docker image that uses "
            "'FROM tencentos/tencentos_server40_mini' (or equivalent TOS 4.x mini tags) "
            "inherits libssh 0.10.5 into the dependency graph. "
            "\n"
            "The openssh server is NOT in the minimal image (not installed = no SSH daemon attack "
            "surface directly from sshd). However libssh is present for git-over-SSH and "
            "any automation tooling that calls libssh functions as a client library. "
            "\n"
            "This confirms that the libssh Terrapin exposure is not just a server-side issue "
            "on full TOS installs — it is part of the base container image that any "
            "TOS 4.x containerized application starts from."
        ),
        "chain": (
            "TOS40M-F01: application container FROM tencentos_server40_mini → "
            "libssh 0.10.5 in dependency graph → "
            "app performs git-over-SSH or SSH automation → "
            "Terrapin MitM attack possible on that SSH session"
        ),
        "references": [
            "CVE-2023-48795",
            "TOS40-F01 (tencent_tos40_container_re.py) — standard container same version",
            "TOS46-C01 (tencent_tos46_components_re.py) — 27 months unfixed",
        ],
    },
    "TOS40M-F02": {
        "title": (
            "openssh Absent from TOS 4.0 Minimal Container (131 packages); "
            "No sshd Attack Surface on Minimal Base Layer; "
            "Only libssh Client Library Present (git/automation use case)"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "component": "openssh absent; libssh-0.10.5-3.tl4 present",
        "description": (
            "The minimal container does not include openssh-server, openssh-clients, or "
            "any openssh subpackage. This means there is no sshd daemon in the base image, "
            "no SSH client binary (/usr/bin/ssh), and no ssh-keygen or ssh-agent. "
            "\n"
            "libssh IS present because it is a dependency of libgit2 and similar libraries "
            "that implement SSH transport at the library level (used by git clone over SSH, "
            "CI runners, automation frameworks). "
            "\n"
            "From an attack surface perspective: the minimal base container has no SSH daemon "
            "(reduced server-side exposure), but retains the libssh library for client-side "
            "SSH operations, which is where the Terrapin vulnerability applies."
        ),
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "tencentos-server-4.0-minimal-x86_64.tar (Docker image, 229MB)",
        "method": "layer.tar extraction; RPM blob header parse (no-magic format)",
        "total_packages": 131,
        "created": "2024-03-22",
        "libssh": "0.10.5-3.tl4 (Terrapin unpatched — same as standard container)",
        "openssh": "ABSENT (not in minimal base)",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
