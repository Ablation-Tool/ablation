"""
TencentOS Server 3.1 AppStream freeradius RE Module
Binary: radiusd (490KB), libfreeradius-radius.so (261KB)
Source: freeradius-3.0.20-15.module+el8.10.0+674+9c8bec55.x86_64.rpm
        Google Drive ID: 1GPaF6ocpChVYj1WI_MaXncbMpsC2K1vp (1.18MB RPM)
Method: rpm2cpio extraction + string scan + spec/patch enumeration
Analysis date: 2026-09-04

DIST TAG NOTE:
  All TOS 3.1 freeradius packages carry dist tags: module+el8.x.0+NNN+hhh
  NOT .tl3. This is the RHEL 8 AppStream modularity dist tag.
  Tencent does NOT rebuild freeradius; packages come from upstream RHEL 8
  AppStream module builds. No Tencent-specific patch layer applies.

VERSION LADDER (all on Google Drive, same parentId = TencentOS-x86_64 folder):
  3.0.20-12.module+el8.6.0+206+096952b1  (Dec 2022 — RHEL 8.6 AppStream era)
  3.0.20-14.module+el8.8.0+465+fc8f8486  (Jun 2023 — RHEL 8.8 AppStream era)
  3.0.20-15.module+el8.10.0+674+9c8bec55 (Aug 2024 — RHEL 8.10 AppStream era) <- LATEST

CROSS-VERSION FREERADIUS TABLE:
  TOS 2.4:  3.0.20-1.tl2.1     Tencent-rebuilt; explicit CVE-2024-3596 patch applied (RHEL-46800)
  TOS 3.1:  3.0.20-15.module+el8.10.0  RHEL 8 AppStream module; BlastRADIUS code present, "auto" default
  TOS 4.6:  3.2.6-3.tl4        Tencent-rebuilt; upgraded from 3.0.x → 3.2.6 specifically for CVE-2024-3596

FINDINGS SUMMARY:
  TOS31-FR-F01 (INFO)   freeradius ships as RHEL 8 AppStream module, not Tencent .tl3 rebuild
  TOS31-FR-F02 (MEDIUM) CVE-2024-3596 (BlastRADIUS): code present, "auto" default is insufficient
  TOS31-FR-F03 (INFO)   TOS 2.4 SRPM has explicit CVE patch; TOS 4.6 upgraded to 3.2.6 for fix
"""

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

FREERADIUS_BINARY_INVENTORY_TOS31 = {
    "package": "freeradius-3.0.20-15.module+el8.10.0+674+9c8bec55.x86_64",
    "dist_tag": "module+el8.10.0+674+9c8bec55",
    "dist_tag_origin": "RHEL 8.10 AppStream modularity stream — NOT a Tencent .tl3 rebuild",
    "build_date": "2024-07-31",
    "gdrive_id": "1GPaF6ocpChVYj1WI_MaXncbMpsC2K1vp",
    "radiusd": {
        "path": "usr/sbin/radiusd",
        "size_bytes": 490272,
        "build_id": "ac1564c843fec47ee19226904a608d1e0b6e0cf8",
        "format": "ELF 64-bit LSB pie executable, x86-64, stripped",
    },
    "libfreeradius_radius_so": {
        "path": "usr/lib64/freeradius/libfreeradius-radius.so",
        "size_bytes": 261 * 1024,
    },
    "version_string_in_binary": "FreeRADIUS Version 3.0.20, for host x86_64-koji-linux-gnu",
    "package_version_label": "radiusd-3.0.20-15.module+el8.10.0+674+9c8bec55.x86_64.debug",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-FR-F01: RHEL AppStream module packaging, no Tencent patch layer
# ──────────────────────────────────────────────────────────────────────────────

FREERADIUS_APPSTREAM_MODULE_PACKAGING = {
    "finding_id": "TOS31-FR-F01",
    "severity": "INFO",
    "title": (
        "TOS 3.1 freeradius packages use RHEL 8 AppStream modularity dist tags "
        "(module+el8.x.0) — not Tencent .tl3 rebuilds; no Tencent-specific security "
        "patch layer; update cadence follows RHEL 8 AppStream module stream"
    ),
    "dist_tag_comparison": {
        "freeradius": "3.0.20-15.module+el8.10.0+674+9c8bec55 (RHEL 8.10 AppStream module)",
        "cyrus_imapd": "3.0.7-26.tl3 (Tencent-maintained, .tl3 dist tag)",
        "openssh": "8.0p1-13.tl3 (Tencent-maintained, .tl3 dist tag)",
        "openssl": "1.1.1k-7.tl3 (Tencent-maintained, .tl3 dist tag)",
    },
    "implication": (
        "freeradius is the ONLY major network daemon on TOS 3.1 that ships directly "
        "from the upstream RHEL 8 AppStream module without Tencent's own security review "
        "and rebuild cycle. Security updates arrive when RHEL 8 AppStream module team "
        "releases them — not when Tencent releases .tl3 security updates. "
        "If the RHEL 8 AppStream module is discontinued before TOS 3.1 EoL, "
        "freeradius would effectively be abandoned."
    ),
    "module_generations_on_drive": [
        "3.0.20-12.module+el8.6.0+206+096952b1 (Dec 2022 — RHEL 8.6 era)",
        "3.0.20-14.module+el8.8.0+465+fc8f8486 (Jun 2023 — RHEL 8.8 era)",
        "3.0.20-15.module+el8.10.0+674+9c8bec55 (Aug 2024 — RHEL 8.10 era, latest)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-FR-F02: CVE-2024-3596 BlastRADIUS — partial mitigation
# ──────────────────────────────────────────────────────────────────────────────

CVE_2024_3596_TOS31 = {
    "finding_id": "TOS31-FR-F02",
    "severity": "MEDIUM",
    "cvss_v3": 6.3,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cve": "CVE-2024-3596",
    "title": (
        "freeradius 3.0.20-15: BlastRADIUS mitigation code present (built 2024-07-31, "
        "post-disclosure) but global default require_message_authenticator = 'auto' — "
        "legacy NAS clients trigger 'no' enforcement; attack viable in mixed environments"
    ),
    "disclosure_date": "2024-07-09",
    "binary_build_date": "2024-07-31",
    "binary_evidence": {
        "blastradius_strings_present": True,
        "detection_strings": [
            "BlastRADIUS check: Received packet without Message-Authenticator.",
            "Setting \"require_message_authenticator = false\" for client %s",
            "UPGRADE THE CLIENT AS YOUR NETWORK IS VULNERABLE TO THE BLASTRADIUS ATTACK.",
            "BlastRADIUS check: Received packet with Message-Authenticator.",
            "Setting \"require_message_authenticator = true\" for client %s",
            "BlastRADIUS check: Received packet with Proxy-State, but without Message-Authenticator.",
            "BlastRADIUS check: Received response to Access-Request without Message-Authenticator.",
        ],
        "config_attribute_present": "FreeRADIUS-Client-Require-MA",
        "binary_flag_string": "require_message_authenticator",
    },
    "default_config": {
        "radiusd_conf_global_security": "require_message_authenticator = auto",
        "clients_conf_comment": "#require_message_authenticator = no",
        "proxy_conf_comment": "#require_message_authenticator = no",
    },
    "auto_mode_behavior": (
        "'auto' determines enforcement per-client based on FIRST packet received: "
        "  - First packet has NO Message-Authenticator → flag switches to 'no' (VULNERABLE). "
        "  - First packet has MA but NOT EAP-Message → flag switches to 'yes' (enforced). "
        "  - First packet has MA AND EAP-Message → stays 'auto' (ambiguous). "
        "WARNING: The switch to 'no' does NOT persist across server restarts. "
        "WARNING: Multiple NASes behind one NATed IP force worst-case (most insecure) behavior. "
        "Any legacy NAS client that does not send Message-Authenticator causes "
        "permanent (until restart) disable of enforcement for its client entry."
    ),
    "attack_path": (
        "1. Legacy NAS sends Access-Request without Message-Authenticator. "
        "2. freeradius (in 'auto' mode) switches client to require_message_authenticator=no. "
        "3. Attacker MitM: intercepts Access-Request, performs MD5 collision on RADIUS MAC. "
        "4. Attacker injects forged Access-Accept response with arbitrary attributes. "
        "5. NAS grants access to unauthorized user. "
        "BlastRADIUS: crafted Access-Accept can set arbitrary RADIUS attributes including "
        "privilege escalation attributes (Cisco-AVPair shell:priv-lvl=15, etc)."
    ),
    "remediation": (
        "Change security.require_message_authenticator from 'auto' to 'yes' in radiusd.conf. "
        "Update all NAS/client devices to send Message-Authenticator. "
        "For mixed environments where legacy clients cannot be updated immediately, "
        "set per-client require_message_authenticator = no ONLY for those specific clients "
        "while tracking them for remediation. "
        "Full fix: upgrade to freeradius 3.2.6+ (TOS 4.6 package) which has proper enforcement."
    ),
    "references": ["CVE-2024-3596", "RHEL-46800", "RHEL-46572"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-FR-F03: Cross-version comparison
# ──────────────────────────────────────────────────────────────────────────────

FREERADIUS_CROSS_VERSION = {
    "finding_id": "TOS31-FR-F03",
    "severity": "INFO",
    "title": "freeradius BlastRADIUS posture across TOS versions",
    "versions": {
        "TOS_2.4 (3.0.20-1.tl2.1)": {
            "dist_tag": ".tl2 (Tencent rebuild)",
            "cve_2024_3596_patch": "EXPLICIT (freeradius-CVE-2024-3596-blastradius-fix.patch, 855 lines, 21 files)",
            "upstream_ref": "RHEL-46800, RHEL-46572 backport from v3.0.x branch",
            "build_date": "2024-07-26",
            "require_message_authenticator_default": "auto (same; requires operator change to yes)",
            "status": "Code backported explicitly, default still auto",
        },
        "TOS_3.1 (3.0.20-15.module+el8.10.0)": {
            "dist_tag": "module+el8.10.0 (RHEL 8 AppStream, not Tencent rebuild)",
            "cve_2024_3596_patch": "IMPLICIT (BlastRADIUS code in binary, no explicit .patch file in SRPM)",
            "build_date": "2024-07-31",
            "require_message_authenticator_default": "auto — vulnerable in mixed environments",
            "status": "Mitigation present, insufficient default",
        },
        "TOS_4.6 (3.2.6-3.tl4)": {
            "dist_tag": ".tl4 (Tencent rebuild)",
            "cve_2024_3596_patch": "FULL VERSION UPGRADE",
            "changelog": "Upgrade version to 3.2.6 (Fix CVE-2024-3596) — 2024-09-19",
            "require_message_authenticator_default": "auto in shipped config (same behavior)",
            "notes": (
                "3.2.6 is a proper stable upstream release vs 3.0.x backport. "
                "Includes all 3.2.x security fixes beyond just CVE-2024-3596."
            ),
            "status": "Best available; still requires operator to set yes for full enforcement",
        },
    },
    "pattern": (
        "All TOS versions ship freeradius with require_message_authenticator = auto as default. "
        "None defaults to the fully-secure 'yes'. The difference between versions is the "
        "quality of the BlastRADIUS code (3.2.6 upstream vs backport) not the default behavior. "
        "Operators must explicitly set 'yes' on ALL versions to be fully protected."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS31-FR-F01": FREERADIUS_APPSTREAM_MODULE_PACKAGING,
    "TOS31-FR-F02": CVE_2024_3596_TOS31,
    "TOS31-FR-F03": FREERADIUS_CROSS_VERSION,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "freeradius-3.0.20-15.module+el8.10.0+674+9c8bec55.x86_64.rpm",
        "method": "binary string scan + config analysis + cross-version SRPM comparison",
        "binary_build_date": "2024-07-31",
        "dist_tag": "module+el8.10.0 (RHEL 8 AppStream module, not .tl3)",
        "cve_2024_3596_blastradius": "PARTIAL — code present, default=auto is insufficient",
        "require_message_authenticator_default": "auto",
        "operator_action_required": "Change to 'yes' in security block of radiusd.conf",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
