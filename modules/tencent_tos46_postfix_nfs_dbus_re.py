"""
TencentOS 4.6 — postfix, nfs-utils, dbus SRPM RE.

Sources: scratchpad/postfix_work/, scratchpad/nfs_work/, scratchpad/dbus_work/
Method: spec changelog + patch file analysis

postfix: version upgrade to 3.8.5 for CVE-2023-51764 (SMTP smuggling)
nfs-utils: 2.6.3 — no CVE patches; TOS config patches only
dbus: 1.14.8 — no CVE patches; one Python3 migration patch
"""

POSTFIX = {
    "package": "postfix",
    "version": "3.8.5",
    "release": "5.tl4",
    "tos_patches": [
        "Patch3000: postfix-3.7.0-config.patch — TOS default config paths",
        "Patch3001: postfix-3.4.0-files.patch — TOS filesystem layout",
        "Patch3002: postfix-3.3.3-alternatives.patch — alternatives system integration",
        "Patch3003: postfix-3.7.0-large-fs.patch — large filesystem support",
        "Patch3004: postfix-3.4.4-chroot-example-fix.patch — chroot config example",
        "Patch3005: postfix-3.7.0-whitespace-name-fix.patch — config parsing fix",
        "Patch3006: postfix-3.6.2-glibc-234-build-fix.patch — glibc 2.34 compat",
        "Patch3007-3009: pflogsumm patches — log summary tool fixes",
    ],
    "cves": {
        "CVE-2023-51764": {
            "title": "SMTP smuggling: non-standard line endings bypass end-of-DATA recognition",
            "severity": "MEDIUM",
            "fixed_by": "version upgrade to 3.8.5",
            "description": (
                "SMTP protocol requires <CR><LF>.<CR><LF> (\\r\\n.\\r\\n) to signal end of "
                "message DATA. Postfix (and many other MTAs) also accepted <LF>.<CR><LF> "
                "(\\n.\\r\\n) as end-of-DATA for historical leniency. "
                "Cisco secure email gateways and similar intermediaries would pass the "
                "non-standard sequence through as-is, while the receiving Postfix server "
                "interpreted it as end of message. An attacker can inject a second SMTP "
                "message body by embedding \\n.\\r\\n into the message body — the "
                "intermediary sees it as part of one message; Postfix sees it as two. "
                "The second 'smuggled' message is delivered with the sender appearing to be "
                "the first message's authenticated sender (which passed SPF/DKIM). "
                "Fix in 3.8.5: reject bare LF (\\n without preceding \\r) in SMTP DATA. "
                "Default behavior changed via 'smtpd_forbid_bare_newline = normalize'. "
                "Reported by Timo Longin (SEC Consult) — multiple SMTP implementations "
                "vulnerable; postfix 3.8.5 applies strictest fix."
            ),
            "pre_auth": True,
            "vector": "SMTP (TCP 25)",
            "class": "smuggling",
            "config_note": "smtpd_forbid_bare_newline = normalize (default in 3.8.5)",
        },
    },
}

NFS_UTILS = {
    "package": "nfs-utils",
    "version": "2.6.3",
    "release": "6.tl4",
    "tos_patches": [
        "Patch3000: nfs-utils-1.2.1-statdpath-man.patch — statd man page path fix",
        "Patch3001: nfs-utils-1.2.1-exp-subtree-warn-off.patch — suppress subtree export warnings",
        "Patch3002: nfs-utils-2.3.1-systemd-gssproxy-restart.patch — gssproxy systemd restart",
        "Patch3003: nfs-utils-2.3.3-man-tcpwrappers.patch — tcpwrappers man page update",
        "Patch3004: nfs-utils-2.3.3-nfsconf-usegssproxy.patch — nfsconf gssproxy integration",
        "Patch3005: nfs-utils-2.4.2-systemd-svcgssd.patch — svcgssd systemd service",
        "Patch5000: 5000-nfs-utils-2.6.1-nfsidmap-warnmsg.patch — TOS nfsidmap warning text",
    ],
    "cves": None,
    "note": (
        "No CVE patches in TOS 4.6 nfs-utils. Version 2.6.3 is current upstream. "
        "Security posture: depends on kernel NFS server security and RPC authentication (Kerberos/AUTH_SYS). "
        "TOS-specific patches are config and warning message adjustments only."
    ),
}

DBUS = {
    "package": "dbus",
    "version": "1.14.8",
    "release": "4.tl4",
    "tos_patches": [
        "Patch5000: mute-autolaunch-testcase.patch — mute dbus session autolaunch in test",
        "0001-tools-Use-Python3-for-GetAllMatchRules.patch — Python2→Python3 migration for dbus tools",
    ],
    "cves": None,
    "note": (
        "No CVE patches in TOS 4.6 dbus. dbus 1.14.x is current maintained branch. "
        "Python2→Python3 migration in tools patch (Python3-only). "
        "D-Bus security posture governed by /etc/dbus-1/ policy files and SELinux."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "MEDIUM",
        "cve": "CVE-2023-51764",
        "package": "postfix-3.8.5",
        "title": "SMTP smuggling: bare LF in DATA allows sender spoofing via header injection",
        "detail": (
            "postfix 3.8.5 (fixed via version upgrade): accept SMTP DATA with bare \\n "
            "without preceding \\r. Intermediaries (Cisco ESA, etc.) see one message; "
            "Postfix sees two. Smuggled message inherits original sender's SPF/DKIM pass. "
            "Fixed: smtpd_forbid_bare_newline=normalize rejects bare LF in DATA. "
            "Pre-auth via SMTP port 25."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "package": "nfs-utils-2.6.3",
        "title": "nfs-utils 2.6.3: no CVE patches — TOS config-only patches",
        "detail": (
            "7 TOS patches are all config/warning adjustments. No security patches. "
            "NFS attack surface depends on export configuration and Kerberos auth."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "package": "dbus-1.14.8",
        "title": "dbus 1.14.8: no CVE patches — Python3 migration + test mute",
        "detail": "2 TOS patches: Python2→Python3 migration in tools; test autolaunch muted.",
    },
]

if __name__ == '__main__':
    print("TOS 4.6 postfix/nfs-utils/dbus RE")
    print()
    print(f"postfix {POSTFIX['version']} — {len(POSTFIX['cves'])} CVE: {list(POSTFIX['cves'].keys())}")
    print(f"nfs-utils {NFS_UTILS['version']} — {len(NFS_UTILS['tos_patches'])} config patches, 0 CVEs")
    print(f"dbus {DBUS['version']} — {len(DBUS['tos_patches'])} TOS patches, 0 CVEs")
    print()
    for f in FINDINGS:
        cve = f"[{f['cve']}] " if f.get('cve') else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {cve}{f['title'][:65]}")
