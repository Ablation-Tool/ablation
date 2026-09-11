"""
Cisco UCS Server Configuration Utility (SCU) 7.1.7 — RE Module
Sources:
  ucs-scu-7.1.7.260200.iso — SCU with container base.tar.gz + duu-linux/duu-windows
  ucs-scu-7.1.7.260100.iso — SCU with older rootfs.img (squashfs, mtime 2018-03-09)

SCU is the bootable ISO for C-Series OS installation, driver deployment,
BIOS configuration, and Redfish-based non-interactive setup.
Both ISO variants share the same Flask/gunicorn web app architecture as HUU;
the 260100 rootfs is from 2018 and uses a shared boot infrastructure with HUU.
"""

FIRMWARE = {
    "targets": [
        {
            "name": "UCS SCU 7.1.7.260200",
            "source": "ucs-scu-7.1.7.260200.iso",
            "key_files": {
                "ucs-scu-container-7.1.7.260200-base.tar.gz": "Full Linux rootfs inside squashfs",
                "duu-linux/ucs_duu":   "Linux Driver Update Utility executable",
                "duu-windows/cacert.pem": "Mozilla CA bundle — 2012 vintage",
                "/usr/sbin/decrypt-file": "AES-256 decrypt wrapper — hardcoded key",
            },
        },
        {
            "name": "UCS SCU 7.1.7.260100",
            "source": "ucs-scu-7.1.7.260100.iso",
            "key_files": {
                "rootfs.img": "Boot rootfs squashfs (mtime 2018-03-09)",
                "rootfs/etc/init.d/hsu-init": "Telnetd gates + imgverify call",
                "rootfs/usr/sbin/imgverify":  "IMG_VERIFY bypass — same as HUU",
            },
        },
    ],
    "supported_os": "RHEL 7-10, SLES 12-16, Ubuntu 20.04-24.04, ESXi 7-9, Windows Server 2019-2025",
    "no_builder_account": True,
    "findings": ["SCU-F1", "SCU-F2", "SCU-F3", "SCU-F4"],
}

# ─────────────────────────────────────────────────────────
# SCU-F1: Same PBKDF2 AES-256 key "zfguijkophju@*%1]" in decrypt-file
#         — 5th confirmed UCS component with this hardcoded key (extends HUU-F1 scope)
# ─────────────────────────────────────────────────────────
SCU_F1 = {
    "id":       "SCU-F1",
    "title":    "UCS SCU 7.1.7.260200 decrypt-file contains the same hardcoded PBKDF2 key "
                "'zfguijkophju@*%1]' as all tested HUU ISOs — 5th distinct UCS component confirmed",
    "status":   "CONFIRMED — strings /usr/sbin/decrypt-file extracted from "
                "ucs-scu-container-7.1.7.260200-base.tar.gz",
    "severity": "CRITICAL",

    "key": "zfguijkophju@*%1]",

    "confirmed_components": [
        "ucs-xe130cm8-huu-6.0.2.260143 (HUU XE130C M8)",
        "ucs-c220m8-huu-6.0.2.260143   (HUU C220 M8)",
        "ucs-c245m8-huu-6.0.2.260180   (HUU C245 M8)",
        "ucs-c480m5-huu-4.2.3r         (HUU C480 M5)",
        "ucs-scu-7.1.7.260200          (SCU — this module)",
    ],

    "decrypt_command": (
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 "
        "-in /root/hsu.tgz.enc -out hsu.tgz -k 'zfguijkophju@*%1]' -nosalt"
    ),

    "impact": (
        "The SCU hsu.tgz.enc contains the SCU Flask web application (hsu_wsgi:app). "
        "Decrypting yields OS installation logic, driver catalog, network configuration API, "
        "and Redfish API handler for non-interactive SCU mode. "
        "The key spans both HUU (firmware update) and SCU (OS configuration) product lines — "
        "it is a shared infrastructure key, not product-specific. "
        "Any of the 5 confirmed ISOs provides the key. All are downloadable from Cisco's "
        "support portal with a valid support contract."
    ),

    "diag_candidate": (
        "ucs-diag-7.1.4.260010.iso squashfs also contains a decrypt-file binary — "
        "not yet confirmed for the key (candidate for 6th confirmation)."
    ),
}

# ─────────────────────────────────────────────────────────
# SCU-F2: cacert.pem in duu-windows/ is a Mozilla CA bundle from December 2012
#         — Windows DUU trusts TLS connections using 14-year-old CA list
# ─────────────────────────────────────────────────────────
SCU_F2 = {
    "id":       "SCU-F2",
    "title":    "duu-windows/cacert.pem in SCU 7.1.7 is a Mozilla CA bundle dated December 29, 2012 — "
                "Windows Driver Update Utility validates TLS with a 14-year-old CA bundle",
    "status":   "CONFIRMED — cacert.pem header: 'Certificate data from Mozilla as of: Sat Dec 29 20:03:40 2012'",
    "severity": "MEDIUM",

    "bundle_date":   "Sat Dec 29 20:03:40 2012",
    "bundle_source": "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt",

    "impact": (
        "The Windows DUU uses cacert.pem to validate HTTPS connections during firmware/driver download. "
        "A 2012 CA bundle includes CAs subsequently revoked (Symantec root distrust 2018 absent), "
        "and does not include modern intermediate CAs added after 2012. "
        "A MITM attacker can present a certificate signed by a compromised 2012-era CA "
        "to serve modified firmware or drivers to the Windows host running DUU."
    ),
}

# ─────────────────────────────────────────────────────────
# SCU-F3: imgverify IMG_VERIFY bypass in SCU 7.1.7.260100 bootable rootfs
#         Same script as HUU 4.3.x/6.0.2; rootfs mtime 2018-03-09
# ─────────────────────────────────────────────────────────
SCU_F3 = {
    "id":       "SCU-F3",
    "title":    "imgverify IMG_VERIFY bypass in SCU 7.1.7.260100 bootable rootfs (mtime 2018-03-09) — "
                "signature verification disabled by default; bypass predates HUU 4.3.x by years",
    "status":   "CONFIRMED — rootfs.img/usr/sbin/imgverify + hsu-init:90 in ucs-scu-7.1.7.260100.iso",
    "severity": "HIGH",

    "bypass_line":    'if [ "$IMG_VERIFY" != "1" ]; then exit 0; fi',
    "call_site":      "hsu-init:90 — imgverify /tmp/*-container-*-base.tar.gz",
    "img_verify_set": False,

    "scope_across_products_and_versions": {
        "SCU 7.1.7.260100 (rootfs 2018)": "PRESENT — oldest confirmed occurrence",
        "HUU 4.3.2 (C480)":               "PRESENT (HUU432-F3)",
        "HUU 4.3.6 (C220/C245)":          "PRESENT (HUU436-F4)",
        "HUU 6.0.2 (C220M8/C245)":        "PRESENT (HUU-F7)",
    },

    "description": (
        "The imgverify bypass `if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi` is present "
        "in the SCU 7.1.7.260100 rootfs.img with a file mtime of 2018-03-09. "
        "hsu-init calls imgverify on the base container tarball without setting IMG_VERIFY=1, "
        "so the check returns success unconditionally. "
        "Confirmed in both SCU and HUU — shared design flaw in the Cisco UCS boot infrastructure "
        "with earliest occurrence at least March 2018."
    ),
}

# ─────────────────────────────────────────────────────────
# SCU-F4: CONFIG_SEC_UTILS_SIGN_MODE + !is_cisco_server telnetd in SCU 7.1.7.260100
# ─────────────────────────────────────────────────────────
SCU_F4 = {
    "id":       "SCU-F4",
    "title":    "SCU 7.1.7.260100 hsu-init activates telnetd on CONFIG_SEC_UTILS_SIGN_MODE=dev "
                "or IPMI !is_cisco_server — shared design with HUU 6.0.2 bootable rootfs",
    "status":   "CONFIRMED — hsu-init:28-35 in rootfs.img from ucs-scu-7.1.7.260100.iso",
    "severity": "MEDIUM",

    "hsu_init_blocks": (
        "28: if [ $CONFIG_SEC_UTILS_SIGN_MODE == 'dev' ]; then telnetd; fi\n"
        "33: if ! is_cisco_server; then telnetd; fi"
    ),

    "telnetd_auth": (
        "All SCU rootfs shadow accounts locked (root:*, sshd:!, messagebus:!). "
        "BusyBox telnetd provides root shell without credentials."
    ),

    "cross_version": {
        "SCU 7.1.7.260100 (rootfs 2018)": "PRESENT — hsu-init:28,33",
        "HUU 6.0.2 C220M8/C245":          "PRESENT — identical code (HUU-F3)",
        "HUU 4.3.x":                       "PARTIAL — CONFIG_SEC gate only",
    },
}

DUU_STRUCTURE = {
    "duu_linux": {
        "ucs_duu":             "Linux DUU executable",
        "get_machine_type.sh": "Bash script to identify UCS server model",
    },
    "duu_windows": {
        "7z.exe":      "7-Zip (for archive extraction)",
        "7z.dll":      "7-Zip DLL",
        "autorun.inf": "Windows autorun configuration",
        "cacert.pem":  "Mozilla CA bundle — 2012 vintage (SCU-F2)",
        "cjson.dll":   "cJSON library for Windows",
    },
}

FINDINGS = [SCU_F1, SCU_F2, SCU_F3, SCU_F4]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:12s}] {f['id']}: {f['title'][:80]}")
