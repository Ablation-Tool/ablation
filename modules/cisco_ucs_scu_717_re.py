"""
Cisco UCS Software Configuration Utility (SCU) 7.1.7.260200 — RE Module
Source: ucs-scu-7.1.7.260200.iso (2.7GB, /media/cowboy/research/Cisco-UCS/)
Format: Bootable Linux ISO with squashfs container + Driver Update Utilities (DUU)
Key files:
  rootfs.img                              — base Linux rootfs (squashfs)
  ucs-scu-container-7.1.7.260200.squashfs — SCU container (squashfs)
  ucs-scu-container-7.1.7.260200-base.tar.gz (inside squashfs) — full Linux rootfs
  duu-linux/  — Driver Update Utility for Linux (ucs_duu, get_machine_type.sh)
  duu-windows/ — Driver Update Utility for Windows (7z.exe/dll, cacert.pem, autorun.inf)
iso-manifest.json: OSInstallation — supports RHEL7-10, SLES12-16, Ubuntu 20-24, ESXi 7-9, Windows 2019-2025

decrypt-file: /usr/sbin/decrypt-file in base.tar.gz (same as HUU pattern)
"""

FIRMWARE = {
    "target":   "Cisco UCS Software Configuration Utility (SCU)",
    "version":  "7.1.7.260200",
    "source":   "ucs-scu-7.1.7.260200.iso",
    "function": "OS installation and driver deployment utility for UCS C-Series and HyperFlex servers",
    "supported_os": "RHEL 7-10, SLES 12-16, Ubuntu 20.04-24.04, ESXi 7-9, Windows Server 2019-2025",
    "findings": ["SCU-F1", "SCU-F2"],
}

# ─────────────────────────────────────────────────────────
# SCU-F1: Same PBKDF2 AES-256 key "zfguijkophju@*%1]" in decrypt-file
#         — 5th confirmed UCS component with this hardcoded key
# ─────────────────────────────────────────────────────────
SCU_F1 = {
    "id":       "SCU-F1",
    "title":    "UCS SCU 7.1.7 decrypt-file contains the same hardcoded PBKDF2 key 'zfguijkophju@*%1]' "
                "as all tested UCS HUU ISOs — confirmed 5th distinct Cisco UCS component with this key",
    "status":   "CONFIRMED — strings /usr/sbin/decrypt-file extracted from "
                "ucs-scu-container-7.1.7.260200-base.tar.gz",
    "severity": "CRITICAL",

    "key":  "zfguijkophju@*%1]",

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
        "Decrypting yields: OS installation logic, driver catalog, network configuration API, "
        "Redfish API handler for non-interactive SCU mode. "
        "Structural scope: the key is now confirmed across BOTH the HUU product line "
        "(firmware update) AND the SCU product line (OS configuration) — this is a "
        "shared infrastructure key, not a product-specific artifact. "
        "Any of the 5 confirmed ISOs provides this key to an attacker. All 5 are publicly downloadable "
        "from Cisco's support portal given a valid support contract."
    ),

    "product_line_scope": (
        "The key's presence in both HUU (Hardware Update Utility) and SCU (Software Configuration Utility) "
        "means it is likely also present in other UCS bootable utilities that share the same "
        "hsu/gunicorn architecture (e.g., UCS Diagnostics, UCS Intersight Infrastructure Service). "
        "The DIAG ISO (ucs-diag-7.1.4.260010.iso) squashfs also contains a decrypt-file binary "
        "(not yet analyzed for the key — candidate for confirmation)."
    ),
}

# ─────────────────────────────────────────────────────────
# SCU-F2: cacert.pem in duu-windows/ is a Mozilla CA bundle from December 2012
#         — Windows DUU trusts TLS connections using 13-year-old CA list
# ─────────────────────────────────────────────────────────
SCU_F2 = {
    "id":       "SCU-F2",
    "title":    "duu-windows/cacert.pem in UCS SCU 7.1.7 is a Mozilla CA bundle dated December 29, 2012 — "
                "Windows Driver Update Utility validates TLS with a 13-year-old CA bundle",
    "status":   "CONFIRMED — cacert.pem header: 'Certificate data from Mozilla as of: Sat Dec 29 20:03:40 2012'",
    "severity": "MEDIUM",

    "bundle_date":   "Sat Dec 29 20:03:40 2012",
    "bundle_source": "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt",

    "impact": (
        "The Windows DUU (ucs_duu.exe equivalent for Windows) uses cacert.pem to validate "
        "HTTPS connections during firmware/driver download. "
        "A CA bundle from 2012 includes: "
        "(1) CAs subsequently revoked (DigiNotar was revoked 2011 — this bundle may predate full cleanup; "
        "Symantec root distrust 2018 — entirely absent), "
        "(2) does NOT include many modern intermediate and root CAs added after 2012, "
        "(3) may trust CAs with known compromised keys never cleaned up in 2012-era bundles. "
        "A MITM attacker on the network segment where the DUU runs could present a certificate "
        "signed by a compromised or distrusted 2012-era CA. If the DUU trusts it, "
        "the attacker can serve modified firmware/drivers to the Windows host."
    ),

    "note": (
        "The SCU is shipped in 2026 but the Windows DUU component's CA bundle has not been updated "
        "since 2012 — a 14-year gap. This is the same category of vulnerability as "
        "outdated component libraries: the SCU was repackaged with a static dependency "
        "from a legacy build pipeline."
    ),
}

DUU_STRUCTURE = {
    "duu_linux": {
        "ucs_duu":             "Linux DUU executable",
        "get_machine_type.sh": "Bash script to identify UCS server model",
        "lsb_release":         "Linux Standard Base release info",
    },
    "duu_windows": {
        "7z.exe":      "7-Zip (for archive extraction)",
        "7z.dll":      "7-Zip DLL",
        "autorun.inf": "Windows autorun configuration",
        "cacert.pem":  "Mozilla CA bundle — 2012 vintage (see SCU-F2)",
        "cjson.dll":   "cJSON library for Windows",
    },
}

SCU_CONTAINER_NOTES = {
    "gunicorn_app":   "hsu_wsgi:app, gunicorn, same pattern as HUU ISOs",
    "nginx":          "nginx on :80, proxy to gunicorn 127.0.0.1:8000",
    "shadow_accounts": "All accounts locked (*) or nologin (!)",
    "python_version": "Python 3.13 (same as modern HUU 6.0.2 builds)",
}

FINDINGS = [SCU_F1, SCU_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
