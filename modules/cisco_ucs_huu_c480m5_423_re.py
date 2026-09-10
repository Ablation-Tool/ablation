"""
Cisco UCS C480 M5 HUU 4.2.3r — Reverse Engineering Module
Source: ucs-c480m5-huu-4.2.3r.iso (/media/cowboy/research/Cisco-UCS/)
ISO built: 2026-07-28 (rootfs timestamp: 20260728224455)
Structure: bzImage + initrd + rootfs.img (squashfs lz4, 136MB, 4395 inodes)
           + ucs-c480m5-huu-container-4.2.3r.squashfs (531MB lz4)
"""

FIRMWARE = {
    "target":      "Cisco UCS C480 M5 HUU 4.2.3r",
    "source":      "ucs-c480m5-huu-4.2.3r.iso",
    "iso_build":   "20260728224455",
    "rootfs":      "rootfs.img — squashfs v4.0 lz4, 136MB, 4395 inodes",
    "container":   "ucs-c480m5-huu-container-4.2.3r.squashfs — 531MB lz4",
    "findings":    ["HUU-M5-F1", "HUU-M5-F2", "HUU-M5-F3"],
    "key_package": "root/hsu.tgz.enc — AES-256-CBC, decrypted with same key as M8 family",
}

# ─────────────────────────────────────────────────────────────────────────────
# HUU-M5-F1: decrypt-file binary hardcodes AES-256-CBC key zfguijkophju@*%1]
#             — cross-generational: same base password as M8 (C220/C245/XE130C)
# ─────────────────────────────────────────────────────────────────────────────
HUU_M5_F1 = {
    "id":       "HUU-M5-F1",
    "title":    "decrypt-file binary hardcodes AES-256-CBC key 'zfguijkophju@*%1]' — "
                "same base password as M8 family, extending cross-generational key reuse to C480 M5",
    "status":   "CONFIRMED — strings /usr/sbin/decrypt-file in rootfs.img and container squashfs",
    "severity": "CRITICAL",

    "binary":          "usr/sbin/decrypt-file (ELF 64-bit, stripped)",
    "sha256_binary":   "29fde35b6134fd78d95d4249f905ef09e9c4a8d7e68c80b808d59bc85ffbde08",
    "same_binary_rootfs_and_container": True,

    "hardcoded_invocation": (
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s.gz -k zfguijkophju@*%1] 2>&1\n"
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s -k zfguijkophju@*%1] 2>&1"
    ),
    "hardcoded_key":   "zfguijkophju@*%1]",
    "kdf_m5":          "PBKDF2-SHA256 (-md sha256 -pbkdf2)",
    "kdf_m8":          "Legacy EVP_BytesToKey (-md md5, no -pbkdf2) — same password, different KDF",

    "encrypted_payload": "root/hsu.tgz.enc (container squashfs) — decrypts to hsu/ Python web application",
    "decryption_verified": "hsu-m5.tgz produced: Flask HUU server, nginx.conf, firmware catalog, Python modules",

    "cross_generational_scope": [
        "C480 M5 (4.2.3r) — HUU-M5-F1 (this finding)",
        "C220 M8 (6.0.2.260143) — confirmed in prior analysis",
        "C245 M8 (6.0.2.260180) — confirmed in prior analysis",
        "XE130C M8 (6.0.2.260143) — confirmed in prior analysis",
        "UCS Diagnostics 7.1.4.260010 — confirmed in prior analysis",
        "UCS SCU 7.1.7.260200 — confirmed in prior analysis",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# HUU-M5-F2: Secure boot container verification commented out in hsu-init;
#             secureboot_enabled flag still set, creating a false indicator
# ─────────────────────────────────────────────────────────────────────────────
HUU_M5_F2 = {
    "id":       "HUU-M5-F2",
    "title":    "hsu-init comments out entire container signature verification block while still setting "
                "/opt/cisco/secureboot_enabled — secure boot state indicator decoupled from verification",
    "status":   "CONFIRMED — /etc/init.d/hsu-init in rootfs.img",
    "severity": "HIGH",

    "source_file": "etc/init.d/hsu-init",

    "commented_verification_block": (
        "# Verification lines are all commented out:\n"
        "#cp \"${ISO_MNTPATH}\"/ucs-c480m5-huu-container-4.2.3r.sig /tmp/\n"
        "#hsu-verify-digest `sha256sum \"${ISO_MNTPATH}\"/ucs-c480m5-huu-container-4.2.3r.squashfs"
        " | awk '{print $1}'` /tmp/ucs-c480m5-huu-container-4.2.3r.sig\n"
        "#if [ $? -ne 0 ]; then\n"
        "#    echo \"Container verification failed.\"\n"
        "#    while [ \"true\" ]; do sleep 3600; done\n"
        "#fi"
    ),
    "remaining_active_line": "touch /opt/cisco/secureboot_enabled",

    "impact": (
        "When the system detects 'Secure boot enabled' in dmesg, the verification code path "
        "is entered but no verification occurs. The file /opt/cisco/secureboot_enabled is "
        "created unconditionally, falsely indicating that secure boot verification passed. "
        "The container squashfs can be replaced with any content; hsu-verify-digest is never called."
    ),

    "verify_binary": "usr/sbin/hsu-verify-digest — present but unreachable via the commented code path",
}

# ─────────────────────────────────────────────────────────────────────────────
# HUU-M5-F3: HUU Redfish/REST API (Flask + nginx) runs as root with no
#             authentication on firmware update, reset, and ISO mount endpoints
# ─────────────────────────────────────────────────────────────────────────────
HUU_M5_F3 = {
    "id":       "HUU-M5-F3",
    "title":    "HUU Redfish REST API (Flask + nginx) runs as root with no authentication — "
                "firmware update, system reset, and ISO mount endpoints accessible without credentials",
    "status":   "CONFIRMED — nginx.conf and run.py / json_api.py in root/hsu.tgz.enc payload",
    "severity": "CRITICAL",

    "nginx_user": "user root;  (nginx.conf line 1 — worker processes execute as root)",
    "flask_auth": "None — no before_request auth hook, no HTTPBasicAuth, no session middleware in run.py or json_api.py",

    "unauthenticated_endpoints": {
        "POST /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate": (
            "Trigger arbitrary firmware update. Accepts JSON body with Targets list "
            "(CIMC, BIOS, etc.), ForceUpdate flag, and Reboot flag. No credential check."
        ),
        "POST /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSDiscover": (
            "Trigger hardware discovery phase. No auth."
        ),
        "POST /redfish/v1/Systems/<id>/Actions/ComputerSystem.Reset": (
            "Trigger server hard/soft reset. No auth."
        ),
        "POST /redfish/v1/Systems/<id>/Actions/Oem/ComputerSystem.MountISO": (
            "Mount arbitrary ISO image. No auth."
        ),
        "GET /redfish/v1/UpdateService/FirmwareInventory": (
            "Enumerate installed firmware versions. No auth."
        ),
    },

    "access_context": (
        "HUU boots as a standalone OS from the ISO. The nginx+gunicorn stack starts "
        "on a network-reachable port. Any host on the management network can reach the API "
        "during a HUU session. No TLS in the active nginx config (HTTPS server block is "
        "fully commented out)."
    ),

    "exec_cmd": (
        "json_api.py:37: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT) — "
        "exec_cmd() passes commands to shell with shell=True. Called with fixed command strings "
        "in the analyzed version; audit of all callers required to rule out user-input injection."
    ),
}

FINDINGS = [HUU_M5_F1, HUU_M5_F2, HUU_M5_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
