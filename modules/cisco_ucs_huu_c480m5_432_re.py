"""
Cisco UCS C480 M5 HUU 4.3.2 — RE Module
Source: ucs-c480m5-huu-4.3.2.260020.iso (/media/cowboy/research/Cisco-UCS/huu/)
Format: ISO → rootfs.img (Squashfs, 2025-12-01) + ucs-c480m5-huu-container-4.3.2.260020.squashfs

Architecture differences from C220/C245 M8 4.3.6:
  - HUU web app: Python Flask + gunicorn3 (same as 6.0.2 generation)
  - hsu_agent ARM32 binary NOT present — Python-only on C480M5
  - App delivery: hsu.tgz.enc (encrypted tar, decrypted to /hsu/ Python package)
  - No xinetd.d telnet (removed in C480M5 vs present in C220/C245)
  - rootfs.img created 2025-12-01 (MUCH newer than C220/C245 M8 4.3.6: 2018-03-09)
  - No CPK format — hsu.tgz.enc used instead for app packaging
  - NVIDIA GPU hook pipeline uses shell=True with unsanitized tag.txt content

Common with 4.3.6:
  - decrypt-file AES-256 key: 'zfguijkophju@*%1]' (identical)
  - ftd dev key fallback
  - hsu-init CONFIG_SEC_UTILS_SIGN_MODE == 'dev' telnetd trigger
  - run_mode DEV/REL key selection at /opt/cisco/run_mode
  - hsu-keys: both dev AND rel keys shipped
"""

FIRMWARE = {
    "target":   "Cisco UCS C480 M5 HUU 4.3.2",
    "version":  "4.3.2.260020",
    "source":   "ucs-c480m5-huu-4.3.2.260020.iso",
    "cimc":     "4.3(2.260020)",
    "base_os":  "Buildroot/BusyBox Linux (rootfs.img created 2025-12-01)",
    "findings": ["HUU432-F1", "HUU432-F2", "HUU432-F3", "HUU432-F4", "HUU432-F5"],
}

# ─────────────────────────────────────────────────────────
# HUU432-F1: decrypt-file hardcoded key — same as 4.3.6 and 6.0.2
#            ADDITIONAL: same key decrypts hsu.tgz.enc (entire Python app)
# ─────────────────────────────────────────────────────────
HUU432_F1 = {
    "id":       "HUU432-F1",
    "title":    "decrypt-file in C480M5 4.3.2 rootfs and container hardcodes AES-256 key "
                "'zfguijkophju@*%1]' — same key decrypts both firmware payloads AND "
                "hsu.tgz.enc (the entire HUU Python application source)",
    "status":   "CONFIRMED — usr/sbin/decrypt-file in rootfs.img and container squashfs; "
                "openssl decryption of root/hsu.tgz.enc successful",
    "severity": "CRITICAL",

    "hardcoded_key": "zfguijkophju@*%1]",

    "affected_surfaces": {
        "firmware_payloads": (
            "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in <firmware.enc> "
            "-out payload.gz -k 'zfguijkophju@*%1]' -nosalt"
        ),
        "hsu_tgz_enc": (
            "root/hsu.tgz.enc (3.4MB) in the container squashfs is the entire HUU Python "
            "application (Flask, gunicorn3, all component hooks, IPMI transport, BMC transport). "
            "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in hsu.tgz.enc "
            "-out hsu.tgz -k 'zfguijkophju@*%1]' -nosalt → yields 12.5MB uncompressed Python app. "
            "VERIFIED: decrypt succeeded, produced valid gzip archive."
        ),
    },

    "app_recovery": (
        "The entire HUU Python application (all firmware update logic, BMC communication, "
        "component hooks, Redfish API implementation) is recoverable from any C480M5 4.3.2 "
        "ISO using only the hardcoded key. This includes: HuuApi.py, RedfishApp.py, HuuApp.py, "
        "all NVIDIA_*_Hook.py files, RAID_Hook.py, host_bmc_transport.py, ipmi_cmd.py, "
        "and 50+ other Python modules."
    ),

    "binary_hashes": {
        "rootfs_decrypt-file":    "64265ce6eb60b03d8067b7988cdad2a49456f228cb6d5255ebcbc0253c4b59e6",
        "C220_M8_4.3.6.260054":   "3df57720dcc61a3e75da525052af6b310c7517548048c481dd46d312a9f05e27",
        "C220_M8_6.0.2.260143":   "586e3267add8932c6dfb85472df30780572809fb8802ee43b7bd7405524ae666",
    },

    "cross_generation_scope": (
        "The key 'zfguijkophju@*%1]' is confirmed in at minimum three distinct decrypt-file "
        "binaries across C480M5 4.3.2, C220/C245 M8 4.3.6, and C220 M8 6.0.2. "
        "C480M5 4.3.2 extends the confirmed scope to include application code encryption — "
        "the key is not only a firmware transport key but also the app-package encryption key."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU432-F2: ftd dev key fallback if release verification fails
#            — variant of 4.3.6 finding; includes HSU_KERNEL_IMGVERIFY branch
# ─────────────────────────────────────────────────────────
HUU432_F2 = {
    "id":       "HUU432-F2",
    "title":    "ftd in C480M5 4.3.2 falls back to dev verification key when release key "
                "signature check fails — same architectural flaw as 4.3.6",
    "status":   "CONFIRMED — usr/sbin/ftd in rootfs.img from ucs-c480m5-huu-4.3.2.260020.iso",
    "severity": "CRITICAL",

    "vulnerable_code": (
        "# ftd (shell script) — with HSU_KERNEL_IMGVERIFY branch:\n"
        "if [ $HSU_KERNEL_IMGVERIFY = '1' ]; then\n"
        "    hsu-set-verify-key /hsu-keys/tools-rel-verify-key.der  # try release key\n"
        "else\n"
        "    export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-rel-verify-key.pem\n"
        "fi\n"
        "imgverify ${tmp_dst_file}_tmp\n"
        "ret=$?\n"
        "if [ $ret != 0 ]; then\n"
        "    # FALLBACK: switch to dev key\n"
        "    if [ $HSU_KERNEL_IMGVERIFY = '1' ]; then\n"
        "        hsu-set-verify-key /hsu-keys/tools-dev-verify-key.der\n"
        "    else\n"
        "        export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-dev-verify-key.pem\n"
        "    fi\n"
        "    imgverify $tmp_dst_file\n"
        "    ret=$?\n"
        "fi"
    ),

    "new_in_432": (
        "HSU_KERNEL_IMGVERIFY=1 branch present: uses hsu-set-verify-key (kernel ioctl path) "
        "instead of LD_PRELOAD/env-var path. Both branches fall back to dev key on release key "
        "verification failure. The two-path design was added for kernel-mode verification support "
        "but does not change the fallback behavior."
    ),

    "both_keys_present": (
        "hsu-keys/ in both rootfs AND container ship: "
        "container-dev/rel-verify-key.{der,pem}, rootfs-dev/rel-verify-key.{der,pem}, "
        "tools-dev/rel-verify-key.{der,pem}, tools-verify-key.{der,pem}."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU432-F3: hsu-init telnetd on CONFIG_SEC_UTILS_SIGN_MODE == "dev"
#            — identical to 4.3.6; build-time trigger, not runtime-exploitable
# ─────────────────────────────────────────────────────────
HUU432_F3 = {
    "id":       "HUU432-F3",
    "title":    "hsu-init in C480M5 4.3.2 rootfs enables telnetd when "
                "CONFIG_SEC_UTILS_SIGN_MODE == 'dev' — build-time trigger, same as 4.3.6",
    "status":   "CONFIRMED — etc/init.d/hsu-init in rootfs.img from ucs-c480m5-huu-4.3.2.260020.iso",
    "severity": "MEDIUM",

    "vulnerable_code": (
        "if [ $CONFIG_SEC_UTILS_SIGN_MODE == \"dev\" ]; then\n"
        "    echo \"Enabling telnetd...\"\n"
        "    telnetd\n"
        "fi"
    ),

    "trigger_note": (
        "Identical to HUU436-F3. CONFIG_SEC_UTILS_SIGN_MODE is a build-time constant. "
        "Production ISOs set it to 'rel'. Telnetd does not execute on shipping firmware."
    ),

    "xinetd_removal": (
        "Unlike C220/C245 M8 4.3.6, C480M5 4.3.2 has NO xinetd.d telnet service. "
        "The unconditional xinetd telnet (HUU436-F5) is absent from both the C480M5 4.3.2 "
        "rootfs and container. This is the only telnet exposure path in 4.3.2."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU432-F4: run_mode DEV/REL key selection
#            — same as 4.3.6; 4.3.2 adds HSU_KERNEL_IMGVERIFY branch
# ─────────────────────────────────────────────────────────
HUU432_F4 = {
    "id":       "HUU432-F4",
    "title":    "hsu-init reads /opt/cisco/run_mode to select DEV vs REL firmware verification key "
                "in C480M5 4.3.2 — writable run_mode enables dev key substitution at next boot",
    "status":   "CONFIRMED — etc/init.d/hsu-init in rootfs.img from ucs-c480m5-huu-4.3.2.260020.iso",
    "severity": "HIGH",

    "vulnerable_code": (
        "run_mode=`cat /opt/cisco/run_mode`\n"
        "if [ $run_mode == 'DEV' ] ; then\n"
        "    if [ -e /hsu-keys/tools-dev-verify-key.der ]; then\n"
        "        if [ $HSU_KERNEL_IMGVERIFY = '1' ]; then\n"
        "            cp /hsu-keys/tools-dev-verify-key.der /tmp/\n"
        "            hsu-set-verify-key /tmp/tools-dev-verify-key.der\n"
        "        fi\n"
        "        export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-dev-verify-key.pem\n"
        "    fi\n"
        "elif [ $run_mode == 'REL' ] ; then\n"
        "    ...\n"
        "fi"
    ),

    "comparison_with_436": "Functionally identical to HUU436-F4; new HSU_KERNEL_IMGVERIFY branch added.",
}

# ─────────────────────────────────────────────────────────
# HUU432-F5: NVIDIA GPU hooks build shell commands with tag.txt content unsanitized
#            — shell=True + string concatenation with firmware-package-controlled tag content
# ─────────────────────────────────────────────────────────
HUU432_F5 = {
    "id":       "HUU432-F5",
    "title":    "Six NVIDIA GPU firmware hooks in HUU Python app build shell commands via "
                "string concatenation of tag.txt content with shell=True — "
                "tag.txt is read from the firmware package without sanitization",
    "status":   "CONFIRMED — NVIDIA_V100_Hook.py, NVIDIA_V100_32GB_Hook.py, NVIDIA_P_Hook.py, "
                "NVIDIA_M10_Hook.py, NVIDIA_M60_Hook.py, NVIDIA_A100_Hook.py in hsu/ app",
    "severity": "MEDIUM",

    "vulnerable_code": (
        "# NVIDIA_A100_Hook.py (identical pattern in all six hooks):\n"
        "tag_file = open(dirname + '/tag.txt', 'r')\n"
        "password = tag_file.read().strip()\n"
        "tag_file.close()\n"
        "\n"
        "command = 'unzip -P revwfvn' + str(password) + ' ' + dirname + '/' + str(file) + ' -d ' + str(dirname)\n"
        "subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL)"
    ),

    "injection_path": (
        "The firmware container is a tar.gz extracted to dirname. "
        "tag.txt is a file inside that tar.gz. "
        "If tag.txt contains shell metacharacters (e.g., '; <cmd>;'), the injected command "
        "executes with the privileges of the gunicorn3 process (root, no User= directive). "
        "The tar.gz itself should be signature-verified by the HUU pipeline, but the "
        "tag.txt content is not checked after extraction. "
        "An attacker who can substitute a firmware package (e.g., via network share delivery, "
        "CIFS mount poisoning, or by obtaining the dev signing key) can achieve RCE "
        "during the NVIDIA GPU firmware update workflow."
    ),

    "affected_hooks": [
        "NVIDIA_V100_Hook.py",
        "NVIDIA_V100_32GB_Hook.py",
        "NVIDIA_P_Hook.py",
        "NVIDIA_M10_Hook.py",
        "NVIDIA_M60_Hook.py",
        "NVIDIA_A100_Hook.py",
    ],

    "hardcoded_prefix": (
        "The ZIP password is always 'revwfvn' + tag_content. "
        "The prefix 'revwfvn' is a hardcoded constant in all six hooks. "
        "If tag.txt is benign, the constructed password is 'revwfvn<tag>'. "
        "This implies all NVIDIA GPU firmware ZIPs in the HUU catalog use the 'revwfvn' prefix scheme."
    ),

    "second_shell_injection": (
        "Line 293 in NVIDIA_A100_Hook.py: "
        "command = 'tar -xvzf ' + firmware_container + ' -C ' + dirname\n"
        "subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL)\n"
        "firmware_container path is derived from the Redfish update API request. "
        "If dirname (slot_info) contains metacharacters, the tar command is also injectable. "
        "Slot info comes from component.get_slot_info(), which is derived from IPMI/hardware enumeration "
        "and is unlikely to contain attacker-controlled metacharacters under normal conditions."
    ),
}

ARCHITECTURE_NOTES = {
    "python_flask_only": (
        "C480M5 4.3.2 uses Python Flask + gunicorn3 — the hsu_agent ARM32 binary (HUU436-F6) "
        "is NOT present. The HUU Python app is delivered via hsu.tgz.enc and decrypted on first boot. "
        "App path on booted system: /hsu/ (current working dir for gunicorn3 at startup)."
    ),
    "no_xinetd_telnet": (
        "C480M5 4.3.2 has no xinetd telnet service. "
        "The unconditional telnet (HUU436-F5, present in C220/C245 M8 4.3.6) is absent. "
        "Only telnet exposure: hsu-init build-time dev trigger (HUU432-F3)."
    ),
    "rootfs_newer": (
        "C480M5 4.3.2 rootfs.img was created 2025-12-01 — MUCH newer than the C220/C245 M8 "
        "4.3.6 rootfs.img (2018-03-09). The C480M5 ships a purpose-built rootfs, not the "
        "ancient 2018 base used in C220/C245. The DIAG and SCU rootfs images also timestamp "
        "at 2018 — this appears to be a server-class-specific decision."
    ),
    "no_auth_on_redfish": (
        "The Flask app has no @before_request auth check, no authentication decorator on any "
        "route class, and no token validation. All Redfish endpoints (inventory, update, verify, "
        "launch mode) are accessible without credentials. This is the same design as 6.0.2 — "
        "the HUU is assumed to run on an isolated network during the upgrade process, but no "
        "enforcement of that assumption exists in the application."
    ),
}

FINDINGS = [HUU432_F1, HUU432_F2, HUU432_F3, HUU432_F4, HUU432_F5]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:90]}")
