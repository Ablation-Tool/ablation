"""
Cisco UCS C220 M8 / C245 M8 HUU 4.3.6 — RE Module
Sources:
  ucs-c220m8-huu-4.3.6.260054.iso (/media/cowboy/research/Cisco-UCS/huu/)
  ucs-c220m8-huu-4.3.6.250039.iso (/media/cowboy/research/Cisco-UCS/huu/)
  ucs-c245m8-huu-4.3.6.250053.iso (/media/cowboy/research/Cisco-UCS/huu/)
Format: ISO → rootfs.img (Squashfs, 2018-03-09) + ucs-*-container-4.3.6.x-base.tar.gz (Squashfs → tar.gz)
CIMC versions bundled: 4.3(6.260054) in C220, 4.3(6.250053) in C245
Generation context: 4.3.6 is one generation before 6.0.x (M8 gen was released with 6.0.x)
                    4.3.x targets C220 M8 and C245 M8 early firmware;
                    6.0.x is the current/shipping firmware for the same hardware.

Architecture change vs 6.0.2:
  - HUU web app replaced: Python Flask + gunicorn → compiled ARM32 binary (hsu_agent) + plugin SOs
  - hsu_agent runs on IMC BMC (ARM32) and communicates via http://169.254.254.2/ (Redfish)
  - nginx.conf: user = 'www' (was 'root' in 6.0.2 XE130C variant)
  - telnetd trigger: 6.0.2 = IPMI Cisco-server identification failure (runtime);
                     4.3.6 = CONFIG_SEC_UTILS_SIGN_MODE == "dev" (build-time, not runtime-exploitable)
"""

FIRMWARE = {
    "target":    "Cisco UCS C220 M8 / C245 M8 HUU 4.3.6",
    "versions":  ["4.3.6.260054 (C220 M8)", "4.3.6.250039 (C220 M8)", "4.3.6.250053 (C245 M8)"],
    "sources":   [
        "ucs-c220m8-huu-4.3.6.260054.iso",
        "ucs-c220m8-huu-4.3.6.250039.iso",
        "ucs-c245m8-huu-4.3.6.250053.iso",
    ],
    "cimc":      {"C220 M8": "4.3(6.260054)", "C245 M8": "4.3(6.250053)"},
    "base_os":   "BusyBox/Buildroot Linux (rootfs.img created 2018-03-09, shipped in 2024+ ISOs)",
    "findings":  ["HUU436-F1", "HUU436-F2", "HUU436-F3", "HUU436-F4", "HUU436-F5", "HUU436-F6"],
}

# ─────────────────────────────────────────────────────────
# HUU436-F1: decrypt-file hardcoded PBKDF2 AES-256-CBC key confirmed in 4.3.6
#            — same key as 6.0.2; THREE DISTINCT BINARIES, ONE KEY
# ─────────────────────────────────────────────────────────
HUU436_F1 = {
    "id":       "HUU436-F1",
    "title":    "decrypt-file in UCS C220/C245 M8 HUU 4.3.6 hardcodes PBKDF2 AES-256-CBC key "
                "'zfguijkophju@*%1]' — same key as 6.0.2 generation, confirming cross-generation presence",
    "status":   "CONFIRMED — usr/sbin/decrypt-file in ucs-c220m8-huu-container-4.3.6.260054-base.tar.gz",
    "severity": "CRITICAL",

    "hardcoded_key": "zfguijkophju@*%1]",

    "vulnerable_command": (
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s.gz "
        "-k zfguijkophju@*%1] -nosalt 2>&1"
    ),

    "binary_hashes": {
        "C220_M8_4.3.6.260054": "3df57720dcc61a3e75da525052af6b310c7517548048c481dd46d312a9f05e27",
        "C220_M8_4.3.6.250039": "3df57720dcc61a3e75da525052af6b310c7517548048c481dd46d312a9f05e27",
        "C245_M8_4.3.6.250053": "3df57720dcc61a3e75da525052af6b310c7517548048c481dd46d312a9f05e27",
        "C480_M5_4.3.2.260020": "64265ce6eb60b03d8067b7988cdad2a49456f228cb6d5255ebcbc0253c4b59e6",
        "C220_M8_6.0.2.260143": "586e3267add8932c6dfb85472df30780572809fb8802ee43b7bd7405524ae666",
    },

    "cross_generation_scope": (
        "C220 M8 4.3.6 and C245 M8 4.3.6 share the IDENTICAL decrypt-file binary (same SHA256). "
        "C480 M5 4.3.2 has a different binary but the same key literal. "
        "C220 M8 6.0.2 has yet another distinct binary but same key. "
        "Three distinct binaries spanning at least two firmware generations (4.3.x → 6.0.x), "
        "all encoding the same AES-256 key. "
        "The key has never rotated across the observed firmware history."
    ),

    "decryption_proof": (
        "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 "
        "-in <any_huu_encrypted_firmware_payload> "
        "-out payload.gz -k 'zfguijkophju@*%1]' -nosalt && gunzip payload.gz"
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F2: ftd fallback to dev verification key if release key fails
#            — same behavior as 6.0.2; confirmed cross-generation
# ─────────────────────────────────────────────────────────
HUU436_F2 = {
    "id":       "HUU436-F2",
    "title":    "ftd in HUU 4.3.6 unconditionally falls back to dev verification key if release key "
                "signature check fails — dev key accepted on production hardware",
    "status":   "CONFIRMED — usr/sbin/ftd in rootfs.img from ucs-c220m8-huu-4.3.6.260054.iso",
    "severity": "CRITICAL",

    "vulnerable_code": (
        "# ftd (shell script):\n"
        "if [ -z $IMGVERIFY_PUB_KEY_FILE ]; then\n"
        "    # Try release key first\n"
        "    hsu-set-verify-key /hsu-keys/tools-rel-verify-key.der\n"
        "    imgverify ${tmp_dst_file}_tmp\n"
        "    ret=$?\n"
        "    if [ $ret != 0 ]; then\n"
        "        # FALLBACK: use dev key\n"
        "        hsu-set-verify-key /hsu-keys/tools-dev-verify-key.der\n"
        "        imgverify $tmp_dst_file\n"
        "        ret=$?\n"
        "    fi\n"
        "fi"
    ),

    "both_keys_present": (
        "Both dev and release keys ship in every production HUU ISO under /hsu-keys/:\n"
        "  container-dev-verify-key.{der,pem}\n"
        "  container-rel-verify-key.{der,pem}\n"
        "  rootfs-dev-verify-key.{der,pem}\n"
        "  rootfs-rel-verify-key.{der,pem}\n"
        "  tools-dev-verify-key.{der,pem}\n"
        "  tools-rel-verify-key.{der,pem}\n"
        "  tools-verify-key.{der,pem}  (additional alias)\n"
        "An attacker who can sign a payload with the dev private key (leaked or derivable) "
        "has it accepted on production hardware via the fallback path."
    ),

    "comparison_with_602": (
        "Same fallback pattern confirmed in 6.0.2. "
        "This is not a regression; it is a persistent design decision across at least two generations."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F3: hsu-init telnetd enabled on CONFIG_SEC_UTILS_SIGN_MODE == "dev"
#            — build-time trigger (not runtime); production ISOs not affected
#            DIFFERENT from 6.0.2 which used IPMI server identification failure (runtime)
# ─────────────────────────────────────────────────────────
HUU436_F3 = {
    "id":       "HUU436-F3",
    "title":    "hsu-init in HUU 4.3.6 enables telnetd when CONFIG_SEC_UTILS_SIGN_MODE == 'dev' — "
                "trigger moved from runtime IPMI failure (6.0.2) to build-time dev flag",
    "status":   "CONFIRMED — etc/init.d/hsu-init in rootfs.img from ucs-c220m8-huu-4.3.6.260054.iso",
    "severity": "MEDIUM",

    "vulnerable_code": (
        "# hsu-init:\n"
        "if [ $CONFIG_SEC_UTILS_SIGN_MODE == \"dev\" ]; then\n"
        "    echo \"Enabling telnetd...\"\n"
        "    telnetd\n"
        "fi"
    ),

    "trigger_analysis": (
        "CONFIG_SEC_UTILS_SIGN_MODE is set at build time (not a runtime-writable env var in production). "
        "Production ISOs set it to 'rel', so this telnetd path does not execute on shipping firmware. "
        "This is a build-system leak — the dev telnetd code ships in production binaries but is "
        "gated by a build-time constant. If the constant is not properly stripped at build time, "
        "a dev image on production hardware would expose an unauthenticated telnet session at boot. "
        "The variable's value cannot be confirmed from static analysis of the shipping ISO alone."
    ),

    "comparison_with_602": (
        "In 6.0.2, hsu-init enables telnetd when ipmitool fails to identify a Cisco server via "
        "OEM IPMI command — a runtime trigger exploitable by spoofing the IPMI response. "
        "In 4.3.6, the trigger is moved to a build-time flag — a security improvement for the "
        "telnetd path specifically. The xinetd telnet (HUU436-F5) remains unconditional in both."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F4: run_mode DEV/REL key selection from /opt/cisco/run_mode
#            — same as 6.0.2; writable run_mode = attacker-selectable key
# ─────────────────────────────────────────────────────────
HUU436_F4 = {
    "id":       "HUU436-F4",
    "title":    "hsu-init reads /opt/cisco/run_mode to select DEV vs REL firmware verification key — "
                "run_mode file writable by local users enables dev key substitution",
    "status":   "CONFIRMED — etc/init.d/hsu-init in rootfs.img from ucs-c220m8-huu-4.3.6.260054.iso",
    "severity": "HIGH",

    "vulnerable_code": (
        "# hsu-init:\n"
        "run_mode=`cat /opt/cisco/run_mode`\n"
        "if [ $run_mode == 'DEV' ] ; then\n"
        "    hsu-set-verify-key /hsu-keys/tools-dev-verify-key.der\n"
        "    export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-dev-verify-key.pem\n"
        "elif [ $run_mode == 'REL' ] ; then\n"
        "    hsu-set-verify-key /hsu-keys/tools-rel-verify-key.der\n"
        "    export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-rel-verify-key.pem\n"
        "fi"
    ),

    "impact": (
        "Writing 'DEV' to /opt/cisco/run_mode (requires local write access to that path) "
        "causes hsu-init to load the dev verification key on the next boot. "
        "Combined with HUU436-F2 (ftd dev key fallback), any payload signed with the dev private key "
        "will be accepted for firmware verification. "
        "Both the dev and release keys ship in every production ISO (see HUU436-F2 key list)."
    ),

    "comparison_with_602": "Identical to HUU-F4 in 6.0.2 — same code, same file path.",
}

# ─────────────────────────────────────────────────────────
# HUU436-F5: xinetd telnet service enabled, no source IP restriction
#            — same as 6.0.2; unconditional on all HUU boots
# ─────────────────────────────────────────────────────────
HUU436_F5 = {
    "id":       "HUU436-F5",
    "title":    "xinetd telnet service enabled (disable=no) with no source IP restriction in HUU 4.3.6 "
                "— unauthenticated cleartext shell access on all HUU/SCU/SDU boots",
    "status":   "CONFIRMED — etc/xinetd.d/telnet in rootfs.img from ucs-c220m8-huu-4.3.6.260054.iso",
    "severity": "HIGH",

    "xinetd_config": (
        "service telnet\n"
        "{\n"
        "    disable     = no\n"
        "    flags       = REUSE\n"
        "    socket_type = stream\n"
        "    wait        = no\n"
        "    user        = root\n"
        "    server      = /usr/sbin/in.telnetd\n"
        "    log_on_failure += USERID\n"
        "}"
    ),

    "impact": (
        "xinetd starts on runlevel 5 (S20xinetd in rc5.d). "
        "Telnet service is enabled with no only_from restriction. "
        "The HUU environment has root with shell (/bin/sh via /initramfs/ — see passwd). "
        "Any host on the same network as the server's management interface during HUU boot "
        "can connect on port 23 and obtain a root shell without authentication. "
        "No session authentication mechanism is present in the telnetd config."
    ),

    "comparison_with_602": (
        "Identical to HUU-F5 in 6.0.2. "
        "This finding is present across the entire observed 4.3.x → 6.0.x firmware range."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F6: hsu_agent service has no User= directive — runs as root on IMC
# ─────────────────────────────────────────────────────────
HUU436_F6 = {
    "id":       "HUU436-F6",
    "title":    "hsu_agent.service (CPK-delivered ARM32 firmware update agent) has no User= "
                "directive — runs as root on the IMC BMC",
    "status":   "CONFIRMED — usr/lib/systemd/system/hsu_agent.service in hsu_agent CPK "
                "from ucs-c220m8-huu-container-4.3.6.260054.squashfs",
    "severity": "MEDIUM",

    "service_unit": (
        "[Service]\n"
        "Type=exec\n"
        "Restart=always\n"
        "RestartSec=5s\n"
        "ExecStartPre=/usr/local/bin/hsu_agent.sh start\n"
        "ExecStart=/usr/local/bin/hsu_agent\n"
        "ExecStopPost=/usr/local/bin/hsu_agent.sh stop\n"
        "EnvironmentFile=-/tmp/hsu-agent/hsu_env"
    ),

    "binary_info": {
        "path":   "/usr/local/bin/hsu_agent",
        "arch":   "ARM32 ELF (runs on IMC BMC, not on host Linux)",
        "debug":  "NOT stripped — full debug symbols present",
        "source_paths": [
            "/sums/build/CSeriesM8/include/ciscosafec",
            "/sums/apps/cisco/hsu_agent/inc",
            "/sums/apps/cisco/hsu_agent/lib/libhsu_helper/inc",
        ],
    },

    "delivery_mechanism": (
        "hsu_agent is delivered via CPK (Cisco Package format) embedded in the HUU squashfs. "
        "CPK header: platform=godzilla1, version=4.3.6.260054, tarOffset=128. "
        "Inner payload: Debian-format .tar.gz (data.tar.gz + control.tar.gz + debian-binary). "
        "Installed to: /usr/local/bin/hsu_agent, /usr/local/lib/libhsu_plugin_*.so, "
        "/var/cisco/hsu-agent/hsu_agent.conf, /usr/lib/systemd/system/hsu_agent.service. "
        "The agent communicates with IMC Redfish at http://169.254.254.2/ (IMC loopback address). "
        "Plugin SOs: libhsu_plugin_swupdate, llf, vic, cmc, retimer, drives, storage, mswitch, expander."
    ),

    "cifs_credential_exposure": (
        "libhsu_helper.so contains CIFS mount command format strings: "
        "'nobrl,soft,username=%s,password=%s,port=%d' — credentials supplied as kernel mount options. "
        "Any local root process can read /proc/mounts and extract the plaintext CIFS password "
        "while the share is mounted. The password is a user-supplied SMB share credential "
        "provided to HUU for firmware image delivery via network share."
    ),
}

ARCHITECTURE_NOTES = {
    "huu_agent_is_imc_binary": (
        "hsu_agent is ARM32 and runs ON the IMC BMC (not on the x86 host running HUU Linux). "
        "It communicates with the IMC Redfish endpoint at http://169.254.254.2/ — the IMC "
        "loopback/sideband address on C-Series servers. The HUU host Linux side (x86_64, gunicorn3) "
        "interacts with hsu_agent via a Unix domain socket at /tmp/hsu-agent/hsu-socket."
    ),
    "nginx_user_www": (
        "Unlike 6.0.2 XE130C M8 (nginx.conf: user root), HUU 4.3.6 nginx.conf uses 'user www'. "
        "The nginx worker privilege escalation (HUU-XE-F2) does NOT apply to 4.3.6. "
        "This confirms HUU-XE-F2 is a regression specific to the XE130C M8 6.0.2 build."
    ),
    "rootfs_img_age": (
        "rootfs.img in 4.3.6 ISO was created 2018-03-09 — same creation date as DIAG-F2 "
        "(the diagnostic utility rootfs). This 2018 base is now 6+ years old and ships "
        "across multiple HUU versions."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F7: builder:builder hardcoded credential in all HUU 4.3.6 container base tarballs
#             DES crypt hash .gLibiNXn0P12 — cracked: password = "builder"
#             Absent in HUU 6.0.2 (fixed)
# ─────────────────────────────────────────────────────────
HUU436_F7 = {
    "id":       "HUU436-F7",
    "title":    "HUU 4.3.6 container base tarballs (C220, C220-039, C245) ship hardcoded "
                "builder:builder credential (DES crypt .gLibiNXn0P12) — absent in HUU 6.0.2",
    "status":   "CONFIRMED — huu436-c220-base/etc/shadow, huu436-c220-039-base/etc/shadow, "
                "huu436-c245-base/etc/shadow; cracked via python3 crypt module",
    "severity": "CRITICAL",

    "shadow_entry":   "builder:.gLibiNXn0P12:15069::",
    "hash_type":      "DES crypt (13 chars, 2-char salt '.g')",
    "cracked_pass":   "builder",
    "uid_gid":        "999:999",
    "home_shell":     "/home/builder — /bin/sh",

    "affected_variants": [
        "huu436-c220-base/etc/shadow",
        "huu436-c220-039-base/etc/shadow",
        "huu436-c245-base/etc/shadow",
    ],

    "scope_across_versions": {
        "HUU 4.3.2 (C480 M5)":    ".gLibiNXn0P12 — PRESENT (same hash, uid 998)",
        "HUU 4.3.6 (C220/C245)":  ".gLibiNXn0P12 — PRESENT (uid 999)",
        "HUU 6.0.2 (all M8)":     "builder ABSENT — FIXED",
    },

    "description": (
        "All HUU 4.3.6 container base tarballs contain /etc/shadow with an active builder account. "
        "The DES crypt hash '.gLibiNXn0P12' decodes to password 'builder' using 2-char salt '.g'. "
        "During an active HUU upgrade session the container OS is reachable; builder provides "
        "shell access with /bin/sh. Fixed in HUU 6.0.2 (builder account absent)."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F8: cis@123co default root password artifact in container init.sh
# ─────────────────────────────────────────────────────────
HUU436_F8 = {
    "id":       "HUU436-F8",
    "title":    "HUU 4.3.6 container init.sh contains commented-out usermod with default root "
                "password 'cis@123co' — development credential artifact in shipping firmware",
    "status":   "CONFIRMED — etc/init.sh line 94 in all three HUU 4.3.6 variants",
    "severity": "MEDIUM",

    "source_file": "etc/init.sh",
    "source_line": 94,
    "artifact":    "# chroot $ROOTFS_DIR sh -c \"usermod --password $(openssl passwd cis@123co) root\"",
    "password":    "cis@123co",
    "current_root": "root:* (disabled — the commented line is not executed)",

    "note": (
        "Plaintext credential artifact embedded in the production init script. "
        "Not present in HUU 4.3.2 C480 init.sh. Specific to the 4.3.6 variants."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU436-F9: imgverify exits 0 when IMG_VERIFY != "1" in HUU 4.3.6 container rootfs
#             Extends HUU-F7 scope to 4.3.6; same bypass confirmed in SCU 7.1.7 (2018) and HUU 4.3.2
# ─────────────────────────────────────────────────────────
HUU436_F9 = {
    "id":       "HUU436-F9",
    "title":    "imgverify in HUU 4.3.6 container rootfs exits 0 when IMG_VERIFY != '1' — "
                "hsu-init calls imgverify without setting IMG_VERIFY; bypass in every HUU examined",
    "status":   "CONFIRMED — huu436-c220-rootfs/usr/sbin/imgverify + hsu-init:75",
    "severity": "HIGH",

    "bypass_line":    'if [ "$IMG_VERIFY" != "1" ]; then exit 0; fi',
    "call_site":      "hsu-init:75 — imgverify /tmp/ucs-*-container-*-base.tar.gz",
    "img_verify_set": False,

    "cross_version": {
        "SCU 7.1.7 (rootfs 2018)":  "PRESENT — oldest confirmed occurrence",
        "HUU 4.3.2 (C480 M5)":      "PRESENT",
        "HUU 4.3.6 (C220/C245)":    "PRESENT — this finding",
        "HUU 6.0.2 (all M8)":       "PRESENT (HUU-F7) — never patched",
    },
}

FINDINGS = [
    HUU436_F1, HUU436_F2, HUU436_F3, HUU436_F4, HUU436_F5, HUU436_F6,
    HUU436_F7, HUU436_F8, HUU436_F9,
]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:90]}")
