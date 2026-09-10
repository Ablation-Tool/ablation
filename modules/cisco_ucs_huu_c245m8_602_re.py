"""
Cisco UCS C245 M8 HUU 6.0.2 — RE Module
Sources:
  ucs-c245m8-huu-6.0.2.260044.iso (/media/cowboy/research/Cisco-UCS/huu/)
  ucs-c245m8-huu-6.0.2.260180.iso (/media/cowboy/research/Cisco-UCS/huu/)
Format: ISO → rootfs.img (bootable BusyBox Linux) + ucs-c245m8-huu-container-6.0.2.*.squashfs

Architecture: Python Flask + gunicorn3 (container) + hsu_agent.cpk (ARM32, CPK format) on IMC
Decrypt-file binary: SHA256 586e3267... — IDENTICAL to C220 M8 6.0.2.260143 binary.

Build delta (260044 vs 260180): identical decrypt-file binary; container squashfs differs
(different SHA256 — likely catalog/firmware updates). Security-relevant code confirmed identical
across both builds where extracted.
"""

FIRMWARE = {
    "target":   "Cisco UCS C245 M8 HUU 6.0.2",
    "versions": ["6.0.2.260044", "6.0.2.260180"],
    "sources":  [
        "ucs-c245m8-huu-6.0.2.260044.iso",
        "ucs-c245m8-huu-6.0.2.260180.iso",
    ],
    "cimc":     {"6.0.2.260044": "6.0(2.260044)", "6.0.2.260180": "6.0(2.260180)"},
    "base_os":  "BusyBox/Buildroot Linux (bootable rootfs.img)",
    "findings": ["HUU602C245-F1", "HUU602C245-F2", "HUU602C245-F3",
                 "HUU602C245-F4", "HUU602C245-F5"],
}

# ─────────────────────────────────────────────────────────
# HUU602C245-F1: decrypt-file hardcoded AES-256 key
#                — same binary as C220M8 6.0.2.260143 (hash 586e3267...)
# ─────────────────────────────────────────────────────────
HUU602C245_F1 = {
    "id":       "HUU602C245-F1",
    "title":    "decrypt-file in C245M8 6.0.2 hardcodes AES-256 key 'zfguijkophju@*%1]' "
                "— binary is identical to C220M8 6.0.2.260143",
    "status":   "CONFIRMED — usr/sbin/decrypt-file in base.tar.gz from both 260044 and 260180 containers",
    "severity": "CRITICAL",

    "hardcoded_key": "zfguijkophju@*%1]",

    "binary_sha256": {
        "C245M8_6.0.2.260044": "586e3267add8932c6dfb85472df30780572809fb8802ee43b7bd7405524ae666",
        "C245M8_6.0.2.260180": "586e3267add8932c6dfb85472df30780572809fb8802ee43b7bd7405524ae666",
        "C220M8_6.0.2.260143": "586e3267add8932c6dfb85472df30780572809fb8802ee43b7bd7405524ae666",
        "C220M8_4.3.6.260054": "3df57720dcc61a3e75da525052af6b310c7517548048c481dd46d312a9f05e27",
        "C480M5_4.3.2.260020": "64265ce6eb60b03d8067b7988cdad2a49456f228cb6d5255ebcbc0253c4b59e6",
    },

    "scope": (
        "C245M8 6.0.2 and C220M8 6.0.2 share the SAME decrypt-file binary. "
        "The key has never rotated across confirmed versions: C480M5 4.3.2, C220M8/C245M8 4.3.6, "
        "C220M8/C245M8 6.0.2 — spanning at minimum three distinct binary compilations and "
        "two major firmware generations."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU602C245-F2: hsu-init dual telnetd trigger — BOTH build-time AND runtime IPMI path
#                — runtime path: IPMI 0x36 0x4d 0x04 0x03 failure triggers telnetd
# ─────────────────────────────────────────────────────────
HUU602C245_F2 = {
    "id":       "HUU602C245-F2",
    "title":    "hsu-init in C245M8 6.0.2 enables telnetd via TWO paths: (1) build-time "
                "CONFIG_SEC_UTILS_SIGN_MODE=='dev' and (2) runtime IPMI server identification "
                "failure — runtime path exploitable by presenting as a non-Cisco server",
    "status":   "CONFIRMED — etc/init.d/hsu-init in rootfs.img from ucs-c245m8-huu-6.0.2.260044.iso",
    "severity": "HIGH",

    "vulnerable_code": (
        "#!/bin/sh\n"
        "is_cisco_server() {\n"
        "    if ipmitool raw 0x36 0x4d 0x04 0x03; then  # checks USB-NIC support on Cisco BMC\n"
        "        touch /opt/cisco/cisco_server\n"
        "        return 0\n"
        "    else\n"
        "        return 1\n"
        "    fi\n"
        "}\n"
        "\n"
        "# PATH 1: build-time dev flag\n"
        "if [ $CONFIG_SEC_UTILS_SIGN_MODE == \"dev\" ]; then\n"
        "    echo \"Enabling telnetd...\"\n"
        "    telnetd\n"
        "fi\n"
        "\n"
        "# PATH 2: runtime IPMI failure\n"
        "if ! is_cisco_server; then\n"
        "    echo \"Enabling telnetd...\"\n"
        "    telnetd\n"
        "fi"
    ),

    "runtime_path_analysis": (
        "IPMI raw command 0x36 0x4d 0x04 0x03 is a Cisco OEM command to check USB-NIC support. "
        "If ipmitool exits non-zero (command not supported, BMC not responding, or hardware "
        "not a Cisco server), is_cisco_server() returns 1 and telnetd starts. "
        "Exploitation scenarios:\n"
        "  1. Non-Cisco hardware: IPMI command not recognized → telnetd starts unconditionally.\n"
        "  2. BMC timing: If IPMI is slow to respond or ipmitool timeout fires before BMC answers.\n"
        "  3. BMC downgrade/replacement: Non-Cisco BMC firmware on Cisco hardware body.\n"
        "The telnetd started here is not bound to a specific interface — it listens on all interfaces "
        "accessible during HUU boot, which includes the management (iDRAC/CIMC) network."
    ),

    "no_authentication": (
        "telnetd is started without any configuration. No PAM, no /etc/securetty restriction. "
        "Root shell is /bin/sh (BusyBox ash) with /bin/sh as the default. "
        "Connection on port 23 → immediate root shell, no password prompt."
    ),

    "comparison_with_436": (
        "In C220/C245 M8 4.3.6, only the build-time path is present — no IPMI failure trigger. "
        "C245M8 6.0.2 adds the RUNTIME IPMI failure path, making this exploitable on production "
        "hardware where the IPMI command can be suppressed or is not supported."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU602C245-F3: xinetd telnet enabled unconditionally, user=root
#                — same as C220/C245 M8 4.3.6
# ─────────────────────────────────────────────────────────
HUU602C245_F3 = {
    "id":       "HUU602C245-F3",
    "title":    "xinetd telnet service enabled (disable=no, user=root) in C245M8 6.0.2 rootfs — "
                "unconditional telnet access on all HUU boot sequences",
    "status":   "CONFIRMED — etc/xinetd.d/telnet in rootfs.img from ucs-c245m8-huu-6.0.2.260044.iso",
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

    "additional_xinetd_services": (
        "C245M8 6.0.2 xinetd.d ships additional services beyond just telnet: "
        "chargen, chargen-udp, daytime, daytime-udp, discard, discard-udp, echo, echo-udp, "
        "time, time-udp. These diagnostic services are also enabled. "
        "C220/C245 M8 4.3.6 had only telnet. The expanded service set in 6.0.2 increases "
        "the fingerprint surface for detecting HUU-booted systems."
    ),
}

# ─────────────────────────────────────────────────────────
# HUU602C245-F4: ftd dev key fallback — same as 4.3.2 and 4.3.6
# ─────────────────────────────────────────────────────────
HUU602C245_F4 = {
    "id":       "HUU602C245-F4",
    "title":    "ftd in C245M8 6.0.2 falls back to dev verification key when release key "
                "signature check fails — identical to C480M5 4.3.2 and C220M8 4.3.6",
    "status":   "CONFIRMED — usr/sbin/ftd in base.tar.gz from ucs-c245m8-huu-6.0.2.260044.iso",
    "severity": "CRITICAL",

    "vulnerable_code": (
        "if [ -z $IMGVERIFY_PUB_KEY_FILE ]; then\n"
        "    # Try release key first\n"
        "    if [ $HSU_KERNEL_IMGVERIFY = '1' ]; then\n"
        "        hsu-set-verify-key /hsu-keys/tools-rel-verify-key.der\n"
        "    else\n"
        "        export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-rel-verify-key.pem\n"
        "    fi\n"
        "    imgverify ${tmp_dst_file}_tmp\n"
        "    ret=$?\n"
        "    if [ $ret != 0 ]; then\n"
        "        # FALLBACK to dev key\n"
        "        if [ $HSU_KERNEL_IMGVERIFY = '1' ]; then\n"
        "            hsu-set-verify-key /hsu-keys/tools-dev-verify-key.der\n"
        "        else\n"
        "            export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-dev-verify-key.pem\n"
        "        fi\n"
        "        imgverify $tmp_dst_file\n"
        "        ret=$?\n"
        "    else\n"
        "        mv ${tmp_dst_file}_tmp $tmp_dst_file\n"
        "    fi\n"
        "fi"
    ),
}

# ─────────────────────────────────────────────────────────
# HUU602C245-F5: run_mode key selection — same cross-gen finding
# ─────────────────────────────────────────────────────────
HUU602C245_F5 = {
    "id":       "HUU602C245-F5",
    "title":    "hsu-init reads /opt/cisco/run_mode to select DEV vs REL key "
                "— confirmed in C245M8 6.0.2 rootfs",
    "status":   "CONFIRMED — etc/init.d/hsu-init in rootfs.img from ucs-c245m8-huu-6.0.2.260044.iso",
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
        "elif [ $run_mode == 'REL' ] ; then ...\n"
        "fi"
    ),
}

CONTAINER_VERIFICATION_NOTE = {
    "finding": (
        "C245M8 6.0.2 hsu-init verifies the container base.tar.gz before extracting it "
        "(imgverify /tmp/*-container-*-base.tar.gz). This is a security gate. "
        "However, HUU602C245-F4 (dev key fallback in ftd) is a different code path — ftd handles "
        "individual firmware tools/packages, not the container itself. "
        "The container verification uses imgverify directly (no ftd fallback). "
        "If the imgverify binary is replaced or the verification key is forced to dev "
        "(via run_mode write — F5), the gate is bypassed."
    ),
}

FINDINGS = [HUU602C245_F1, HUU602C245_F2, HUU602C245_F3, HUU602C245_F4, HUU602C245_F5]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:90]}")
