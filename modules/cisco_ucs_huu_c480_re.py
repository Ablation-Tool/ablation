"""
Cisco UCS HUU C480M5 4.2.3r ISO RE

Target:  ucs-c480m5-huu-4.2.3r.iso
         C480 M5 Host Upgrade Utility, version 4.2.3r (older generation)
         Structure differs from 6.0.2: direct overlay squashfs container,
         encrypted Python app (hsu.tgz.enc), Python 2.7/3.x mixed environment
Files:   rootfs.img (squashfs, OpenEmbedded)
         ucs-c480m5-huu-container-4.2.3r.squashfs (direct overlay FS)
         /root/hsu.tgz.enc (encrypted Python app)
         /usr/sbin/decrypt-file (ELF64, stripped; decrypts hsu.tgz.enc)
         /etc/init.d/hsu-init (rootfs)
         /etc/init.sh (container)
         /root/hsu/*.py (decrypted app: NVIDIA_*_Hook.py, ipmi_cmd.py, etc.)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c480_re",
    "firmware": "ucs-c480m5-huu-4.2.3r.iso",
    "components": {
        "decrypt-file (/usr/sbin/decrypt-file)": (
            "x86-64 ELF stripped; decrypts /root/hsu.tgz.enc to /tmp/hsu.tgz; "
            "hsu.tgz.enc header: 'Salted__' (OpenSSL EVP_BytesToKey, MD5 KDF, 1 iteration); "
            "key embedded in decrypt-file binary, same ISO as encrypted payload"
        ),
        "hsu-init (/etc/init.d/hsu-init, rootfs)": (
            "Secure boot verification block entirely commented out; "
            "still sets /opt/cisco/secureboot_enabled; "
            "telnetd enabled if DEBUG == 'yes'; DEBUG=no in hsu-profile.sh"
        ),
        "NVIDIA firmware hooks (/root/hsu/NVIDIA_*_Hook.py)": (
            "6 files: A100, M10, M60, P, V100, V100_32GB; "
            "firmware ZIP extraction: 'unzip -P revwfvn<tag.txt> <file> -d <dir>' "
            "with shell=True; tag.txt content from firmware package"
        ),
        "ipmi_cmd.py (/root/hsu/ipmi_cmd.py)": (
            "BMC password inline in ipmitool subprocess: "
            "' -U ' + username + ' -P ' + password, shell=True"
        ),
        "hsu-profile.sh": (
            "DEBUG=no; CONTAINER_MNT_TYPE=overlay; "
            "run_mode read from /run_mode (root FS, not authenticated)"
        ),
    },
    "finding_count": "6F [1C+3H+2M+0L]",
    "cumulative": "741 [69C+246H+234M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "HUU Python app encrypted with key in same-ISO binary (security theater)",
        "description": (
            "The HUU Python application is stored as /root/hsu.tgz.enc with "
            "the OpenSSL 'Salted__' header (EVP_BytesToKey, MD5 KDF, 1 iteration). "
            "The decryption key is embedded in /usr/sbin/decrypt-file, an x86-64 ELF "
            "stripped binary that ships in the same squashfs container as the "
            "encrypted payload. "
            "Running 'decrypt-file /root/hsu.tgz.enc /tmp/hsu.tgz' on the mounted "
            "container decrypts the application to a valid gzip archive "
            "containing the full Python source of the HUU Redfish API, firmware hooks, "
            "and IPMI utilities. "
            "The encryption provides no protection: key and ciphertext are "
            "co-located on the same read-only medium. "
            "Additionally, EVP_BytesToKey with MD5 and 1 iteration is the weakest "
            "OpenSSL enc default -- a known passphrase brute-force target."
        ),
        "evidence": {
            "file_encrypted": "/root/hsu.tgz.enc",
            "header_hex": "5361 6c74 6564 5f5f fe1b 047f 9ad5 ... (Salted__<8-byte salt>)",
            "decryption_binary": "/usr/sbin/decrypt-file (ELF64, stripped, ships in same container)",
            "set_workbase": (
                "if [ -e \"${WORKBASE}\".tgz.enc ]; then\n"
                "    decrypt-file \"${WORKBASE}\".tgz.enc /tmp/hsu.tgz\n"
                "    tar -xzvf /tmp/hsu.tgz\n"
                "fi"
            ),
            "decrypted_output": "7710720 bytes gzip; contains 60+ Python source files",
        },
        "impact": (
            "Any attacker with ISO access can mount the container squashfs, "
            "run decrypt-file, and obtain full HUU Python source. "
            "Source includes firmware update logic, IPMI credential handling, "
            "and NVIDIA firmware hook paths. "
            "Source modification is possible if the ISO is re-mastered."
        ),
        "remediation": (
            "Remove the decryption key from the same distribution medium. "
            "Use code signing rather than symmetric encryption for integrity protection."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Container signature verification commented out in hsu-init",
        "description": (
            "hsu-init in the rootfs includes a secure boot container verification block "
            "that is entirely commented out, while still setting the secureboot_enabled flag: "
            "'dmesg | grep \"Secure boot enabled\"; if [ $? -eq 0 ]; then ... "
            "touch /opt/cisco/secureboot_enabled; fi'. "
            "The verification commands that were once present are all commented: "
            "'#cp .../ucs-c480m5-huu-container-4.2.3r.sig /tmp/', "
            "'#hsu-verify-digest sha256sum .../container.squashfs ... /tmp/container.sig', "
            "'#if [ $? -ne 0 ]; then echo \"Container verification failed.\" ...; fi'. "
            "When secure boot is detected, only the flag file is created; the container "
            "squashfs is mounted and used without any cryptographic verification. "
            "This is distinct from the imgverify bypass in HUU 6.0.2: "
            "in 4.2.3r, the verification code existed and was explicitly disabled."
        ),
        "evidence": {
            "file": "/etc/init.d/hsu-init (rootfs.img)",
            "code": (
                "dmesg | grep \"Secure boot enabled\"\n"
                "if [ $? -eq 0 ]; then\n"
                "    echo \"Secure boot is enabled.\"\n"
                "    #cp \"${ISO_MNTPATH}\"/ucs-c480m5-huu-container-4.2.3r.sig /tmp/\n"
                "    #hsu-verify-digest `sha256sum \"${ISO_MNTPATH}\"/ucs-c480m5-huu-container-4.2.3r.squashfs | awk '{print $1}'` /tmp/ucs-c480m5-huu-container-4.2.3r.sig\n"
                "    #if [ $? -ne 0 ]; then\n"
                "    #    echo \"Container verification failed.\"\n"
                "    #    while [ \"true\" ]; do sleep 3600; done\n"
                "    #fi\n"
                "    touch /opt/cisco/secureboot_enabled\n"
                "fi"
            ),
        },
        "impact": (
            "A tampered container squashfs is accepted as valid even when secure boot "
            "is enabled. Verification infrastructure existed and was removed, suggesting "
            "a deliberate regression rather than a design omission."
        ),
        "remediation": (
            "Restore the container signature verification block. "
            "The signature check must complete before mounting the container."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "NVIDIA firmware ZIP extraction: command injection via tag.txt content",
        "description": (
            "Six NVIDIA GPU firmware update hook files (NVIDIA_A100_Hook.py, "
            "NVIDIA_M10_Hook.py, NVIDIA_M60_Hook.py, NVIDIA_P_Hook.py, "
            "NVIDIA_V100_Hook.py, NVIDIA_V100_32GB_Hook.py) extract the firmware ZIP "
            "using a shell command constructed from a tag.txt file in the firmware package: "
            "'tag_file = open(dirname + \"/tag.txt\", \"r\"); password = tag_file.read().strip()'. "
            "The password is concatenated directly into a shell command: "
            "'command = \"unzip -P revwfvn\" + str(password) + \" \" + dirname + \"/\" "
            "+ str(file) + \" -d \" + str(dirname)' "
            "and executed with subprocess.check_call(command, shell=True). "
            "tag.txt is part of the firmware package content, not a fixed value. "
            "A crafted firmware package where tag.txt contains shell metacharacters "
            "(e.g., '$(id)' or '; telnetd;') causes arbitrary command execution "
            "during the firmware update workflow. "
            "The same firmware_container tar extraction uses the same shell=True pattern: "
            "'tar -xvzf ' + firmware_container + ' -C ' + dirname."
        ),
        "evidence": {
            "files": (
                "NVIDIA_A100_Hook.py:298-309, NVIDIA_M10_Hook.py:316-327, "
                "NVIDIA_P_Hook.py:240-251, NVIDIA_V100_Hook.py:234-245, "
                "NVIDIA_M60_Hook.py (same), NVIDIA_V100_32GB_Hook.py (same)"
            ),
            "code": (
                "tag_file = open(dirname + \"/tag.txt\", 'r')\n"
                "password = tag_file.read().strip()\n"
                "tag_file.close()\n"
                "\n"
                "command = \"unzip -P revwfvn\" + str(password) + \" \"\n"
                "          + dirname + \"/\" + str(file) + \" -d \" + str(dirname)\n"
                "subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL)"
            ),
            "partial_passphrase_prefix": "revwfvn (hardcoded, prepended to tag.txt content)",
        },
        "impact": (
            "Arbitrary command execution as root during NVIDIA GPU firmware update. "
            "Attacker needs to deliver a crafted firmware package to the HUU firmware "
            "repository (NFS, HTTP, or local USB) with a malicious tag.txt. "
            "Affects any C480M5 server running GPU firmware updates via HUU 4.2.3r."
        ),
        "remediation": (
            "Pass password to unzip via subprocess argument list (not shell=True). "
            "Validate tag.txt content against an allowlist of printable alphanumeric characters "
            "before use in any command construction."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "BMC password passed inline in ipmitool command-line argument",
        "description": (
            "ipmi_cmd.py IPMIConfig class constructs ipmitool commands with "
            "the BMC password inline: "
            "'cmd = cmd + \" -U \" + self.username + \" -P \" + self.password', "
            "executed with subprocess.check_output(cmd, shell=True). "
            "Identical pattern to SCU 7.1.7.260100. "
            "All IPMI operations (hardware inventory, firmware status, sensor reads) "
            "expose BMC credentials in /proc/<pid>/cmdline for the duration of each "
            "ipmitool call."
        ),
        "evidence": {
            "file": "/root/hsu/ipmi_cmd.py:105",
            "code": "cmd = cmd + \" -I lanplus -N 2 -H \" + self.ip + \" -U \" + self.username + \" -P \" + self.password",
        },
        "impact": (
            "Any local process with /proc access can harvest BMC credentials "
            "during IPMI-intensive operations (discovery, update). "
            "In a compromised container, no additional privilege needed."
        ),
        "remediation": "Pass IPMI password via environment variable (IPMITOOL_PASSWORD) or stdin.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "run_mode read from unauthenticated root filesystem path",
        "description": (
            "hsu-init reads the operational mode from '/run_mode' at the root of the "
            "filesystem: 'run_mode=`cat /run_mode`'. "
            "Based on this value, DEV or REL verification keys are loaded via hsu-set-verify-key. "
            "The /run_mode file is in the root filesystem (initramfs/boot environment), "
            "not authenticated by any signature or TPM-sealed value. "
            "With container verification disabled (F2) and encryption bypassed (F1), "
            "an attacker who can modify the boot medium can set run_mode to 'DEV' "
            "to cause the dev verification key to be loaded, enabling acceptance "
            "of dev-signed firmware and tools."
        ),
        "evidence": {
            "file": "/etc/init.d/hsu-init (rootfs.img)",
            "code": (
                "run_mode=`cat /run_mode`\n"
                "if [ $run_mode == 'DEV' ] ; then\n"
                "    if [ -e /hsu-keys/tools-dev-verify-key.der ]; then\n"
                "        hsu-set-verify-key /hsu-keys/tools-dev-verify-key.der\n"
                "    fi\n"
                "elif [ $run_mode == 'REL' ] ; then\n"
                "    if [ -e /hsu-keys/tools-rel-verify-key.der ]; then\n"
                "        hsu-set-verify-key /hsu-keys/tools-rel-verify-key.der\n"
                "    fi\n"
                "fi"
            ),
            "run_mode_location": "/run_mode in rootfs.img squashfs (not in /opt/cisco/)",
        },
        "impact": (
            "Boot-time key selection controllable by an attacker who can modify the ISO. "
            "Enables loading dev-signed tools and firmware in production hardware."
        ),
        "remediation": (
            "Derive run_mode from a TPM-sealed measurement or signed boot parameter. "
            "At minimum, do not read run_mode from a mutable plaintext file."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "DEBUG flag controls telnetd; plaintext in same-ISO hsu-profile.sh",
        "description": (
            "hsu-init enables telnetd if DEBUG == 'yes': "
            "'if [ $DEBUG == \"yes\" ] ; then telnetd; fi'. "
            "DEBUG is sourced from /etc/profile.d/hsu-profile.sh which sets 'export DEBUG=no'. "
            "hsu-profile.sh is in the rootfs.img squashfs; with container integrity "
            "bypassed (F1, F2), modifying DEBUG=yes in hsu-profile.sh enables network "
            "telnet access. "
            "Unlike HUU 6.0.2 which uses hardware detection (is_cisco_server()), "
            "the 4.2.3r telnetd gate is a single plaintext string comparison. "
            "No authentication is required on the resulting telnet session by default."
        ),
        "evidence": {
            "hsu_init": "if [ $DEBUG == \"yes\" ] ; then telnetd; fi",
            "hsu_profile": "export DEBUG=no",
            "profile_location": "/etc/profile.d/hsu-profile.sh (rootfs.img squashfs)",
        },
        "impact": (
            "Trivial telnetd activation by modifying one plaintext variable in the rootfs. "
            "Enables unauthenticated network access to the HUU boot environment."
        ),
        "remediation": (
            "Remove telnetd from production builds entirely. "
            "If debug access is required, gate on a signed boot parameter."
        ),
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
