"""
Cisco UCS HUU C220M8 4.3.6.250039 ISO RE

Target:  ucs-c220m8-huu-4.3.6.250039.iso
         C220 M8 Host Upgrade Utility, version 4.3.6.250039
         base.tar.gz container architecture; Python 3.x; AMD GPU support added;
         hsu_agent.cpk: ARM32 systemd service for OOB BMC firmware update
Files:   rootfs.img (squashfs, OpenEmbedded)
         ucs-c220m8-huu-container-4.3.6.250039.squashfs -> base.tar.gz
         /root/hsu.tgz.enc (encrypted app)
         cpk/hsu_agent.cpk (ARM32 deb wrapped in CPK, deploys to BMC CIMC)
         /etc/init.sh (container orchestrator; start_hsu_agent with timefile injection)
         /root/hsu/AMD_GPU_Hook.py (AMD GPU firmware update, shell=True)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c220_436_re",
    "firmware": "ucs-c220m8-huu-4.3.6.250039.iso",
    "components": {
        "hsu_agent.cpk (cpk/ in container squashfs)": (
            "ARM32 ELF (PIE, GNU_RELRO partial, stripped); "
            "[pkg] header format: headerVersion=2, platform=godzilla1 (C220M8 codename); "
            "inner: gzip tar -> deb (control.tar.gz + data.tar.gz); "
            "no signature field in [pkg] header; delivered to BMC CIMC via OOB; "
            "installs: hsu_agent binary, hsu_agent.sh, libhsu_plugin_*.so, systemd service"
        ),
        "hsu_agent.service (in deb data.tar.gz)": (
            "EnvironmentFile=-/tmp/hsu-agent/hsu_env; "
            "hsu_agent.sh creates /tmp/hsu-agent/ and /tmp/hsu-agent/hsu_env; "
            "if libjemalloc exists: writes LD_PRELOAD=... to /tmp/hsu-agent/hsu_env; "
            "Unix socket at /tmp/hsu-agent/hsu-socket"
        ),
        "init.sh /etc/init.sh (container)": (
            "start_hsu_agent(): "
            "chroot MNTPATH sh -c 'cd WORKBASE && $(cat MNTPATH/WORKBASE/logs/timefile) && python hsu-redfish.py'; "
            "$(cat timefile) executed as shell command; timefile from bind-mounted /logs/"
        ),
        "AMD_GPU_Hook.py + AMD_MI210_GPU_Hook.py": (
            "AMD GPU firmware update hooks; "
            "firmware paths (bios_rom, plx_fw) from catalog; "
            "all calls: subprocess.check_output(cmd, shell=True)"
        ),
    },
    "finding_count": "6F [0C+4H+2M+0L]",
    "cumulative": "765 [72C+259H+242M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "timefile command injection in start_hsu_agent() via command substitution",
        "description": (
            "init.sh start_hsu_agent() launches the HUU Redfish application with: "
            "'chroot \"${MNTPATH}\" sh -c \"cd ${WORKBASE} && "
            "$(cat ${MNTPATH}/${WORKBASE}/logs/timefile) && python ${WORKBASE}/hsu-redfish.py\"'. "
            "The content of logs/timefile is evaluated via command substitution ($()) "
            "inside the double-quoted shell string. "
            "${MNTPATH}/${WORKBASE}/logs/ is bind-mounted from /logs/ on the host: "
            "'mount --bind /logs \"${MNTPATH}/${WORKBASE}/logs\"'. "
            "timefile is intended to hold a time-setting command (e.g., 'date -s \"...\"'). "
            "An attacker who can write to /logs/timefile on the HUU boot medium "
            "(bootable USB, PXE, or firmware repository) can inject arbitrary shell commands "
            "that execute in the HUU container context as root before hsu-redfish.py starts."
        ),
        "evidence": {
            "file": "/etc/init.sh (container base.tar.gz)",
            "code": (
                "chroot \"${MNTPATH}\" sh -c "
                "\"cd ${WORKBASE} && "
                "$(cat ${MNTPATH}/${WORKBASE}/logs/timefile) && "
                "python ${WORKBASE}/hsu-redfish.py 2> ${WORKBASE}/logs/BootMode.log | "
                "tee ${WORKBASE}/logs/HSUAgent &\""
            ),
            "bind_mount": "mount --bind /logs \"${MNTPATH}/${WORKBASE}/logs\"",
            "timefile_path": "${MNTPATH}/${WORKBASE}/logs/timefile = /mnt/cdrom/root/hsu/logs/timefile",
        },
        "impact": (
            "Pre-placed timefile on boot medium achieves root code execution in the HUU container "
            "before the Redfish API starts. "
            "Enables persistence across HUU sessions by modifying hsu-redfish.py or other container files."
        ),
        "remediation": (
            "Do not evaluate timefile content via command substitution. "
            "Pass timezone as a signed parameter, not executable content. "
            "Validate timefile against a strict date format before execution."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "hsu_agent EnvironmentFile in /tmp enables LD_PRELOAD injection on BMC",
        "description": (
            "hsu_agent.service specifies EnvironmentFile=-/tmp/hsu-agent/hsu_env. "
            "hsu_agent.sh init_config() creates /tmp/hsu-agent/ and /tmp/hsu-agent/hsu_env: "
            "'mkdir -p /tmp/hsu-agent/; touch /tmp/hsu-agent/hsu_env'. "
            "If /usr/local/lib/libjemalloc.so.2 exists, init_config() writes "
            "'LD_PRELOAD=/usr/local/lib/libjemalloc.so.2' to /tmp/hsu-agent/hsu_env. "
            "The LD_PRELOAD mechanism is active when libjemalloc is present. "
            "A process with write access to /tmp on the CIMC BMC filesystem "
            "that creates /tmp/hsu-agent/hsu_env before init_config() runs "
            "can inject LD_PRELOAD pointing to an attacker-controlled shared library. "
            "hsu_agent loads and executes the injected library with its privileges."
        ),
        "evidence": {
            "service_file": "EnvironmentFile=-/tmp/hsu-agent/hsu_env",
            "startup_script": (
                "mkdir -p /tmp/hsu-agent/\n"
                "touch /tmp/hsu-agent/hsu_env\n"
                "if [ -e /usr/local/lib/libjemalloc.so.2 ]; then\n"
                "    echo LD_PRELOAD=/usr/local/lib/libjemalloc.so.2 > /tmp/hsu-agent/hsu_env\n"
                "fi"
            ),
            "binary": "hsu_agent: ARM32 PIE, stripped, partial RELRO",
        },
        "impact": (
            "LD_PRELOAD injection into hsu_agent on the CIMC BMC. "
            "hsu_agent is the OOB firmware update agent; code execution in its context "
            "grants access to firmware update operations and BMC management functions."
        ),
        "remediation": "Place hsu_agent environment file in a protected directory (/var/cisco/ or /run/). Not /tmp.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "hsu_agent Unix socket at /tmp/hsu-agent/hsu-socket accessible to co-resident processes",
        "description": (
            "hsu_agent.sh stop handler: "
            "'echo \"{\\\"method\\\":\\\"stop\\\"}\" | ncat -U /tmp/hsu-agent/hsu-socket'. "
            "hsu_agent listens on a Unix domain socket at /tmp/hsu-agent/hsu-socket. "
            "/tmp is world-readable and typically world-writable on Linux BMC systems. "
            "Any process running on the CIMC BMC with access to the /tmp filesystem "
            "can send JSON commands to hsu_agent via the socket. "
            "The stop command format ({\"method\":\"stop\"}) implies a JSON-RPC style interface. "
            "Other methods (start, update, inventory queries) may also be accepted. "
            "Socket permissions are not visible from static analysis but /tmp residence "
            "means non-root processes can typically interact with it."
        ),
        "evidence": {
            "file": "hsu_agent.sh in deb data.tar.gz",
            "stop_cmd": "echo '{\"method\":\"stop\"}' | ncat -U /tmp/hsu-agent/hsu-socket",
            "socket_location": "/tmp/hsu-agent/hsu-socket (/tmp = world-accessible)",
        },
        "impact": (
            "Co-resident process on CIMC can issue stop (and potentially other) commands "
            "to hsu_agent, disrupting firmware update operations. "
            "If the JSON interface accepts update or exec methods, command injection possible."
        ),
        "remediation": "Move socket to /run/ or /var/run/ with restrictive permissions (mode 0600, owned root).",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "hsu_agent CPK delivered without signature verification",
        "description": (
            "hsu_agent.cpk uses a proprietary [pkg] header format with fields: "
            "headerVersion, platform, version, hsu_version, tarOffset. "
            "There is no signature field, no checksum field, and no crypto material "
            "in the [pkg] header. "
            "The inner payload is a gzip tar containing a deb package "
            "(control.tar.gz + data.tar.gz). "
            "The outer container squashfs has imgverify called on base.tar.gz, "
            "but the cpk/ directory is in the squashfs directly (not in base.tar.gz), "
            "meaning it is not covered by any integrity check. "
            "An attacker who can substitute hsu_agent.cpk on the container squashfs "
            "(possible after imgverify bypass from F6 / shared finding) "
            "delivers a malicious ARM32 binary to the CIMC BMC as a systemd service."
        ),
        "evidence": {
            "cpk_header": (
                "[pkg]\\nheaderVersion=2\\nplatform=godzilla1\\n"
                "version=4.3.6.250039\\nhsu_version=1.0.2\\ntarOffset=128"
            ),
            "no_signature_field": "No sig, hash, or rsa field in [pkg] header",
            "cpk_location": "cpk/ directory in squashfs (NOT in base.tar.gz, not under imgverify)",
            "inner_format": "gzip tar -> deb (control + data.tar.gz) -> ARM32 ELF",
        },
        "impact": (
            "Malicious hsu_agent installs as a persistent systemd service on the CIMC BMC "
            "and gains access to OOB firmware update operations (CIMC, BIOS, VIC adapters, Board Controller). "
            "BMC-level persistence survives OS reinstallation."
        ),
        "remediation": "Add RSA signature to CPK format. Verify CPK signature before installation on BMC.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "AMD GPU firmware paths from catalog used in shell=True subprocess calls",
        "description": (
            "AMD_GPU_Hook.py and AMD_MI210_GPU_Hook.py execute firmware flash commands "
            "using firmware file paths from the component catalog: "
            "'cmd = amdgflash_tool + \" -i=\" + str(oem_data[\"plx_index\"]) "
            "+ \" -f -plx_write=\" + plx_fw' "
            "and similar constructions, all with subprocess.check_output(cmd, shell=True). "
            "plx_fw and bios_rom are obtained via "
            "component.get_firmware_by_name(\"amd_plx.bin\") and "
            "component.get_firmware_by_name(\"amd_vbios.rom\"). "
            "These paths originate from the firmware catalog (Catalog.json). "
            "A crafted Catalog.json with a firmware path containing shell metacharacters "
            "(e.g., 'amd_vbios.rom; id >>/tmp/pwned') causes injection during AMD GPU update."
        ),
        "evidence": {
            "file": "/root/hsu/AMD_GPU_Hook.py:519,538,558",
            "code": (
                "plx_fw = component.get_firmware_by_name('amd_plx.bin')\n"
                "cmd = amdgflash_tool + ' -i=' + str(oem_data['plx_index']) "
                "+ ' -f -plx_write=' + plx_fw\n"
                "subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)"
            ),
        },
        "impact": (
            "Catalog injection achieves code execution during AMD GPU firmware update. "
            "Catalog.json is validated only by MD5 (same weakness as ESU firmware bundles)."
        ),
        "remediation": "Pass firmware paths via subprocess argument list (not shell=True). Validate catalog paths against a safe regex.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "imgverify bypass via IMG_VERIFY unset; hsu.tgz.enc with co-located decrypt-file",
        "description": (
            "Identical to C480M5 4.3.2 F4 and F6: "
            "imgverify exits 0 when IMG_VERIFY is unset (IMG_VERIFY not in hsu-profile.sh). "
            "hsu.tgz.enc uses new-format cipher (not Salted__) but decrypt-file "
            "ships in the same rootfs.img squashfs. "
            "Running 'chroot rootfs /usr/sbin/decrypt-file /tmp/hsu.tgz.enc /tmp/out.tgz' "
            "decrypts the 42MB Python app (confirmed empirically). "
            "Both issues confirmed present in godzilla1 (C220M8) as well as pandora (C480M5)."
        ),
        "evidence": {
            "imgverify": "if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi",
            "hsu_tgz_enc_size": "42342400 bytes gzip (larger than C480M5 4.3.2 due to more GPU hooks)",
        },
        "impact": "Same as C480M5 4.3.2 F4/F6 -- tampered container accepted; full Python source extractable.",
        "remediation": "Set IMG_VERIFY=1. Remove decrypt-file from distribution.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
