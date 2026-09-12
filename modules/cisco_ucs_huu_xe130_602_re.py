"""
Cisco UCS HUU XE130CM8 6.0.2.260143 ISO RE

Target:  ucs-xe130cm8-huu-6.0.2.260143.iso
         XE130 CM8 Host Upgrade Utility, version 6.0.2.260143
         Platform codename: pandora (shared with C480M5)
         6.0.2 container architecture: base.tar.gz inside squashfs;
         Two init scripts: init.sh (outer bootstrap) + init-huu.sh (container orchestrator);
         New hooks vs 4.3.6: BlueField_Hook.py (DPU), AMD_AI_NIC_Hook.py;
         WISTRON ODM identity bypass in init.sh;
         IMG_VERIFY explicitly hardcoded to 0 in preinit_container_env()
Files:   rootfs.img (squashfs, OpenEmbedded)
         ucs-xe130cm8-huu-container-6.0.2.260143-base.tar.gz (inside squashfs)
         /root/hsu/hsu.tgz.enc (42MB, 6.0.2 cipher format, decrypt-file co-located)
         /etc/init.sh (outer bootstrap; WISTRON ODM bypass; timefile injection)
         /etc/init-huu.sh (container orchestrator; IMG_VERIFY=0 default)
         /root/hsu/BlueField_Hook.py (DPU firmware; --nosignature RPM; bfb-install injection)
         /root/hsu/AMD_AI_NIC_Hook.py (AI NIC firmware; unxz path injection)
         /root/hsu/HuuApp.py (CMCSecureBoot, UCSUpdate -- no auth)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_xe130_602_re",
    "firmware": "ucs-xe130cm8-huu-6.0.2.260143.iso",
    "components": {
        "/etc/init-huu.sh (preinit_container_env)": (
            "Line 357: '[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0'; "
            "explicitly sets IMG_VERIFY=0 when unset, defaulting the bypass to active; "
            "IMGVERIFY_PUB_KEY_FILE exported to /hsu-keys/tools-verify-key.pem "
            "(key present but verification skipped when IMG_VERIFY=0)"
        ),
        "/etc/init.sh (setup_dev)": (
            "WISTRON-TODO comment: "
            "'Temporary fix to workaround the platform ID issue in Mustang. Revert it once the PID issue is resolved'; "
            "if [ ! -f '/opt/cisco/cisco_server' ]; then "
            "cp /etc/enable_usb_nic_wistron.sh /etc/enable_usb_nic.sh; fi -- "
            "replaces Cisco NIC config with WISTRON ODM variant when platform marker absent"
        ),
        "/root/hsu/BlueField_Hook.py": (
            "DPU firmware update for NVIDIA BlueField (BF2/BF3); "
            "rpm --nodeps -i {rshim.rpm} --ignoresize --nosignature (shell=True); "
            "bfb-install --bfb {firmware} --rshim {rshim_id} (shell=True); "
            "firmware from component.get_firmware_by_name() (catalog-controlled path)"
        ),
        "/root/hsu/AMD_AI_NIC_Hook.py": (
            "AMD AI NIC (Pensando/Elba DSC) firmware update; "
            "unxz -f {dst_nicctl_compressed} (shell=True); "
            "dst_nicctl_compressed derived from catalog-controlled firmware path"
        ),
        "/root/hsu/HuuApp.py": (
            "CMCSecureBoot + UCSUpdate with no auth; "
            "same codebase as C480M5 4.3.2 and C245M8/C220M8 4.3.6; "
            "extends to 6.0.2 line on pandora platform"
        ),
    },
    "finding_count": "6F [1C+3H+2M+0L]",
    "cumulative": "777 [75C+265H+244M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated CMCSecureBoot and UCSUpdate carry forward to 6.0.2 line on XE130CM8",
        "description": (
            "HuuApp.py in the XE130CM8 6.0.2 container includes CMCSecureBoot "
            "and UCSUpdate with no authentication, identical to C480M5 4.3.2 (F1/F2), "
            "C245M8 4.3.6 (F1/F2), and C220M8 4.3.6. "
            "XE130CM8 uses platform codename pandora (same as C480M5). "
            "POST /huu/v1/CMCSecureBoot with '{\"SecureBoot\": false}' disables "
            "secure boot on available CMC objects with no auth check. "
            "POST /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate "
            "triggers async firmware flash with no auth check. "
            "No before_request hook, no @auth decorator exists in app.py, "
            "HuuApp.py, or RedfishApp.py. "
            "This finding now spans 4 distinct products / 3 version branches: "
            "C480M5 4.3.2, C245M8 4.3.6, C220M8 4.3.6, XE130CM8 6.0.2."
        ),
        "evidence": {
            "file": "/root/hsu/HuuApp.py in base.tar.gz",
            "routes": (
                "POST /huu/v1/CMCSecureBoot; "
                "POST /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate"
            ),
            "platforms": "pandora (C480M5 4.3.2, XE130CM8 6.0.2), mountadams2 (C245M8 4.3.6), godzilla1 (C220M8 4.3.6)",
        },
        "impact": (
            "Unauth secure boot toggle and firmware flash across all four products. "
            "Finding confirmed unpatched from 4.3.2 (2026-Q1) through 6.0.2 (2026-Q2)."
        ),
        "remediation": "Require session token on all HuuApp endpoints. Fix has not been applied across 3 version branches.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "BlueField DPU firmware RPM installed with --nosignature (verification explicitly bypassed)",
        "description": (
            "BlueField_Hook.py installs the rshim kernel module RPM with: "
            "'rpm --nodeps -i /tmp/rshim.rpm --ignoresize --nosignature' "
            "via subprocess.check_output(cmd, shell=True). "
            "The code comment includes an example output showing the signature warning "
            "that --nosignature suppresses: "
            "'warning: rshim-2.0.8-1.el9.x86_64.rpm: "
            "Header V4 RSA/SHA256 Signature, key ID fd431d51: NOKEY'. "
            "This is an intentional bypass -- the developer observed the warning "
            "and added --nosignature to suppress it instead of importing the signing key. "
            "The RPM is copied from the firmware catalog location before installation: "
            "'shutil.copy(rshim_rpm_file, dst_rpm_file)' with dst_rpm_file = '/tmp/rshim.rpm'. "
            "An attacker who substitutes rshim_rpm_file (catalog-controlled path) delivers "
            "an arbitrary RPM that installs without signature verification."
        ),
        "evidence": {
            "file": "/root/hsu/BlueField_Hook.py:279",
            "code": (
                "cmd = f'rpm --nodeps -i {dst_rpm_file} --ignoresize --nosignature'\n"
                "output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)"
            ),
            "comment": (
                "# rpm --nodeps -i rshim-2.0.8-1.el9.x86_64.rpm --ignoresize --nosignature\n"
                "# warning: rshim-2.0.8-1.el9.x86_64.rpm: "
                "Header V4 RSA/SHA256 Signature, key ID fd431d51: NOKEY"
            ),
        },
        "impact": (
            "Malicious RPM package installs without signature verification during BlueField DPU firmware update. "
            "rshim is a kernel module -- malicious rshim achieves kernel-level code execution. "
            "BlueField DPUs are present in XE130CM8 configurations as SmartNIC accelerators."
        ),
        "remediation": "Import the signing key and verify RPM signatures. Do not use --nosignature in production.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "BlueField DPU bfb-install firmware path injection via catalog",
        "description": (
            "BlueField_Hook.py triggers DPU firmware flash with: "
            "'cmd = f\"sh -x /usr/sbin/bfb-install --bfb {firmware} "
            "--rshim {rshim_id} >> {workbase_path}/logs/bfb-install_debug_log_{slot}.txt 2>&1\"' "
            "via subprocess.check_output(cmd, shell=True). "
            "firmware = component.get_firmware_by_name(firmware_name=firmware_name) "
            "retrieves the path from Catalog.json. "
            "A crafted Catalog.json entry for the BlueField firmware with a path containing "
            "shell metacharacters achieves command injection when bfb-install runs. "
            "bfb-install operates with root privileges and interacts with the DPU via rshim. "
            "rshim_id is derived from hardware enumeration via lspci output parsing "
            "(additional injection if lspci output is attacker-influenced in a VM)."
        ),
        "evidence": {
            "file": "/root/hsu/BlueField_Hook.py:493",
            "code": (
                "firmware = component.get_firmware_by_name(firmware_name=firmware_name)\n"
                "cmd = f'sh -x /usr/sbin/bfb-install --bfb {firmware} "
                "--rshim {rshim_id} >> .../bfb-install_debug_log_{slot}.txt 2>&1'\n"
                "output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)"
            ),
        },
        "impact": "Code execution during BlueField DPU firmware update via catalog path injection.",
        "remediation": "Pass firmware path and rshim ID via subprocess argument list.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "timefile command injection persists in 6.0.2 line via init.sh start_hsu_agent()",
        "description": (
            "init.sh start_hsu_agent() in XE130CM8 6.0.2 carries the identical injection "
            "from C220M8/C245M8 4.3.6: "
            "'chroot \"${MNTPATH}\" sh -c \"cd ${WORKBASE} && "
            "$(cat ${MNTPATH}/${WORKBASE}/logs/timefile) && python ${WORKBASE}/hsu-redfish.py\"'. "
            "TIME_FILE is exported at line 10: 'export TIME_FILE=/root/hsu/logs/timefile'. "
            "The /logs bind-mount delivers attacker-controlled timefile content. "
            "This injection is now confirmed across 4.3.6 and 6.0.2 release branches."
        ),
        "evidence": {
            "file": "/etc/init.sh:67",
            "code": (
                "chroot \"${MNTPATH}\" sh -c "
                "\"cd ${WORKBASE} && $(cat ${MNTPATH}/${WORKBASE}/logs/timefile) "
                "&& python ${WORKBASE}/hsu-redfish.py 2> "
                "${WORKBASE}/logs/BootMode.log | tee ${WORKBASE}/logs/HSUAgent &\""
            ),
            "branches": "C220M8/C245M8 4.3.6 (init.sh MD5: 8569fb14...) and XE130CM8 6.0.2 (init.sh MD5: 672809...)",
        },
        "impact": "Root code execution in HUU container before Redfish API starts via pre-planted timefile on boot medium.",
        "remediation": "Do not evaluate timefile content via command substitution.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "IMG_VERIFY explicitly hardcoded to 0 in preinit_container_env() (vendor-active bypass)",
        "description": (
            "init-huu.sh preinit_container_env() at line 357: "
            "'[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0'. "
            "In 4.3.x, IMG_VERIFY was simply absent from hsu-profile.sh (bypass by omission). "
            "In 6.0.2, the bypass is made explicit: "
            "when IMG_VERIFY is not set in the environment, init-huu.sh actively sets it to 0. "
            "imgverify still checks 'if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi' -- "
            "IMG_VERIFY=0 causes immediate exit(0) (bypass). "
            "The verification key file is exported: "
            "'export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-verify-key.pem', "
            "confirming the infrastructure exists but is disabled by the 0 default. "
            "An operator who sets IMG_VERIFY=1 before booting would enable verification; "
            "the production boot path never does this."
        ),
        "evidence": {
            "file": "/etc/init-huu.sh:357",
            "code": (
                "export IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-verify-key.pem\n"
                "[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0"
            ),
            "imgverify": "if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi",
        },
        "impact": (
            "Container integrity verification never executes in production. "
            "Tampered base.tar.gz accepted without error. "
            "The hardcoded 0 default is a more explicit bypass than the 4.3.x omission."
        ),
        "remediation": "Change default to IMG_VERIFY=1. Remove the 0-default line entirely.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "WISTRON ODM identity bypass via absent /opt/cisco/cisco_server marker",
        "description": (
            "init.sh setup_dev() contains: "
            "'# WISTRON-TODO: Temporary fix to workaround the platform ID issue in Mustang. "
            "Revert it once the PID issue is resolved' "
            "followed by: "
            "'if [ ! -f \"/opt/cisco/cisco_server\" ]; then "
            "cp /etc/enable_usb_nic_wistron.sh /etc/enable_usb_nic.sh; fi'. "
            "When /opt/cisco/cisco_server does not exist, the WISTRON ODM NIC "
            "configuration script replaces the Cisco NIC configuration. "
            "The TODO comment references a platform ID issue on 'Mustang' (development codename) "
            "and was marked as temporary but shipped in production 6.0.2.260143. "
            "An attacker who can delete /opt/cisco/cisco_server on the HUU host "
            "triggers the WISTRON script path, which may enable additional interfaces "
            "or apply different network configuration. "
            "The comment reveals: ODM manufacturer (WISTRON), development codename (Mustang), "
            "and a known platform ID defect in shipping firmware."
        ),
        "evidence": {
            "file": "/etc/init.sh:22-27",
            "code": (
                "# WISTRON-TODO: Temporary fix to workaround the platform ID issue in Mustang. "
                "Revert it once the PID issue is resolved\n"
                "if [ ! -f \"/opt/cisco/cisco_server\" ]; then\n"
                "  cp /etc/enable_usb_nic_wistron.sh /etc/enable_usb_nic.sh\n"
                "fi"
            ),
            "reveals": "ODM=WISTRON, platform codename=Mustang (XE130CM8 internal name), unresolved PID defect",
        },
        "impact": (
            "Platform identity check bypass via marker-file deletion. "
            "Intelligence disclosure: ODM identity, internal platform name, unresolved hardware defect. "
            "WISTRON NIC script may configure additional network interfaces not intended for production."
        ),
        "remediation": "Remove the WISTRON conditional path from production builds. Resolve the PID issue properly.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
