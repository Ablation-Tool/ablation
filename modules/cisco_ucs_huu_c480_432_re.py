"""
Cisco UCS HUU C480M5 4.3.2.260020 ISO RE

Target:  ucs-c480m5-huu-4.3.2.260020.iso
         C480 M5 Host Upgrade Utility, version 4.3.2.260020
         Transition build: base.tar.gz container (was direct overlay in 4.2.3r),
         hsu.tgz.enc retained but encryption format changed (no Salted__ header),
         6 NVIDIA hooks unchanged from 4.2.3r, new HuuApp API endpoints added
Files:   rootfs.img (squashfs, OpenEmbedded)
         ucs-c480m5-huu-container-4.3.2.260020.squashfs -> base.tar.gz inside
         /root/hsu.tgz.enc (encrypted Python app, new cipher format)
         /usr/sbin/decrypt-file (ELF64, stripped; ships in rootfs)
         /root/hsu/HuuApp.py (new: CMCSecureBoot, UCSUpdate, UCSDiscovery)
         /root/hsu/NVIDIA_*_Hook.py (6 hooks, same code as 4.2.3r)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c480_432_re",
    "firmware": "ucs-c480m5-huu-4.3.2.260020.iso",
    "components": {
        "hsu.tgz.enc (/root/hsu.tgz.enc in base.tar.gz)": (
            "Encrypted Python app, 12MB gzip; "
            "header NO LONGER starts with 'Salted__' (cipher format changed from 4.2.3r); "
            "decrypt-file still ships in rootfs (c5c63da355bfb74c092083113c7bfd24); "
            "same structural flaw: key and ciphertext co-located"
        ),
        "HuuApp.py (/root/hsu/HuuApp.py)": (
            "Flask Blueprint; registers UCSUpdate, UCSDiscovery, CMCSecureBoot; "
            "NO auth middleware anywhere in app.py, HuuApp.py, RedfishApp.py; "
            "CMCSecureBoot: POST /huu/v1/CMCSecureBoot sets secure boot on both chassis CMCs; "
            "UCSUpdate: POST /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate "
            "triggers async firmware update"
        ),
        "hsu-init (/etc/init.d/hsu-init, rootfs)": (
            "Container verification restored (imgverify called on base.tar.gz); "
            "imgverify still exits 0 when IMG_VERIFY unset; "
            "run_mode from /opt/cisco/run_mode (fixed from 4.2.3r /run_mode); "
            "telnetd if CONFIG_SEC_UTILS_SIGN_MODE == 'dev' (not in profile)"
        ),
        "NVIDIA hooks": (
            "6 files (A100, M10, M60, P, V100, V100_32GB); "
            "identical code to 4.2.3r: unzip -P revwfvn<tag.txt> shell=True"
        ),
    },
    "finding_count": "6F [2C+3H+1M+0L]",
    "cumulative": "747 [71C+249H+235M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated CMCSecureBoot endpoint disables secure boot on both chassis CMCs",
        "description": (
            "HuuApp.py registers CMCSecureBoot at POST /huu/v1/CMCSecureBoot. "
            "The handler reads the 'SecureBoot' boolean from the request body and calls "
            "cmc_obj[CMC1].set_secure_boot(secure_boot) and cmc_obj[CMC2].set_secure_boot(secure_boot) "
            "for both chassis slots on the C480M5 dual-node chassis. "
            "There is no authentication middleware in app.py, HuuApp.py, or anywhere else in the Flask app. "
            "No session token, no HTTP basic auth, no before_request hook, "
            "no @auth decorator exists on any route. "
            "Any host reachable on port 80 of the HUU management interface can toggle secure boot "
            "on both CMCs with a single unauthenticated HTTP POST: "
            "'curl -X POST -H \"Content-Type: application/json\" "
            "-d \\'{ \"SecureBoot\": false }\\' http://<huu-ip>/huu/v1/CMCSecureBoot'. "
            "Disabling secure boot permanently alters the firmware trust chain "
            "for the C480M5 chassis management controllers."
        ),
        "evidence": {
            "file": "/root/hsu/HuuApp.py",
            "route": "POST /huu/v1/CMCSecureBoot",
            "code": (
                "class CMCSecureBoot(Resource):\n"
                "    def post(self):\n"
                "        ...\n"
                "        secure_boot = request_data[huu_api.SECURE_BOOT]\n"
                "        ...\n"
                "        state = self.enable_secure_boot(secure_boot)\n"
                "\n"
                "    def enable_secure_boot(self, secure_boot):\n"
                "        cmc_obj[CMC1].set_secure_boot(secure_boot)\n"
                "        cmc_obj[CMC2].set_secure_boot(secure_boot)"
            ),
            "auth_check": "grep -rn before_request,@auth,token,Authorization: 0 matches in app.py/HuuApp.py/RedfishApp.py",
        },
        "impact": (
            "Unauthenticated attacker on the management network can permanently disable "
            "secure boot on C480M5 CMC1 and CMC2, eliminating firmware integrity enforcement "
            "on both chassis controllers. "
            "During HUU operation (firmware update sessions), this surface is accessible "
            "to any host on the management VLAN."
        ),
        "remediation": (
            "Require authentication on all HuuApp endpoints. "
            "At minimum, gate CMCSecureBoot behind session token verification."
        ),
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": "Unauthenticated firmware update trigger via UCSUpdate POST endpoint",
        "description": (
            "HuuApp.py registers UCSUpdate at POST "
            "/redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate. "
            "No authentication is required. "
            "A POST with a JSON body specifying 'Mode', 'Targets', and 'Reboot' "
            "triggers an async firmware update task that calls huu_api.update(task_id) "
            "and optionally huu_api.exit_hsu() for a host reboot. "
            "Targets can include '/redfish/v1/UpdateService/FirmwareInventory/CIMC' "
            "(BMC firmware) and BIOS components. "
            "curl -X POST -H 'Content-Type: application/json' "
            "-d '{\"Mode\": \"Update\", \"Targets\": "
            "[\"/redfish/v1/UpdateService/FirmwareInventory/CIMC\"], "
            "\"Reboot\": true}' http://<huu-ip>/redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate "
            "initiates a firmware flash and host reboot with no credential check."
        ),
        "evidence": {
            "file": "/root/hsu/HuuApp.py",
            "route": "POST /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate",
            "code": (
                "class UCSUpdate(Resource):\n"
                "    def post(self):\n"
                "        # no auth check\n"
                "        err_resp = huu_api.verify_post_request(request=request, empty_post_data=True)\n"
                "        ...\n"
                "        task_id = huu_api.generate_task_id(huu_api.huu_base_obj.mode)\n"
                "        async_task = AsyncUpdate(task_id=task_id)\n"
                "        async_task.start()"
            ),
        },
        "impact": (
            "Unauthenticated attacker on the management network can flash CIMC/BIOS firmware "
            "and trigger a host reboot during HUU operation. "
            "Combined with the NVIDIA injection finding (F3), a crafted firmware package "
            "on an accessible NFS/HTTP path results in code execution during update."
        ),
        "remediation": "Require authentication on all firmware update endpoints.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "NVIDIA firmware ZIP extraction command injection via tag.txt (persists from 4.2.3r)",
        "description": (
            "Six NVIDIA GPU firmware hooks (NVIDIA_A100_Hook.py, NVIDIA_M10_Hook.py, "
            "NVIDIA_M60_Hook.py, NVIDIA_P_Hook.py, NVIDIA_V100_Hook.py, NVIDIA_V100_32GB_Hook.py) "
            "are identical to 4.2.3r. "
            "The command injection via tag.txt content in subprocess.check_call(command, shell=True) "
            "is unchanged. "
            "'command = \"unzip -P revwfvn\" + str(password) + \" \" + dirname + \"/\" "
            "+ str(file) + \" -d \" + str(dirname)' with password from tag.txt. "
            "This finding persists unpatched across at least two major HUU version branches."
        ),
        "evidence": {
            "files": "NVIDIA_A100_Hook.py:330, same code as 4.2.3r hooks",
            "code": (
                "tag_file = open(dirname + \"/tag.txt\", 'r')\n"
                "password = tag_file.read().strip()\n"
                "command = \"unzip -P revwfvn\" + str(password) + \" \" + dirname + \"/\" "
                "+ str(file) + \" -d \" + str(dirname)\n"
                "subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL)"
            ),
        },
        "impact": "Arbitrary code execution during NVIDIA GPU firmware update. Same as 4.2.3r finding.",
        "remediation": "Pass password via subprocess argument list, not shell string construction.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "imgverify bypass via IMG_VERIFY unset now sole protection for base.tar.gz",
        "description": (
            "Container verification was restored in 4.3.2 (was commented out in 4.2.3r): "
            "'if ! imgverify /tmp/ucs-*-container-*-base.tar.gz >> /tmp/imgverify.log 2>&1; then "
            "fatal \"Base container signature verification failed!\"; fi'. "
            "However, imgverify still exits 0 when IMG_VERIFY is unset: "
            "'if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi'. "
            "IMG_VERIFY is not set in hsu-profile.sh. "
            "The restored verification call is the ONLY protection for base.tar.gz integrity "
            "in 4.3.2 (4.2.3r had commented verification but encrypted app). "
            "The imgverify bypass completely neutralizes the restored protection."
        ),
        "evidence": {
            "hsu_init": (
                "if ! imgverify /tmp/ucs-*-container-*-base.tar.gz; then\n"
                "    fatal \"Base container signature verification failed!\"\n"
                "fi"
            ),
            "imgverify": "if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi",
            "profile": "hsu-profile.sh: IMG_VERIFY not set",
        },
        "impact": (
            "Tampered base.tar.gz accepted as verified. "
            "The restoration of the verification call in 4.3.2 provides no real protection "
            "because imgverify's first check exits success on any non-1 value including unset."
        ),
        "remediation": "Set IMG_VERIFY=1 unconditionally in hsu-profile.sh.",
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": "BMC password inline in ipmitool subprocess (persists from 4.2.3r)",
        "description": (
            "ipmi_cmd.py line 126: "
            "'cmd = cmd + \" -I lanplus -N 2 -H \" + self.ip + \" -U \" + self.username "
            "+ \" -P \" + self.password' with subprocess.check_output(cmd, shell=True). "
            "Identical to 4.2.3r and SCU 7.1.7.260100. "
            "BMC password visible in /proc/<pid>/cmdline throughout IPMI operations."
        ),
        "evidence": {
            "file": "/root/hsu/ipmi_cmd.py:126",
            "code": "cmd = cmd + \" -I lanplus -N 2 -H \" + self.ip + \" -U \" + self.username + \" -P \" + self.password",
        },
        "impact": "BMC credential harvest by any process with /proc access during update operations.",
        "remediation": "Pass IPMI password via environment variable or stdin.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "hsu.tgz.enc cipher format changed but decrypt-file co-location persists",
        "description": (
            "4.3.2 hsu.tgz.enc no longer uses the 'Salted__' header seen in 4.2.3r. "
            "The first 16 bytes are: 07 75 8f e8 eb 57 43 4e bc 62 cb 4f 93 e8 b5 88 "
            "(not the EVP_BytesToKey/MD5 format). "
            "The encryption format was hardened between 4.2.3r and 4.3.2. "
            "However, /usr/sbin/decrypt-file (SHA1: dd487811432df9995794461e836c6f9a47b90c56) "
            "still ships in the rootfs.img squashfs of the same ISO. "
            "Running 'sudo chroot rootfs /usr/sbin/decrypt-file /tmp/hsu.tgz.enc /tmp/out.tgz' "
            "successfully decrypts the 12MB gzip (confirmed empirically). "
            "The structural flaw persists: key and ciphertext on the same medium."
        ),
        "evidence": {
            "header_hex_432": "07 75 8f e8 eb 57 43 4e bc 62 cb 4f 93 e8 b5 88 (not Salted__)",
            "header_hex_423r": "53 61 6c 74 65 64 5f 5f ... (Salted__ EVP_BytesToKey)",
            "decrypt_file_hash": "c5c63da355bfb74c092083113c7bfd24",
            "decrypt_file_location": "/usr/sbin/decrypt-file in rootfs.img (same squashfs distribution)",
            "decrypted_size": "12482560 bytes gzip",
        },
        "impact": (
            "Cisco hardened the encryption format between versions, but co-location of "
            "key and ciphertext means the improvement provides no meaningful protection. "
            "Attacker with ISO access can still extract full Python source."
        ),
        "remediation": "Separate encryption key from distribution medium entirely.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
