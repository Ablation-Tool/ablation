"""
Cisco UCS HUU C245M8 6.0.2 ISO RE

Targets: ucs-c245m8-huu-6.0.2.260044.iso
         ucs-c245m8-huu-6.0.2.260180.iso
         C245 M8 Host Upgrade Utility, version 6.0.2 (AMD EPYC), two patch levels
         Platform codename: mountadams2
         6.0.2 container architecture: base.tar.gz in squashfs;
         Both versions: identical init-huu.sh (MD5: b85596e6...);
         260044: CPK version=6.0(2.260044) matches ISO;
         260180: CPK version=6.0(2.260096) -- hsu_agent is 84 builds stale vs ISO
Files:   rootfs.img (squashfs), base.tar.gz container (both versions)
         /etc/init.sh: WISTRON-TODO + timefile injection (identical across both)
         /etc/init-huu.sh: IMG_VERIFY=0 default (identical MD5 between 260044 and 260180)
         /root/hsu/hsu.tgz.enc: different between 260044 and 260180 (new builds)
         cpk/hsu_agent.cpk: [pkg] platform=mountadams2; 260180 bundles stale agent
         BlueField_Hook.py, AMD_AI_NIC_Hook.py, HuuApp.py (same as XE130CM8 6.0.2)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c245_602_re",
    "firmware": "ucs-c245m8-huu-6.0.2.260044.iso / ucs-c245m8-huu-6.0.2.260180.iso",
    "components": {
        "CPK 260180 version mismatch": (
            "260180 ISO bundles CPK with version=6.0(2.260096), hsu_version=1.0.1; "
            "ISO version is 6.0.2.260180 (84 build IDs ahead of CPK); "
            "260044 ISO bundles CPK version=6.0(2.260044) (aligned); "
            "hsu_agent deployed to CIMC BMC from 260180 ISO is 84 builds stale"
        ),
        "init-huu.sh (identical MD5 between 260044 and 260180)": (
            "preinit_container_env(): "
            "[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0; "
            "IMGVERIFY_PUB_KEY_FILE=/hsu-keys/tools-verify-key.pem present but unused"
        ),
        "init.sh (same WISTRON-TODO as XE130CM8 6.0.2)": (
            "WISTRON-TODO: 'Temporary fix to workaround platform ID issue in Mustang'; "
            "timefile injection in start_hsu_agent() ($(cat timefile) in double-quoted shell)"
        ),
        "BlueField_Hook.py + AMD_AI_NIC_Hook.py": (
            "Identical to XE130CM8 6.0.2: "
            "BlueField RPM --nosignature; bfb-install catalog path injection; "
            "AMD AI NIC unxz path injection"
        ),
        "HuuApp.py": (
            "CMCSecureBoot + UCSUpdate no auth; "
            "extends to C245M8 6.0.2 line (confirms unpatched 4.3.6 -> 6.0.2)"
        ),
    },
    "finding_count": "6F [1C+3H+2M+0L]",
    "cumulative": "783 [76C+268H+246M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated CMCSecureBoot and UCSUpdate persist in C245M8 6.0.2 (4.3.6 unfixed)",
        "description": (
            "HuuApp.py in C245M8 6.0.2.260044 and 6.0.2.260180 contains CMCSecureBoot "
            "and UCSUpdate with no authentication. "
            "Identical to C245M8 4.3.6 (F1/F2) and XE130CM8 6.0.2 (F1). "
            "Confirmed across five distinct firmware images on mountadams2 platform: "
            "4.3.6.250053, 6.0.2.260044, 6.0.2.260180; "
            "and pandora platform: C480M5 4.3.2, XE130CM8 6.0.2. "
            "No authentication middleware added between 4.3.6 and 6.0.2."
        ),
        "evidence": {
            "file": "/root/hsu/HuuApp.py (base.tar.gz)",
            "confirmed_versions": (
                "C480M5 4.3.2, C245M8 4.3.6, C220M8 4.3.6, "
                "XE130CM8 6.0.2, C245M8 6.0.2.260044, C245M8 6.0.2.260180"
            ),
        },
        "impact": "Persistent unpatched unauth firmware-flash and secure-boot-toggle across 2 major version branches.",
        "remediation": "Require authentication on all HuuApp endpoints.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "CPK version mismatch in 260180 ISO: hsu_agent deployed to CIMC is 84 builds stale",
        "description": (
            "The hsu_agent.cpk bundled in ucs-c245m8-huu-6.0.2.260180.iso "
            "has a [pkg] header with version=6.0(2.260096), hsu_version=1.0.1. "
            "The ISO version is 6.0.2.260180, 84 build IDs ahead of the bundled CPK version. "
            "The corresponding 260044 ISO bundles CPK version=6.0(2.260044) -- correctly aligned. "
            "When a server is updated using the 260180 ISO, hsu_agent.cpk is deployed to the CIMC BMC "
            "with code from build 260096. "
            "Any security fixes, functional changes, or bug fixes made to hsu_agent "
            "between builds 260096 and 260180 are not applied to the BMC. "
            "The mismatch is invisible to the operator: the ISO reports 6.0.2.260180 "
            "but the BMC agent is at 6.0(2.260096). "
            "Static analysis cannot determine what changed between 260096 and 260180 "
            "in the CPK content (the ARM32 binary ships stripped)."
        ),
        "evidence": {
            "cpk_260044": "[pkg] version=6.0(2.260044) (aligned with ISO)",
            "cpk_260180": "[pkg] version=6.0(2.260096) (84 builds behind ISO 6.0.2.260180)",
            "cpk_field": "No signature field; no integrity check on CPK in squashfs",
        },
        "impact": (
            "BMC CIMC runs hsu_agent at a code level that does not match the ISO version. "
            "Security fixes applied to the ISO after build 260096 are absent on the BMC. "
            "Operator has no visibility into the version mismatch during or after deployment."
        ),
        "remediation": "Ensure hsu_agent.cpk version matches the ISO version before shipping. Automate version alignment checks in the build pipeline.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "BlueField DPU RPM installed with --nosignature (persists in C245M8 6.0.2)",
        "description": (
            "BlueField_Hook.py carries the --nosignature RPM install pattern "
            "from XE130CM8 6.0.2 (F2) into C245M8 6.0.2. "
            "Both 260044 and 260180 contain identical BlueField_Hook.py "
            "(hook list diff between C245M8 6.0.2 and XE130CM8 6.0.2 is empty). "
            "'rpm --nodeps -i /tmp/rshim.rpm --ignoresize --nosignature' "
            "via subprocess.check_output(cmd, shell=True). "
            "Confirmed unpatched across pandora (XE130CM8) and mountadams2 (C245M8) platforms."
        ),
        "evidence": {
            "file": "/root/hsu/BlueField_Hook.py:279",
            "cmd": "rpm --nodeps -i {dst_rpm_file} --ignoresize --nosignature",
            "platforms": "XE130CM8 6.0.2 and C245M8 6.0.2 (identical hook list)",
        },
        "impact": "Malicious rshim RPM achieves kernel module execution without signature verification.",
        "remediation": "Import signing key. Verify RPM signatures before installation.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "timefile command injection persists in C245M8 6.0.2",
        "description": (
            "init.sh start_hsu_agent() at line 67 carries the same timefile injection "
            "confirmed across C220M8 4.3.6, C245M8 4.3.6, and XE130CM8 6.0.2. "
            "'chroot \"${MNTPATH}\" sh -c "
            "\"cd ${WORKBASE} && $(cat ${MNTPATH}/${WORKBASE}/logs/timefile) "
            "&& python ${WORKBASE}/hsu-redfish.py\"'. "
            "Both C245M8 6.0.2 versions have identical init.sh behavior. "
            "Finding unpatched across all 6.0.2 variants."
        ),
        "evidence": {
            "file": "/etc/init.sh:67",
            "injection": "$(cat ${MNTPATH}/${WORKBASE}/logs/timefile) in double-quoted shell string",
            "versions": "C245M8 6.0.2.260044 and 6.0.2.260180",
        },
        "impact": "Root code execution in HUU container via pre-planted timefile.",
        "remediation": "Do not evaluate timefile via command substitution.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "IMG_VERIFY=0 default persists in C245M8 6.0.2 (init-huu.sh MD5 identical between 260044 and 260180)",
        "description": (
            "init-huu.sh between C245M8 6.0.2.260044 and 6.0.2.260180 has the same MD5 "
            "(b85596e66a01928bd0584dbc197ace10). "
            "preinit_container_env(): "
            "'[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0'. "
            "Identical to XE130CM8 6.0.2 (F5). "
            "The verification key is present (IMGVERIFY_PUB_KEY_FILE set) "
            "but verification never runs with IMG_VERIFY=0."
        ),
        "evidence": {
            "file": "/etc/init-huu.sh (MD5: b85596e6... in both 260044 and 260180)",
            "line": "[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0",
        },
        "impact": "Tampered container accepted without error in both 260044 and 260180.",
        "remediation": "Change default to IMG_VERIFY=1.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "WISTRON ODM identity bypass persists in C245M8 6.0.2 (unresolved across 4.3.6 and 6.0.2)",
        "description": (
            "init.sh setup_dev() carries the WISTRON-TODO ODM bypass "
            "from XE130CM8 6.0.2 (F6) into C245M8 6.0.2. "
            "C245M8 (mountadams2) and XE130CM8 (pandora) are different server platforms; "
            "the WISTRON ODM code is present in both. "
            "'Temporary fix to workaround platform ID issue in Mustang' "
            "shipped in 4.3.6 (2025-Q2) and 6.0.2 (2026-Q1) -- not fixed across at least "
            "two major version branches and three distinct server models "
            "(C245M8 4.3.6, XE130CM8 6.0.2, C245M8 6.0.2)."
        ),
        "evidence": {
            "file": "/etc/init.sh:22-27 (both 260044 and 260180)",
            "platforms": "C245M8 4.3.6 (same init.sh behavior), XE130CM8 6.0.2, C245M8 6.0.2",
            "comment": "WISTRON-TODO: Temporary fix to workaround the platform ID issue in Mustang",
        },
        "impact": "ODM bypass unresolved since at least 4.3.6 (2025). Reveals WISTRON ODM, Mustang codename, unresolved PID defect.",
        "remediation": "Resolve the PID detection issue. Remove the WISTRON conditional path from production.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
