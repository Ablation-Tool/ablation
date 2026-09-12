"""
Cisco UCS HUU C220M8 6.0.2.260143 ISO RE

Target:  ucs-c220m8-huu-6.0.2.260143.iso
         C220 M8 Host Upgrade Utility, version 6.0.2.260143 (Intel Xeon)
         Platform codename: godzilla1
         6.0.2 container architecture; init.sh MD5 identical to XE130CM8 6.0.2.260143;
         CPK: platform=godzilla1, version=6.0(2.260095), hsu_version=1.0.2 (48-build lag)
Files:   rootfs.img (squashfs), ucs-c220m8-huu-container-6.0.2.260143-base.tar.gz
         /etc/init.sh (identical to XE130CM8 6.0.2: WISTRON-TODO, timefile injection)
         /etc/init-huu.sh (IMG_VERIFY=0 default)
         cpk/hsu_agent.cpk ([pkg] godzilla1, version=6.0(2.260095), hsu_version=1.0.2)
         /root/hsu/hsu.tgz.enc (32303424 bytes; identical hook list to XE130CM8 6.0.2)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c220_602_re",
    "firmware": "ucs-c220m8-huu-6.0.2.260143.iso",
    "components": {
        "hsu_agent.cpk (cpk/ in container squashfs)": (
            "[pkg] headerVersion=2, platform=godzilla1, version=6.0(2.260095), "
            "hsu_version=1.0.2, tarOffset=128; "
            "ISO version is 6.0.2.260143 -- CPK is 48 builds behind (260143-260095); "
            "hsu_version=1.0.2 on godzilla1 vs 1.0.1 on mountadams2 and pandora"
        ),
        "/etc/init.sh": (
            "MD5: 672809303e2c3cfa9926b6d18b532f71 -- identical to XE130CM8 6.0.2.260143; "
            "WISTRON-TODO ODM bypass; timefile injection in start_hsu_agent()"
        ),
        "/etc/init-huu.sh": (
            "preinit_container_env(): [ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0; "
            "identical to C245M8 6.0.2 and XE130CM8 6.0.2"
        ),
        "Hook list": (
            "Identical to XE130CM8 6.0.2 and C245M8 6.0.2.260044 (diff empty); "
            "includes HuuApp.py (CMCSecureBoot + UCSUpdate), BlueField_Hook.py, "
            "AMD_AI_NIC_Hook.py, PLXSwitch_Hook.py, Intel_GPU_Hook.py"
        ),
    },
    "finding_count": "6F [1C+3H+2M+0L]",
    "cumulative": "795 [77C+274H+250M+193L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated CMCSecureBoot and UCSUpdate confirmed on godzilla1 platform in 6.0.2",
        "description": (
            "HuuApp.py in C220M8 6.0.2.260143 contains CMCSecureBoot and UCSUpdate "
            "with no authentication. "
            "Identical hook list to XE130CM8 6.0.2 (diff empty). "
            "Confirmed across six distinct firmware images on three platforms: "
            "pandora: C480M5 4.3.2, XE130CM8 6.0.2; "
            "mountadams2: C245M8 4.3.6, C245M8 6.0.2.260044, C245M8 6.0.2.260180; "
            "godzilla1: C220M8 4.3.6 (HuuApp.py confirmed post-analysis), C220M8 6.0.2.260143. "
            "No authentication added between 4.3.6 and 6.0.2 on any platform."
        ),
        "evidence": {
            "file": "/root/hsu/HuuApp.py (base.tar.gz)",
            "confirmed_platforms": (
                "pandora (C480M5 4.3.2, XE130CM8 6.0.2), "
                "mountadams2 (C245M8 4.3.6, 6.0.2.260044, 6.0.2.260180), "
                "godzilla1 (C220M8 4.3.6, 6.0.2.260143)"
            ),
        },
        "impact": (
            "Persistent unpatched unauth firmware-flash and secure-boot-toggle across "
            "all three C-series platform codenames in both 4.3.x and 6.0.x branches."
        ),
        "remediation": "Require authentication on all HuuApp endpoints.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "CPK hsu_agent 48 builds stale in C220M8 6.0.2.260143 (version=6.0(2.260095))",
        "description": (
            "hsu_agent.cpk in the C220M8 6.0.2.260143 container has [pkg] version=6.0(2.260095). "
            "The ISO version is 6.0.2.260143, placing the CPK 48 build IDs behind the ISO. "
            "The hsu_agent binary has hsu_version=1.0.2 on godzilla1 "
            "vs hsu_version=1.0.1 on mountadams2 (C245M8) and pandora (XE130CM8). "
            "The version differential: "
            "C220M8 6.0.2.260143 bundles CPK 6.0(2.260095) (48-build lag); "
            "C245M8 6.0.2.260044 bundles CPK 6.0(2.260044) (aligned); "
            "C245M8 6.0.2.260180 bundles CPK 6.0(2.260096) (84-build lag). "
            "XE130CM8 6.0.2.260143 ships no CPK (no hsu_agent on pandora platform). "
            "The CIMC BMC on C220M8 receives hsu_agent at build 6.0(2.260095) "
            "when updated from the 6.0.2.260143 ISO. "
            "The version mismatch is not exposed to the operator."
        ),
        "evidence": {
            "cpk_header": "[pkg] platform=godzilla1 version=6.0(2.260095) hsu_version=1.0.2",
            "iso_version": "6.0.2.260143 (48 builds ahead of CPK)",
            "comparison": (
                "C245M8 6.0.2.260044: CPK=6.0(2.260044) aligned; "
                "C245M8 6.0.2.260180: CPK=6.0(2.260096) 84-build lag; "
                "C220M8 6.0.2.260143: CPK=6.0(2.260095) 48-build lag; "
                "XE130CM8 6.0.2.260143: no CPK"
            ),
        },
        "impact": (
            "CIMC BMC runs hsu_agent at build 260095 while the ISO reports 260143. "
            "Security and functional fixes to hsu_agent between builds 260095 and 260143 absent on BMC."
        ),
        "remediation": "Align CPK version with ISO version. Automate version check in build pipeline.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "BlueField DPU RPM --nosignature install and bfb-install catalog injection (persists on godzilla1)",
        "description": (
            "BlueField_Hook.py in C220M8 6.0.2 is identical to XE130CM8 6.0.2 (F2/F3) "
            "and C245M8 6.0.2 (F3). "
            "'rpm --nodeps -i {rshim.rpm} --ignoresize --nosignature' (shell=True); "
            "'sh -x /usr/sbin/bfb-install --bfb {firmware} --rshim {rshim_id}' (shell=True); "
            "firmware from Catalog.json (catalog-controlled path). "
            "BlueField DPUs are supported in C220M8 via OCP3 slots. "
            "Confirmed unpatched across godzilla1, mountadams2, and pandora platforms."
        ),
        "evidence": {
            "file": "/root/hsu/BlueField_Hook.py:279,493",
            "platforms": "godzilla1 (C220M8), mountadams2 (C245M8), pandora (XE130CM8) -- identical code",
        },
        "impact": "Unsigned RPM and catalog-controlled bfb-install on all three platform codenames.",
        "remediation": "Verify RPM signatures. Pass firmware path via subprocess argument list.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "timefile injection persists in C220M8 6.0.2 (init.sh identical to XE130CM8 6.0.2)",
        "description": (
            "init.sh start_hsu_agent() in C220M8 6.0.2.260143 has MD5 "
            "672809303e2c3cfa9926b6d18b532f71, identical to XE130CM8 6.0.2.260143. "
            "timefile injection at line 67 is present and unchanged: "
            "'chroot \"${MNTPATH}\" sh -c "
            "\"cd ${WORKBASE} && $(cat ${MNTPATH}/${WORKBASE}/logs/timefile) "
            "&& python ${WORKBASE}/hsu-redfish.py\"'. "
            "The shared init.sh MD5 confirms the same injection surface "
            "on both godzilla1 (Intel) and pandora (XE130CM8) platforms."
        ),
        "evidence": {
            "init_sh_md5": "672809303e2c3cfa9926b6d18b532f71 (C220M8 6.0.2 = XE130CM8 6.0.2)",
            "injection": "$(cat timefile) in double-quoted shell string",
        },
        "impact": "Root code execution in HUU container via pre-planted timefile.",
        "remediation": "Do not evaluate timefile via command substitution.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "WISTRON ODM identity bypass persists on godzilla1 (Intel C220M8)",
        "description": (
            "init.sh setup_dev() carries the WISTRON-TODO conditional across "
            "XE130CM8 (pandora), C245M8 (mountadams2), and now C220M8 (godzilla1). "
            "The C220M8 is an Intel Xeon rack server ODM'd by WISTRON. "
            "The platform ID issue (Mustang codename) is present on the Intel platform "
            "in addition to AMD (mountadams2) and the XE platform (pandora). "
            "All three platform codenames carry the unfixed WISTRON-TODO at 6.0.2."
        ),
        "evidence": {
            "file": "/etc/init.sh (MD5: 672809..., identical to XE130CM8 6.0.2)",
            "platforms": "godzilla1 (C220M8 Intel), mountadams2 (C245M8 AMD), pandora (XE130CM8)",
        },
        "impact": "WISTRON NIC script deployed on all C-series godzilla1 servers when /opt/cisco/cisco_server absent.",
        "remediation": "Remove WISTRON-TODO from all platform init.sh variants.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "IMG_VERIFY=0 default in init-huu.sh; hsu.tgz.enc with co-located decrypt-file",
        "description": (
            "preinit_container_env() in init-huu.sh: "
            "'[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0'. "
            "Same as XE130CM8 6.0.2 (F5) and C245M8 6.0.2 (F5). "
            "hsu.tgz.enc (32303424 bytes) with new-format cipher; "
            "decrypt-file ships in the same rootfs.img squashfs (confirmed empirically: "
            "chroot rootfs /usr/sbin/decrypt-file -> 46489600 byte gzip). "
            "CPK (hsu_agent.cpk) is in cpk/ directory in squashfs, "
            "outside base.tar.gz and not covered by imgverify."
        ),
        "evidence": {
            "imgverify": "[ -z \"$IMG_VERIFY\" ] && export IMG_VERIFY=0 in preinit_container_env()",
            "decrypt_result": "46489600 bytes (decrypted; timestamp 2026-06-17)",
            "cpk_location": "cpk/ in squashfs (not in base.tar.gz, not under imgverify)",
        },
        "impact": "Tampered container accepted without verification across all godzilla1 6.0.2 deployments.",
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
