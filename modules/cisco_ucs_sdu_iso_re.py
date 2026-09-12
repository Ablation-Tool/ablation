"""
Cisco UCS SDU (Server Diagnostics Utility) ISO RE

Target:  ucs-diag-7.1.4.260010.iso
         Server Diagnostics Utility 7.1.4.260010 - hardware diagnostics for C-series
         SquashFS-based bootable Linux; Python 3.13; SSHD + nginx/gunicorn stack
         New target class vs HUU/SCU: full hardware diagnostics (memory, CPU, storage, GPU)
Files:   rootfs.img (squashfs, shared OpenEmbedded base)
         ucs-sdu-container-7.1.4.260010.squashfs -> base.tar.gz inside
         /root/sdu/ Python app (Redfish API, hardware inventory, diagnostic runner)
         /etc/init-sdu.sh (container orchestrator)
         /etc/ssh/sshd_config (OpenSSH, AuthorizedKeysFile .ssh/authorized_keys)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_sdu_iso_re",
    "firmware": "ucs-diag-7.1.4.260010.iso",
    "components": {
        "rootfs.img (squashfs)": (
            "Shared OpenEmbedded base; "
            "dual telnetd gates: CONFIG_SEC_UTILS_SIGN_MODE='dev' AND is_cisco_server() failure; "
            "imgverify bypass (IMG_VERIFY unset = exit 0)"
        ),
        "SDU container (base.tar.gz)": (
            "Python 3.13 + Flask-RESTful Redfish API; "
            "gunicorn on 127.0.0.1:8000, nginx on 0.0.0.0:80; "
            "SSHD running on port 22 (X11Forwarding yes); "
            "modules: RedfishApp.py, InventoryApp.py, bmc.py, cpu.py, memory.py, storage.py, gpu.py"
        ),
        "/root/sdu/RedfishApp.py": (
            "Flask-RESTful; UCSBmcToHostScpCredentials at /redfish/v1/Oem/GetBmcToHostScpCredentials; "
            "UCSClearSel at /redfish/v1/Systems/<id>/LogServices/SEL/Actions/LogService.ClearLog; "
            "UCSComputerSystem at /redfish/v1/Systems (exposes serial number unauthenticated); "
            "NO auth middleware in any file"
        ),
        "/etc/shadow": (
            "root:*:15069:0:99999:7 (locked, no password login); "
            "SSHD AuthorizedKeysFile .ssh/authorized_keys; "
            "no pre-baked authorized_keys or ssh host key in container"
        ),
    },
    "finding_count": "6F [1C+3H+2M+0L]",
    "cumulative": "753 [72C+252H+237M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated GetBmcToHostScpCredentials endpoint in SDU (third product with this flaw)",
        "description": (
            "UCSBmcToHostScpCredentials is registered at GET "
            "/redfish/v1/Oem/GetBmcToHostScpCredentials with no authentication. "
            "Implementation is identical to the SCU 7.1.7.260100 CRITICAL finding: "
            "reads /tmp/huu.cred (HUU_CRED_PATH) and returns username:password split in JSON. "
            "The diagnostics utility (SDU) runs during hardware validation sessions, "
            "which may occur before full security hardening of a server deployment. "
            "No before_request middleware, no auth decorator, no token validation present "
            "in app.py, RedfishApp.py, or InventoryApp.py. "
            "This marks the third distinct Cisco UCS product (SCU, SDU + HUU code path) "
            "carrying the same unauth credential endpoint from a shared codebase."
        ),
        "evidence": {
            "file": "/root/sdu/RedfishApp.py",
            "route": "GET /redfish/v1/Oem/GetBmcToHostScpCredentials",
            "code": (
                "class UCSBmcToHostScpCredentials(Resource):\n"
                "    def get(self):\n"
                "        with open(const.HUU_CRED_PATH, 'r') as fd:\n"
                "            cred = fd.read()\n"
                "        credList = cred.split(':')\n"
                "        return redfish_api.response(\n"
                "            {const.USERNAME: credList[0].strip(),\n"
                "             const.PASSWORD: credList[1].strip()}, 200)"
            ),
            "shared_codebase": "Identical to SCU finding F1 (ucs-scu-7.1.7.260100.iso)",
        },
        "impact": (
            "BMC SCP credentials available unauthenticated to any host on the management network. "
            "SDU diagnostics sessions create windows where servers are accessible on the "
            "management VLAN with elevated hardware access. "
            "Credential cross-use with CIMC web UI provides full BMC access."
        ),
        "remediation": "Require authentication on all Redfish endpoints. This flaw is present in at least three products sharing a common codebase.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Dual telnetd activation paths: dev sign mode AND non-Cisco hardware detection",
        "description": (
            "hsu-init in the SDU rootfs has TWO independent telnetd activation conditions, "
            "both of which open an unauthenticated Telnet session: "
            "(1) CONFIG_SEC_UTILS_SIGN_MODE == 'dev' -- the env variable is not set in "
            "hsu-profile.sh, so any environment injection enables this path. "
            "(2) is_cisco_server() failure -- ipmitool raw 0x36 0x4d 0x04 0x03 fails "
            "on VMs, bare-metal non-Cisco hardware, and any hardware without the "
            "Cisco OEM IPMI extension. "
            "SDU is used across diverse hardware configurations including lab/staging "
            "environments where VMs are common. "
            "Either condition independently triggers telnetd. "
            "No authentication is required on the resulting Telnet session."
        ),
        "evidence": {
            "file": "/etc/init.d/hsu-init (rootfs.img)",
            "code": (
                "if [ $CONFIG_SEC_UTILS_SIGN_MODE == \"dev\" ]; then\n"
                "    echo \"Enabling telnetd...\"\n"
                "    telnetd\n"
                "fi\n"
                "\n"
                "if ! is_cisco_server; then\n"
                "    echo \"Enabling telnetd...\"\n"
                "    telnetd\n"
                "fi"
            ),
            "profile": "hsu-profile.sh: CONFIG_SEC_UTILS_SIGN_MODE not set",
        },
        "impact": (
            "Unauthenticated Telnet access on management network in any VM or non-Cisco deployment. "
            "Two independent code paths mean removing one does not prevent the other from triggering."
        ),
        "remediation": "Remove both telnetd activation blocks from production builds.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Serial-number-gated destructive actions bypassed via unauthenticated GET",
        "description": (
            "Multiple SDU endpoints (Reset, ClearSel, MountISO, EnableBackend) "
            "accept a serial number in the URL path as the only authorization check: "
            "'if redfish_api.server_prop[\"Serial Number\"] != system_id.strip(): return 400'. "
            "The serial number is freely obtainable without authentication from "
            "GET /redfish/v1/Systems, which returns the server's serial number in "
            "computer_system_response['SerialNumber']. "
            "Two-step bypass: "
            "GET /redfish/v1/Systems (no auth) -> extract serial; "
            "POST /redfish/v1/Systems/<serial>/LogServices/SEL/Actions/LogService.ClearLog -> "
            "clears all system event logs. "
            "Same bypass applies to ComputerSystem.Reset (host reboot), "
            "ComputerSystem.MountISO, and ComputerSystem.EnableBackend."
        ),
        "evidence": {
            "step_1": "GET /redfish/v1/Systems returns serial number unauthenticated",
            "step_2": "POST /redfish/v1/Systems/<serial>/LogServices/SEL/Actions/LogService.ClearLog",
            "code": (
                "class UCSClearSel(Resource):\n"
                "    def post(self, system_id):\n"
                "        if redfish_api.server_prop['Serial Number'] != system_id.strip():\n"
                "            return 400\n"
                "        # no further auth\n"
                "        if redfish_api.clear_sel():\n"
                "            return 204"
            ),
            "affected_endpoints": (
                "ClearSel, Reset, MountISO, EnableBackend, TechSupport, GetFaultEngineLogs"
            ),
        },
        "impact": (
            "Unauthenticated reset, SEL clear, and mount operations on any SDU-booted server "
            "reachable on the management network. "
            "SEL clear destroys forensic evidence. "
            "Reset causes a service disruption."
        ),
        "remediation": "Serial number is not a secret. Use session tokens for all write endpoints.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "imgverify bypass via IMG_VERIFY unset; SDU container accepted without verification",
        "description": (
            "Same imgverify bypass as HUU and SCU: "
            "'if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi'. "
            "hsu-init calls imgverify on the SDU base.tar.gz before extraction: "
            "'if ! imgverify /tmp/*-container-*-base.tar.gz; then "
            "fatal \"Base container signature verification failed!\"; fi'. "
            "IMG_VERIFY is not set in hsu-profile.sh, so imgverify always returns 0. "
            "A tampered SDU container is accepted without error. "
            "Diagnostics binaries (memtest, lsidiag, GPU tools) run as root in the chroot; "
            "replacing them with backdoored versions via a tampered container "
            "gives root code execution during diagnostics sessions."
        ),
        "evidence": {
            "imgverify": "if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi",
            "hsu_init": "if ! imgverify /tmp/*-container-*-base.tar.gz; then fatal ...; fi",
            "profile": "IMG_VERIFY not set in hsu-profile.sh",
        },
        "impact": "Tampered diagnostics tools run as root without detection during hardware validation.",
        "remediation": "Set IMG_VERIFY=1 unconditionally in hsu-profile.sh.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "SSHD running in diagnostics container with X11Forwarding enabled",
        "description": (
            "The SDU container starts OpenSSH sshd as a service (etc/init.d/sshd in base.tar.gz). "
            "sshd_config enables X11Forwarding yes and sets "
            "AuthorizedKeysFile .ssh/authorized_keys. "
            "No host key is pre-baked in the container; keys are generated at runtime. "
            "Root password is locked (root:* in shadow), but the authorized_keys mechanism "
            "means any caller who can write to /home/root/.ssh/authorized_keys "
            "(e.g., via the unauthenticated Redfish write endpoints F3) can establish "
            "an SSH session. "
            "SSHD is not expected in a diagnostics utility: the attack surface "
            "exposed is absent from HUU and SCU."
        ),
        "evidence": {
            "file": "/etc/ssh/sshd_config in base.tar.gz",
            "active_options": (
                "AuthorizedKeysFile .ssh/authorized_keys\n"
                "X11Forwarding yes\n"
                "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
                "ClientAliveInterval 15"
            ),
            "shadow": "root:*:15069 (locked)",
        },
        "impact": (
            "SSHD in a diagnostics container expands the management network attack surface. "
            "Combined with the unauthenticated write primitives in F3, "
            "authorized_keys injection enables persistent SSH access."
        ),
        "remediation": "Remove SSHD from SDU unless a documented use case requires it. Disable X11Forwarding.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Pre/post-init scripts executed via chroot without path validation",
        "description": (
            "init-sdu.sh accepts --pre-init-script and --post-init-script CLI arguments "
            "and executes them via 'chroot \"${MNTPATH}\" sh \"${PRE_INIT_SCRIPT}\"'. "
            "No path whitelisting or validation is performed. "
            "Same pattern as SCU init-scu.sh F5. "
            "If an attacker can influence the init-sdu.sh CLI arguments "
            "(via Redfish launch parameters or compromised orchestration), "
            "an arbitrary shell script executes in the SDU chroot as root."
        ),
        "evidence": {
            "file": "/etc/init-sdu.sh",
            "arg": "--pre-init-script PRE_INIT_SCRIPT passed on CLI",
            "execution": "chroot \"${MNTPATH}\" sh \"${PRE_INIT_SCRIPT}\"",
        },
        "impact": "Arbitrary code execution in SDU chroot as root if CLI argument is controllable.",
        "remediation": "Whitelist allowed script paths or remove the feature.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
