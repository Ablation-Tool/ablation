"""
Cisco UCS SCU (Server Configuration Utility) ISO RE

Target:  ucs-scu-7.1.7.260100.iso
         Server Configuration Utility 7.1.7.260100, OS provisioning for C-series
         SquashFS-based bootable Linux; RHEL/SLES/Ubuntu/VMware/Windows support
Files:   rootfs.img (squashfs, shared OpenEmbedded base with HUU)
         ucs-scu-container-7.1.7.260100-base.tar.gz
         /root/scu/ Python app (Redfish API, NIOS installer, storage modules)
         /etc/init-scu.sh (container orchestrator)
         /usr/sbin/imgverify (shared with HUU)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_scu_iso_re",
    "firmware": "ucs-scu-7.1.7.260100.iso",
    "components": {
        "rootfs.img (squashfs)": (
            "Shared OpenEmbedded base with HUU; "
            "same imgverify, hsu-init, hsu-profile.sh; "
            "IMG_VERIFY not set in hsu-profile.sh"
        ),
        "SCU container (base.tar.gz)": (
            "Python 3.5 + Flask-RESTful Redfish API; "
            "gunicorn on 127.0.0.1:8000, nginx on 0.0.0.0:80; "
            "modules: RedfishApp.py, ipmi_cmd.py, nios_install.py, "
            "host_bmc_transport.py, storage_api.py"
        ),
        "/root/scu/RedfishApp.py": (
            "Flask-RESTful app; registers UCSBmcToHostScpCredentials at "
            "/redfish/v1/Oem/GetBmcToHostScpCredentials; "
            "no before_request auth middleware; no auth decorator on any resource"
        ),
        "/root/scu/Constants.py": (
            "HUU_CRED_PATH = '/tmp/huu.cred'; "
            "CREDENTIALS_FILE_PATH = '/root/credentials.txt'; "
            "TECH_SUPPORT_UPLOAD_URL = 'https://169.254.0.17/hsu/v1/Actions/UploadTechSupport'"
        ),
        "/root/scu/ipmi_cmd.py": (
            "IPMIConfig class; ipmitool subprocess call with "
            "'-P ' + self.password inline; shell=True"
        ),
        "/etc/init-scu.sh": (
            "Orchestrator; init_chroot_rest -> gunicorn, nginx; "
            "verify_platform calls platform_check.py; "
            "pre_init_script and post_init_script executed via "
            "'chroot MNTPATH sh POST_INIT_SCRIPT'"
        ),
    },
    "finding_count": "6F [1C+3H+2M+0L]",
    "cumulative": "735 [68C+243H+232M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated Redfish endpoint exposes BMC SCP credentials",
        "description": (
            "UCSBmcToHostScpCredentials in /root/scu/RedfishApp.py registers a GET handler "
            "at /redfish/v1/Oem/GetBmcToHostScpCredentials with no authentication requirement. "
            "The handler reads /tmp/huu.cred (HUU_CRED_PATH in Constants.py) and returns "
            "username and password fields in the JSON response body. "
            "No before_request middleware, no auth decorator, and no token validation are "
            "present in the Flask app. "
            "nginx proxies the management network (0.0.0.0:80) to gunicorn (127.0.0.1:8000) "
            "without a TLS layer. "
            "Any host that can reach port 80 on the SCU boot environment can extract "
            "the BMC-to-host SCP credentials with a single unauthenticated HTTP GET. "
            "The comment in the source code acknowledges this: "
            "'curl -k http://localhost/redfish/v1/Oem/GetBmcToHostScpCredentials'."
        ),
        "evidence": {
            "file": "/root/scu/RedfishApp.py",
            "class": "UCSBmcToHostScpCredentials(Resource)",
            "code": (
                "class UCSBmcToHostScpCredentials(Resource):\n"
                "    \"\"\"This class provides bmc credentials.\n"
                "\n"
                "    curl -k http://localhost/redfish/v1/Oem/GetBmcToHostScpCredentials\n"
                "    \"\"\"\n"
                "\n"
                "    def get(self):\n"
                "        try:\n"
                "            with open(const.HUU_CRED_PATH, \"r\") as fd:\n"
                "                cred = fd.read()\n"
                "        ...\n"
                "        credList = cred.split(\":\")\n"
                "        return redfish_api.response(\n"
                "            {const.USERNAME: credList[0].strip(),\n"
                "             const.PASSWORD: credList[1].strip()}, 200\n"
                "        )"
            ),
            "route_registration": (
                "UCSBmcToHostScpCredentials: "
                "\"/redfish/v1/Oem/GetBmcToHostScpCredentials\","
            ),
            "constants": "HUU_CRED_PATH = \"/tmp/huu.cred\"",
            "no_auth": "grep before_request/auth_required: no matches in RedfishApp.py",
        },
        "impact": (
            "BMC SCP credentials exposed to any host reachable on the management network "
            "during SCU-boot operations (OS provisioning, firmware update workflows). "
            "Credential enables SCP file transfer to/from BMC filesystem. "
            "If the credential is shared with other BMC access paths (IPMI, web UI), "
            "impact extends to full BMC compromise."
        ),
        "remediation": (
            "Require authentication (session token or basic auth) on all Redfish endpoints. "
            "At minimum, restrict GetBmcToHostScpCredentials to localhost-only access "
            "at the nginx layer."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "imgverify signature bypass identical to HUU (IMG_VERIFY unset exits 0)",
        "description": (
            "The rootfs.img in the SCU ISO shares the same OpenEmbedded base as HUU. "
            "/usr/sbin/imgverify contains: "
            "'if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi' as its first check. "
            "hsu-profile.sh in the SCU rootfs does not set IMG_VERIFY. "
            "Signature verification for the container base.tar.gz and rootfs are bypassed "
            "by default; imgverify always returns 0 (success) without verifying. "
            "The SCU container is extracted under the imgverify check the same as HUU: "
            "'if ! imgverify /tmp/*-container-*-base.tar.gz; then fatal ...; fi'."
        ),
        "evidence": {
            "file": "/usr/sbin/imgverify (rootfs)",
            "bypass_line": "if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi",
            "profile": "/etc/profile.d/hsu-profile.sh: IMG_VERIFY not set",
            "shared_base": "Same OpenEmbedded rootfs as ucs-c220m8-huu-6.0.2.260143.iso",
        },
        "impact": (
            "Tampered SCU container accepted as verified. "
            "An attacker with access to the boot media or PXE boot path can substitute "
            "a malicious container that passes imgverify and runs as root."
        ),
        "remediation": "Set IMG_VERIFY=1 in hsu-profile.sh. Fail closed on unset variable.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Telnetd enabled on non-Cisco hardware (is_cisco_server() fails on VMs)",
        "description": (
            "hsu-init in the SCU rootfs shares the same is_cisco_server() check as HUU. "
            "When ipmitool raw 0x36 0x4d 0x04 0x03 fails (VMs, bare-metal non-Cisco, "
            "hardware without Cisco OEM IPMI extension), telnetd is enabled: "
            "'if ! is_cisco_server; then echo \"Enabling telnetd...\"; telnetd; fi'. "
            "SCU is specifically used in OS-provisioning deployments before the server "
            "is fully configured -- scenarios where non-Cisco hardware and virtual "
            "test environments are common. "
            "Additionally, CONFIG_SEC_UTILS_SIGN_MODE == 'dev' enables telnetd, "
            "and this variable is not set in hsu-profile.sh."
        ),
        "evidence": {
            "file": "/etc/init.d/hsu-init (rootfs)",
            "code": (
                "if ! is_cisco_server; then\n"
                "    echo \"Enabling telnetd...\"\n"
                "    telnetd\n"
                "fi"
            ),
        },
        "impact": (
            "Unencrypted Telnet service on management network in non-Cisco deployments. "
            "Pre-authentication exposure at the boot environment level."
        ),
        "remediation": "Remove telnetd activation from hsu-init. Use SSH if remote access required.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "BMC password passed as inline ipmitool command-line argument",
        "description": (
            "ipmi_cmd.py IPMIConfig class constructs ipmitool subprocess calls with "
            "the BMC password inline: "
            "'cmd = cmd + \" -I lanplus -N 2 -H \" + self.ip + \" -U \" + self.username "
            "+ \" -P \" + self.password'. "
            "The command is executed with subprocess.check_output(cmd, shell=True). "
            "When shell=True is used with a constructed command string, the full command "
            "including '-P <password>' is visible in /proc/<pid>/cmdline for the duration "
            "of the ipmitool process. "
            "Any process running in the SCU container with /proc access can read these "
            "credentials. ipmitool is called throughout the SCU workflow for IPMI "
            "operations (firmware update, hardware inventory, sensor reads)."
        ),
        "evidence": {
            "file": "/root/scu/ipmi_cmd.py",
            "code": (
                "if self.mode == \"remote\":\n"
                "    cmd = cmd + \" -I lanplus -N 2 -H \" + self.ip\n"
                "    cmd = cmd + \" -U \" + self.username\n"
                "    cmd = cmd + \" -P \" + self.password\n"
                "...\n"
                "output = subprocess.check_output(cmd, shell=True, "
                "stderr=subprocess.STDOUT)"
            ),
            "visibility": "/proc/<pid>/cmdline contains full command with -P <password>",
        },
        "impact": (
            "BMC credentials visible in process list to any local process with /proc access. "
            "In a compromised container, credential harvest requires only /proc read. "
            "ipmitool calls are frequent during firmware update and inventory operations."
        ),
        "remediation": (
            "Pass IPMI password via environment variable (IPMITOOL_PASSWORD) or "
            "a temporary credentials file. Do not pass secrets as command-line arguments."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Pre/post-init scripts executed via chroot without path validation",
        "description": (
            "init-scu.sh run_pre_init_script() and run_post_init_script() accept "
            "PRE_INIT_SCRIPT and POST_INIT_SCRIPT values from command-line arguments "
            "('--pre-init-script' and '--post-init-script') and execute them via: "
            "'chroot \"${MNTPATH}\" sh \"${PRE_INIT_SCRIPT}\" > ...; return 1'. "
            "The script path is taken directly from the argument without validation or "
            "whitelisting. "
            "init_chroot_python() and other init modes pass these flags from external "
            "callers (Redfish API, NIHUU launch modes). "
            "If an attacker can influence the PRE_INIT_SCRIPT path argument (via "
            "Redfish API injection or compromised boot parameter), an arbitrary shell "
            "script is executed in the SCU chroot context."
        ),
        "evidence": {
            "file": "/etc/init-scu.sh",
            "code": (
                "run_pre_init_script() {\n"
                "  if [ ! -f \"${PRE_INIT_SCRIPT}\" ]; then\n"
                "    return 0\n"
                "  fi\n"
                "  log 'Running pre init script...'\n"
                "  chroot \"${MNTPATH}\" sh \"${PRE_INIT_SCRIPT}\" "
                ">\"${LOGS_DIR}\"/pre_init_script.log 2>&1\n"
                "  return 1\n"
                "}"
            ),
            "argument": "--pre-init-script, --post-init-script passed on CLI",
        },
        "impact": (
            "If PRE_INIT_SCRIPT is controllable by an attacker (via Redfish API "
            "launch parameters or NIHUU configuration), arbitrary code executes "
            "in the SCU chroot as root."
        ),
        "remediation": (
            "Whitelist allowed pre/post-init script paths or remove the feature. "
            "Do not accept executable paths from external input."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "HTTP-only management interface; dev verification keys in production ISO",
        "description": (
            "SCU web UI served over HTTP only (0.0.0.0:80) identical to HUU F5. "
            "ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3 declared in nginx.conf "
            "but no ssl_certificate activated. "
            "Additionally, the SCU container base.tar.gz includes the same "
            "/hsu-keys/ directory with both dev and rel RSA-2048 keypairs for "
            "container/rootfs/tools verification (identical to HUU F6). "
            "Two distinct security issues combined in one finding."
        ),
        "evidence": {
            "nginx_config": "listen 80 default_server (no TLS)",
            "keys": "/hsu-keys/: dev and rel keypairs present (shared base with HUU)",
        },
        "impact": (
            "OS provisioning operations (credential inputs, configuration data) "
            "transmitted in cleartext. Dev-signed containers accepted when run_mode "
            "is absent or set to DEV."
        ),
        "remediation": "Activate TLS with self-signed certificate. Strip dev keys from production builds.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
