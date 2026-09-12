"""
Intersight Private Virtual Appliance -- andromeda-node-init.py + diag.py RE

Target:  intersight-appliance-installer-kvm-1.1.7-0.a-disk1.qcow2 (2.4GB)
OS:      AlmaLinux 9.8 (LVM VG almalinux, root + opt_cisco volumes)
Scripts: /usr/local/bin/andromeda-node-init.py (1021L systemd oneshot)
         /usr/local/bin/diag.py (admin login shell, diagnostic CLI)
Session: 37
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_intersight_node_init_re",
    "firmware": "intersight-appliance-installer-kvm-1.1.7-0.a-disk1.qcow2",
    "components": {
        "andromeda-node-init.py": (
            "OVF-based node init script, 1021L, systemd oneshot "
            "(cisco.com.andromeda-node-config.service)"
        ),
        "diag.py": (
            "Admin login shell (/usr/local/bin/diag.py), restricted CLI "
            "for network/connectivity diagnostics"
        ),
    },
    "finding_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 56, "HIGH": 214, "MEDIUM": 208, "LOW": 185},
    "cumulative_total": 663,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "AWS Deployment Writes Admin Password Cleartext to World-Readable File",
        "component": "andromeda-node-init.py",
        "function": "set_admin_password()",
        "evidence": {
            "code": (
                "if self.is_aws:\n"
                "    admin_pwd_file = '/usr/local/etc/andromeda_password.cfg'\n"
                "    with open(admin_pwd_file, 'w') as fh:\n"
                "        fh.write(self.properties.get('password'))\n"
                "    uid = pwd.getpwnam('ansible').pw_uid\n"
                "    gid = grp.getgrnam('ansible').gr_gid\n"
                "    chown(admin_pwd_file, uid, gid)\n"
                "    chmod(admin_pwd_file, 0o644)  # world-readable"
            ),
            "file": "/usr/local/etc/andromeda_password.cfg",
            "mode": "0o644 (world-readable)",
            "owner": "ansible:ansible",
            "source": "OVF property 'password' (passed via AWS user-data or vCenter OVF envelope)",
        },
        "impact": (
            "The admin account password for the Intersight Private Appliance is written "
            "in plaintext to a world-readable file on every AWS deployment. Any local "
            "process or user (including unprivileged service accounts, ansible scripts, "
            "or a low-privilege shell obtained via another vector) can read the admin "
            "credential from /usr/local/etc/andromeda_password.cfg without authentication. "
            "The admin password grants full appliance control."
        ),
        "remediation": (
            "Remove the file entirely or restrict to mode 0600 owned by root. "
            "If persistence of the credential is required, store a bcrypt hash "
            "and zeroize the plaintext file after PAM/shadow update completes. "
            "Audit all AWS Intersight deployments for this file."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Default Appliance Environment is 'dev'; Debug Services Deployed Without Explicit OVF Override",
        "component": "andromeda-node-init.py",
        "function": "get_appliance_environment()",
        "evidence": {
            "code": (
                "def get_appliance_environment(self):\n"
                "    if self.properties.get('disable-dev-env') == 'True':\n"
                "        return APPLIANCE_ENV_STR.format('qa')\n"
                "    return APPLIANCE_ENV_STR.format('dev')  # unconditional default"
            ),
            "default_env": "dev (not qa, not prod)",
            "consequence": (
                "Debug Kubernetes/pod services are deployed unless the caller sets "
                "OVF property disable-dev-env=True at first boot"
            ),
        },
        "impact": (
            "Production Intersight appliances deployed via vCenter or KVM without "
            "explicitly setting disable-dev-env=True run in 'dev' environment mode. "
            "Debug endpoints, unauthenticated health/metrics APIs, and development-mode "
            "service configurations are active on production-facing infrastructure. "
            "The property is not documented in the public installation guide."
        ),
        "remediation": (
            "Default should be 'qa' or 'prod'. Require explicit opt-in to dev environment. "
            "Audit all deployed appliances for environment=dev. "
            "Publish the disable-dev-env OVF property in the installation guide."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Debug Package Deployment Controlled by File Absence; Absent by Default",
        "component": "andromeda-node-init.py",
        "function": "config_control_of_debug_packages()",
        "evidence": {
            "code": (
                "control_debug_path = '/cisco/software/dont_deploy_debug_service.txt'\n"
                "\n"
                "def config_control_of_debug_packages(self):\n"
                "    if not path.isfile(self.control_debug_path):\n"
                "        if self.properties.get('skip-debug') == 'True':\n"
                "            with open(self.control_debug_path, 'a'):\n"
                "                utime(self.control_debug_path, None)\n"
                "    # Default: file does not exist -> debug packages ARE deployed"
            ),
            "control_file": "/cisco/software/dont_deploy_debug_service.txt",
            "default_state": "file absent -> debug packages deployed",
            "opt_out_mechanism": "OVF property skip-debug=True creates the control file",
        },
        "impact": (
            "Debug service packages are deployed on every appliance where skip-debug=True "
            "is not set in the OVF envelope. The deployment is gated on the absence of "
            "a sentinel file rather than its presence -- the secure default requires explicit "
            "action. Any deployment using the standard OVA template without customizing "
            "OVF properties runs debug services. The control file path is inside "
            "/cisco/software/ which is the ansible working directory."
        ),
        "remediation": (
            "Invert the logic: create the sentinel file by default and require explicit "
            "enable-debug=True to remove it. Document skip-debug in the OVA deployment guide."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "diag.py Passes Cleartext Password in sshpass Subprocess Arguments (Visible to ps)",
        "component": "diag.py",
        "line": 228,
        "evidence": {
            "code": (
                "ret = subprocess.call([\n"
                "    'sudo', 'sshpass', '-p', server['passwd'],\n"
                "    'scp', '-o', 'StrictHostKeyChecking=no', '-o', 'UpdateHostKeys=no',\n"
                "    server['local_path'], serverpath\n"
                "])"
            ),
            "visibility": (
                "Process arguments are visible to any local user via /proc/<pid>/cmdline "
                "or 'ps aux' for the lifetime of the scp transfer"
            ),
            "context": (
                "admin user login shell; triggered when user selects tech-support "
                "file transfer option from the diagnostic menu"
            ),
        },
        "impact": (
            "The remote server password for tech-support SCP transfers is passed as a "
            "command-line argument to sshpass. Any process on the appliance with access "
            "to /proc (all unprivileged processes by default) can read the password from "
            "/proc/<pid>/cmdline during the transfer window. The sshpass manpage documents "
            "this as insecure and recommends using -e (environment variable) or -f (file) instead."
        ),
        "remediation": (
            "Pass the password via environment variable (SSHPASS env + sshpass -e) or a "
            "secure temp file (sshpass -f) restricted to mode 0600. "
            "Both approaches keep the credential out of /proc/<pid>/cmdline."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "OVF ssh-authorized-keys Property Injected into ansible authorized_keys Without Content Validation",
        "component": "andromeda-node-init.py",
        "function": "config_ssh_authorized_keys()",
        "evidence": {
            "code": (
                "def config_ssh_authorized_keys(self):\n"
                "    ssh_public_keys = [open('{}/.ssh/id_rsa.pub'.format(self.ansible_home_dir)).read()]\n"
                "    with open(self.ssh_authorized_keys_path, 'r') as fhdl:\n"
                "        for line in fhdl:\n"
                "            if ssh_public_keys[0] in line:\n"
                "                return  # idempotency guard, skips on re-run\n"
                "    if self.properties['ssh-authorized-keys'] != '':\n"
                "        ssh_public_keys.extend(self.properties['ssh-authorized-keys'].split(','))\n"
                "    with open(self.ssh_authorized_keys_path, 'a') as fhdl:\n"
                "        for ssh_key in ssh_public_keys:\n"
                "            fhdl.write('%s\\n' % ssh_key)"
            ),
            "target_file": "/home/ansible/.ssh/authorized_keys",
            "account": "ansible (uid=1001, /bin/bash, runs Ansible playbooks for setup-services)",
            "validation": "None; raw OVF string split on comma and appended verbatim",
        },
        "impact": (
            "An operator with control over the OVF envelope (vCenter admin, AWS user-data, "
            "or any system that delivers the OVF XML) can inject arbitrary SSH public keys "
            "into the ansible account's authorized_keys on first boot. The ansible account "
            "runs Ansible playbooks during appliance initialization and has broad access to "
            "the /cisco/software/ working tree. The OVF property is not sanitized for key "
            "format, options flags (command= , no-port-forwarding, etc.), or count."
        ),
        "remediation": (
            "Validate each key against SSH public key format before appending "
            "(ssh-keygen -l -f or a regex gating on key-type prefix). "
            "Enforce a maximum key count. "
            "Consider whether the ssh-authorized-keys OVF property should be disabled "
            "on production deployments."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "World-Writable /tmp/net.conf Used as JSON Network Config Source",
        "component": "andromeda-node-init.py + diag.py",
        "evidence": {
            "andromeda_code": (
                "NET_CONF_PATH = '/tmp/net.conf'\n"
                "# andromeda-node-init.py reads this file as JSON for network config "
                "if it exists prior to OVF-based config"
            ),
            "diag_code": (
                "NET_CONF_PATH = '/tmp/net.conf'\n"
                "NET_LOCK   = '/tmp/net.lck'\n"
                "NET_FORCE  = '/tmp/net.force'\n"
                "# diag.py writes network config as JSON to /tmp/net.conf "
                "and signals changes via /tmp/net.force"
            ),
            "path_mode": "/tmp world-writable (sticky bit set, but file creation unrestricted)",
            "format": "JSON with keys: ipv4-addr, ipv4-prefix, ipv4-gw, dns-server, hostname, etc.",
        },
        "impact": (
            "Network configuration (IP, gateway, DNS, hostname) is sourced from a file "
            "in world-writable /tmp. If a low-privilege process or user places a crafted "
            "net.conf before the init service reads it, the appliance network config can "
            "be overridden at boot. In an environment where another vulnerability provides "
            "pre-boot file write access (e.g., a shared volume, OVF custom script, or "
            "cloud user-data), DNS redirection or gateway substitution becomes possible."
        ),
        "remediation": (
            "Move net.conf to a root-owned path (/run/cisco/ or /etc/cisco/) with mode 0600. "
            "Validate contents against expected schema and IP address formats before applying."
        ),
    },
]


def run_module():
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Firmware: {MODULE_SUMMARY['firmware']}")
    for component, desc in MODULE_SUMMARY["components"].items():
        print(f"  {component}: {desc}")
    counts = MODULE_SUMMARY["finding_counts"]
    print(
        f"Findings: {sum(counts.values())} "
        f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
        f"{counts['MEDIUM']}M/{counts['LOW']}L]"
    )
    cc = MODULE_SUMMARY["cumulative_counts"]
    print(
        f"Cumulative: {MODULE_SUMMARY['cumulative_total']} "
        f"[{cc['CRITICAL']}C+{cc['HIGH']}H+{cc['MEDIUM']}M+{cc['LOW']}L]"
    )
    print()
    for f in FINDINGS:
        sev = f["severity"]
        print(f"  {f['id']} [{sev}] {f['title']}")
        print(f"    Component: {f['component']}")
        print(f"    Impact: {f['impact'][:120]}...")
        print()


if __name__ == "__main__":
    run_module()
