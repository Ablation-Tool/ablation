"""
Cisco Intersight Private Virtual Appliance RE Module 1
Image: intersight-appliance-installer-kvm-1.1.7-0.a (disk1.qcow2, 45GB QCOW2 v3)
OS: AlmaLinux 9, kernel 5.14.x, UEFI boot via GRUB2/shim
LVM: almalinux VG (root 14G, home 6G, opt_cisco 9G, tmp 5G, var_tmp 5G)
Additional VG: file_cisco (/cisco, populated at deploy time)

8 findings: 0C/3H/2M/3L
Cumulative: 551 [54C+182H+167M+148L]
"""

# ============================================================
# APPLIANCE IDENTITY
# ============================================================

INTERSIGHT_APPLIANCE = {
    "image": "intersight-appliance-installer-kvm-1.1.7-0.a.tar.gz",
    "disk": "disk1.qcow2",
    "disk_format": "QCOW2 v3",
    "disk_size_virtual_gb": 45,
    "os": "AlmaLinux 9",
    "version": "1.1.7-0.a",
    "build_date": "2026-06-18T22:59:37.476896Z",
    "build_type": "release",
    "alma9_pulp_date": "2024-05-07-000000",
    "build_info_file": "/etc/build-info.json",
    "internal_codenames": {
        "Bender": {
            "git_hash": "483c36c4fea9f9efa1373a436210494821e93314",
            "branch": "master",
            "role": "Intersight Private Virtual Appliance OS/bootstrap layer",
        },
        "Enchilada": {
            "git_hash": "534cc6ac901d180ed0a807c1734e6c85f4bfcc1e",
            "role": "Secondary component (likely Kubernetes/service layer)",
        },
    },
    "lvm": {
        "almalinux_vg": ["root(14G)", "home(6G)", "opt_cisco(9G)", "tmp(5G)", "var_tmp(5G)"],
        "file_cisco_vg": ["/cisco (9G, populated at deploy time from /cisco/software/ansible/)"],
    },
    "fstab_security_mounts": {
        "/tmp": "nodev,nosuid,noexec",
        "/var/tmp": "nodev,nosuid,noexec",
        "/home": "nodev,nosuid",
        "/var": "nodev,nosuid",
        "/boot/efi": "fmask=0177 (EFI files mode 0600)",
    },
    "services": ["ciscosshd", "haproxy", "nginx", "ansible (via systemd)", "etcd", "Kubernetes"],
    "accounts": {
        "root": "locked (!!)",
        "admin": "locked at install, set via OVF/cloud-init; NOPASSWD sudo ALL",
        "ansible": "deployment service account; NOPASSWD sudo ALL",
        "tac": "Cisco TAC account; NOPASSWD sudo ALL; password aging: min=7d no-max inact=30d",
        "andro": "password aging: min=7d max=365d warn=7d inact=30d",
        "nginx": "locked",
        "haproxy": "locked",
    },
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "INTERSIGHT-F1",
        "severity": "HIGH",
        "title": "AWS_ADMIN_PASSWORD_WRITTEN_CLEARTEXT_WORLD_READABLE",
        "file": "/usr/local/bin/andromeda-node-init.py",
        "function": "NodeConfig.set_admin_password()",
        "detail": (
            "When deploying to AWS (is_aws=True), andromeda-node-init.py::set_admin_password() "
            "writes the plaintext admin password to /usr/local/etc/andromeda_password.cfg "
            "with permissions 0644 (world-readable) and ownership ansible:ansible. "
            "Exact code path:\n"
            "  admin_pwd_file = '/usr/local/etc/andromeda_password.cfg'\n"
            "  with open(admin_pwd_file, 'w') as fh:\n"
            "      fh.write(self.properties.get('password'))  # plaintext\n"
            "  chown(admin_pwd_file, uid, gid)  # ansible:ansible\n"
            "  chmod(admin_pwd_file, 0o644)     # WORLD-READABLE\n"
            "The admin password is sourced from OVF environment properties at first boot. "
            "Any authenticated local user on the AWS-deployed Intersight appliance "
            "can read the admin console password directly from the filesystem. "
            "VMware deployments do not trigger this path (is_aws check); "
            "AWS deployments are confirmed affected."
        ),
    },
    {
        "id": "INTERSIGHT-F2",
        "severity": "HIGH",
        "title": "TLS_PRIVATE_KEY_CHMOD_644_BEFORE_ETCD_WRITE",
        "file": "/usr/local/bin/cert_management_console.py",
        "function": "CertificateManager.post_certificate_installation()._update_etcd_with_certificate()",
        "detail": (
            "cert_management_console.py::post_certificate_installation() explicitly sets "
            "chmod 644 (world-readable) on the TLS private key file before writing it to etcd:\n"
            "  # Set certificate file permissions to 0644\n"
            "  cmd = ['sudo', 'chmod', '644', file_path]  # file_path = echo-web.key\n"
            "This runs against both CERT_PATH (/opt/cisco/echo/etc/echo-web.crt) AND "
            "CERT_KEY_PATH (/opt/cisco/echo/etc/echo-web.key). "
            "After chmod 644, the private key file is world-readable on disk. "
            "The key is then written to etcd at CERT_KEY_ETCD_PATH='appliance.privkey.echo-web' "
            "via: sudo /opt/cisco/etcd/etcdv3.sh put appliance.privkey.echo-web < echo-web.key\n"
            "The APPLIANCE-DEFAULT.key at /opt/cisco/echo/etc/APPLIANCE-DEFAULT.key "
            "is the pre-installed default TLS key used before a custom cert is configured. "
            "Impact: any local user can read the HTTPS private key for the web interface "
            "regardless of whether a default or custom certificate is installed."
        ),
    },
    {
        "id": "INTERSIGHT-F3",
        "severity": "HIGH",
        "title": "TAC_ACCOUNT_NOPASSWD_SUDO_ALL_CISCO_BACKDOOR",
        "file": "/etc/sudoers.d/ (all files concatenated)",
        "detail": (
            "Three accounts on the Intersight appliance have NOPASSWD: ALL sudo configured:\n"
            "  ansible ALL=(ALL:ALL) NOPASSWD: ALL\n"
            "  admin   ALL=(ALL:ALL) NOPASSWD: ALL\n"
            "  tac     ALL=(ALL:ALL) NOPASSWD: ALL\n"
            "The 'tac' account is a Cisco Technical Assistance Center account "
            "found in /etc/shadow with password aging: min=7d, no max, 7d warn, 30d inactivity. "
            "tac has NOPASSWD sudo ALL -- once the account password is set/activated, "
            "Cisco TAC support personnel gain full root on the appliance. "
            "There is no documented per-deployment key rotation or temporal limiting "
            "for tac credentials in the analyzed image. "
            "Similarly: ansible NOPASSWD sudo ALL enables any process running as ansible "
            "to escalate to root without authentication. setup-services.sh runs as ansible. "
            "admin NOPASSWD sudo ALL is operationally justified but eliminates the "
            "password-as-second-factor for console sessions."
        ),
    },
    {
        "id": "INTERSIGHT-F4",
        "severity": "MEDIUM",
        "title": "TLS_PRIVATE_KEY_STORED_IN_ETCD_AT_WELL_KNOWN_PATH",
        "detail": (
            "The TLS private key for the Intersight HTTPS web interface (echo-web) is stored "
            "in etcd at a well-known, predictable path: 'appliance.privkey.echo-web'. "
            "The public certificate is stored at 'appliance.cert.echo-web'. "
            "Storage mechanism: sudo /opt/cisco/etcd/etcdv3.sh put appliance.privkey.echo-web < echo-web.key\n"
            "etcd is the Kubernetes cluster store for the Intersight appliance. "
            "If etcd is accessible without authentication (the default in self-hosted Kubernetes "
            "unless TLS client auth is explicitly configured), any host-level access "
            "with etcdctl connectivity can retrieve the private key: "
            "etcdctl get appliance.privkey.echo-web\n"
            "This provides an alternative path to the private key beyond the world-readable file."
        ),
    },
    {
        "id": "INTERSIGHT-F5",
        "severity": "MEDIUM",
        "title": "CISCOSSH_NOT_STRIPPED_SHIPS_WITH_SYMBOL_TABLE",
        "detail": (
            "CiscoSSH binary at /usr/local/sbin/sshd (964KB, BuildID ea5880a2895083be4a9a5a87b681018128a66ac4) "
            "ships NOT STRIPPED in the production appliance image. "
            "ELF: 64-bit LSB pie executable, x86-64, dynamically linked, not stripped. "
            "Version strings: 'CSCO_CSM_CiscoSSH_1.19.92', 'OpenSSH 10.2p1'. "
            "The binary is linked against CiscoSSL (custom OpenSSL): "
            "LD_LIBRARY_PATH=/opt/cisco/ssl/lib64 set via ciscosshd.service. "
            "CiscoSSL libcrypto.so.1.1 and libssl.so.1.1 present in /opt/cisco/ssl/lib64/ "
            "(static archives also shipped: libcrypto.a 5.9MB, libssl.a 1.1MB). "
            "KexAlgorithms in sshd_config include diffie-hellman-group14-sha256 (2048-bit DH, "
            "weaker than group16/group18). "
            "DenyUsers/DenyGroups root set (instead of PermitRootLogin no -- functionally "
            "equivalent but different policy path). "
            "Full KexAlgorithm list: ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, "
            "diffie-hellman-group14-sha256, diffie-hellman-group16-sha512."
        ),
    },
    {
        "id": "INTERSIGHT-F6",
        "severity": "LOW",
        "title": "CLOUD_INIT_ADMIN_PASSWORD_BASE64_NOT_ENCRYPTED",
        "file": "/usr/local/bin/read_cloud_init_params.py",
        "detail": (
            "The cloud-init configuration path for KVM deployments stores the admin password "
            "as base64 encoding (not encryption) in /etc/my-appliance-config.yaml:\n"
            "  custom_dict['password'] = base64.b64decode(user_input['admin_password']).decode('utf-8')\n"
            "base64 is trivially reversible. Anyone who can read the cloud-init YAML file "
            "recovers the admin password with: base64 -d <<< <value>. "
            "The decoded password is then passed to andromeda-node-init.py via "
            "/tmp/net.conf (JSON dict written to /tmp with no documented permission restrictions). "
            "Note: this does not apply to OVF environment properties (VMware deployments) "
            "where properties are read from the OVF XML environment directly; "
            "but the KVM cloud-init path exposes the password via the YAML file."
        ),
    },
    {
        "id": "INTERSIGHT-F7",
        "severity": "LOW",
        "title": "BUILD_INFO_EXPOSES_INTERNAL_CODENAMES_AND_GIT_HASHES",
        "file": "/etc/build-info.json",
        "detail": (
            "build-info.json is installed with default file permissions (readable by all users). "
            "Contents expose internal repository names and commit hashes:\n"
            "  BenderBranch: master\n"
            "  BenderGitHash: 483c36c4fea9f9efa1373a436210494821e93314\n"
            "  EnchiladaGitHash: 534cc6ac901d180ed0a807c1734e6c85f4bfcc1e\n"
            "  BuildDate: 2026-06-18T22:59:37.476896Z\n"
            "  Alma9PulpDate: 2024-05-07-000000\n"
            "'Bender' is the codename for the Intersight Private Virtual Appliance "
            "bootstrap/OS layer. 'Enchilada' is a secondary component (Kubernetes/services layer). "
            "These git hashes, combined with access to internal Cisco repositories, "
            "enable pinpointing the exact source code version for vulnerability research."
        ),
    },
    {
        "id": "INTERSIGHT-F8",
        "severity": "LOW",
        "title": "SYSCTL_MISSING_KPTR_RESTRICT_AND_DMESG_RESTRICT",
        "detail": (
            "The Intersight appliance sysctl.conf applies standard hardening "
            "(kernel.randomize_va_space=2, fs.suid_dumpable=0, TCP syncookies, rp_filter, "
            "martian logging, etc.) but omits two kernel information disclosure controls:\n"
            "  Missing: kernel.kptr_restrict -- kernel pointers in /proc/kallsyms and "
            "similar interfaces are visible to unprivileged users (kptr_restrict defaults to 0). "
            "Kernel symbols including function addresses aid KASLR bypass in exploit development.\n"
            "  Missing: kernel.dmesg_restrict -- dmesg output is readable by unprivileged users "
            "(default 0). dmesg may expose kernel addresses, loaded module paths, hardware details.\n"
            "Also absent: kernel.perf_event_paranoid=3 (hardware perf counters accessible to "
            "non-privileged users). "
            "The appliance runs AlmaLinux 9 with ASLR enabled and SELinux active -- "
            "these omissions are hardening gaps, not direct exploits."
        ),
    },
]

# ============================================================
# CISCOSSH DETAIL
# ============================================================

CISCOSSH = {
    "binary": "/usr/local/sbin/sshd",
    "version": "CiscoSSH 1.19.92",
    "base": "OpenSSH 10.2p1",
    "build_id": "ea5880a2895083be4a9a5a87b681018128a66ac4",
    "stripped": False,
    "crypto_library": "CiscoSSL (custom OpenSSL fork)",
    "crypto_path": "/opt/cisco/ssl/lib64/",
    "crypto_libs": ["libcrypto.so.1.1 (3.5MB)", "libssl.so.1.1 (730KB)"],
    "static_archives_shipped": ["libcrypto.a (5.9MB)", "libssl.a (1.1MB)"],
    "sshd_config": "/etc/ssh/sshd_config",
    "kex_algorithms": [
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
    ],
    "ciphers": ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes256-ctr", "aes192-ctr"],
    "macs": ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"],
    "root_access": "DenyUsers root; DenyGroups root",
    "session_limits": "MaxSessions 4; MaxStartups 10:30:60; MaxAuthTries 4",
    "client_alive": "ClientAliveInterval 900; ClientAliveCountMax 3",
    "note": (
        "DH group14-sha256 (2048-bit) included alongside group16. "
        "CiscoSSL version not extractable from libcrypto.so strings -- "
        "no OpenSSL version string present; only function name symbols."
    ),
}

# ============================================================
# PRIVILEGE MODEL
# ============================================================

PRIVILEGE_MODEL = {
    "sudo_nopasswd_all": ["ansible", "admin", "tac"],
    "tac_account_detail": {
        "purpose": "Cisco Technical Assistance Center support access",
        "shadow_aging": "min=7d, no max age, warn=7d, inact=30d",
        "sudo": "tac ALL=(ALL:ALL) NOPASSWD: ALL",
        "activation": "Account locked at image build; activated when Cisco TAC sets password",
    },
    "ansible_account_detail": {
        "purpose": "Ansible automation service account",
        "home": "/home/ansible",
        "ssh_key_behavior": "ansible SSH public key auto-added to authorized_keys at first boot",
        "sudo": "ansible ALL=(ALL:ALL) NOPASSWD: ALL AND ansible ALL=(ALL:ALL) NOPASSWD: /usr/bin/yum",
        "executes": "setup-services.sh (from /cisco/software/ansible/appliance/startup.sh)",
    },
}

# ============================================================
# CREDENTIAL FLOW MAP
# ============================================================

CREDENTIAL_FLOW = {
    "vmware_path": (
        "OVF XML environment (guestinfo.ovfEnv) "
        "-> andromeda-node-init.py::consume_ovf() "
        "-> self.properties['password'] (plaintext in memory) "
        "-> usermod -p <sha512-hash> admin "
        "-> NOT written to disk (VMware path does not trigger is_aws branch)"
    ),
    "aws_path": (
        "EC2 instance metadata + OVF properties "
        "-> andromeda-node-init.py::consume_ovf() "
        "-> self.properties['password'] "
        "-> usermod -p <sha512-hash> admin "
        "-> /usr/local/etc/andromeda_password.cfg (PLAINTEXT, mode 0644, ansible:ansible)"
    ),
    "kvm_cloud_init_path": (
        "/etc/my-appliance-config.yaml (admin_password: base64-encoded) "
        "-> read_cloud_init_params.py::base64.b64decode() "
        "-> /tmp/net.conf (JSON, permissions unspecified) "
        "-> andromeda-node-init.py::consume_ovf() reads /tmp/net.conf "
        "-> usermod -p <sha512-hash> admin"
    ),
    "tls_key_path": (
        "/opt/cisco/echo/etc/echo-web.key (TLS private key) "
        "-> cert_management_console.py::chmod(644) [WORLD-READABLE] "
        "-> etcdv3.sh put appliance.privkey.echo-web [IN ETCD]"
    ),
}

MODULE_SUMMARY = {
    "module": "cisco_ucs_intersight_appliance_re",
    "target": "Intersight Private Virtual Appliance 1.1.7-0.a (KVM/QCOW2)",
    "findings": [f["title"] for f in FINDINGS],
    "finding_counts": {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 2, "LOW": 3},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 182, "MEDIUM": 167, "LOW": 148},
    "cumulative_total": 551,
    "top_findings": [
        "F1 HIGH: Admin password written cleartext to world-readable file on AWS deployments",
        "F2 HIGH: TLS private key explicitly chmod 644 before etcd write",
        "F3 HIGH: tac/ansible/admin accounts have NOPASSWD sudo ALL",
    ],
}
