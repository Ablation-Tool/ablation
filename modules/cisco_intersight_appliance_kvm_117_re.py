"""
Cisco Intersight On-Premises Appliance — KVM Installer 1.1.7-0.a — RE Module
Source: intersight-appliance-installer-kvm-1.1.7-0.a.tar.gz
Format: 8x QCOW2 disks (45GB virtual each); disk1 = AlmaLinux 9 OS volume
OS: AlmaLinux 9, kernel 5.14.0-687.5.3.el9_8 (RHEL 9.8 ABI)
LVM: almalinux VG (root 14G + home 6G + opt_cisco 9G + tmp 5G + var_tmp 5G)

Filesystem access method:
  sudo qemu-nbd --connect=/dev/nbd0 disk1.qcow2
  sudo vgchange -ay almalinux
  sudo mount /dev/mapper/almalinux-root /mnt/intersight-root
  sudo mount /dev/mapper/almalinux-opt_cisco /mnt/intersight-cisco

opt_cisco layout (disk1): OpenSSL 1.1 build tree (ssl/), setup scripts (bin/), empty dc/ volume
Full app stack (etcd/mongo/rabbit/consul/vault/k8s) lives on separate disks (disk3-disk8).
"""

FIRMWARE = {
    "target":      "Cisco Intersight On-Premises Appliance KVM Installer",
    "version":     "1.1.7-0.a",
    "source":      "intersight-appliance-installer-kvm-1.1.7-0.a.tar.gz",
    "disks":       "8x QCOW2 (disk1 = 45GB virtual, 1.65GB sparse OS volume)",
    "base_os":     "AlmaLinux 9, kernel 5.14.0-687.5.3.el9_8",
    "lvm_layout":  "almalinux VG: root(14G) home(6G) opt_cisco(9G) tmp(5G) var_tmp(5G)",
    "app_stack":   "etcd + MongoDB + RabbitMQ + Consul + Vault + Kubernetes + Jenkins (from get_dev_name.sh)",
    "custom_ssh":  "CiscoSSH 1.19.92 / OpenSSH 10.2p1 (Cisco fork at /usr/local/bin/ssh)",
    "findings":    ["ISA-F1", "ISA-F2", "ISA-F3", "ISA-F4", "ISA-F5", "ISA-F6",
                    "ISA-F7", "ISA-F8", "ISA-F9", "ISA-F10"],
}

# ─────────────────────────────────────────────────────────
# ISA-F1 — 'andro' (Andromeda) cloud service user has NOPASSWD:ALL sudo
# ─────────────────────────────────────────────────────────
ISA_F1 = {
    "id":       "ISA-F1",
    "title":    "'andro' Andromeda cloud service user granted NOPASSWD:ALL sudo — "
                "any code execution as this user escalates to unrestricted root",
    "status":   "CONFIRMED — /etc/sudoers + /etc/passwd + /etc/group + /etc/shadow in disk1",
    "severity": "HIGH",

    "sudoers_entry": "%andro ALL=(ALL) NOPASSWD: ALL",

    "passwd_entry": "andro:x:1003:1002:Andromeda user:/home/andro:/sbin/nologin",
    "shadow_entry": "andro:!!:20622:7:365:7:30::",
    "group_entry":  "andro:x:1002:andro",

    "account_model": (
        "The 'andro' user is the Cisco Andromeda (Intersight cloud management) service account. "
        "Shell is /sbin/nologin — interactive login is blocked. "
        "Shadow has !! — no password set. "
        "Despite nologin + locked password, any vulnerability in a service running as 'andro' "
        "grants full unrestricted sudo to any user/command via the %andro group sudoers rule. "
        "The minimum password age (7 days) and max age (365 days) confirm it is a managed account, "
        "not a disposable credential — it is an intentional service identity."
    ),

    "escalation_path": (
        "1. Exploit any vulnerability in a process running as UID 1003 (andro)\n"
        "2. sudo -s with no password required → root shell\n"
        "No intermediate steps needed — NOPASSWD:ALL collapses the privilege hierarchy."
    ),

    "impact": (
        "Root on the Intersight Appliance. The appliance manages Kubernetes deployments, "
        "stores Intersight Cloud connection credentials, and is the control plane for "
        "connected UCS infrastructure. Full root = access to all managed infrastructure keys."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F2 — Cisco TAC backdoor account 'tac' with pam_cisco_ct.so auth + NOPASSWD ALL sudo
# ─────────────────────────────────────────────────────────
ISA_F2 = {
    "id":       "ISA-F2",
    "title":    "Cisco TAC backdoor account 'tac' authenticates via pam_cisco_ct.so (Consent Token) "
                "and has unrestricted NOPASSWD:ALL sudo — full root on any Intersight Appliance via CT",
    "status":   "CONFIRMED — /etc/passwd + /etc/shadow + /etc/sudoers.d/tac + /etc/pam.d/sshd + "
                "/etc/security/pam_cisco_ct.ini + /usr/lib64/security/pam_cisco_ct.so in disk1",
    "severity": "HIGH",

    "passwd_entry": "tac:x:1004:1004:Cisco TAC access:/home/tac:/bin/bash",
    "shadow_entry": "tac:!!:20622:7::7:30::",
    "sudoers_entry": "tac ALL=(ALL:ALL) NOPASSWD: ALL  (/etc/sudoers.d/tac)",

    "pam_stack": (
        "/etc/pam.d/sshd uses 'auth substack password-auth-ct'.\n"
        "password-auth-ct inserts:\n"
        "  auth [success=done user_unknown=ignore perm_denied=1 default=ok] pam_cisco_ct.so\n"
        "pam_cisco_ct.ini: users = tac (CT auth applies ONLY to the tac user).\n"
        "If pam_cisco_ct.so returns success → authentication complete, pam_unix skipped.\n"
        "If pam_cisco_ct.so returns perm_denied → skip 1 line (past pam_unix.so sufficient).\n"
        "CT authentication: challenge-response using RSA signature. "
        "Device generates nonce, Cisco signs it with CT DEV private key, user pastes token."
    ),

    "ct_cert": {
        "subject":  "O=Cisco, OU=DEV, CN=CT-IntersightAppliance-Debug-Access",
        "issuer":   "CN=CT-IntersightAppliance-IMG-SIGNING, OU=RELEASE, O=Cisco",
        "notBefore": "2023-02-28",
        "notAfter":  "2053-02-20",
        "embedded_in": "/etc/security/pam_cisco_ct.ini as product_ct_signing_x509_cert",
    },

    "analysis": (
        "The 'tac' account authenticates via Cisco's Consent Token (CT) system, not password/SSH keys. "
        "The CT flow: (1) device generates nonce via ct_local_generate_challenge, "
        "(2) user sends nonce to Cisco TAC, (3) Cisco signs nonce with CT DEV private key, "
        "(4) signed token pasted as SSH 'password', (5) pam_cisco_ct.so verifies RSA sig against "
        "the embedded DEV certificate, (6) if valid → authenticated. "
        "The DEV certificate (OU=DEV) is valid for 30 years (2023-2053). "
        "It is the SAME certificate in every Intersight Appliance deployment — "
        "scoped only by product_name/product_key_name, not per-device or per-customer. "
        "Any party possessing Cisco's CT DEV private key for CT-IntersightAppliance-Debug-Access "
        "can authenticate as 'tac' on ANY Intersight Appliance worldwide."
    ),

    "impact": (
        "Authentication as 'tac' + NOPASSWD sudo = unrestricted root. "
        "The appliance is the control plane for all connected UCS infrastructure and stores "
        "Intersight cloud connection credentials. "
        "Scope: every Intersight On-Premises Appliance deployment globally. "
        "Revocation requires appliance software update to replace the embedded certificate — "
        "no runtime revocation mechanism visible in pam_cisco_ct.ini."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F3 — diag.py SCP tech-support upload exposes password via process list
#           and disables SSH host key verification (StrictHostKeyChecking=no)
# ─────────────────────────────────────────────────────────
ISA_F3 = {
    "id":       "ISA-F3",
    "title":    "diag.py SCP tech-support transfer exposes remote host password via process list "
                "and silently disables SSH host key verification",
    "status":   "CONFIRMED — /usr/local/bin/diag.py line 228 in disk1",
    "severity": "MEDIUM",

    "source_file": "/usr/local/bin/diag.py (admin user login shell)",
    "line":        228,

    "vulnerable_invocation": (
        'subprocess.call(["sudo", "sshpass", "-p", server[\'passwd\'], "scp", '
        '"-o", "StrictHostKeyChecking=no", "-o", "UpdateHostKeys=no", '
        'server[\'local_path\'], serverpath])'
    ),

    "issues": {
        "process_list_exposure": (
            "sshpass -p <password> passes the user-provided password as a command-line argument. "
            "On Linux, command-line arguments are visible in /proc/<pid>/cmdline to any local user "
            "with access to procfs. Any process running concurrently can read the tech-support "
            "destination password during the SCP transfer window."
        ),
        "host_key_verification_disabled": (
            "StrictHostKeyChecking=no: OpenSSH accepts any server host key without verification. "
            "UpdateHostKeys=no: prevents host key updates in known_hosts. "
            "Combined effect: the SCP transfer proceeds even if the destination server presents "
            "a forged key — full MITM of tech-support bundles without detection."
        ),
        "sftp_auto_add_policy": (
            "The SFTP path (sftptransfer() function) uses paramiko.AutoAddPolicy() — "
            "equivalent to StrictHostKeyChecking=no for the SFTP code path. "
            "Both transfer protocols disable host verification."
        ),
    },

    "user_input": (
        "The destination hostname, username, and password are collected interactively from the "
        "admin user via sys_input() in getserverdetails(). The password is stored in server['passwd'] "
        "and passed directly to sshpass without any redaction."
    ),

    "impact": (
        "An attacker with: (1) access to the admin diag.py session or its process namespace, "
        "or (2) ability to MITM the management network during tech-support collection, "
        "can capture tech-support destination credentials or intercept appliance diagnostic bundles."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F4 — worker-bootstrap.sh uses IMDSv1 unauthenticated metadata access
#           (applies to AWS-deployed Intersight nodes)
# ─────────────────────────────────────────────────────────
ISA_F4 = {
    "id":       "ISA-F4",
    "title":    "worker-bootstrap.sh uses IMDSv1 (unauthenticated IMDS) for instance metadata "
                "and IAM credential retrieval — vulnerable to SSRF-to-IAM-role theft on AWS nodes",
    "status":   "CONFIRMED — /usr/local/bin/worker-bootstrap.sh in disk1 (AWS Intersight cloud deployment)",
    "severity": "MEDIUM",

    "source_file": "/usr/local/bin/worker-bootstrap.sh",
    "target_scope": "AWS-deployed Intersight nodes (not KVM on-premises instances)",

    "imdsv1_calls": [
        "curl http://169.254.169.254/latest/meta-data/instance-id",
        "curl http://169.254.169.254/latest/dynamic/instance-identity/document",
        "curl http://169.254.169.254/latest/dynamic/instance-identity/document/ | jq '.accountId'",
    ],

    "no_imdsv2_token": (
        "None of the curl commands include the IMDSv2 token header "
        "(-H 'X-aws-ec2-metadata-token: ...'). "
        "IMDSv1 requests to 169.254.169.254 are unauthenticated and can be triggered "
        "by any process or SSRF vulnerability that can make requests from the EC2 instance."
    ),

    "downstream_ops": (
        "After fetching instance identity, the script calls:\n"
        "  aws ec2 describe-tags --region $aws_region ...\n"
        "  (implicit IAM role credential use via IMDS endpoint)\n"
        "IAM credentials for the instance role are accessible at "
        "169.254.169.254/latest/meta-data/iam/security-credentials/<role>. "
        "An SSRF vulnerability in any Intersight service reaching this endpoint "
        "yields temporary AWS credentials for the IAM instance role."
    ),

    "app_stack_from_script": (
        "get_dev_name.sh documents the application disk map: "
        "boot, docker-repo, etcd, mongodb, rabbitmq, consul, vault, jenkins. "
        "This confirms the full Intersight cloud infrastructure: "
        "Kubernetes + etcd, MongoDB, RabbitMQ, HashiCorp Vault, Consul, Jenkins."
    ),

    "impact": (
        "SSRF in any Intersight Appliance service → IMDSv1 request → "
        "AWS temporary IAM credentials for the EC2 instance role → "
        "AWS API access scoped to whatever the instance role permits "
        "(typically including S3 bucket access for Intersight software bundles "
        "and EC2 describe operations)."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F5 — ansible, admin, and tac all have NOPASSWD:ALL sudo
#           — triple privilege escalation surface on locked accounts
# ─────────────────────────────────────────────────────────
ISA_F5 = {
    "id":       "ISA-F5",
    "title":    "ansible, admin, and tac each have NOPASSWD:ALL sudo via sudoers.d — "
                "three separate locked accounts with unrestricted root escalation paths",
    "status":   "CONFIRMED — /etc/sudoers.d/{ansible,admin,tac} in disk1",
    "severity": "HIGH",

    "sudoers_entries": {
        "/etc/sudoers.d/ansible": "ansible ALL=(ALL:ALL) NOPASSWD: ALL",
        "/etc/sudoers.d/admin":   "admin ALL=(ALL:ALL) NOPASSWD: ALL",
        "/etc/sudoers.d/tac":     "tac ALL=(ALL:ALL) NOPASSWD: ALL",
    },

    "account_state": {
        "ansible": "shadow !! (locked), /bin/bash shell — no password auth possible",
        "admin":   "shadow !! (locked), /usr/local/bin/diag.py shell — restricted login shell",
        "tac":     "shadow !! (locked), /bin/bash shell — pam_cisco_ct.so auth (see ISA-F2)",
    },

    "analysis": (
        "All three accounts are locked (!! shadow) — no direct password SSH auth. "
        "Each is accessible via a different mechanism: "
        "'tac' via CT token (ISA-F2), 'ansible' via SSH key injection or Ansible playbook, "
        "'admin' via diag.py restricted shell with authenticated CT/console access. "
        "All three grant root on first sudo call (no password challenge). "
        "The sudoers.d fragmentation means each account's privilege was added independently — "
        "not a single decision but three separate grants across the account lifecycle."
    ),

    "impact": (
        "Any one of three accounts, if accessed, immediately yields root. "
        "The ansible account is of particular interest: if any Ansible playbook on a jump host "
        "or CI/CD pipeline stores credentials for the Intersight Appliance, "
        "those credentials bypass the password requirement and grant root directly."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F6 — cloud-init almalinux user has NOPASSWD:ALL sudo
#           — SSH key injection via hypervisor = root
# ─────────────────────────────────────────────────────────
ISA_F6 = {
    "id":       "ISA-F6",
    "title":    "cloud-init default user 'almalinux' has NOPASSWD:ALL sudo — "
                "hypervisor-level SSH key injection yields unrestricted root",
    "status":   "CONFIRMED — /etc/cloud/cloud.cfg in disk1",
    "severity": "MEDIUM",

    "cloud_cfg_entry": (
        "default_user:\n"
        "  name: almalinux\n"
        "  lock_passwd: True\n"
        "  groups: [adm, systemd-journal]\n"
        "  sudo: ['ALL=(ALL) NOPASSWD:ALL']\n"
        "  shell: /bin/bash"
    ),

    "analysis": (
        "Cloud-init creates the 'almalinux' user with NOPASSWD:ALL sudo on first boot. "
        "The account's password is locked (lock_passwd: True) — authentication is SSH key only. "
        "Cloud-init injects SSH keys from the hypervisor's guestinfo or OVF environment. "
        "Attack vector: an attacker with access to the KVM hypervisor (e.g., compromised vCenter, "
        "libvirt socket, or cloud-init datasource) can inject an arbitrary SSH public key "
        "into cloud-init metadata before first boot. On boot, cloud-init creates the "
        "almalinux account with the attacker's key. SSH as almalinux → sudo -s → root. "
        "This is a pre-boot hypervisor-level privilege escalation path."
    ),

    "setup_script_note": (
        "setup-services.sh checks OVF env for skip-init flag via vmtoolsd: "
        "'vmtoolsd --cmd info-get guestinfo.ovfEnv'. "
        "A hypervisor operator can also set skip-init=True to suppress Ansible playbook execution, "
        "potentially leaving the appliance in a partial state exploitable during initialization."
    ),

    "impact": (
        "Hypervisor access → cloud-init key injection → root on Intersight Appliance. "
        "Relevant in multi-tenant environments or where vCenter/libvirt credentials are shared."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F7 — /etc/kubernetes/ansible.kubeconfig deployed world-readable (mode 0644)
#           containing kube_admin_password (system:masters cluster admin bearer token)
# Source: disk3 LVM file_cisco/cisco — Ansible installer playbooks
# ─────────────────────────────────────────────────────────
ISA_F7 = {
    "id":       "ISA-F7",
    "title":    "Intersight Appliance installer deploys /etc/kubernetes/ansible.kubeconfig "
                "with mode 0644 (world-readable); file contains kube_admin_password bearer token "
                "granting system:masters (cluster admin) Kubernetes API access",
    "status":   "CONFIRMED — tasks/setup-kubernetes-user-credentials.yml + "
                "kubernetes/config/ansible-kubeconfig.j2 in disk3 file_cisco/cisco LVM",
    "severity": "HIGH",

    "installer_task": (
        "# tasks/setup-kubernetes-user-credentials.yml:\n"
        "- name: Backup ansible-user's kubeconfig\n"
        "  become: true\n"
        "  copy:\n"
        "    src: ~ansible/.kube/config\n"
        "    dest: /etc/kubernetes/ansible.kubeconfig\n"
        "    mode: 0644   # ← world-readable"
    ),

    "kubeconfig_template": (
        "# kubernetes/config/ansible-kubeconfig.j2:\n"
        "users:\n"
        "- user:\n"
        "    token: {{ kube_admin_password }}   # system:masters admin token\n"
        "  name: admin\n"
        "current-context: admin"
    ),

    "token_generation": (
        "kube_admin_password is generated via 'openssl rand -hex 16' "
        "(tasks/get-kube-credentials.yml) and stored separately in etcd per token name. "
        "Static bearer token — non-expiring, only invalidated by API server restart. "
        "The token is written to /var/lib/kubernetes/token.csv (mode 0600, root-only) — "
        "but the kubeconfig backup at /etc/kubernetes/ansible.kubeconfig (mode 0644) "
        "is readable by any local user without privilege escalation."
    ),

    "impact": (
        "Any local user on the Intersight Appliance can read "
        "/etc/kubernetes/ansible.kubeconfig and extract the kube_admin_password bearer token. "
        "Presenting this token to the Kubernetes API server authenticates as 'admin' in "
        "system:masters — full cluster admin: create/delete pods, read secrets across all "
        "namespaces, deploy arbitrary workloads. "
        "The Intersight Appliance Kubernetes cluster runs the full application stack "
        "(etcd, MongoDB, RabbitMQ, Consul, Vault, Equinox cloud connector). "
        "Cluster admin access = read all application secrets stored in Kubernetes Secrets."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F8 — Kubernetes API server uses --token-auth-file (static token CSV)
#           deprecated K8s 1.19, removed K8s 1.29; tokens non-expiring + non-revocable
#           without full API server restart
# Source: disk3 LVM file_cisco/cisco — Ansible installer playbooks
# ─────────────────────────────────────────────────────────
ISA_F8 = {
    "id":       "ISA-F8",
    "title":    "Intersight Appliance kube-apiserver starts with --token-auth-file=/var/lib/kubernetes/token.csv — "
                "static CSV token auth deprecated in Kubernetes 1.19, removed in 1.29; "
                "tokens are non-expiring and cannot be invalidated without restarting the API server",
    "status":   "CONFIRMED — kubernetes/config/kube-apiserver.service.tls.j2 line 35 + "
                "kubernetes/config/token.j2 in disk3 file_cisco/cisco LVM",
    "severity": "MEDIUM",

    "apiserver_flag": "--token-auth-file=/var/lib/kubernetes/token.csv",

    "token_csv_template": (
        "# kubernetes/config/token.j2 — written to /var/lib/kubernetes/token.csv (mode 0600):\n"
        "{{ kube_admin_password }},admin,admin,system:masters\n"
        "{{ kube_readonly_password }},kube-readonly,kube-readonly\n"
        "{{ kubelet_bootstrap_token }},kubelet-bootstrap,10001,\"system:bootstrappers\"\n"
        "# format: token,username,uid[,group1[,group2...]]\n"
        "# kube_admin_password → system:masters (cluster admin)\n"
        "# kubelet_bootstrap_token → system:bootstrappers (node join)"
    ),

    "deprecation_timeline": (
        "K8s 1.19 (Aug 2020): static token file authentication marked deprecated. "
        "K8s 1.29 (Dec 2023): --token-auth-file flag removed from kube-apiserver. "
        "Intersight Appliance 1.1.7 (2025): still uses this mechanism. "
        "Static tokens in token.csv have no expiry field — they are valid indefinitely "
        "until the file is edited and the API server is restarted. "
        "Token rotation requires: (1) edit token.csv, (2) restart kube-apiserver. "
        "There is no online token revocation path."
    ),

    "compound_risk": (
        "Paired with ISA-F7: the world-readable ansible.kubeconfig exposes the "
        "kube_admin_password token value. Since static tokens cannot be rotated "
        "without an API server restart (service disruption), a leaked token provides "
        "persistent cluster admin access until the operator takes an explicit disruptive action. "
        "The absence of token expiry means there is no automatic credential rotation."
    ),

    "impact": (
        "An attacker who reads /etc/kubernetes/ansible.kubeconfig (ISA-F7) obtains a "
        "bearer token that cannot be expired on a schedule — only manually invalidated "
        "via API server restart. In post-incident scenarios, silent token theft may go "
        "undetected: no audit log entry for bearer-token auth beyond the request log, "
        "no expiry-based trip wire, no certificate revocation equivalent."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F9 — DNS and Equinox service kubeconfigs provisioned with kube_admin_password
#           (cluster admin token) via 'For now, use admin credentials' comment
# Source: disk3 LVM file_cisco/cisco — Ansible installer playbooks
# ─────────────────────────────────────────────────────────
ISA_F9 = {
    "id":       "ISA-F9",
    "title":    "Intersight Appliance installer provisions /etc/kubernetes/dns.kubeconfig and "
                "/etc/kubernetes/equinox.kubeconfig with kube_admin_password (system:masters) "
                "acknowledged by inline 'For now, use admin credentials' comment",
    "status":   "CONFIRMED — tasks/setup-kubernetes-user-credentials.yml lines 107-132 "
                "in disk3 file_cisco/cisco LVM",
    "severity": "MEDIUM",

    "playbook_excerpt": (
        "# tasks/setup-kubernetes-user-credentials.yml lines 107-132:\n"
        "\n"
        "    # For now, use admin credentials.\n"
        "    - name: Generate dns kubeconfig\n"
        "      ...password: '{{ kube_admin_password }}'\n"
        "      dest: /etc/kubernetes/dns.kubeconfig\n"
        "\n"
        "    # For now use admin credentials.\n"
        "    - name: Generate equinox kubeconfig\n"
        "      ...password: '{{ kube_admin_password }}'\n"
        "      dest: /etc/kubernetes/equinox.kubeconfig"
    ),

    "service_context": {
        "dns": "CoreDNS service configuration — read access to cluster DNS records sufficient",
        "equinox": "Intersight cloud connector — bridges on-premises appliance to Cisco Intersight cloud; "
                   "requires cluster coordination but NOT cluster admin privilege",
    },

    "principle_of_least_privilege": (
        "Both services were acknowledged as over-privileged at time of coding ('For now'). "
        "DNS management requires get/watch/list on ConfigMaps in kube-system, not system:masters. "
        "The Equinox cloud connector requires read access to namespaces and deployments — "
        "a custom ClusterRole scoped to those resources is sufficient. "
        "Provisioning both with the cluster admin token widens the blast radius of "
        "any compromise of either service's kubeconfig file or process."
    ),

    "impact": (
        "A vulnerability in CoreDNS or the Equinox cloud connector that allows reading "
        "/etc/kubernetes/dns.kubeconfig or /etc/kubernetes/equinox.kubeconfig "
        "yields system:masters cluster admin access — the same privilege level "
        "as the full ansible admin. "
        "The Equinox connector is of particular interest: it maintains connectivity to "
        "Cisco Intersight cloud, and a compromised Equinox process with cluster admin "
        "can read all Kubernetes Secrets including stored cloud API credentials."
    ),
}

# ─────────────────────────────────────────────────────────
# ISA-F10 — MongoDB TLS mode defaults to 'preferTLS' — accepts plaintext connections
# Source: disk3 LVM file_cisco/cisco — Ansible installer playbooks
# ─────────────────────────────────────────────────────────
ISA_F10 = {
    "id":       "ISA-F10",
    "title":    "Intersight Appliance Ansible installer sets mongodb_tls_mode to 'preferTLS' — "
                "MongoDB accepts non-TLS plaintext connections when TLS handshake fails or is "
                "not initiated by the client",
    "status":   "CONFIRMED — vars/mongodb-tls-params.yml in disk3 file_cisco/cisco LVM",
    "severity": "LOW",

    "vars_file": "vars/mongodb-tls-params.yml",
    "setting":   "mongodb_tls_mode: \"preferTLS\"",

    "tls_mode_behavior": (
        "MongoDB TLS modes:\n"
        "  disabled   — no TLS, all connections plaintext\n"
        "  allowTLS   — accepts both TLS and non-TLS\n"
        "  preferTLS  — accepts both TLS and non-TLS (client negotiation-dependent)\n"
        "  requireTLS — rejects any non-TLS connection\n"
        "'preferTLS' is functionally equivalent to 'allowTLS' — a client connecting "
        "without TLS is not rejected. The 'require' is advisory from the server's perspective."
    ),

    "deployment_context": (
        "MongoDB is part of the Intersight Appliance application stack. "
        "In a correctly deployed appliance, all pod-to-MongoDB connections should use TLS "
        "via the onprem-ca.crt trust chain. "
        "preferTLS leaves a fallback path: any pod or local process that connects to MongoDB "
        "without TLS (e.g., a debug tool, a misconfigured service, or a container with "
        "a missing CA bundle) receives plaintext MongoDB traffic including collection data. "
        "requireTLS would eliminate this fallback without requiring client changes for "
        "correctly configured services."
    ),

    "impact": (
        "Low — requires network access to the MongoDB port within the cluster. "
        "In a shared-namespace or compromised pod scenario, a process connecting to MongoDB "
        "without TLS succeeds, allowing unencrypted data transfer and potential "
        "credential capture on the cluster network."
    ),
}


ISA_ACCOUNTS = {
    "root":      {"uid": 0,    "shadow": "!! (locked)", "shell": "/bin/bash",             "sudo": "direct root"},
    "ansible":   {"uid": 1001, "shadow": "!! (locked)", "shell": "/bin/bash",             "sudo": "NOPASSWD:ALL (sudoers.d/ansible)"},
    "admin":     {"uid": 1002, "shadow": "!! (locked)", "shell": "/usr/local/bin/diag.py","sudo": "NOPASSWD:ALL (sudoers.d/admin)"},
    "andro":     {"uid": 1003, "shadow": "!! (locked)", "shell": "/sbin/nologin",         "sudo": "%andro ALL=(ALL) NOPASSWD: ALL (/etc/sudoers)"},
    "tac":       {"uid": 1004, "shadow": "!! (CT auth)","shell": "/bin/bash",             "sudo": "NOPASSWD:ALL (sudoers.d/tac)"},
    "almalinux": {"uid": None, "shadow": "locked (cloud-init SSH key)", "shell": "/bin/bash", "sudo": "ALL=(ALL) NOPASSWD:ALL (cloud.cfg)"},
}

ISA_CUSTOM_SSH = {
    "path":    "/usr/local/bin/ssh (+ scp, sftp)",
    "version": "CiscoSSH 1.19.92, OpenSSH 10.2p1",
    "note":    "Cisco fork of OpenSSH 10.2p1 in /usr/local/bin, overrides system OpenSSH in PATH",
}

FINDINGS = [ISA_F1, ISA_F2, ISA_F3, ISA_F4, ISA_F5, ISA_F6,
            ISA_F7, ISA_F8, ISA_F9, ISA_F10]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
