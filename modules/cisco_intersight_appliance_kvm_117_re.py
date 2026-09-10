"""
Cisco Intersight On-Premises Appliance — KVM Installer 1.1.7-0.a — RE Module
Source: intersight-appliance-installer-kvm-1.1.7-0.a.tar.gz
Format: 8x QCOW2 disks (45GB virtual each); disk1 = AlmaLinux 9 OS volume
OS: AlmaLinux 9, kernel 5.14.0-687.5.3.el9_8 (RHEL 9.8 ABI)
LVM: almalinux VG (root 14G + home 6G + opt_cisco 9G + tmp 5G + var_tmp 5G)
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
    "findings":    ["ISA-F1", "ISA-F2", "ISA-F3", "ISA-F4"],
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
# ISA-F2 — Cisco TAC backdoor SSH account 'tac' with /bin/bash in all deployments
# ─────────────────────────────────────────────────────────
ISA_F2 = {
    "id":       "ISA-F2",
    "title":    "Cisco TAC SSH backdoor account 'tac' with /bin/bash shell present in all appliance deployments",
    "status":   "CONFIRMED — /etc/passwd + /etc/shadow in disk1",
    "severity": "MEDIUM",

    "passwd_entry": "tac:x:1004:1004:Cisco TAC access:/home/tac:/bin/bash",
    "shadow_entry": "tac:!!:20622:::::::",
    "group_entry":  "tac:x:1004:",

    "analysis": (
        "The 'tac' account exists in all Intersight Appliance deployments (baked into the installer image). "
        "Shadow entry !! = no password; authentication requires an SSH key that Cisco TAC controls. "
        "The comment field 'Cisco TAC access' explicitly documents the intent: "
        "Cisco TAC can SSH into any deployed Intersight Appliance with this account. "
        "The account has /bin/bash shell — full interactive access, not a restricted shell. "
        "Customers deploying the on-premises appliance (chosen specifically for data sovereignty) "
        "receive a system with a Cisco-controlled SSH entry point."
    ),

    "sudo_membership": "tac not in sudoers or wheel — limited to tac user's own privileges",

    "impact": (
        "Persistent remote access capability for Cisco personnel to any deployed Intersight Appliance. "
        "The account is pre-provisioned; no customer action activates or authorizes it. "
        "Customers who deploy on-premises for data sovereignty have no mechanism "
        "to remove this account without breaking the appliance management model. "
        "SSH key is Cisco-controlled — compromise of Cisco's TAC SSH keys = access to all appliances."
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

ISA_ACCOUNTS = {
    "root":    {"uid": 0,    "shadow": "!! (locked)",   "shell": "/bin/bash",       "sudo": "via wheel if added"},
    "ansible": {"uid": 1001, "shadow": "!! (locked)",   "shell": "/bin/bash",       "sudo": "not in sudoers"},
    "admin":   {"uid": 1002, "shadow": "!! (locked)",   "shell": "/usr/local/bin/diag.py", "sudo": "not in sudoers"},
    "andro":   {"uid": 1003, "shadow": "!! (locked)",   "shell": "/sbin/nologin",   "sudo": "%andro ALL=(ALL) NOPASSWD: ALL"},
    "tac":     {"uid": 1004, "shadow": "!! (key-based)", "shell": "/bin/bash",      "sudo": "not in sudoers"},
}

ISA_CUSTOM_SSH = {
    "path":    "/usr/local/bin/ssh (+ scp, sftp)",
    "version": "CiscoSSH 1.19.92, OpenSSH 10.2p1",
    "note":    "Cisco fork of OpenSSH 10.2p1 in /usr/local/bin, overrides system OpenSSH in PATH",
}

FINDINGS = [ISA_F1, ISA_F2, ISA_F3, ISA_F4]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
