"""
Intersight Private Virtual Appliance -- cert_management_console.py + worker-bootstrap.sh RE

Target:  intersight-appliance-installer-kvm-1.1.7-0.a-disk1.qcow2
Scripts: /usr/local/bin/cert_management_console.py (TLS cert ops, admin shell module)
         /usr/local/bin/worker-bootstrap.sh (AWS worker node Ansible bootstrap)
         /usr/local/bin/read_cloud_init_params.py (cloud-init -> /tmp/net.conf)
         /usr/local/bin/andromeda-node-shutdown.py (VM clone SSH key comment)
Session: 37
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_intersight_cert_bootstrap_re",
    "firmware": "intersight-appliance-installer-kvm-1.1.7-0.a-disk1.qcow2",
    "components": {
        "cert_management_console.py": (
            "TLS certificate management module for diag.py admin shell; "
            "handles CSR generation, cert upload, etcd storage, service restart"
        ),
        "worker-bootstrap.sh": (
            "AWS worker node bootstrap script; fetches and executes "
            "Ansible playbooks from S3 based on EC2 instance metadata"
        ),
        "read_cloud_init_params.py": (
            "Cloud-init parameter reader; decodes YAML config and writes "
            "network config + plaintext admin password to /tmp/net.conf"
        ),
        "andromeda-node-shutdown.py": (
            "Shutdown counterpart to node-init; handles SSH key cleanup. "
            "Contains acknowledged VM-clone SSH key reuse risk."
        ),
    },
    "finding_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 57, "HIGH": 216, "MEDIUM": 210, "LOW": 186},
    "cumulative_total": 669,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "TLS Private Key Set World-Readable (mode 0644) via chmod in post_certificate_installation()",
        "component": "cert_management_console.py",
        "function": "post_certificate_installation() -> _update_etcd_with_certificate()",
        "evidence": {
            "code": (
                "def _update_etcd_with_certificate(etcd_path, file_path, description):\n"
                "    # Set certificate file permissions to 0644\n"
                "    cmd = ['sudo', 'chmod', '644', file_path]\n"
                "    ret, out = run_command(cmd, ...)\n"
                "    ...\n"
                "\n"
                "# Called for BOTH the cert AND the private key:\n"
                "_update_etcd_with_certificate(CERT_ETCD_PATH,     CERT_PATH,     'certificate')\n"
                "_update_etcd_with_certificate(CERT_KEY_ETCD_PATH, CERT_KEY_PATH, 'certificate key')\n"
                "\n"
                "CERT_KEY_PATH = '/opt/cisco/echo/etc/echo-web.key'  # private key"
            ),
            "result": "TLS private key at /opt/cisco/echo/etc/echo-web.key set to mode 0644",
            "comment": "Code comment reads 'Set certificate file permissions to 0644' -- "
                       "the same function applied to both cert and key without differentiating",
        },
        "impact": (
            "Every time a certificate is installed through the admin diagnostic shell, "
            "the TLS private key for the Intersight web interface (echo-web) is explicitly "
            "set to world-readable mode 0644. Any local user or process on the appliance "
            "can read the private key from /opt/cisco/echo/etc/echo-web.key. "
            "The key is also stored in etcd (see F2), but the filesystem exposure is "
            "independent and requires no etcd access."
        ),
        "remediation": (
            "chmod 600 (or 640 if a group read is needed) on the private key file. "
            "The certificate (.crt) can remain 644; the key (.key) must not. "
            "Split _update_etcd_with_certificate into separate cert/key helpers "
            "with correct mode constants for each."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "TLS Private Key Written to Etcd in Plaintext",
        "component": "cert_management_console.py",
        "function": "post_certificate_installation() -> _update_etcd_with_certificate()",
        "evidence": {
            "code": (
                "CERT_KEY_ETCD_PATH = 'appliance.privkey.echo-web'\n"
                "\n"
                "cmd_str = f'sudo /opt/cisco/etcd/etcdv3.sh put {etcd_path} < {file_path}'\n"
                "result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)"
            ),
            "etcd_key": "appliance.privkey.echo-web",
            "mechanism": (
                "etcdv3.sh puts the raw PEM private key as a string value in the "
                "cluster etcd key-value store; any pod or process with etcd read access "
                "can retrieve it via: etcdctl get appliance.privkey.echo-web"
            ),
        },
        "impact": (
            "The Intersight appliance TLS private key is stored unencrypted in the "
            "cluster etcd store under a predictable key path. Etcd is accessible to all "
            "pods in the Kubernetes cluster running on the appliance. Any pod with "
            "etcd read permission -- including debug/dev pods deployed by default (see F2 "
            "in prior module) -- can exfiltrate the TLS private key. The key path "
            "appliance.privkey.echo-web is a stable, predictable target."
        ),
        "remediation": (
            "Encrypt the private key before storing in etcd, or use a Kubernetes Secret "
            "with encryption-at-rest configured. Do not use a raw etcdv3 put for secret material. "
            "Audit etcd for other keys storing unencrypted credentials or private keys."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Worker Bootstrap Uses IMDSv1 (No Token) for EC2 Instance Identity",
        "component": "worker-bootstrap.sh",
        "evidence": {
            "code": (
                "instance_id=\"$(curl http://169.254.169.254/latest/meta-data/instance-id)\"\n"
                "aws_region=`curl http://169.254.169.254/latest/dynamic/instance-identity/document | ...`\n"
                "aws_account_id=\"$(curl http://169.254.169.254/latest/dynamic/instance-identity/document/ | ...)\""
            ),
            "missing": "No X-aws-ec2-metadata-token header; no PUT /latest/api/token preflight",
            "context": (
                "andromeda-node-init.py uses IMDSv2 correctly; "
                "worker-bootstrap.sh uses IMDSv1 on the same nodes"
            ),
        },
        "impact": (
            "Worker node bootstrap uses IMDSv1 for instance identity and region lookup. "
            "IMDSv1 is vulnerable to SSRF: any application on the worker node that "
            "fetches arbitrary URLs can reach 169.254.169.254 and retrieve instance metadata "
            "including the IAM role credentials used for subsequent aws CLI calls. "
            "The retrieved credentials are then used for `aws s3 cp` and `aws ec2 describe-tags` "
            "in the same script, meaning SSRF against IMDS yields code execution through "
            "the bootstrap Ansible playbooks."
        ),
        "remediation": (
            "Add IMDSv2 token acquisition: "
            "TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' "
            "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600') "
            "then pass -H \"X-aws-ec2-metadata-token: $TOKEN\" on all IMDS curl calls. "
            "Enable IMDSv2-only at the instance level via EC2 metadata options."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "Ansible Playbooks Fetched from S3 and Executed Without Integrity Verification",
        "component": "worker-bootstrap.sh",
        "evidence": {
            "code": (
                "aws s3 cp s3://$bootstrap_bucket_url/ ~/ --recursive | tee -a ~/aws-cp.log\n"
                "cd ~/irongate/ && ansible-playbook node-master.yml"
            ),
            "no_verification": (
                "No checksum validation, no S3 object signing check, "
                "no GPG/PGP signature on downloaded playbooks"
            ),
            "bootstrap_bucket_url": (
                "Variable set via cloud-init userdata; not defined in script -- "
                "empty variable causes aws s3 cp s3:/// (failure) "
                "or is injected by whoever provides userdata"
            ),
        },
        "impact": (
            "Worker node Ansible playbooks are fetched from S3 and executed directly "
            "with no integrity check. If the S3 bucket has overly permissive write ACLs "
            "or if the IAM role attached to the instance allows s3:PutObject on the "
            "bootstrap bucket, an attacker can replace node-master.yml with arbitrary "
            "commands that execute at the privilege level of the bootstrap process "
            "on every new worker node joining the cluster. "
            "The `--recursive` flag fetches all files in the bucket prefix, expanding "
            "the attack surface to any file the playbook imports."
        ),
        "remediation": (
            "Verify playbook checksums against a manifest signed with a key not stored "
            "in S3. Enable S3 bucket versioning + object lock. Restrict the bootstrap "
            "IAM role to s3:GetObject only. Consider using SSM Parameter Store "
            "or Secrets Manager for bootstrap config instead of S3."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Cloud-Init Path Writes Plaintext Admin Password to World-Readable /tmp/net.conf",
        "component": "read_cloud_init_params.py",
        "evidence": {
            "code": (
                "if user_input['admin_password']:\n"
                "    # Password is base64-encoded\n"
                "    custom_dict['password'] = base64.b64decode(\n"
                "        user_input['admin_password']\n"
                "    ).decode('utf-8')\n"
                "\n"
                "if custom_dict:\n"
                "    with open('/tmp/net.conf', 'w') as fh:\n"
                "        fh.write(json.dumps(custom_dict))"
            ),
            "source_file": "/etc/my-appliance-config.yaml",
            "destination": "/tmp/net.conf (world-writable path)",
            "encoding": "base64 in YAML, plaintext in /tmp/net.conf JSON",
        },
        "impact": (
            "The cloud-init code path (distinct from the OVF path in andromeda-node-init.py) "
            "decodes the admin password from base64 and writes it as plaintext into "
            "/tmp/net.conf before andromeda-node-init.py reads and applies it. "
            "The base64 encoding in the YAML config provides no security -- it is "
            "decoded on write. Combined with the world-writable /tmp path, any local "
            "process can read the admin password from /tmp/net.conf during the window "
            "between write and consumption by the init service."
        ),
        "remediation": (
            "Handle the password separately from network config. "
            "Write it to a root-owned, mode 0600 temp file rather than the shared net.conf. "
            "Delete it immediately after the init service applies it."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "Developer Comment Acknowledges Predictable SSH Private Keys on Cloned VM Instances",
        "component": "andromeda-node-shutdown.py",
        "evidence": {
            "comment": (
                "# If the seed is cloned, every VM will get predictable SSH private keys.\n"
                "# In initial tests, each AWS ec2 instance actually had the exact same private key."
            ),
            "context": (
                "Shutdown script handles SSH key cleanup before VM cloning; "
                "comment implies the seed VM's ansible SSH keypair persisted into "
                "production AMIs during initial AWS deployments"
            ),
            "function": "delete_ssh_keys() -- deletes ansible ~/.ssh/id_rsa + id_rsa.pub",
        },
        "impact": (
            "The development team confirmed during testing that cloned Intersight instances "
            "carried identical SSH private keys, meaning any instance could authenticate "
            "as the ansible user to any other instance. The shutdown script is meant to "
            "mitigate this, but the risk re-emerges if the shutdown script is not run "
            "before a VM snapshot or AMI is captured. OVF templates distributed without "
            "running the shutdown script would carry the pre-seeded key."
        ),
        "remediation": (
            "Generate ansible SSH keypair at first boot in andromeda-node-init.py "
            "rather than relying on the shutdown script to delete a pre-seeded key. "
            "Assert no id_rsa exists before proceeding with any operation that relies "
            "on the ansible key for inter-node communication."
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
