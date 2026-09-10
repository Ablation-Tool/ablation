"""
Cisco Vulnerability Management (CVM) Virtual Tunnel (VT) Client 1.4.14 — RE Module
Source: cvm-vt-client-1.4.14-x86_64.ova (4.8GB OVA, EC2-exported VMDK)
Internal name: kvt-20260512195935 (Kenna VT build 434, built 2026-05-12)
OS: Rocky Linux 9.7 (Blue Onyx), XFS root partition (11GB virtual)
Signing cert: CN=CiscoVulnerabilityManagement, OU=Release, O=Cisco
               Issued by: Innerspace SubCA RSA (same CA as coeus/ESA)

Architecture:
  The VT is an outbound HTTPS connector. It dials api.kennasecurity.com (now
  Cisco Vulnerability Management SaaS) using a per-tenant API key, receives
  tunneled commands/files from the cloud platform, and executes them locally.
  This enables the CVM SaaS to scan on-premises networks without inbound firewall rules.

Build pipeline: Packer (ami.pkr.hcl) + Ansible (client.yml) → EC2 AMI → OVA export
  Packer project: github.com-internal; S3 bucket: kenna-operation-services-images-import
  Build artifacts left at: /tmp/packer-provisioner-ansible-local/<uuid>/ on the deployed image
"""

FIRMWARE = {
    "target":    "Cisco Vulnerability Management Virtual Tunnel Client",
    "version":   "1.4.14 / kvt build 434",
    "source":    "cvm-vt-client-1.4.14-x86_64.ova",
    "os":        "Rocky Linux 9.7",
    "arch":      "x86_64",
    "signing":   "CN=CiscoVulnerabilityManagement, OU=Release, O=Cisco (Innerspace SubCA RSA)",
    "findings":  ["CVMVT-F1", "CVMVT-F2", "CVMVT-F3"],
}

# ─────────────────────────────────────────────────────────
# CVMVT-F1: Incomplete Packer cleanup — full build tree in /tmp with credential defaults
# ─────────────────────────────────────────────────────────
CVMVT_F1 = {
    "id":       "CVMVT-F1",
    "title":    "Packer build artifacts not cleaned from /tmp — full Ansible source + initial credential "
                "defaults ('rootpw vagrant', 'vt_api_token: test') exposed on every deployed VT instance",
    "status":   "CONFIRMED — /tmp/packer-provisioner-ansible-local/<uuid>/ on disk-1.vmdk",
    "severity": "HIGH",

    "artifact_path": "/tmp/packer-provisioner-ansible-local/6a038bee-2acb-d4c2-7dd7-3525cd43c1d7/",

    "exposed_artifacts": {
        "ami.pkr.hcl":             "Packer build config — includes variable names (vt_api_token, ssh_password, aws_bucket)",
        "ansible/client.yml":      "Full Ansible playbook — default creds and infrastructure config",
        "http/ks.cfg":             "Rocky Linux 9.4 kickstart — initial root password 'vagrant'",
        "scripts/cleanup.sh":      "Cleanup script that was run but does NOT remove /tmp/packer-* directory",
        "templates/*.j2":          "Jinja2 templates for API token, API host, network config, SSH config",
        "kvt-20260512195935/*":    "Build artifact directory",
    },

    "credential_defaults_in_artifacts": {
        "ks.cfg:rootpw":          "vagrant  (initial root password set by kickstart; overridden by Ansible)",
        "client.yml:vt_api_token": "test    (default VT API token in playbook; overridden by Packer --extra-vars at build time)",
        "client.yml:api_host":    "api.kennasecurity.com  (Kenna/CVM SaaS endpoint)",
    },

    "cleanup_failure": (
        "cleanup.sh removes Ansible, zeros free space, and runs yum clean. "
        "It does NOT remove /tmp/packer-provisioner-ansible-local/ nor any other Packer stage dirs. "
        "The full build tree — including Ansible playbooks, kickstart config, template files, "
        "and build variable names — is present on every deployed VT instance filesystem."
    ),

    "impact": (
        "An attacker with read access to any deployed VT instance's filesystem (via the VT's own "
        "tunnel channel if compromised, or by recovering an OVA export) gains: "
        "(1) the initial root password 'vagrant' (useful for forensic/offline analysis if the "
        "password was never changed by the Ansible playbook — the current root hash does NOT "
        "match 'vagrant', confirming it was changed), "
        "(2) the complete build pipeline structure, variable names, and infrastructure identifiers "
        "(AWS S3 bucket, Packer project layout), "
        "(3) the Ruby source code for the VT application and all Jinja2 config templates."
    ),

    "aws_exposure": (
        "ami.pkr.hcl exposes: aws_bucket = 'kenna-operation-services-images-import' (Cisco/Kenna's "
        "internal S3 bucket for VM image imports). The bucket name is sufficient for targeted "
        "S3 enumeration if the bucket has misconfigured ACLs."
    ),
}

# ─────────────────────────────────────────────────────────
# CVMVT-F2: SSH_USE_STRONG_RNG=0 — SSH daemon strong RNG explicitly disabled
# ─────────────────────────────────────────────────────────
CVMVT_F2 = {
    "id":       "CVMVT-F2",
    "title":    "CVM VT sshd_sysconfig sets SSH_USE_STRONG_RNG=0 — SSH daemon strong RNG disabled "
                "to suppress a Nessus scanner false positive",
    "status":   "CONFIRMED — templates/sshd_sysconfig.j2 in Packer artifacts",
    "severity": "LOW",

    "config_line": "SSH_USE_STRONG_RNG=0",

    "context": (
        "The sshd_sysconfig.j2 template comment: 'This will fix nessus cbc ciphers coming up in "
        "any vuln scans'. The operator disabled strong RNG for SSH (SSH_USE_STRONG_RNG=0) to "
        "suppress a Nessus scanner finding rather than addressing the underlying cipher configuration. "
        "On RHEL/Rocky, SSH_USE_STRONG_RNG controls whether sshd uses a hardware RNG (FIPS) or the "
        "kernel's PRNG for session key generation. Setting to 0 uses the kernel PRNG."
    ),

    "impact": (
        "SSH session keys are generated using the kernel PRNG rather than a hardware/FIPS RNG. "
        "On systems with low entropy (e.g., freshly booted VMs with no user interaction), "
        "this marginally reduces forward secrecy strength. The risk is LOW in modern kernel versions "
        "where /dev/urandom is cryptographically strong. The decision to set this for scanner "
        "suppression rather than actually fixing the cipher config is a process failure."
    ),
}

# ─────────────────────────────────────────────────────────
# CVMVT-F3: amazon-ssm-agent present — AWS SSM remote management access for Cisco's AWS account
# ─────────────────────────────────────────────────────────
CVMVT_F3 = {
    "id":       "CVMVT-F3",
    "title":    "amazon-ssm-agent present and enabled on deployed CVM VT instances — "
                "Cisco's AWS account can access any VT instance via SSM without SSH",
    "status":   "CONFIRMED — /etc/systemd/system/amazon-ssm-agent.service in disk-1.vmdk",
    "severity": "MEDIUM",

    "service_unit": "/etc/systemd/system/amazon-ssm-agent.service (WantedBy=multi-user.target)",

    "analysis": (
        "The AWS Systems Manager (SSM) agent is installed and enabled at boot. "
        "On an EC2 instance, SSM allows the AWS account with IAM permissions to execute commands "
        "via Session Manager without any network access or SSH key. "
        "The OVF descriptor says this was 'Generated by EC2 VM Export' — the VM was running in "
        "Cisco's AWS account before being exported as OVA. "
        "If a customer deploys this OVA in their OWN vSphere/KVM environment rather than AWS EC2, "
        "the SSM agent would fail to connect (no IMDS), which is harmless. "
        "However, if the customer re-runs this image in AWS EC2 under an IAM role, the SSM agent "
        "is active and Cisco's AWS account (or any IAM principal with ssm:StartSession on the "
        "instance) has unrestricted shell access."
    ),

    "note": (
        "This is an artifact of Cisco's EC2-based build pipeline — the OVA was exported directly "
        "from an EC2 instance with SSM installed. The SSM agent should have been removed or "
        "disabled in the cleanup phase for customer-facing OVA distribution."
    ),
}

VT_APPLICATION_NOTES = {
    "ruby_script":     "/usr/local/bin/kenna_virtual_tunnel.rb (KennaVirtualTunnel class)",
    "api_key_file":    "/etc/kenna_api.key (empty in base image — populated at deployment)",
    "api_host_file":   "/etc/kenna_api_host (empty in base image — populated at deployment)",
    "proxy_creds":     "/etc/kenna_proxy.creds (optional, empty in base image)",
    "api_header":      "X-Risk-Token: <api_key>  (sent in HTTPS requests to CVM SaaS)",
    "tunnel_endpoint": "https://<api_host>/tunnel.json",
    "openssh":         "Custom-built OpenSSH 9.9p1 (from cdn.openbsd.org, SHA256-verified at build time)",
}

FINDINGS = [CVMVT_F1, CVMVT_F2, CVMVT_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
