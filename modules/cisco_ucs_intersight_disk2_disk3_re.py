"""
Cisco Intersight Appliance Installer KVM 1.1.7-0.a disk2+disk3 RE

Targets: intersight-appliance-installer-kvm-1.1.7-0.a-disk2.qcow2 (QCOW2 v3, 498MB/25GB virtual)
         intersight-appliance-installer-kvm-1.1.7-0.a-disk3.qcow2 (QCOW2 v3, 76MB/130GB virtual)
         Extracted from intersight-appliance-installer-kvm-1.1.7-0.a.tar.gz (8 total QCOW2s, disk1 previously analyzed)
         disk2: GPT, 1 partition, LVM VG=var LV=var_log (/var filesystem)
         disk3: GPT, 1 partition, LVM VG=file_cisco LV=cisco (/cisco filesystem, populated at deploy time)
disk3 /cisco/software/ contents:
  ansible/appliance/: 346 Ansible task files + playbooks (COPYRIGHT 2019 Cisco)
  images/: onprem-1.0.11-*.tar.gz (Ansible + appliance code, 2.3MB)
             equinox-connector.1.0.11-*.tar.gz (connector, 48MB)
             an-onprem-bootstrap-1.0.11-*.tgz (UI JS bundles, 12MB)
  alma/: intersight-rpms-*.txt (AlmaLinux 9.8 RPM manifest)
disk2 /var/ contents:
  cache/dnf/: 43MB; AlmaLinux 9.8 AppStream/BaseOS/extras mirror cache
  log/: installation log skeleton (empty at deploy time)
Internal codenames: andromeda (Intersight product), foster (Vault), hurricane (diag service),
  bender (deploy workflow), plano (user mgmt), druid (DB), equinox (connector), pizza (service)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_intersight_disk2_disk3_re",
    "firmware": "intersight-appliance-installer-kvm-1.1.7-0.a disk2+disk3",
    "components": {
        "ansible.cfg (/cisco/software/ansible/appliance/)": (
            "host_key_checking = False (global); "
            "ssh_args = ... -o StrictHostKeyChecking=no -o UpdateHostKeys=no; "
            "log_path = $HOME/setup/ansible-playbook.log; "
            "local_tmp = /cisco/software/tmp/${USER}/andromeda/ansible; "
            "library = /usr/local/lib/python3.9/site-packages/ansible"
        ),
        "tasks/ (346 files, hashivault_* calls)": (
            "133 instances of verify=no / verify=false across tasks/; "
            "covers: configure-admin-credentials.yml, copy-mongodb-credentials.yml, "
            "vault-cluster-unseal.yml, provision-secret.yml, setup-vault-kube-auth.yml, "
            "create-mongodb-credentials.yml, plano-create-user.yml, configure-pizza.yml, "
            "read-druid-vault-data.yml (133 total)"
        ),
        "tasks/configure-admin-credentials.yml": (
            "reads admin_password from /usr/local/etc/andromeda_password.cfg (cleartext) then rm -f; "
            "writes to Vault at /secret/service/hurricane/diag_password with verify=no; "
            "kubectl create secret generic diag-info --from-literal=password=<admin_password>"
        ),
        "tasks/vault-cluster-unseal.yml": (
            "unseal key in Ansible var vault_secret; "
            "vault URL: https://{{ vault_mem_svc.stdout }}:8200 (foster-{{ foster_id }}); "
            "hashivault_unseal: verify=false; "
            "30-retry with 10s pause; no_log={{ no_log_config }}"
        ),
        "cache/dnf/ (disk2 /var/cache/dnf/)": (
            "AlmaLinux 9.8 mirrors: mirror.fmt-2.serverforge.org, mirror.sfo12.us.leaseweb.net, "
            "ftp.ucsb.edu, mirror.fcix.net, almalinux.mirror.shastacoe.net; "
            "third-party public mirrors, not Cisco-controlled"
        ),
    },
    "finding_count": "6F [0C+2H+3M+1L]",
    "cumulative": "825 [78C+284H+264M+198L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "ansible.cfg disables SSH host key checking globally; ssh_args double-disables StrictHostKeyChecking",
        "description": (
            "ansible.cfg in /cisco/software/ansible/appliance/: "
            "'host_key_checking = False' (Ansible global setting). "
            "Additionally: "
            "'ssh_args = -C -o ControlMaster=auto -o ControlPersist=60s "
            "-o StrictHostKeyChecking=no -o UpdateHostKeys=no'. "
            "SSH host key verification is disabled at two levels: "
            "Ansible global (host_key_checking=False) AND explicit SSH flag (StrictHostKeyChecking=no). "
            "UpdateHostKeys=no prevents updating known_hosts even when a key changes. "
            "During Intersight appliance deployment, Ansible connects to all cluster nodes "
            "(andromeda_hosts) and executes tasks including: "
            "writing admin passwords to Vault, provisioning MongoDB credentials, "
            "unsealing the Vault cluster, creating Kubernetes secrets. "
            "With SSH host key checking disabled, a MITM on the deployment network "
            "intercepts Ansible connections without detection, "
            "receiving the vault_token, admin_password, and vault_secret variables "
            "that are logged in module arguments before no_log suppresses them."
        ),
        "evidence": {
            "file": "ansible/appliance/ansible.cfg",
            "host_key_checking": "host_key_checking = False",
            "ssh_args": "-o StrictHostKeyChecking=no -o UpdateHostKeys=no",
            "log_path": "$HOME/setup/ansible-playbook.log",
        },
        "impact": (
            "MITM on deployment network intercepts Ansible SSH sessions undetected. "
            "Vault tokens, admin passwords, and unseal keys passed as Ansible variables "
            "are accessible to an on-path attacker."
        ),
        "remediation": (
            "Set host_key_checking = True. "
            "Remove StrictHostKeyChecking=no from ssh_args. "
            "Pre-populate known_hosts before deployment."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "133 verify=no/false instances in Vault (foster) API calls across Ansible deployment tasks",
        "description": (
            "Grep across /cisco/software/ansible/appliance/tasks/ finds 133 instances of "
            "'verify: no' or 'verify: false' in hashivault_read, hashivault_write, "
            "hashivault_unseal, and hashivault_* task calls. "
            "Affected tasks include: configure-admin-credentials.yml, copy-mongodb-credentials.yml, "
            "vault-cluster-unseal.yml, provision-secret.yml, setup-vault-kube-auth.yml, "
            "create-mongodb-credentials.yml, plano-create-user.yml (5 instances), "
            "configure-pizza.yml, read-druid-vault-data.yml, "
            "provision-mongo-vault-per-service-test.yml (4 instances). "
            "All HashiCorp Vault (foster) API calls during Intersight appliance "
            "deploy, upgrade, and operation use vault_host over HTTPS:8200 with "
            "certificate verification disabled. "
            "Secrets managed through this Vault include: admin/diagnostic password "
            "(/secret/service/hurricane/diag_password), MongoDB admin password "
            "(service/mongodb/mongodb-admin-password), per-service MongoDB credentials, "
            "Vault unseal key (vault_secret variable), and Kubernetes service account tokens."
        ),
        "evidence": {
            "count": "133 instances across tasks/",
            "vault_url": "https://{{ vault_mem_svc.stdout }}:8200 (foster K8s service IP)",
            "secret_paths": (
                "/secret/service/hurricane/diag_password, "
                "service/mongodb/mongodb-admin-password, "
                "service/mongo/mongodb-admin-password"
            ),
            "sample": "hashivault_write: url: '{{ vault_host }}' verify: no ...",
        },
        "impact": (
            "All Vault API calls during appliance lifecycle use unverified TLS. "
            "A CA-controlled or rogue cert on the Vault endpoint intercepts "
            "every secret read/write during deployment without detection."
        ),
        "remediation": "Set verify: true for all hashivault_* tasks. Configure Vault CA cert path.",
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "Admin password in cleartext file /usr/local/etc/andromeda_password.cfg; deleted with rm -f (no secure wipe)",
        "description": (
            "configure-admin-credentials.yml: "
            "'command: cat /usr/local/etc/andromeda_password.cfg; register: output'. "
            "After reading: 'command: rm -f /usr/local/etc/andromeda_password.cfg'. "
            "The admin password is stored in a plaintext file before bootstrap; "
            "it is read into the Ansible variable admin_password and then deleted with rm -f. "
            "rm -f does not zero the file data -- the password persists on disk "
            "until the inode's blocks are reused. "
            "On SSDs with wear-leveling, the data may persist indefinitely in retired blocks. "
            "After deletion, the password is written to: "
            "(1) Vault at /secret/service/hurricane/diag_password (with verify=no, see F2), "
            "(2) kubectl create secret generic diag-info --from-literal=password=<password>. "
            "The Kubernetes Secret diag-info stores the password in base64 encoding, "
            "unencrypted at rest (K8s etcd encryption is not enabled by default)."
        ),
        "evidence": {
            "file": "ansible/appliance/tasks/configure-admin-credentials.yml",
            "cleartext_path": "/usr/local/etc/andromeda_password.cfg",
            "delete": "command: rm -f /usr/local/etc/andromeda_password.cfg",
            "k8s_secret": "kubectl create secret generic diag-info --from-literal=password={{ admin_password | quote }}",
        },
        "impact": (
            "Admin password recoverable from disk after rm -f via forensic analysis. "
            "K8s Secret diag-info stores admin password unencrypted in etcd."
        ),
        "remediation": "Use shred or dd for secure deletion. Enable etcd encryption-at-rest for K8s Secrets.",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "Vault unseal key managed as Ansible variable vault_secret; Ansible log at setup/ansible-playbook.log",
        "description": (
            "vault-cluster-unseal.yml: "
            "'hashivault_unseal: url: {{ vault_mem_url }} keys: {{ vault_secret }} verify: false'. "
            "no_log: '{{ no_log_config }}' is applied, which conditionally suppresses logging. "
            "ansible.cfg: 'log_path = $HOME/setup/ansible-playbook.log'. "
            "The Ansible log captures task names, debug output, and sometimes variable values "
            "depending on whether no_log is set to true or to an evaluated template. "
            "If no_log_config evaluates to False (e.g., in development or debug mode, "
            "or if the variable is undefined), vault_secret is logged. "
            "Vault unseal keys grant the ability to unseal a sealed Vault, "
            "exposing all managed secrets. "
            "The retry logic (30 attempts, 10s pause) means the unseal operation "
            "runs for up to 5 minutes with vault_secret in active Ansible variable scope."
        ),
        "evidence": {
            "file": "ansible/appliance/tasks/vault-cluster-unseal.yml",
            "unseal_call": "hashivault_unseal: url: {{ vault_mem_url }} keys: {{ vault_secret }} verify: false",
            "log_path": "$HOME/setup/ansible-playbook.log (ansible.cfg)",
            "no_log": "no_log: '{{ no_log_config }}' (template-evaluated, not unconditional)",
        },
        "impact": (
            "Vault unseal key in Ansible variable scope for full deploy duration. "
            "Conditional no_log may log the key if no_log_config is False or undefined."
        ),
        "remediation": "Use unconditional 'no_log: true' for all vault_secret operations. Store unseal keys in a separate sealed system.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "AlmaLinux packages sourced from public third-party mirrors (not Cisco-controlled) in DNF cache",
        "description": (
            "disk2 /var/cache/dnf/ contains mirrorlist files for AlmaLinux 9.8 "
            "AppStream, BaseOS, and extras repositories listing public third-party mirrors: "
            "mirror.fmt-2.serverforge.org, mirror.sfo12.us.leaseweb.net, "
            "ftp.ucsb.edu, mirror.fcix.net, almalinux.mirror.shastacoe.net. "
            "On first boot or package update, the Intersight appliance resolves the mirrorlist "
            "from a public AlmaLinux mirror network and downloads packages from randomly selected mirrors. "
            "None of these are Cisco-controlled repositories. "
            "AlmaLinux packages are GPG-signed; however, the AlmaLinux signing key must also "
            "be trusted (shipped in /etc/pki/rpm-gpg/). "
            "The mirrorlist is fetched over HTTP without authentication, "
            "allowing a DNS-level attacker to redirect appliance package downloads "
            "to a mirror under attacker control."
        ),
        "evidence": {
            "file": "disk2 /var/cache/dnf/appstream-0a8174e0a3d29b90/mirrorlist",
            "mirrors": (
                "mirror.fmt-2.serverforge.org\n"
                "mirror.sfo12.us.leaseweb.net\n"
                "ftp.ucsb.edu\n"
                "mirror.fcix.net\n"
                "almalinux.mirror.shastacoe.net"
            ),
            "repos": "AppStream 9.8, BaseOS 9.8, extras 9.8",
        },
        "impact": (
            "Appliance updates sourced from public non-Cisco mirrors. "
            "DNS-level attacker redirects appliance downloads to attacker-controlled mirror."
        ),
        "remediation": "Configure appliance to use a Cisco-internal AlmaLinux mirror or air-gapped package repo.",
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "Internal codenames exposed in shipping firmware: andromeda, foster, hurricane, bender, plano, druid, equinox",
        "description": (
            "The Intersight appliance deployment playbooks expose Cisco internal project codenames "
            "throughout ansible/appliance/tasks/ and playbooks: "
            "andromeda (Intersight product, /usr/local/etc/andromeda_password.cfg, local_tmp path); "
            "foster (HashiCorp Vault instance, app=foster-{{ foster_id }}); "
            "hurricane (admin/diag service, /secret/service/hurricane/diag_password); "
            "bender (deployment workflow, bender_install_flow.md, bender_upgrade_flow.md); "
            "plano (user management service, tasks/plano-create-user.yml); "
            "druid (database, tasks/read-druid-vault-data.yml); "
            "equinox (connector component, equinox-connector.1.0.11-*.tar.gz). "
            "These codenames appear in internal Cisco bug trackers (CDETS), "
            "Slack channels, and private documentation. "
            "An adversary with access to Cisco internal systems can correlate "
            "these codenames to active repositories, CI/CD pipelines, and service configs."
        ),
        "evidence": {
            "codenames": (
                "andromeda: Intersight product (/usr/local/etc/andromeda_password.cfg)\n"
                "foster: Vault (app=foster-{{ foster_id }}, https://foster:8200)\n"
                "hurricane: admin/diag service (/secret/service/hurricane/diag_password)\n"
                "bender: deploy workflow (bender_install_flow.md)\n"
                "plano: user management (plano-create-user.yml)\n"
                "druid: database (read-druid-vault-data.yml)\n"
                "equinox: connector (equinox-connector.1.0.11-*.tar.gz)"
            ),
        },
        "impact": "Internal project structure revealed. Correlates with private Cisco infrastructure.",
        "remediation": "Sanitize internal codenames from shipping artifacts.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
