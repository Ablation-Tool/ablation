"""
Cisco UCS FI NX-OS Inter-FI SSH Peer Connectivity RE

Target:  ucsfi.10.5.1.I60.2b.F.bin (1.5GB MBR disk image, FI 6.0.2b.A bundles)
         Same NX-OS image; this module covers the inter-FI SSH peer trust infrastructure:
         upgrade coordination, CLI peer exec, HA cluster host key sync, passwordless admin
         All FI HA pairs (6400/6500/6600/x-direct) use this same SSH trust model
Key files: spm/isan/bin/sam_upgrade.sh (firmware upgrade peer SSH coordination)
           spm/isan/bin/cli-peer-exec.sh (CLI command execution on peer FI)
           spm/isan/bin/ssh-peer-exec.sh (SSH command execution on peer FI)
           spm/isan/bin/correct_ssh_keys.sh (post-cluster-sync key correction)
           spm/isan/bin/sam_startup_main.sh (UCSM startup, admin passwordless setup)
           spm/isan/bin/peer_restore.sh (peer config transfer during restore)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi_nxos_ssh_peer_re",
    "firmware": "ucsfi.10.5.1.I60.2b.F.bin (NX-OS FI 6.0.2b.A, all FI 6400/6500/6600/x-direct)",
    "components": {
        "spm/isan/bin/sam_upgrade.sh (4 SSH calls)": (
            "All: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null; "
            "exec_sam_upgrade via SSH (root exec on peer), "
            "set_boot via SSH, "
            "remove activation lock via SSH, "
            "touch activation lock via SSH"
        ),
        "spm/isan/bin/cli-peer-exec.sh": (
            "ssh samdme@$PEER_IP ... $MYARGS "
            "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no; "
            "$MYARGS unquoted: word-split from unquoted args loop; "
            "sed key normalization: s/^\\(samdme;127.*export\\)*/export/ "
            "(attacker-controlled args passed through)"
        ),
        "spm/isan/bin/sam_startup_main.sh (setup_admin_passwordless_login)": (
            "Comment: 'Enabling the admin user to access the root shell by running "
            "run cid from the NXOS shell'; "
            "SYSTEM_PRI_KEY=/opt/internal_id_rsa (pre-generated, no passphrase per "
            "cisco_ucs_fi_bundle_602b_re F4); "
            "copies to ADMIN_PRI_KEY_PATH=/mnt/pss/ssh/admin/internal_id_rsa; "
            "chmod 644 on authorized_keys; chown admin:network-admin on private key; "
            "host key sync: scp ${HOST_SSH}/ssh_host_* samdme@${PEER_IP}:/opt/ "
            "(wildcard matches private keys; no StrictHostKeyChecking on this SCP)"
        ),
        "spm/isan/bin/correct_ssh_keys.sh": (
            "Trigger: samdme key size != 2048-bit; runs post-cluster-sync + 1200s sleep; "
            "scp samdme@${PEER_IP}:/opt/id_rsa.pub /opt/id_rsa.pub.peer.old (no SCH); "
            "cat /opt/id_rsa.pub.peer >> /var/home/samdme/.ssh/authorized_keys; "
            "ssh -o StrictHostKeyChecking=no samdme@${PEER_IP} sudo cp ... authorized_keys"
        ),
        "spm/isan/bin/peer_restore.sh": (
            "restore_check: calls sam_restore_check.sh <peer> <admin_passwd> (F3 of backup module); "
            "restore_config: scp -oPasswordAuthentication=no samdme@$peer:$SAMCONFIG_B "
            "/tmp/sam.config.b (fixed /tmp path); "
            "$SSH -oPasswordAuthentication=no (no explicit StrictHostKeyChecking)"
        ),
    },
    "finding_count": "6F [0C+2H+3M+1L]",
    "cumulative": "867 [81C+298H+283M+204L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null used systemically across ALL inter-FI SSH operations: firmware upgrade, exec, CLI peer exec, and lock management",
        "description": (
            "spm/isan/bin/sam_upgrade.sh contains 4 SSH invocations to PEER_IP, "
            "all using -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null: "
            "(1) exec_sam_upgrade execution on peer (triggers root exec via setuid(0) wrapper); "
            "(2) set_boot execution on peer (firmware boot target change); "
            "(3) activation lock file removal on peer; "
            "(4) activation lock file creation on peer. "
            "spm/isan/bin/cli-peer-exec.sh: two SSH invocations (4GFI and 2GFI paths) both "
            "with -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no. "
            "spm/isan/bin/ssh-peer-exec.sh: "
            "'ssh samdme@$PEER_IP -p 30000 -q -t -o UserKnownHostsFile=/dev/null "
            "-o StrictHostKeyChecking=no'. "
            "spm/isan/bin/correct_ssh_keys.sh: "
            "'ssh -o StrictHostKeyChecking=no samdme@${PEER_IP} sudo /bin/cp ...'. "
            "Combined effect: every inter-FI SSH call trusts any host at PEER_IP without "
            "host key verification. An attacker who controls the L2 segment between the "
            "two FIs can ARP-spoof PEER_IP and intercept all peer management traffic: "
            "firmware upgrades (exec_sam_upgrade as root), CLI exec, and key distribution. "
            "PEER_IP is derived from sam.config or cluster state; "
            "in the 4GFI case it is a fixed loopback-adjacent address (127.12.0.1/127.12.0.2) "
            "accessible only from within the FI container network namespace."
        ),
        "evidence": {
            "file": "spm/isan/bin/sam_upgrade.sh (4 calls), cli-peer-exec.sh (2 calls), ssh-peer-exec.sh (1 call), correct_ssh_keys.sh (1 call)",
            "representative": (
                "sam_upgrade.sh:135: ${SSH} samdme@${PEER_IP} "
                "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                "${UCS_ISAN_CMD_SAM_UPGRADE_HELPER_SH} set_boot ${NEW_IMAGE}\n"
                "cli-peer-exec.sh:44: ssh samdme@$PEER_IP -p 30000 -q -t "
                "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYARGS"
            ),
        },
        "impact": (
            "ARP spoof of PEER_IP intercepts all inter-FI SSH: firmware upgrade execution, "
            "CLI peer exec, and SSH host key distribution. "
            "exec_sam_upgrade path executes as root (setuid(0)) on peer -- "
            "MITM of this call yields RCE as root on the peer FI."
        ),
        "remediation": (
            "Use SSH certificate authority (CA) with machine certificates for FI-to-FI auth. "
            "At minimum, use a pre-seeded known_hosts file with the peer FI's host key "
            "fingerprint rather than UserKnownHostsFile=/dev/null."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "sam_startup_main.sh setup_admin_passwordless_login() explicitly documents creating passwordless admin SSH for root shell access ('run cid'); chmod 644 on admin authorized_keys",
        "description": (
            "spm/isan/bin/sam_startup_main.sh setup_admin_passwordless_login() function: "
            "Comment at lines 552-559: "
            "'During the initial setup, it is necessary to configure passwordless login "
            "for the admin user. This is a temporary workaround to address the following "
            "scenarios: 1. Allowing the peer FI to join the cluster. "
            "2. Enabling the admin user to access the root shell by running run cid from "
            "the NXOS shell.' "
            "Implementation: "
            "SYSTEM_PRI_KEY='/opt/internal_id_rsa' (no-passphrase key, confirmed in "
            "cisco_ucs_fi_bundle_602b_re F4 via binary strings analysis); "
            "ADMIN_PRI_KEY_PATH='/mnt/pss/ssh/admin/internal_id_rsa'; "
            "'if [ ! -f $ADMIN_PRI_KEY_PATH ]; then cp $SYSTEM_PRI_KEY $ADMIN_PRI_KEY_PATH'; "
            "ADMIN_AUTH_KEYS_PATH='/mnt/pss/ssh/admin/authorized_keys'; "
            "'chmod 644 $ADMIN_PUB_KEY_PATH $ADMIN_AUTH_KEYS_PATH' -- "
            "authorized_keys set to world-readable (chmod 644). "
            "The setup creates a passwordless SSH key path that lets any entity "
            "knowing the admin username SSH to the FI without a password or passphrase. "
            "The comment explicitly states this enables 'root shell access via run cid'. "
            "The private key is chowned to admin:network-admin without an explicit chmod, "
            "inheriting whatever permission the cp from /opt/internal_id_rsa established."
        ),
        "evidence": {
            "file": "spm/isan/bin/sam_startup_main.sh lines 552-594",
            "comment": (
                "# Enabling the admin user to access the root shell by running "
                "`run cid` from the NXOS shell."
            ),
            "key_path": "SYSTEM_PRI_KEY=/opt/internal_id_rsa (no passphrase)",
            "chmod": "chmod 644 $ADMIN_AUTH_KEYS_PATH (world-readable authorized_keys)",
        },
        "impact": (
            "Passwordless admin SSH enables any entity with network access to authenticate "
            "as admin without credentials, then escalate to root via 'run cid'. "
            "The comment documents this as intended behavior -- it is not an accident."
        ),
        "remediation": (
            "Gate 'run cid' behind a separate authentication step. "
            "Remove passwordless SSH for admin once cluster setup completes. "
            "Set authorized_keys to mode 600, not 644."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "correct_ssh_keys.sh appends peer-fetched RSA public key to samdme authorized_keys without verifying key authenticity; 1200-second attack window post-cluster-sync",
        "description": (
            "spm/isan/bin/correct_ssh_keys.sh trigger condition: "
            "samdme authorized_keys RSA key size is not 2048-bit "
            "(legacy 1024-bit key present). "
            "When triggered: "
            "'scp -o ConnectTimeout=5 samdme@${PEER_IP}:/opt/id_rsa.pub /opt/id_rsa.pub.peer.old' "
            "-- fetches peer's RSA public key via SCP (no explicit StrictHostKeyChecking). "
            "'cat /opt/id_rsa.pub.peer >> /var/home/samdme/.ssh/authorized_keys' "
            "-- appends fetched key to samdme's authorized_keys unconditionally. "
            "No signature verification, certificate validation, or CA check on the fetched key. "
            "Any key material at /opt/id_rsa.pub on the peer is appended verbatim. "
            "The script sleeps 1200 seconds (20 minutes) after cluster-sync completion "
            "before executing -- a 20-minute window during which an attacker who has "
            "already compromised the peer FI can place a backdoor key at /opt/id_rsa.pub "
            "to be fetched and added to samdme's authorized_keys on this FI. "
            "The subsequent SSH call uses StrictHostKeyChecking=no to confirm the copy "
            "on the peer side, but the damage (backdoor key added to local authorized_keys) "
            "is already done after the SCP step."
        ),
        "evidence": {
            "file": "spm/isan/bin/correct_ssh_keys.sh",
            "fetch": "scp samdme@${PEER_IP}:/opt/id_rsa.pub /opt/id_rsa.pub.peer.old",
            "append": "cat /opt/id_rsa.pub.peer >> /var/home/samdme/.ssh/authorized_keys",
            "window": "sleep 1200 after cluster sync before key correction runs",
        },
        "impact": (
            "Peer FI compromise + 20-minute window = backdoor RSA key added to "
            "samdme authorized_keys on the local FI. "
            "samdme has NOPASSWD:ALL sudo (cisco_ucs_fi_bundle_602b_re F1 = network-admin group)."
        ),
        "remediation": (
            "Verify fetched key against a CA-signed certificate before appending. "
            "Use SSH certificates (ssh-keygen -s) instead of raw authorized_keys management."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "cli-peer-exec.sh passes unquoted $MYARGS to SSH command line; word-splitting enables SSH option injection via attacker-controlled argument",
        "description": (
            "spm/isan/bin/cli-peer-exec.sh constructs the SSH peer exec command: "
            "'ssh samdme@$PEER_IP -p 30000 -q -t "
            "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "
            "-o ConnectTimeout=5 $MYARGS'. "
            "$MYARGS is unquoted -- it undergoes word-splitting and glob expansion by bash. "
            "MYARGS is assembled from the script's positional arguments in a while loop. "
            "Each arg goes through a sed normalization: "
            "'key=$( echo $key | sed -e \"s/^\\(samdme;127.*export\\)*/export/\" )' "
            "and then unconditionally appended to MYARGS. "
            "The sed pattern is a complex regex with optional match (*) -- it does not "
            "reliably strip all control sequences. "
            "If a caller can inject an argument containing '-o ProxyCommand=malicious_cmd', "
            "bash word-splitting passes it as a separate SSH -o option, enabling command "
            "execution on the local host in the context of the SSH client. "
            "The 4GFI path uses port 30000; the fallback path (2GFI/3GFI) uses default port. "
            "Both paths are identical in the unquoted MYARGS pattern."
        ),
        "evidence": {
            "file": "spm/isan/bin/cli-peer-exec.sh lines 44-47",
            "pattern": "ssh samdme@$PEER_IP ... $MYARGS (unquoted; word-split by bash)",
            "injection_vector": "-o ProxyCommand=... passes as SSH option if in attacker-controlled arg",
        },
        "impact": (
            "SSH option injection via ProxyCommand or similar in $MYARGS enables "
            "local command execution as the script's running user if caller can control arguments."
        ),
        "remediation": (
            "Quote $MYARGS: use \"$MYARGS\" and validate args against an allowlist. "
            "Use ssh -- $MYARGS to prevent option injection after the -- separator."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "sam_startup_main.sh syncs SSH host PRIVATE keys to peer FI via SCP with wildcard (ssh_host_*); both FIs share identical SSH private host keys",
        "description": (
            "spm/isan/bin/sam_startup_main.sh FI-A cluster init path: "
            "'scp ${HOST_SSH}/ssh_host_* samdme@${PEER_IP}:/opt/' "
            "where HOST_SSH is the FI SSH host key directory. "
            "The glob ${HOST_SSH}/ssh_host_* matches ALL host key files including: "
            "ssh_host_rsa_key (RSA private key), "
            "ssh_host_rsa_key.pub (RSA public key), "
            "ssh_host_ecdsa_key (ECDSA private), "
            "ssh_host_ed25519_key (Ed25519 private), etc. "
            "ALL private SSH host keys are transmitted to the peer FI and installed at /opt/. "
            "FI-B then moves these to the host SSH directory, making both FIs in the "
            "HA pair use identical SSH host private keys (verified: 'diff $HOST_TMP_SSH/ssh_host_rsa_key "
            "$HOST_SSH/ssh_host_rsa_key' before deciding whether to replace). "
            "Consequences: "
            "(1) Private SSH host key material travels unencrypted over the cluster network "
            "during FI-B initialization (the SCP has no explicit StrictHostKeyChecking setting, "
            "and if this is the first connection, the host key is unknown); "
            "(2) Both FIs share the same SSH fingerprint -- a client that trusted FI-A "
            "will accept FI-B's fingerprint as identical, masking any FI swap; "
            "(3) Compromise of either FI's private key compromises both."
        ),
        "evidence": {
            "file": "spm/isan/bin/sam_startup_main.sh lines 529-530",
            "copy_cmd": "scp ${HOST_SSH}/ssh_host_* samdme@${PEER_IP}:/opt/",
            "wildcard": "ssh_host_* matches all private key files: rsa, ecdsa, ed25519",
            "same_key_check": "diff ${HOST_TMP_SSH}/ssh_host_rsa_key ${HOST_SSH}/ssh_host_rsa_key",
        },
        "impact": (
            "SSH private host key material for both FIs transmitted over cluster network during init. "
            "Both FIs share identical host keys -- compromise of one key compromises both FI identities."
        ),
        "remediation": (
            "Generate independent SSH host keys on each FI. "
            "If shared identity is required by design, derive the shared key from a "
            "hardware-bound secret rather than transmitting private key material over the network."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "peer_restore.sh downloads peer SAM config to fixed /tmp/sam.config.b path; world-readable /tmp with no integrity verification",
        "description": (
            "spm/isan/bin/peer_restore.sh restore_config() function: "
            "'$SCP -oPasswordAuthentication=no $SAMDME@$peer:$SAMCONFIG_B $SAM_CONFIG_B_TMP' "
            "where SAM_CONFIG_B_TMP='/tmp/sam.config.b'. "
            "The downloaded SAM configuration (SAMCONFIG_B) is written to a fixed filename "
            "in /tmp/ -- world-readable and world-writable with sticky bit. "
            "No content integrity check (no hash verification, no signature) is performed "
            "on the downloaded config before 'cat $SAM_CONFIG_B_TMP >> $SAM_CONFIG_TMP'. "
            "The config content is directly appended to the local SAM config without validation. "
            "Fixed filename enables: "
            "(1) Race attack: a local process creates /tmp/sam.config.b before the SCP "
            "and fills it with malicious config content; the SCP will overwrite it "
            "(unless the pre-created file has restrictive permissions), but on failure "
            "the existing malicious content is used; "
            "(2) Symlink attack: /tmp/sam.config.b -> /etc/passwd redirects the SCP "
            "output to a critical system file. "
            "The script also removes SAMCONFIG_B from the peer after download without "
            "error-checking the deletion, allowing a stale config to persist on the peer."
        ),
        "evidence": {
            "file": "spm/isan/bin/peer_restore.sh lines 37-43",
            "download": "$SCP ... $SAMDME@$peer:$SAMCONFIG_B /tmp/sam.config.b",
            "use": "cat /tmp/sam.config.b >> $SAM_CONFIG_TMP (direct append, no integrity check)",
        },
        "impact": (
            "Symlink or race attack on /tmp/sam.config.b redirects peer SAM config content "
            "or injects malicious config into the local UCSM SAM configuration."
        ),
        "remediation": (
            "Use a mkstemp-generated unique filename for the downloaded config. "
            "Verify a hash or signature of the downloaded content before appending."
        ),
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
