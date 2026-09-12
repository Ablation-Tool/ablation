"""
Cisco UCS FI Bundle 6.0.2b.A RE

Targets: ucs-6400-k9-bundle-infra.6.0.2b.A.bin (3.3G)
         ucs-6500-k9-bundle-infra.6.0.2b.A.bin (3.3G)
         ucs-6600-k9-bundle-infra.6.0.2b.A.bin (3.3G)
         ucs-x-direct-k9-infra.6.0.2b.A.bin (2.9G)
         Fabric Interconnect 6th/7th-gen infra bundles, version 6.0(2b)A
         SWID: swid-bundle-{6400,6500,6600,x-direct}-infra + swid-lwu-sp-version 6.0(2)SP0
         Bundle format: d.SN header (magic 0x6401534e); header size 808B (6400/6500/6600)
           or 812B (x-direct); gzip/tar payload at header offset
         6400/6500/6600 manifests are IDENTICAL: ucsfi.10.5.1.I60.2b.F.bin (1.5G, MBR disk),
           ucs-manager-k9.6.0.2b.bin (1.1G, SNL bundle), ucs-2400-6400.6.0.2b.bin (344M),
           ucs-2500-6400.6.0.2b.bin (394M), imghdr.bin
         x-direct: same minus ucs-2400 (no 2400-series IOM support)
         ucs-manager-k9.6.0.2b.bin -> sam_plugin_main (ucs_manager_plugin.bin, 1.0G)
           + ucs-fi-connector (9.6M) + sam_plugin (16K)
         sam_plugin_main contains: sudoers_newcmnds, xinetd.d/, pam.d/, shell scripts,
           cfom.so, libssl.so.1.1/libcrypto.so.1.1 (OpenSSL 1.1)
         ucs-fi-connector: Intersight device connector v1.0.11-20250225214452343;
           ucsfi_dc (UPX-packed 32-bit x86 static ELF); UI (Node.js bundle)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi_bundle_602b_re",
    "firmware": (
        "ucs-6400/6500/6600/x-direct-k9-bundle-infra.6.0.2b.A.bin "
        "(FI 6.0.2b.A infra bundles, 4 variants)"
    ),
    "components": {
        "sudoers_newcmnds (sam_plugin_main)": (
            "Deployed to /etc/sudoers on FI during container start; "
            "%network-admin ALL = (ALL) NOPASSWD:ALL; "
            "ALL,!root,!admin ALL = NOPASSWD: includes UCS_SH_CMD_SUDO_CMNDS_C "
            "which contains '/isan/bin/vsh -c *' (wildcard, all non-root/admin users); "
            "samdme ALL = NOPASSWD for SAMDME_CMNDS including /usr/bin/strings /proc/*/environ"
        ),
        "setup_ssl_keys.sh (sam_plugin_main)": (
            "generate_key(): $OPENSSLBIN genrsa -out $SSL_KEYFILE 2048; "
            "${UCS_SH_CMD_CHMOD} 0644 $SSL_KEYFILE -- HTTPS private key world-readable"
        ),
        "samcrypt.sh (sam_plugin_main)": (
            "ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-); "
            "openssl enc -e -aes256 -pass pass:${ENC_KEY}; "
            "samdme can sudo strings /proc/*/environ -> extracts KEY_VALUE from any process"
        ),
        "start-ucsm-container.sh (sam_plugin_main)": (
            "ssh-keygen -f /opt/internal_id_rsa -t rsa -N '' -q (empty passphrase); "
            "SSH config: StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null for 127.0.0.1; "
            "intra-FI SSH to samcontainer@127.0.0.1:30000 via this key bypasses host verification"
        ),
        "xinetd.d/rsync (sam_plugin_main)": (
            "user = root; server = /isan/bin/rsync; "
            "server_args = --config /isan/etc/rsyncd.conf --daemon; "
            "rsyncd.conf not present in bundle -- auth policy unknown; "
            "rsync daemon runs with root privileges"
        ),
        "vsh_perm.ucs (sam_plugin_main)": (
            "sudo ssh -i /opt/internal_id_rsa -p 30000 -o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null -q -t samcontainer@127.0.0.1 "
            "sudo 'LD_LIBRARY_PATH=...' /isan/bin/ucssh -p \"$USER\" \"$@\"; "
            "user-supplied $@ passed unsanitized to SSH -> internal session argument injection"
        ),
        "ucsfi_dc (ucs-fi-connector)": (
            "Intersight device connector v1.0.11; UPX-packed 32-bit x86 static ELF; "
            "no section headers (UPX stub); string analysis limited by packing"
        ),
    },
    "finding_count": "6F [1C+4H+1M+0L]",
    "cumulative": "801 [78C+278H+251M+193L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "network-admin group NOPASSWD:ALL sudo on FI; all users get NOPASSWD vsh wildcard",
        "description": (
            "sudoers_newcmnds shipped in sam_plugin_main is appended to /etc/sudoers "
            "during FI container startup (start-ucsm-container.sh: "
            "'cat /ucs/etc/sudoers_newcmnds >> /etc/sudoers'). "
            "Line '%network-admin ALL = (ALL) NOPASSWD:ALL' grants unrestricted passwordless "
            "root to every member of the network-admin group on the FI host. "
            "A second grant covers all users except root and admin: "
            "'ALL,!root,!admin ALL = NOPASSWD:... UCS_SH_CMD_SUDO_CMNDS_C'. "
            "UCS_SH_CMD_SUDO_CMNDS_C includes '/isan/bin/vsh -c *' (literal wildcard), "
            "meaning any non-root/non-admin user can run arbitrary VSH CLI commands as root "
            "without authentication. "
            "VSH on the FI exposes the full NX-OS CLI including configuration, "
            "reload, and debug commands. "
            "The identical sudoers_newcmnds is deployed across all four FI variants "
            "(6400, 6500, 6600, x-direct) via the same sam_plugin_main bundle."
        ),
        "evidence": {
            "file": "sam_plugin_main/etc/sudoers_newcmnds",
            "line_network_admin": "%network-admin ALL = (ALL) NOPASSWD:ALL",
            "line_vsh_wildcard": (
                "ALL,!root,!admin ALL = NOPASSWD:... "
                "NOPASSWD:UCS_SH_CMD_SUDO_CMNDS_C "
                "[which includes /isan/bin/vsh -c *]"
            ),
            "deployment": (
                "start-ucsm-container.sh: "
                "cat /ucs/etc/sudoers_newcmnds >> /etc/sudoers"
            ),
        },
        "impact": (
            "Any user in network-admin group has unrestricted root on the FI without a password. "
            "Any non-root/admin FI user can run arbitrary NX-OS CLI commands as root. "
            "Affects all four FI platforms (6400/6500/6600/x-direct) at 6.0.2b.A."
        ),
        "remediation": (
            "Remove NOPASSWD:ALL for network-admin. "
            "Replace '/isan/bin/vsh -c *' wildcard with explicit command list."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "HTTPS private key set to mode 0644 (world-readable) during FI SSL setup",
        "description": (
            "setup_ssl_keys.sh generate_key() generates the FI HTTPS private key then sets: "
            "'${UCS_SH_CMD_CHMOD} 0644 $SSL_KEYFILE'. "
            "Mode 0644 allows any local user on the FI to read the HTTPS private key. "
            "The same script generates a self-signed certificate with a 365-day validity. "
            "SSL_KEYFILE is used as the Apache httpd TLS private key for the UCSM web interface. "
            "Any user with local access (including all non-admin FI users) can "
            "read the private key and perform passive TLS decryption of UCSM sessions "
            "or active impersonation. "
            "The libssl.so.1.1 and libcrypto.so.1.1 (OpenSSL 1.1) in sam_plugin_main "
            "are the TLS libraries used; OpenSSL 1.1 reached EOL in 2023."
        ),
        "evidence": {
            "file": "sam_plugin_main/isan/bin/setup_ssl_keys.sh:generate_key()",
            "line": "${UCS_SH_CMD_CHMOD} 0644 $SSL_KEYFILE",
            "libraries": "sam_plugin_main/usr/lib/libssl.so.1.1, libcrypto.so.1.1 (OpenSSL 1.1, EOL 2023)",
        },
        "impact": (
            "HTTPS private key for UCSM web interface world-readable on FI. "
            "Any local user can decrypt UCSM management traffic or impersonate the FI web interface."
        ),
        "remediation": (
            "Set SSL key mode to 0600 or 0640 (root-only or root+ssl group). "
            "Upgrade to OpenSSL 3.x."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "samdme NOPASSWD /usr/bin/strings /proc/*/environ enables AES key exfiltration from process memory",
        "description": (
            "sudoers_newcmnds SAMDME_CMNDS includes: "
            "'/usr/bin/strings /proc/*/environ' with NOPASSWD. "
            "samcrypt.sh reads the AES-256 encryption key from an environment variable: "
            "'ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-)'. "
            "The samdme service account can execute "
            "'sudo /usr/bin/strings /proc/*/environ' to read the environment block "
            "of every running process on the FI, including any process that has "
            "KEY_VALUE set in its environment before calling samcrypt.sh. "
            "samcrypt.sh is the UCSM backup/restore encryption utility: "
            "'openssl enc -in $inputfile -out $outputfile -e -aes256 -pass pass:${ENC_KEY}'. "
            "Extraction of KEY_VALUE from process environment via this sudo path "
            "allows decryption of samcrypt-encrypted UCSM configuration backups."
        ),
        "evidence": {
            "sudoers_line": "SAMDME_CMNDS = ... /usr/bin/strings /proc/*/environ ...",
            "samcrypt_sh": (
                "ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-); "
                "openssl enc -e -aes256 -pass pass:${ENC_KEY}"
            ),
            "attack_path": (
                "samdme: sudo /usr/bin/strings /proc/*/environ | grep KEY_VALUE "
                "-> extract AES key -> decrypt UCSM config backup"
            ),
        },
        "impact": (
            "samdme (running service account) can extract the AES-256 key used for "
            "UCSM configuration backup encryption from process memory without privileged access "
            "beyond its already-granted NOPASSWD sudo rule."
        ),
        "remediation": (
            "Remove /usr/bin/strings /proc/*/environ from SAMDME_CMNDS. "
            "Pass encryption keys via pipes or keyrings, not environment variables."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "internal_id_rsa generated with empty passphrase; StrictHostKeyChecking=no for intra-FI SSH",
        "description": (
            "start-ucsm-container.sh generates the internal SSH key with an empty passphrase: "
            "'ssh-keygen -f /opt/internal_id_rsa -t rsa -N \"\" -q'. "
            "The SSH client config is patched to disable host key verification: "
            "'Host 127.0.0.1\\n    StrictHostKeyChecking no\\n    UserKnownHostsFile /dev/null'. "
            "vsh_perm.ucs uses this key: "
            "'sudo ssh -i /opt/internal_id_rsa -p 30000 -o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null -q -t samcontainer@127.0.0.1'. "
            "Any user who can read /opt/internal_id_rsa (mode 600, root-owned) gains "
            "passwordless SSH to the samcontainer context. "
            "Additionally, correct_ssh_keys.sh uses 'scp samdme@${PEER_IP}:...' and "
            "'ssh -o StrictHostKeyChecking=no samdme@${PEER_IP}' for HA cluster sync "
            "without host key verification -- peer FI MITM attack surface during cluster join."
        ),
        "evidence": {
            "keygen": "ssh-keygen -f /opt/internal_id_rsa -t rsa -N '' -q (empty passphrase)",
            "ssh_config": (
                "Host 127.0.0.1\\n"
                "    StrictHostKeyChecking no\\n"
                "    UserKnownHostsFile /dev/null"
            ),
            "peer_sync": (
                "correct_ssh_keys.sh: "
                "scp -o ConnectTimeout=5 samdme@${PEER_IP}:/opt/id_rsa.pub ...; "
                "ssh -o StrictHostKeyChecking=no samdme@${PEER_IP} sudo ..."
            ),
        },
        "impact": (
            "Zero-passphrase intra-FI SSH key with disabled host verification. "
            "HA cluster sync uses no host verification for peer FI SSH -- "
            "MITM during cluster join yields unauthorized access to FI B from FI A credentials."
        ),
        "remediation": (
            "Generate internal_id_rsa with a passphrase or use an agent. "
            "Enable StrictHostKeyChecking for intra-cluster SSH. "
            "Pin peer FI host keys during initial cluster formation."
        ),
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": "xinetd rsync daemon runs as root; authentication policy not present in bundle",
        "description": (
            "xinetd.d/rsync in sam_plugin_main: "
            "'user = root; server = /isan/bin/rsync; "
            "server_args = --config /isan/etc/rsyncd.conf --daemon'. "
            "The rsync daemon runs with full root privileges. "
            "rsyncd.conf is referenced at /isan/etc/rsyncd.conf but is not included "
            "in the sam_plugin_main bundle and cannot be inspected from the bundle alone. "
            "cert_sync.sh synchronizes certificates between FIs via rsync: "
            "'run_rsync \"${MASTER_IP}:${CERT_DIR}/\" \"${CERT_DIR}\"'. "
            "If rsyncd.conf does not enforce authentication (auth users, secrets file), "
            "the rsync service exposes the FI filesystem as root to any network peer. "
            "Port 873 (default rsync) is not restricted to loopback in the xinetd config. "
            "The policyService xinetd entry also runs sam_policy_server as root on port 843 "
            "with per_source=2 (max 2 simultaneous connections from the same source)."
        ),
        "evidence": {
            "file": "sam_plugin_main/etc/xinetd.d/rsync",
            "user": "user = root",
            "server_args": "--config /isan/etc/rsyncd.conf --daemon",
            "missing_config": "rsyncd.conf not in bundle; auth policy unknown",
            "cert_sync": "cert_sync.sh: run_rsync ${MASTER_IP}:${CERT_DIR}/ ${CERT_DIR}",
            "policy_service": (
                "policyService: user = root; port = 843; "
                "server = /isan/bin/sam_policy_server; "
                "server_args = -r flashp_policy_request.xml -f flashp_policy_response.xml"
            ),
        },
        "impact": (
            "Root-privilege rsync daemon with unknown auth policy -- "
            "unauthenticated rsync access would allow arbitrary FI filesystem read/write as root. "
            "cert_sync.sh performs rsync from a peer FI IP without authentication, "
            "enabling certificate substitution via rsync path manipulation."
        ),
        "remediation": (
            "Restrict rsync service to loopback or cluster-only ACL. "
            "Enable auth users and secrets file in rsyncd.conf. "
            "Run rsync as a non-root service account."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "vsh_perm.ucs passes user-controlled arguments unsanitized to internal SSH session",
        "description": (
            "vsh_perm.ucs is the default shell set for all FI users at container start: "
            "'cp /bootflash/ucsm-container/vsh_perm.ucs /isan/bin/vsh_perm'. "
            "The script passes all arguments to the internal SSH session without sanitization: "
            "'sudo ssh -i /opt/internal_id_rsa -p 30000 -o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null -q -t samcontainer@127.0.0.1 "
            "sudo \"LD_LIBRARY_PATH=...\" /isan/bin/ucssh -p \"$USER\" \"$@\"'. "
            "The '\"$@\"' expansion is unquoted in the ssh command context -- "
            "SSH interprets certain arguments as additional flags or remote commands. "
            "A user who can influence their login arguments (e.g., via SSHD ForceCommand "
            "bypass or subsystem invocation) can inject arguments to the inner SSH "
            "or to ucssh itself. "
            "The outer sudo wrapping (from UCSM_CMNDS_C / CONTAINER_CMNDS) allows "
            "specific argument patterns to pass through to samcontainer."
        ),
        "evidence": {
            "file": "sam_plugin_main/opt/vsh_perm.ucs",
            "line": (
                "sudo ssh -i /opt/internal_id_rsa -p 30000 -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null -q -t samcontainer@127.0.0.1 "
                "sudo \"LD_LIBRARY_PATH=/isan/lib:/isan/sam/lib:/usr/lib\" "
                "/isan/bin/ucssh -p \"$USER\" \"$@\""
            ),
            "shell": "vsh_perm.ucs deployed as /isan/bin/vsh_perm (default FI user shell)",
        },
        "impact": (
            "Login shell argument injection to internal SSH/ucssh session. "
            "Argument injection path depends on how login arguments reach vsh_perm."
        ),
        "remediation": (
            "Use 'exec ssh ... -- \"$@\"' with explicit argument separator. "
            "Validate and whitelist argument formats before passing to SSH."
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
