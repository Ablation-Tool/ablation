"""
Cisco UCSM 6.0(2b) Container Runtime RE Module
Source: ucs-manager-k9.6.0.2b.bin (inside ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Component: ucs_manager_plugin.bin (SN-wrapped, 1GB) inner tar layer 3
Files analyzed:
  ./opt/start-ucsm-container.sh (14408 bytes)
  ./opt/ucssh.py (16892 bytes)
  ./opt/vsh_perm.ucs (1492 bytes)
  ./etc/sudoers_newcmnds (10077 bytes)
  ./etc/sudoers.defaults (419 bytes)
  ./etc/xinetd.d/rsync (227 bytes)
  ./etc/xinetd.d/policyService (365 bytes)

8 findings: 0C/4H/3M/1L
Cumulative: 638 [55C+206H+197M+180L]
"""

# ============================================================
# UCSM CONTAINER ARCHITECTURE
# ============================================================

CONTAINER_ARCHITECTURE = {
    "container_type": "LXC via libvirt (virsh -c lxc:///)",
    "container_name": "vdc_1_UCSM",
    "rootfs_source": "/bootflash/ucsm-container/rootfs.tgz",
    "rootfs_mount": "/isan/vs/UCSM/rootfs",
    "container_ssh_port": 30000,
    "container_ssh_user": "samcontainer",
    "host_to_container_ssh_key": "/opt/internal_id_rsa",
    "bind_mounts": {
        "/bootflash": "${ROOTFS_DIR}/bootflash",
        "/workspace": "${ROOTFS_DIR}/workspace",
        "/opt": "${ROOTFS_DIR}/opt",
        "/spare": "${ROOTFS_DIR}/spare",
        "/etc": "${ROOTFS_DIR}/nxos/etc",
        "/mnt/pss/ssh": "${ROOTFS_DIR}/mnt/pss/ssh",
        "/var/home": "${ROOTFS_DIR}/var/home",
        "/isan/etc/licenses": "${ROOTFS_DIR}/ucs/isan/etc/licenses",
        "/var/run/netns": "${ROOTFS_DIR}/var/run/netns",
    },
    "container_auth_symlinks": {
        "${ROOTFS_DIR}/etc/passwd": "/nxos/etc/passwd",
        "${ROOTFS_DIR}/etc/group": "/nxos/etc/group",
        "${ROOTFS_DIR}/etc/shadow": "/nxos/etc/shadow",
    },
    "user_shell": "/isan/bin/vsh_perm",
    "user_shell_source": "/bootflash/ucsm-container/vsh_perm.ucs",
    "user_shell_description": (
        "All UCSM admin logins: ssh -> vsh_perm -> "
        "sudo ssh -i /opt/internal_id_rsa -p 30000 samcontainer@127.0.0.1 "
        "-> sudo LD_LIBRARY_PATH=... /isan/bin/ucssh -p $USER"
    ),
}

INTERNAL_KEY_GENERATION = {
    "condition": "if [ ! -f /opt/internal_id_rsa ]",
    "command": "ssh-keygen -f /opt/internal_id_rsa -t rsa -N '' -q",
    "passphrase": "empty (no passphrase)",
    "post_generation": "chmod 600 /opt/internal_id_rsa",
    "authorized_keys_target": "/var/home/samcontainer/.ssh/authorized_keys",
    "authorized_keys_population": "cat /opt/internal_id_rsa.pub >> authorized_keys",
    "persistence": "Key generated once; survives all reboots (file presence check, not regeneration)",
}

SUDOERS_NOTABLE_COMMANDS = {
    "arbitrary_file_write": "/usr/bin/sed -i *",
    "sam_config_read": "/bin/cat /opt/db/sam.config",
    "shadow_chmod": "/bin/chmod 640 /etc/shadow",
    "internal_ssh": (
        "/usr/bin/ssh -i /opt/internal_id_rsa -p 30000 "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-q -t samcontainer*"
    ),
    "find_wildcard": "/usr/bin/find",
    "sam_config_remove": "/bin/rm -rf /opt/db/sam.config.b",
    "kill_sigusr1": "/bin/kill -s SIGUSR1 *",
    "kill_sigusr2": "/bin/kill -s SIGUSR2 *",
}

XINETD_SERVICES = {
    "rsync": {
        "socket_type": "stream",
        "protocol": "tcp",
        "user": "root",
        "server": "/isan/bin/rsync",
        "server_args": "--config /isan/etc/rsyncd.conf --daemon",
        "disable": "no",
        "wait": "no",
    },
    "policyService": {
        "socket_type": "stream",
        "protocol": "tcp",
        "port": 843,
        "user": "root",
        "server": "/isan/bin/sam_policy_server",
        "server_args": (
            "-r /isan/etc/flashp_policy_request.xml "
            "-f /isan/etc/flashp_policy_response.xml"
        ),
        "disable": "no",
        "cps": "25 30",
        "per_source": 2,
    },
}

SSH_CONFIG = {
    "host_root_ssh_config_switch_net": {
        "Host": "127.12.0.*",
        "UserKnownHostsFile": "/dev/null",
        "StrictHostKeyChecking": "no",
        "note": "127.12.0.1=FI-A, 127.12.0.2=FI-B management plane loopback",
    },
    "container_root_ssh_config": {
        "Host": "127.0.0.1",
        "KexAlgorithms": "ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-group16-sha512",
        "StrictHostKeyChecking": "no",
        "UserKnownHostsFile": "/dev/null",
    },
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "UCSM-CTR-F1",
        "severity": "HIGH",
        "title": "SUDOERS_SED_WILDCARD_ALLOWS_ARBITRARY_FILE_OVERWRITE",
        "detail": (
            "sudoers_newcmnds grants sudo access to '/usr/bin/sed -i *' with a wildcard "
            "that matches any arguments including any file path. "
            "Any process executing in the UCSM container context with sudo access can use "
            "'sudo sed -i' to modify any file on the system: "
            "sam.config (set securityDisabled=yes to disable all iptables), "
            "/etc/shadow (modify admin password hash), "
            "/isan/etc/rsyncd.conf (expose arbitrary paths via rsync), "
            "/opt/internal_id_rsa.pub (replace authorized key), "
            "or any other file. "
            "The sudoers file is appended from '/ucs/etc/sudoers_newcmnds' at each container start "
            "('cat /ucs/etc/sudoers_newcmnds >> /etc/sudoers') without content validation. "
            "The wildcard '*' in 'sed -i *' is not constrained to a directory prefix, "
            "making this effectively an unrestricted file modification grant. "
            "Source: ./etc/sudoers_newcmnds line: '/usr/bin/sed -i *' in UCSM_CMNDS_C alias."
        ),
    },
    {
        "id": "UCSM-CTR-F2",
        "severity": "HIGH",
        "title": "OPT_BIND_MOUNT_CREATES_BIDIRECTIONAL_CONTAINER_HOST_SHARED_SECRET_STORE",
        "detail": (
            "start-ucsm-container.sh binds /opt bidirectionally into the container: "
            "'mount -o bind /opt ${ROOTFS_DIR}/opt'. "
            "/opt contains: /opt/internal_id_rsa (passwordless SSH key), "
            "/opt/db/sam.config (admin password hash + sharedSecret + securityDisabled flag), "
            "/opt/db/flash/dme.db (sqlite MODB containing all managed object XML). "
            "Any process inside the container with write access to /opt "
            "writes directly to the host NX-OS filesystem /opt. "
            "Container compromise via any UCSM software vulnerability gives full read/write "
            "access to all host secrets in /opt without container escape primitives. "
            "The bind mount is persistent across all container lifecycle operations. "
            "There is no mount isolation layer (overlayfs, copy-on-write) between "
            "container and host for this path."
        ),
    },
    {
        "id": "UCSM-CTR-F3",
        "severity": "HIGH",
        "title": "CONTAINER_AUTH_DATABASE_SYMLINKED_TO_HOST_NXOS_ETC",
        "detail": (
            "start-ucsm-container.sh removes the container's own passwd/group/shadow "
            "and replaces them with symlinks to the host NX-OS /nxos/etc/: "
            "'rm -rf ${ROOTFS_DIR}/etc/passwd ${ROOTFS_DIR}/etc/group ${ROOTFS_DIR}/etc/shadow' "
            "followed by 'ln -sf /nxos/etc/passwd ${ROOTFS_DIR}/etc/passwd', "
            "'ln -sf /nxos/etc/group ${ROOTFS_DIR}/etc/group', "
            "'ln -sf /nxos/etc/shadow ${ROOTFS_DIR}/etc/shadow'. "
            "Container processes with root privileges that modify /etc/shadow "
            "are directly modifying the host NX-OS shadow file. "
            "Any UCSM software bug allowing container root execution results in "
            "host authentication database modification without a host-level vulnerability. "
            "The sam_startup.sh already demonstrates this model: "
            "it reads sam.config and applies the adminPasswd field to /etc/shadow at every boot "
            "(UCSM-SAM-F5). Container root equivalence to host shadow write is by design."
        ),
    },
    {
        "id": "UCSM-CTR-F4",
        "severity": "HIGH",
        "title": "RSYNC_EXPOSED_AS_ROOT_VIA_XINETD_SERVICE_ENABLED_ON_ALL_INTERFACES",
        "detail": (
            "xinetd.d/rsync configures rsync as a persistent TCP service: "
            "user=root, server=/isan/bin/rsync, "
            "server_args='--config /isan/etc/rsyncd.conf --daemon', disable=no. "
            "rsync runs as root with configuration sourced from /isan/etc/rsyncd.conf. "
            "The content of rsyncd.conf is not available in the analyzed layers "
            "(it is in the main UCSM runtime binary beyond the current window), "
            "but rsync as root with an undisclosed daemon config on all TCP interfaces "
            "presents an unauthenticated file read/write surface. "
            "If rsyncd.conf includes any module with 'read only = no' and path=/opt or path=/, "
            "any network peer can read /opt/internal_id_rsa, /opt/db/sam.config, "
            "or write arbitrary files as root. "
            "The service is xinetd-spawned (not standalone daemon), so no persistent "
            "authentication state; each TCP connection receives a fresh rsync daemon as root."
        ),
    },
    {
        "id": "UCSM-CTR-F5",
        "severity": "MEDIUM",
        "title": "USER_SHELL_REPLACED_FROM_BOOTFLASH_AT_EVERY_CONTAINER_START",
        "detail": (
            "start-ucsm-container.sh replaces the UCSM admin shell at every container restart: "
            "'cp /bootflash/ucsm-container/vsh_perm.ucs /isan/bin/vsh_perm'. "
            "The source path /bootflash/ucsm-container/vsh_perm.ucs is in /bootflash, "
            "which is bind-mounted into the container: 'mount -o bind /bootflash ${ROOTFS_DIR}/bootflash'. "
            "Any process with write access to /bootflash (inside or outside the container) "
            "can replace vsh_perm.ucs with an arbitrary shell script. "
            "The replacement takes effect at the next container restart (which occurs on UCSM upgrade, "
            "reboot, or manual restart). "
            "The replaced shell executes under the admin user context for all UCSM SSH logins. "
            "The normal vsh_perm.nxos is backed up first ('cp /isan/bin/vsh_perm /isan/bin/vsh_perm.nxos') "
            "but the replacement is unconditional."
        ),
    },
    {
        "id": "UCSM-CTR-F6",
        "severity": "MEDIUM",
        "title": "HOST_NETWORK_NAMESPACES_BIND_MOUNTED_WITH_EXEC_INTO_CONTAINER",
        "detail": (
            "start-ucsm-container.sh mounts host network namespaces into the container "
            "with exec permission: "
            "'mount --rbind /var/run/netns ${ROOTFS_DIR}/var/run/netns' "
            "followed by 'mount -o exec,remount,bind /var/run/netns ${ROOTFS_DIR}/var/run/netns'. "
            "The --rbind option recursively binds all submounts including the management namespace. "
            "The 'exec' remount explicitly enables executable code in the netns mount. "
            "Container processes with CAP_SYS_ADMIN or equivalent can join any host network "
            "namespace via the mounted /var/run/netns/management (and others). "
            "A commented-out 'make-rslave' directive indicates isolation was considered but not applied: "
            "'#mount --make-rslave /var/run/netns $ROOTFS_DIR/var/run/netns'. "
            "Joining the management namespace from container context enables traffic inspection "
            "on the management plane without host-level vulnerability."
        ),
    },
    {
        "id": "UCSM-CTR-F7",
        "severity": "MEDIUM",
        "title": "USERNAME_INJECTED_INTO_SSH_REMOTE_COMMAND_WITH_ONLY_BACKSLASH_SANITIZATION",
        "detail": (
            "vsh_perm.ucs constructs an SSH remote command using $USER: "
            "\"sudo ssh -i /opt/internal_id_rsa -p 30000 ... samcontainer@127.0.0.1 "
            "sudo 'LD_LIBRARY_PATH=...' /isan/bin/ucssh -p '$USER' '$@'\". "
            "Before injection, only backslashes are escaped: "
            "\"USER=$(echo $USER| sed 's/\\\\/\\\\\\\\/g')\". "
            "No other sanitization is applied to characters including "
            "semicolons, backticks, dollar signs, parentheses, or pipe. "
            "For LDAP/AD-integrated UCS deployments the username comes from the "
            "remote login identity (format: 'ucs-<domain-name>\\<user-name>'). "
            "A crafted LDAP username containing shell metacharacters would be expanded "
            "by the remote container shell when it parses the SSH remote command string. "
            "The ucssh binary at /isan/bin/ucssh runs as the second argument receiver; "
            "command injection before '-p $USER' reaches the remote sudo invocation."
        ),
    },
    {
        "id": "UCSM-CTR-F8",
        "severity": "LOW",
        "title": "SAM_POLICY_SERVER_ON_PORT_843_RUNNING_AS_ROOT_VIA_XINETD",
        "detail": (
            "xinetd.d/policyService configures sam_policy_server on TCP port 843: "
            "user=root, server=/isan/bin/sam_policy_server, disable=no, "
            "server_args='-r /isan/etc/flashp_policy_request.xml "
            "-f /isan/etc/flashp_policy_response.xml', per_source=2, cps=25 30. "
            "Port 843 is the Adobe Flash socket policy server port, "
            "used historically for cross-domain socket policy enforcement. "
            "sam_policy_server runs as root on all interfaces. "
            "The request/response XML files determine what policy is served; "
            "if the response file is writable, an attacker can serve an allow-all "
            "Flash socket policy to any Flash-capable client connecting to the FI. "
            "The per_source=2 limit constrains connection rate but not content. "
            "The binary /isan/bin/sam_policy_server is in the main UCSM runtime "
            "beyond the analyzed window; its memory safety properties are unknown."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_ucsm_container_re",
    "source_binary": "ucs-manager-k9.6.0.2b.bin",
    "extraction_path": (
        "FI-bundle SN(808) -> gzip -> tar -> UCSM SN(748) -> gzip -> inner_tar "
        "-> sam_plugin_main SN(748) at inner_tar[10027520] -> gzip -> inner3 tar"
    ),
    "files_analyzed": [
        "./opt/start-ucsm-container.sh (14408 bytes) - LXC container orchestration",
        "./opt/ucssh.py (16892 bytes) - Python upgrade/migration framework",
        "./opt/vsh_perm.ucs (1492 bytes) - Admin user shell proxy",
        "./etc/sudoers_newcmnds (10077 bytes) - Container sudo grants",
        "./etc/sudoers.defaults (419 bytes) - Sudo env preservation",
        "./etc/xinetd.d/rsync (227 bytes) - rsync service as root",
        "./etc/xinetd.d/policyService (365 bytes) - Flash policy server as root",
    ],
    "key_architecture_facts": {
        "container_type": "LXC via virsh/libvirt (vdc_1_UCSM)",
        "opt_shared": "bidirectional bind mount (host /opt == container /opt)",
        "auth_db_shared": "container etc/{passwd,group,shadow} symlinked to host /nxos/etc/",
        "internal_key_generated": "ssh-keygen -N '' on first boot, persists at /opt/internal_id_rsa",
        "netns_shared": "--rbind with exec remount into container",
        "user_shell_source": "replaced from /bootflash/ucsm-container/vsh_perm.ucs every container start",
        "sudoers_appended": "from /ucs/etc/sudoers_newcmnds at container start without validation",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 4, "MEDIUM": 3, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 206, "MEDIUM": 197, "LOW": 180},
    "cumulative_total": 638,
}
