"""
Cisco Catalyst 9000 Series IOS-XE 17.18.04 RE module
Target: cat9k_iosxe.17.18.04.SPA.bin (1.2GB)
Platform: Catalyst 9000 (bigbang/nyquist/passport/starfleet/symphony hardware families)
Architecture: x86-64, systemd 255 PID 1, SquashFS + sub-package layered mount

Extraction path:
  Outer .bin: CW_TLV metadata (deadbeef magic) + rpboot ELF (gz at 0x4AC9)
    + DER signature + initramfs CPIO (gz at 0x9DEDCE, 175MB, 2487 files)
    + DER signature + SquashFS (0x3FDF329, 1.18GB xz, 10 inodes at outer level)

  Initramfs CPIO (175MB, extracted /tmp/cat9k-initrd/):
    init -> usr/lib/systemd/systemd (x86-64 ELF, systemd 255)
    common (147KB bash library: code signing, ROMMON, package verification)
    explode-common (63KB bash: filesystem init, mount, FRU startup)
    codesign.pubkey (19200 bytes, custom binary format ae02 25ab 1234 cd01)
    codesign.revkey (300 bytes, custom binary format)
    verify_packages.sh, mount_packages.sh, hugepages.sh

  Outer SquashFS (1.18GB xz, /tmp/cat9k-squashfs/): 8 sub-packages
    cat9k-rpbase.17.18.04.SPA.pkg (1.1GB) - main OS
    cat9k-guestshell.17.18.04.SPA.pkg (1.9MB) - guestshell container
    cat9k-webui.17.18.04.SPA.pkg (20MB) - web management UI
    cat9k-srdriver.17.18.04.SPA.pkg (39MB) - switch/route driver
    cat9k-cc_srdriver.17.18.04.SPA.pkg (25MB) - card complex driver
    cat9k-wlc.17.18.04.SPA.pkg, cat9k-lni.17.18.04.SPA.pkg

  Sub-package format: 20-byte SHA1 + 32-byte header + deadbeef magic
    Inner SquashFS at offset 0x400 (1024 bytes) inside each .pkg
    rpbase inner SquashFS: xz-compressed, 59,004 inodes, 1.02GB on disk

  rpbase inner SquashFS top-level: platform-specific directories
    bigbang/ nyquist/ passport/ starfleet/ symphony/
    Each contains a complete platform filesystem overlay

Platform codenames (bigbang family):
  bigbang, nyquist, passport, starfleet, symphony
  From packages.conf .UnifiedPlatformList field

Build provenance (from packages.conf .pkginfo):
  Build: 17.18.04 (release date 2026-07-18)
  .BuildPath: /nobackup/mcpre/s2c-build-ws/binos/linkfarm/cat9k_universalk9-stage/img/rp_super_universalk9
  .Version: 17.18.04.0.759.1784396682..IOSXE
  .SW_DESCRIPTION: V1718_4_FC1-0-g150b070c01e17 (git short hash: 150b070c01e17)
  User: mcpre
  .PKGUID: feda5b3482420cdd040e3f5b127b49e20d10933e

initramfs /etc/passwd key accounts:
  root:*:0:0:root:/root:/bin/bash
  binos:x:85:85:binos administrative user:/usr/binos/conf:/usr/binos/conf/bshell.sh
  guestshell:!:1000:1000::/home/guestshell: (no shell, no password lock)
  dockeruser:*:1000000:65536:Dockeruser:/:/sbin/nologin
  limiteduser:x:1003:1003:Limiteduser:/:/sbin/nologin

rpbase /etc/group key entries (bigbang platform):
  bprocs:x:85:binos
  docker:x:65535:dockeruser,binos
  network-admin:x:50000:guestshell
  guestshell:x:1000:
"""

FIRMWARE = {
    "target":     "Cisco Catalyst 9000 IOS-XE 17.18.04.SPA",
    "file":       "cat9k_iosxe.17.18.04.SPA.bin",
    "model":      "Catalyst 9000 Series (bigbang/nyquist/passport/starfleet/symphony)",
    "arch":       "x86-64; systemd 255 PID 1; SquashFS + sub-package layered mount",
    "size_bytes": 1249489705,
    "build_date": "2026-07-18",
    "git_hash":   "150b070c01e17",
    "build_path": "/nobackup/mcpre/s2c-build-ws/binos/linkfarm/cat9k_universalk9-stage",
    "build_user": "mcpre",
    "findings":   ["CAT9K-F1", "CAT9K-F2", "CAT9K-F3", "CAT9K-F4", "CAT9K-F5",
                   "CAT9K-F6", "CAT9K-F7", "CAT9K-F8", "CAT9K-F9", "CAT9K-F10",
                   "CAT9K-F11", "CAT9K-F12", "CAT9K-F13"],
}

# CAT9K-F1: Hardcoded OpenResty RSA private key shipped to every device
CAT9K_F1 = {
    "id":       "CAT9K-F1",
    "title":    "Hardcoded RSA-2048 private key (fallback.key) for OpenResty HTTPS "
                "shipped at bigbang/usr/binos/openresty/etc/ssl/cert/fallback.key "
                "with matching certificate at fallback.pem; same key on every IOS-XE "
                "17.18.04 device using the default web UI TLS certificate",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — fallback.key extracted directly from rpbase inner SquashFS "
                "(bigbang/usr/binos/openresty/etc/ssl/cert/fallback.key, 1675 bytes); "
                "BEGIN RSA PRIVATE KEY header confirmed; corresponding fallback.pem (1302 bytes) "
                "confirmed in same directory; key is RSA-2048 modulus verified",
    "cwe":      ["CWE-321 (Use of Hard-coded Cryptographic Key)",
                 "CWE-798 (Use of Hard-coded Credentials)"],
    "files":    ["bigbang/usr/binos/openresty/etc/ssl/cert/fallback.key",
                 "bigbang/usr/binos/openresty/etc/ssl/cert/fallback.pem"],
    "key_format": "PEM RSA PRIVATE KEY (PKCS#1, unencrypted), 2048-bit",
    "key_prefix": "MIIEowIBAAKCAQEAtIMcrNW2PVhaozQsgAEIVjg0U0W0eu3fPKxRFHKjYNJDV0DI",
    "cert_subject": "OpenResty web UI HTTPS fallback certificate",
    "impact": (
        "The same RSA private key is embedded in every Catalyst 9K device running "
        "17.18.04. Any party who extracts this key (from any device or firmware image) "
        "can impersonate the HTTPS web management interface of any Cat9K that uses the "
        "fallback certificate (devices without an administrator-configured custom cert). "
        "Impact: (1) MITM attacks against management sessions: browser users who accept "
        "the default cert can have their credentials intercepted by any network-adjacent "
        "attacker presenting the same hardcoded cert; (2) passive decryption of captured "
        "TLS sessions if ephemeral key exchange is absent (RSA key exchange without PFS); "
        "(3) phishing of device management interfaces at scale."
    ),
    "note": "OpenResty is the nginx-based reverse proxy that fronts the IOS-XE web UI "
            "(WebUI service). The 'fallback' cert is used when no device-specific certificate "
            "has been configured via 'ip http secure-certificate'. Many enterprise deployments "
            "do not replace the default certificate. Platforms affected: all five Cat9K "
            "hardware families (bigbang, nyquist, passport, starfleet, symphony) as the key "
            "is in the bigbang/ platform tree; other platforms likely share the same key "
            "(not independently verified for nyquist/passport/starfleet/symphony).",
}

# CAT9K-F2: Unauthenticated rsync daemon exposes full storage as root
CAT9K_F2 = {
    "id":       "CAT9K-F2",
    "title":    "rsync daemon (xinetd port 873) configured uid=root, gid=root, use chroot=no, "
                "no auth users, no secrets file, no hosts allow — exposes bootflash, harddisk, "
                "flash, /var, license storage, ROMMON upgrade area, and chassis filesystem "
                "for unauthenticated read/write; pre/post exec hooks on chasfs and unifiedfs_rcmd "
                "modules execute scripts on file transfer",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — rsyncd.conf extracted from bigbang/etc/rsyncd.conf; "
                "uid=root gid=root use chroot=no confirmed; no auth users or secrets file "
                "in any module; xinetd.conf confirmed rsync service on port 873 as root; "
                "module inventory: bootflash(rw), flash(rw), flash1(rw), usbflash0(rw), "
                "harddisk(rw), vol(rw), misc(rw), chasfs(rw+exec), global_chasfs(rw), "
                "install_file(rw), unifiedfs_rcmd(rw+exec), rommon_upgrade_ngwc(rw), "
                "license_level(rw), prst_sync(rw), backup_image(rw), patch(rw), var(rw), "
                "disk0(rw), appstore_flash(rw), appstore_hd(rw), cc_chasfs(rw), cfg(rw)",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-732 (Incorrect Permission Assignment for Critical Resource)"],
    "files":    ["bigbang/etc/rsyncd.conf", "bigbang/etc/xinetd.conf"],
    "rsync_config_key_lines": [
        "use chroot = no",
        "uid = root",
        "gid = root",
        "log file = /dev/null",
        "(no auth users, no secrets file, no hosts allow in entire config)",
    ],
    "high_value_modules": [
        "[bootflash] path=/bootflash read_only=false timeout=50",
        "[harddisk] path=/harddisk read_only=false timeout=50",
        "[rommon_upgrade_ngwc] path=/tmp/rommon_upgrade_ngwc read_only=false",
        "[license_level] path=/lic0 read_only=false incoming chmod=Fugo=rw",
        "[chasfs] path=/tmp/rp/chasfs pre/post-xfer exec=chasync_prepost_rsync.sh",
        "[unifiedfs_rcmd] path=/tmp/unifiedfs (remote FS command execution) pre/post-xfer exec",
        "[install_file] path=/tmp/installer read_only=false",
        "[backup_image] path=/backup_image read_only=false timeout=50",
        "[patch] path=/tmp/patch read_only=false",
        "[var] path=/var read_only=false",
    ],
    "exec_hooks": [
        "chasfs: pre-xfer exec=/usr/binos/conf/chasync_prepost_rsync.sh",
        "chasfs_bp: pre-xfer exec=/usr/binos/conf/chasync_prepost_rsync.sh",
        "chasfs_fp: pre-xfer exec=/usr/binos/conf/chasync_prepost_rsync.sh",
        "unifiedfs: pre-xfer exec=/usr/binos/conf/unifiedfs/unifiedfs_helper.sh",
        "unifiedfs_rcmd: pre-xfer exec=/usr/binos/conf/unifiedfs/unifiedfs_remote_fmt.sh",
        "tdlresolve_dst: post-xfer exec=/usr/binos/conf/tdl_cleanup_epochs.sh",
    ],
    "impact": (
        "Any host that can reach port 873 on a Cat9K management interface can read and "
        "write all storage (bootflash/harddisk/ROMMON) without credentials. Attack paths: "
        "(1) direct firmware replacement via [bootflash] or [harddisk]; "
        "(2) ROMMON firmware write via [rommon_upgrade_ngwc] for persistent low-level "
        "compromise; (3) arbitrary root code execution via pre/post exec hooks — writing "
        "a file to [unifiedfs_rcmd] triggers /usr/binos/conf/unifiedfs/unifiedfs_remote_fmt.sh "
        "as root; (4) configuration exfiltration via [cfg] (all config data); "
        "(5) license manipulation via [license_level] and [prst_sync]; "
        "(6) crash image replacement via [backup_image]. The security boundary is entirely "
        "IOS-XE ACL/firewall configuration — the rsync daemon itself provides no protection."
    ),
    "note": "rsync is the primary inter-FRU synchronization mechanism in IOS-XE. "
            "RP-to-CC, RP-to-FP, and RP-to-BP synchronization all use rsync over the internal "
            "fabric network. The design assumes the internal fabric is isolated; the ACL "
            "configuration determines whether external hosts can reach port 873. "
            "Production Cat9K deployments frequently have the management VRF reachable from "
            "enterprise networks, making this a realistic attack surface in misconfigured deployments.",
}

# CAT9K-F3: NFS /tmp exported rw no_root_squash to 10.0.0.0/8
CAT9K_F3 = {
    "id":       "CAT9K-F3",
    "title":    "NFS export /tmp to 10.0.0.0/255.0.0.0 with rw,no_root_squash "
                "(fsid=250) allows any host in the 10.x.x.x range to mount /tmp "
                "read-write with root privileges preserved; /misc also exported ro "
                "to 10.0.0.0/8 (fsid=251)",
    "severity": "HIGH",
    "status":   "CONFIRMED — bigbang/etc/exports extracted; /tmp 10.0.0.0/255.0.0.0 "
                "(fsid=250,sync,rw,no_subtree_check,no_root_squash) confirmed; "
                "/misc 10.0.0.0/255.0.0.0 (fsid=251,sync,ro,no_subtree_check,root_squash) confirmed",
    "cwe":      ["CWE-732 (Incorrect Permission Assignment for Critical Resource)",
                 "CWE-284 (Improper Access Control)"],
    "files":    ["bigbang/etc/exports"],
    "export_line": "/tmp  10.0.0.0/255.0.0.0(fsid=250,sync,rw,no_subtree_check,no_root_squash)",
    "impact": (
        "A host in 10.x.x.x that can reach the NFS port can mount /tmp as root with "
        "no squashing. Combined with world-writable /tmp/gdbserver, /tmp/strace, "
        "/tmp/lddebug (CAT9K-F5), and rsync's [install_file]=/tmp/installer (CAT9K-F2), "
        "a 10.x.x.x attacker can plant files that influence the boot or upgrade process. "
        "Package verification debug logs at /tmp/pkg_cs_debug/ are also readable, "
        "exposing failed code-signing attempts."
    ),
}

# CAT9K-F4: PermitRootLogin yes
CAT9K_F4 = {
    "id":       "CAT9K-F4",
    "title":    "sshd_config PermitRootLogin yes — SSH direct root login enabled; "
                "host keys stored at /config/.ssh/ (runtime-generated, not in firmware); "
                "PasswordAuthentication defaults to yes (not explicitly disabled); "
                "ChallengeResponseAuthentication also defaults to yes",
    "severity": "HIGH",
    "status":   "CONFIRMED — bigbang/etc/ssh/sshd_config extracted; "
                "PermitRootLogin yes at line 29 confirmed; PasswordAuthentication "
                "and ChallengeResponseAuthentication commented out (both default yes); "
                "HostKey paths: /config/.ssh/ssh_host_rsa_key, ssh_host_ecdsa_key, "
                "ssh_host_ed25519_key",
    "cwe":      ["CWE-250 (Execution with Unnecessary Privileges)",
                 "CWE-284 (Improper Access Control)"],
    "files":    ["bigbang/etc/ssh/sshd_config"],
    "sshd_config_line": "PermitRootLogin yes",
    "impact": (
        "Direct root SSH login is available if the root account has any credential. "
        "Combined with PermitRootLogin yes, password authentication enabled by default, "
        "and any weak/empty credential (if present at runtime), an attacker with network "
        "access to SSH has a direct path to a root shell."
    ),
}

# CAT9K-F5: World-writable debug directories created at every boot
CAT9K_F5 = {
    "id":       "CAT9K-F5",
    "title":    "explode-common creates /tmp/gdbserver, /tmp/strace, /tmp/lddebug "
                "with chmod 777 at every boot (in both make_dirs and mount_zram_tmp "
                "code paths); these directories persist for the lifetime of the running system",
    "severity": "HIGH",
    "status":   "CONFIRMED — explode-common bash source examined; lines 72-76 and 103-107 "
                "both contain: for dir in gdbserver strace lddebug; do "
                "must mkdir -p /tmp/$dir; chmod 777 /tmp/$dir; done",
    "cwe":      ["CWE-732 (Incorrect Permission Assignment for Critical Resource)",
                 "CWE-489 (Active Debug Code)"],
    "files":    ["explode-common"],
    "world_writable_paths": ["/tmp/gdbserver", "/tmp/strace", "/tmp/lddebug"],
    "impact": (
        "Any local user (guestshell GID 1000, limiteduser, dockeruser) can write into "
        "/tmp/gdbserver and /tmp/strace. If any process searches PATH or LD_PRELOAD "
        "against these directories, or if any service auto-starts binaries placed there, "
        "a low-privilege user can execute code in a higher-privilege context. The directories "
        "also serve as an injection point for the NFS no_root_squash export (CAT9K-F3): "
        "a 10.x.x.x attacker can plant a gdbserver or strace binary that will be executed "
        "if the system or any admin invokes the tool by name from /tmp/."
    ),
    "note": "The comment in explode-common near the gdbserver/strace/lddebug mkdir block "
            "references ROMMON SR_INIT_DEBUG and acknowledges a window between boot start "
            "and ROMMON variable load — these directories are created before the ROMMON "
            "debug flag check, meaning they exist on every boot regardless of debug mode.",
}

# CAT9K-F6: ROMMON_SR_INIT_DEBUG enables bash xtrace at early boot
CAT9K_F6 = {
    "id":       "CAT9K-F6",
    "title":    "ROMMON variable ROMMON_SR_INIT_DEBUG enables bash set -o xtrace "
                "at early boot (explode-common line 641); xtrace prints every shell "
                "command, expansion, and argument to stderr/log before execution; "
                "sensitive runtime values (crypto keys, temp credentials, ROMMON variables) "
                "passed as arguments or interpolated in commands appear in the trace output",
    "severity": "HIGH",
    "status":   "CONFIRMED — explode-common lines 638-643: "
                "if [[ ${ROMMON_SR_INIT_DEBUG:-} ]]; then set -o xtrace; fi; "
                "ROMMON vars loaded by save_and_load_rommon_vars via /rommon_to_env binary",
    "cwe":      ["CWE-532 (Insertion of Sensitive Information into Log File)",
                 "CWE-489 (Active Debug Code)"],
    "files":    ["explode-common", "mount_packages.sh"],
    "rommon_vars": ["ROMMON_SR_INIT_DEBUG", "ROMMON_SR_MGMT_VRF",
                    "ROMMON_PACKAGES_OVERRIDE", "ROMMON_DEBUG_CONF",
                    "ROMMON_TFTP_SERVER", "ROMMON_XE_RECOVER_ACTION",
                    "DEVICE_MANAGED_MODE"],
    "impact": (
        "An attacker with ROMMON access (physical console or ROMMON CVE) can set "
        "ROMMON_SR_INIT_DEBUG to capture a full trace of the IOS-XE boot process, "
        "including: code signing verification commands and arguments, ROMMON variable "
        "values, filesystem mount parameters, package integrity check output, and any "
        "credentials or keys passed as command-line arguments during boot. Trace output "
        "goes to the boot console, which is recorded in crash logs and accessible via "
        "the management plane after boot completes."
    ),
}

# CAT9K-F7: ROMMON attack surface: PACKAGES_OVERRIDE and DEBUG_CONF
CAT9K_F7 = {
    "id":       "CAT9K-F7",
    "title":    "ROMMON variables ROMMON_PACKAGES_OVERRIDE and ROMMON_DEBUG_CONF "
                "allow boot-time package selection override and attacker-controlled "
                "debug configuration loading respectively; ROMMON_DEBUG_CONF supports "
                "tftp: prefix for remote fetch (uses ROMMON_TFTP_SERVER); debug.conf "
                "settings FRU_NO_WATCHDOG=1 and PVP_IGN_CRITICAL_PROC_DOWN=1 disable "
                "watchdog and critical process monitoring",
    "severity": "HIGH",
    "status":   "CONFIRMED — explode-common lines 1059-1115: ROMMON_PACKAGES_OVERRIDE "
                "overrides BOOTED_CONF_PATH with comment 'OVERRIDING PROVISIONING FILE'; "
                "lines 862-880: find_debug_conf() reads ROMMON_DEBUG_CONF via get_conf_file "
                "supporting tftp: prefix; lines 930-939: PVP_IGN_CRITICAL_PROC_DOWN=1 "
                "and FRU_NO_WATCHDOG=1 checked from /tmp/debug.conf",
    "cwe":      ["CWE-494 (Download of Code Without Integrity Check)",
                 "CWE-489 (Active Debug Code)"],
    "files":    ["explode-common"],
    "attack_paths": [
        "ROMMON_PACKAGES_OVERRIDE: point to attacker-controlled packages.conf "
        "(local or tftp:path) to boot from unsigned or modified packages",
        "ROMMON_DEBUG_CONF=tftp:<server>/<path>: fetch debug config from TFTP "
        "server; set FRU_NO_WATCHDOG=1 to disable watchdog before persistent "
        "modification; set PVP_IGN_CRITICAL_PROC_DOWN=1 to suppress alerts",
        "ROMMON_XE_RECOVER_ACTION: triggers zero_device call on recovery",
    ],
    "code_comment": "# We assume that the ROMMON keeps people from tftp-booting\n"
                    "# MCP_FIXME: Though we assume this, it would be smarter to\n"
                    "# test the assumption and die with an appropriate error message\n"
                    "# if the assumption fails to hold.",
    "impact": (
        "Requires ROMMON access (physical console, ROMMON vulnerability CVE, or breakin "
        "during power cycle). With ROMMON access: ROMMON_PACKAGES_OVERRIDE can substitute "
        "a crafted packages.conf to load unsigned software. ROMMON_DEBUG_CONF+TFTP allows "
        "injecting a debug config that disables watchdog and process monitoring, creating "
        "a stable environment for persistent modification. The MCP_FIXME comment in "
        "explode-common explicitly acknowledges the assumption about ROMMON security "
        "is untested."
    ),
}

# CAT9K-F8: binos user is member of docker group
CAT9K_F8 = {
    "id":       "CAT9K-F8",
    "title":    "binos user (UID 85, GID 85, shell /usr/binos/conf/bshell.sh) is "
                "member of the docker group (GID 65535) in bigbang/etc/group; "
                "docker group membership provides effective root via container escape "
                "(mount host filesystem, run privileged container)",
    "severity": "HIGH",
    "status":   "CONFIRMED — bigbang/etc/group extracted; docker:x:65535:dockeruser,binos "
                "confirmed; binos is the IOS-XE administrative user (UID 85) with custom "
                "restricted shell bshell.sh; dockeruser also in docker group",
    "cwe":      ["CWE-269 (Improper Privilege Management)",
                 "CWE-250 (Execution with Unnecessary Privileges)"],
    "files":    ["bigbang/etc/group"],
    "group_line": "docker:x:65535:dockeruser,binos",
    "impact": (
        "If the binos shell restriction (bshell.sh) can be bypassed or if binos can "
        "invoke docker commands, the binos user can run a privileged container or mount "
        "the host filesystem to obtain full root access. Combined with PermitRootLogin yes "
        "(CAT9K-F4) and the rsync/NFS access surfaces (CAT9K-F2/F3), this provides a "
        "privilege escalation path from binos to root."
    ),
}

# CAT9K-F9: xinetd TFTP servers running as root
CAT9K_F9 = {
    "id":       "CAT9K-F9",
    "title":    "xinetd exposes two TFTP servers as root: standard TFTP on UDP 69 "
                "(tftpd -c /tftp /tftp/inv, create mode, read from /tftp, write to "
                "/tftp/inv) and tftp-private on UDP 16069 (tftpd -c, create mode, "
                "no path restriction); both services run as root user=root",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — bigbang/etc/xinetd.conf extracted; tftp-private (port 16069) "
                "server_args=-c user=root confirmed; tftp (port 69) server_args=-c /tftp "
                "/tftp/inv user=root confirmed",
    "cwe":      ["CWE-284 (Improper Access Control)",
                 "CWE-732 (Incorrect Permission Assignment for Critical Resource)"],
    "files":    ["bigbang/etc/xinetd.conf"],
    "services": [
        "tftp-private: UDP/16069, tftpd -c (create mode), user=root, no path restriction",
        "tftp: UDP/69, tftpd -c /tftp /tftp/inv, user=root, write to /tftp/inv",
    ],
    "impact": (
        "tftp-private on UDP/16069 with -c flag and no path argument runs as root with "
        "no directory restriction — write destination is CWD or caller-specified. "
        "Standard TFTP on UDP/69 allows writes to /tftp/inv as root. These are used "
        "for inter-FRU package distribution (CC fetches drivers from RP via TFTP). "
        "Access control relies entirely on IOS-XE ACL configuration."
    ),
}

# CAT9K-F10: systemd 255 as initramfs PID 1
CAT9K_F10 = {
    "id":       "CAT9K-F10",
    "title":    "initramfs init is systemd 255 (x86-64 ELF PIC, dynamically linked to "
                "libsystemd-core-255.so and libsystemd-shared-255.so, GLIBC_2.34+); "
                "full systemd unit ecosystem including binos.target, binos_script.service, "
                "chasfs.service, xinetd services — attack surface is full systemd "
                "rather than a minimal custom init",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — /tmp/cat9k-initrd/init -> usr/lib/systemd/systemd confirmed; "
                "ELF strings show libsystemd-core-255.so, libsystemd-shared-255.so, "
                "GLIBC_2.34/GLIBC_2.7/GLIBC_2.8/GLIBC_2.4 symbol versioning; "
                "systemd unit files in usr/lib/systemd/system/ confirmed",
    "cwe":      ["CWE-1104 (Use of Unmaintained Third Party Components)"],
    "files":    ["usr/lib/systemd/systemd"],
    "key_units": [
        "binos_script.service: ExecStart=/etc/init.d/binos start (runs as root)",
        "boothelper.service: ExecStart=/usr/binos/conf/boothelper_evt.sh --daemon",
        "chasfs.service: ExecStart=/etc/init.d/chasfs_boottime.sh",
        "agetty-iosd.service: ExecStart=/etc/init.d/agetty-iosd start (console relay)",
        "binos.target: full BinOS stack target",
    ],
    "impact": (
        "Full systemd 255 expands the attack surface vs a minimal init. Known systemd "
        "privilege escalation and local DoS CVEs apply if the systemd version is unpatched. "
        "The service unit model (Type=forking, RemainAfterExit, Restart=always) also "
        "means misconfigured units can restart crashed processes indefinitely, masking "
        "crash-based detection of exploitation attempts."
    ),
}

# CAT9K-F11: Build artifacts expose internal development infrastructure
CAT9K_F11 = {
    "id":       "CAT9K-F11",
    "title":    "Platform codenames (bigbang, nyquist, passport, starfleet, symphony), "
                "build user (mcpre), build path "
                "(/nobackup/mcpre/s2c-build-ws/binos/linkfarm/cat9k_universalk9-stage), "
                "and git hash (150b070c01e17) exposed in packages.conf .pkginfo and "
                "SquashFS directory layout",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — packages.conf .pkginfo extracted from outer SquashFS; "
                ".BuildPath, .SW_DESCRIPTION (V1718_4_FC1-0-g150b070c01e17), User=mcpre "
                "confirmed; bigbang/nyquist/passport/starfleet/symphony top-level dirs "
                "in rpbase inner SquashFS confirmed",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)"],
    "files":    ["packages.conf", ".pkginfo"],
    "codenames": ["bigbang", "nyquist", "passport", "starfleet", "symphony"],
    "build_details": {
        "user": "mcpre",
        "build_path": "/nobackup/mcpre/s2c-build-ws/binos/linkfarm/cat9k_universalk9-stage",
        "git_hash": "150b070c01e17",
        "pkg_uid": "feda5b3482420cdd040e3f5b127b49e20d10933e",
    },
}

# CAT9K-F12: codesign.pubkey in custom undocumented binary format
CAT9K_F12 = {
    "id":       "CAT9K-F12",
    "title":    "codesign.pubkey at initramfs root is 19,200 bytes in an undocumented "
                "Cisco-proprietary binary format (magic: ae02 25ab 1234 cd01 0001 0202); "
                "not standard PEM/DER/PKCS#8/SubjectPublicKeyInfo; "
                "codesign.revkey (300 bytes) uses same format; both verified by "
                "code_sign_verify binary (usr/bin/code_sign_verify ELF PIC stripped)",
    "severity": "LOW",
    "status":   "CONFIRMED — /tmp/cat9k-initrd/codesign.pubkey (19200 bytes) read; "
                "first bytes ae02 25ab 1234 cd01 0001 0202 confirmed; file(1) reports 'data'; "
                "codesign.revkey (300 bytes) confirmed in same format",
    "cwe":      ["CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)"],
    "files":    ["codesign.pubkey", "codesign.revkey", "usr/bin/code_sign_verify"],
    "key_header_hex": "ae0225ab1234cd0100010202",
    "impact": (
        "Undocumented key format complicates independent verification of the signing "
        "trust chain. Security researchers cannot validate key parameters (algorithm, "
        "key size, curve) without reverse-engineering code_sign_verify. If the format "
        "encodes weaker parameters than claimed, the code-signing chain provides "
        "less protection than assumed."
    ),
}

# CAT9K-F13: Lab artifact daytime service in production xinetd
CAT9K_F13 = {
    "id":       "CAT9K-F13",
    "title":    "xinetd includes a TCP daytime service (type=INTERNAL, disable=no) "
                "with comment '# used for the lab time hack remove eventually' and "
                "MCP_FIXME tag; service runs as root and is enabled in production firmware",
    "severity": "LOW",
    "status":   "CONFIRMED — bigbang/etc/xinetd.conf extracted; daytime service block "
                "with 'type = INTERNAL, id = daytime-stream, socket_type = stream, "
                "protocol = tcp, user = root, wait = no, disable = no' confirmed; "
                "comment '# used for the lab time hack remove eventually' and "
                "'# MCP_FIXME' tag confirmed",
    "cwe":      ["CWE-489 (Active Debug Code)"],
    "files":    ["bigbang/etc/xinetd.conf"],
    "service_comment": "# used for the lab time hack remove eventually\n# MCP_FIXME",
    "impact": (
        "Lab artifact in production firmware. The MCP_FIXME tag confirms Cisco "
        "engineering intended to remove this service before production but did not. "
        "Minimal direct impact (daytime only returns current time), but confirms a "
        "pattern of lab configuration leaking into release builds. "
        "Consistent with MCP_FIXME patterns in explode-common (untested ROMMON "
        "assumption, CAT9K-F7) and lagging lab artifact cleanup across multiple modules."
    ),
}

FINDINGS = [
    CAT9K_F1,
    CAT9K_F2,
    CAT9K_F3,
    CAT9K_F4,
    CAT9K_F5,
    CAT9K_F6,
    CAT9K_F7,
    CAT9K_F8,
    CAT9K_F9,
    CAT9K_F10,
    CAT9K_F11,
    CAT9K_F12,
    CAT9K_F13,
]

SUMMARY = {
    "total": 13,
    "critical": 2,
    "high":     6,
    "medium":   3,
    "low":      2,
    "by_id": [f["id"] for f in FINDINGS],
}
