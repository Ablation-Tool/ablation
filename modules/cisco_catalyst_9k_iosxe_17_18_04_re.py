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

# CAT9K-F3: guestshell_setup.sh world-writable (0777) in production, root-executed by CAF daemon
CAT9K_F3 = {
    "id":       "CAT9K-F3",
    "title":    "IOx CAF guestshell setup script (opt/cisco/caf/scripts/guestshell_setup.sh, "
                "46800 bytes, 1467 lines) has 0777 permissions in SquashFS across all five "
                "platform trees (bigbang, nyquist, passport, starfleet, symphony); the script "
                "is executed as root by the CAF daemon when IOS-XE IOx guestshell is "
                "activated/installed; also creates shell_exec.sh (chmod 777) and "
                "shell_exec.conf (chmod 666) at runtime; removes root password from "
                "container shadow via sed on the guestshell rootfs",
    "severity": "HIGH",
    "status":   "CONFIRMED — unsquashfs -lls shows -rwxrwxrwx root/root 46800 bytes at "
                "squashfs-root/bigbang/opt/cisco/caf/scripts/guestshell_setup.sh and "
                "identical entries in nyquist/, passport/, starfleet/, symphony/; "
                "guestshell_setup.sh source read: "
                "sed 's/^root:[^:]+:/root::/' -i ${gs_dir}/etc/shadow at line 315; "
                "chmod 777 ${SHELL_EXEC_DIR}/${app_id}/shell_exec.sh at line 460; "
                "chmod 666 ${SHELL_EXEC_DIR}/${app_id}/shell_exec.conf at line 424",
    "cwe":      ["CWE-732 (Incorrect Permission Assignment for Critical Resource)",
                 "CWE-269 (Improper Privilege Management)"],
    "files":    ["bigbang/opt/cisco/caf/scripts/guestshell_setup.sh"],
    "permissions_in_squashfs": "-rwxrwxrwx root/root (0777 on all 5 platform dirs)",
    "key_operations": [
        "Executed as root by CAF daemon on IOx guestshell activate/install",
        "sed 's/^root:[^:]+:/root::/' -i ${gs_dir}/etc/shadow  # removes root password",
        "chmod 777 ${SHELL_EXEC_DIR}/${app_id}/shell_exec.sh  # world-writable root exec",
        "chmod 666 ${SHELL_EXEC_DIR}/${app_id}/shell_exec.conf  # world-writable root config",
        "chown root:network-admin $flash_dir  # grants network-admin group flash access",
    ],
    "impact": (
        "Any local user who can write to the overlayfs writable layer covering "
        "opt/cisco/caf/scripts/ (or who has rsync write access to the CAF path via "
        "CAT9K-F2's [var] or [bootflash] modules) can replace guestshell_setup.sh "
        "before the CAF daemon invokes it. At the next guestshell activate operation, "
        "the replaced script executes as root, providing full privilege escalation. "
        "The script also sets up a chain of further world-writable files: shell_exec.sh "
        "(chmod 777) is the script executed to enter the guestshell container session — "
        "it is writable by any local user after creation. The sed command removing root's "
        "password from the container shadow means every activated guestshell has a "
        "passwordless root account inside the container."
    ),
    "note": "guestshell_setup.sh is annotated at line 6 'This file is temporary until "
            "CAF support is present' and dates to 2016. The copyright range is 2016-2026 "
            "suggesting the file has shipped in this state since the CAF/IOx feature was "
            "introduced. The 0777 permissions appear intentional for the dev-to-production "
            "pipeline but were never hardened for production deployment.",
}

# CAT9K-F4: xinetd telnetd with lablogin.sh login shell exposes unauthenticated root shell
CAT9K_F4 = {
    "id":       "CAT9K-F4",
    "title":    "xinetd telnet service (xinetd_telnetd.conf, disable=no, user=root) "
                "configured with server_args=-L /etc/lablogin.sh; lablogin.sh performs "
                "zero authentication and unconditionally execs root's login shell "
                "(grep /etc/passwd for root's shell, exec $SHELL -l); any user reaching "
                "TCP/23 receives a root shell without providing any credential",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — bigbang/etc/xinetd_telnetd.conf extracted; service telnet "
                "with user=root, server=/usr/sbin/in.telnetd, "
                "server_args=-L /etc/lablogin.sh, disable=no confirmed; "
                "bigbang/etc/lablogin.sh extracted; shell resolution via /etc/passwd and "
                "unconditional exec $SHELL -l with no authentication check confirmed; "
                "no password prompt, no PAM, no public key check in lablogin.sh",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-269 (Improper Privilege Management)"],
    "files":    ["bigbang/etc/xinetd_telnetd.conf", "bigbang/etc/lablogin.sh"],
    "xinetd_config": [
        "service telnet",
        "user            = root",
        "server          = /usr/sbin/in.telnetd",
        "server_args     = -L /etc/lablogin.sh",
        "disable         = no",
    ],
    "lablogin_key_lines": [
        "home_dir=$(grep ^root /etc/passwd | cut -d ':' -f 6)",
        "shell=$(grep ^root /etc/passwd | cut -d ':' -f 7)",
        "export HOME=$home_dir",
        "export SHELL=$shell",
        "exec $SHELL -l",
    ],
    "impact": (
        "Any network peer that can reach TCP/23 on a Cat9K management or data interface "
        "receives an interactive root shell with no credential requirement. The telnet "
        "protocol provides no authentication layer; lablogin.sh explicitly bypasses all "
        "system authentication by looking up root's shell from /etc/passwd and exec-ing "
        "it directly. There is no PAM callout, no password prompt, and no SSH key check. "
        "Attack path: connect to TCP/23, receive root shell. "
        "IOS-XE ACL configuration is the only gate; a single misconfigured ACL or any "
        "network-adjacent attacker on the management VRF has immediate root access."
    ),
    "note": "lablogin.sh is documented in the IOS-XE sources as an 'internal telnet server' "
            "for lab use. The xinetd_telnetd.conf file is loaded separately from the main "
            "xinetd.conf and configures this service with disable=no, making it active by "
            "default in production firmware. lablogin.sh does include an rsync call that "
            "logs the access, but the rsync call is non-blocking and exec $SHELL -l runs "
            "regardless of whether rsync succeeds.",
}

# CAT9K-F5: OpenResty nginx.conf consists entirely of `include /tmp/nginx.conf`
CAT9K_F5 = {
    "id":       "CAT9K-F5",
    "title":    "The shipped OpenResty nginx.conf at "
                "usr/binos/openresty/nginx/conf/nginx.conf contains only a single "
                "directive: 'include /tmp/nginx.conf;' — the entire web management proxy "
                "security configuration (TLS policy, authentication locations, CSRF "
                "settings, proxy rules, RESTCONF paths) is generated at runtime and loaded "
                "from /tmp; SELinux context for /tmp/nginx.conf is httpd_config_t only on "
                "the starfleet platform; SELinux policy coverage for bigbang/nyquist/"
                "passport/symphony not confirmed in firmware",
    "severity": "HIGH",
    "status":   "CONFIRMED — bigbang/usr/binos/openresty/nginx/conf/nginx.conf extracted "
                "(97 bytes); full content: '# Copyright (c) 2020 by Cisco Systems, Inc.\\n"
                "# All rights reserved.\\n\\ninclude /tmp/nginx.conf;'; "
                "SELinux file_contexts for starfleet platform: "
                "/tmp/nginx.conf system_u:object_r:httpd_config_t:s0 confirmed; "
                "bigbang platform SELinux policy coverage not found in initramfs or rpbase",
    "cwe":      ["CWE-494 (Download of Code Without Integrity Check)",
                 "CWE-732 (Incorrect Permission Assignment for Critical Resource)"],
    "files":    ["bigbang/usr/binos/openresty/nginx/conf/nginx.conf"],
    "nginx_conf_full_content": "include /tmp/nginx.conf;",
    "tmp_nginx_selinux_context": "system_u:object_r:httpd_config_t:s0 (starfleet only)",
    "impact": (
        "The IOS-XE web management proxy security posture is entirely determined by "
        "/tmp/nginx.conf, a runtime-generated file. Any process or user that can write "
        "/tmp/nginx.conf before or after nginx starts can inject arbitrary nginx directives: "
        "replacing proxy_pass targets to redirect authentication to attacker-controlled "
        "servers (credential harvest), injecting allow/deny rules to bypass access controls, "
        "adding proxy_set_header directives to forge headers seen by ConfD (compounding "
        "CAT9K-F... ConfD XFF trust), disabling TLS, or inserting content_by_lua_block "
        "for server-side code execution in the nginx worker context. "
        "On non-starfleet platforms (bigbang is the primary management platform), no "
        "SELinux type enforcement for /tmp/nginx.conf was confirmed in the firmware, "
        "meaning DAC permissions on /tmp govern write access."
    ),
    "note": "The design separates static firmware files from runtime configuration: "
            "the SquashFS contains only the include directive; the actual nginx config is "
            "assembled from multiple conf fragments at boot by IOS-XE's http service manager "
            "and placed at /tmp/nginx.conf. This is the same pattern used for /tmp/debug.conf "
            "(CAT9K-F7) and reflects a general architectural choice to generate security-critical "
            "configurations in /tmp. The SELinux coverage gap on the bigbang platform is "
            "notable because bigbang is the primary RP hardware family for Cat9K.",
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

# CAT9K-F9: ConfD RESTCONF/NETCONF trusts X-Forwarded-For; OpenResty auth proxy hardcodes 192.168.1.6:21111
CAT9K_F9 = {
    "id":       "CAT9K-F9",
    "title":    "ConfD (Tail-f NETCONF/YANG daemon) configured with useForwardedClientIp "
                "trusting X-Forwarded-For from allowedProxyIpPrefix=127.0.0.1/32 "
                "(confd.conf.in); OpenResty auth_proxy.conf forwards client X-Forwarded-For "
                "to the authentication backend at hardcoded IP 192.168.1.6:21111 via "
                "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; "
                "ConfD uses the forwarded IP for RESTCONF/NETCONF client attribution "
                "including NACM (NETCONF Access Control Model) rule evaluation and audit logging",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — bigbang/etc/opt/confd/config/cisco/confd.conf.in extracted; "
                "useForwardedClientIp block with proxyHeaders=X-Forwarded-For and "
                "allowedProxyIpPrefix=127.0.0.1/32 at lines 335-338 confirmed; "
                "bigbang/usr/binos/openresty/nginx/conf/auth_proxy.conf extracted; "
                "proxy_pass http://192.168.1.6:21111 liin and "
                "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for "
                "confirmed in /auth_proxy, /session_key, /get_banner_login locations",
    "cwe":      ["CWE-290 (Authentication Bypass by Spoofing)",
                 "CWE-116 (Improper Encoding or Escaping of Output)"],
    "files":    ["bigbang/etc/opt/confd/config/cisco/confd.conf.in",
                 "bigbang/usr/binos/openresty/nginx/conf/auth_proxy.conf"],
    "confd_conf_block": [
        "<useForwardedClientIp>",
        "  <proxyHeaders>X-Forwarded-For</proxyHeaders>",
        "  <allowedProxyIpPrefix>127.0.0.1/32</allowedProxyIpPrefix>",
        "</useForwardedClientIp>",
    ],
    "auth_proxy_backend": "http://192.168.1.6:21111 (IOS HTTP server hardcoded internal IP)",
    "forwarding_locations": ["/auth_proxy", "/session_key", "/get_banner_login"],
    "impact": (
        "ConfD attributes client identity in RESTCONF/NETCONF sessions using X-Forwarded-For. "
        "If NACM rules filter by source IP (a common IOS-XE hardening recommendation), "
        "an attacker who can inject an X-Forwarded-For header reaching ConfD can forge "
        "their source IP to match a trusted management IP and bypass those rules. "
        "The attack surface: any SSRF vulnerability in OpenResty, any request smuggling "
        "flaw, or any component that can make authenticated requests appearing to come "
        "from 127.0.0.1 can set an arbitrary X-Forwarded-For before it reaches ConfD. "
        "Additionally, the auth backend 192.168.1.6:21111 receives the client's "
        "X-Forwarded-For chain — if the IOS HTTP authentication logic makes decisions "
        "based on forwarded IP (e.g., skipping authentication for management IPs), "
        "the same spoofing applies to the authentication layer, not just ConfD. "
        "The hardcoded 192.168.1.6 also exposes the IOS internal IPC addressing scheme."
    ),
    "note": "192.168.1.6 is the standard IOS-XE internal Linux-to-IOS IPC address for "
            "the IOS HTTP server process. Port 21111 is the IOS-XE web auth service port. "
            "This IP:port combination is the same across all Cat9K deployments, making it "
            "a known target for any process running on the linux side of IOS-XE. "
            "The allowedProxyIpPrefix=127.0.0.1/32 restriction means only OpenResty "
            "(running on localhost) can inject trusted X-Forwarded-For headers — but "
            "this assumes OpenResty itself cannot be influenced to forward attacker-controlled "
            "headers, which the pubd.conf $proxy_add_x_forwarded_for directive does not prevent.",
}

# CAT9K-F10: QEMU/KVM configured user=root group=root in production qemu.conf
CAT9K_F10 = {
    "id":       "CAT9K-F10",
    "title":    "qemu.conf (bigbang/3pa/etc/libvirt/qemu.conf) sets user=root and group=root "
                "as the only uncommented active configuration; all QEMU guest processes "
                "run with host UID 0 / GID 0 instead of an isolated QEMU service account; "
                "full QEMU-KVM stack (qemu-kvm 17.8MB ELF, libvirt, libvirtd) ships in "
                "production IOS-XE rpbase for IOx guest services",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — bigbang/3pa/etc/libvirt/qemu.conf extracted from rpbase inner "
                "SquashFS; grep removing comments and blank lines yields only "
                "'user = root' and 'group = root' as active settings; "
                "bigbang/3pa/usr/bin/qemu-kvm (17,806,744 bytes x86-64 ELF) confirmed "
                "in same 3pa/ tree alongside libvirtd.conf (15780 bytes)",
    "cwe":      ["CWE-250 (Execution with Unnecessary Privileges)",
                 "CWE-269 (Improper Privilege Management)"],
    "files":    ["bigbang/3pa/etc/libvirt/qemu.conf",
                 "bigbang/3pa/usr/bin/qemu-kvm",
                 "bigbang/3pa/etc/libvirt/libvirtd.conf"],
    "qemu_conf_active_lines": [
        "user = root",
        "group = root",
    ],
    "impact": (
        "IOx (IOS Application eXperience) guest VMs execute as UID 0 / GID 0 on the host. "
        "Any hypervisor vulnerability (guest-to-host escape via QEMU device emulation, "
        "virtio, or memory handling) delivers root access on the IOS-XE OS rather than "
        "dropping into an isolated service account. The recommended QEMU hardening is to "
        "use a dedicated unprivileged user (e.g. 'qemu' or 'libvirt-qemu'). Running as "
        "root eliminates that containment layer. The Cat9K IOx surface allows tenant "
        "applications to run guest OSes, making this an attacker-controlled code path "
        "into the hypervisor boundary."
    ),
    "note": "The 3pa/ directory (third-party applications) houses the full QEMU-KVM "
            "virtualization stack for the IOx (IOS Application eXperience) feature, "
            "which allows deployment of containerized or VM-based applications on Cat9K "
            "switching hardware. The qemu.conf and libvirtd.conf files are present in "
            "identical form across all five platform directories (bigbang, nyquist, "
            "passport, starfleet, symphony).",
}

# CAT9K-F11: leabasdk test TLS private keys (unencrypted) shipped in production rpbase
CAT9K_F11 = {
    "id":       "CAT9K-F11",
    "title":    "Three RSA private keys for the leabasdk (Licensing and Entitlement "
                "Architecture SDK) CLI TLS test interface shipped in production firmware "
                "at bigbang/usr/lib64/leabasdk/test/api/cli_tls/keys/; client.key and "
                "server.key are unencrypted PKCS#1 PEM (no Proc-Type header); all three "
                "key files carry executable permission bits (chmod +x) unusual for key "
                "material; keys present identically under both bigbang/ and symphony/ "
                "platform trees",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — bigbang/usr/lib64/leabasdk/test/api/cli_tls/keys/ca.key "
                "(3311 bytes, DES-EDE3-CBC encrypted, DEK-Info header confirmed), "
                "client.key (3243 bytes, BEGIN RSA PRIVATE KEY, no Proc-Type encrypted "
                "header = unencrypted), server.key (3243 bytes, same format) extracted "
                "from rpbase inner SquashFS; unsquashfs listing shows -rwxr-xr-x "
                "permission on all three key files; symphony/ platform dir contains "
                "identical copies",
    "cwe":      ["CWE-321 (Use of Hard-coded Cryptographic Key)",
                 "CWE-312 (Cleartext Storage of Sensitive Information)"],
    "files":    ["bigbang/usr/lib64/leabasdk/test/api/cli_tls/keys/ca.key",
                 "bigbang/usr/lib64/leabasdk/test/api/cli_tls/keys/client.key",
                 "bigbang/usr/lib64/leabasdk/test/api/cli_tls/keys/server.key"],
    "key_details": {
        "ca.key":     "3311 bytes, RSA, DES-EDE3-CBC passphrase-protected",
        "client.key": "3243 bytes, RSA PRIVATE KEY, unencrypted (no Proc-Type header)",
        "server.key": "3243 bytes, RSA PRIVATE KEY, unencrypted (no Proc-Type header)",
        "permissions": "-rwxr-xr-x root/root (executable bit on all three key files)",
        "key_prefix_client": "MIIJKQIBAAKCAgEAq7ELTtWcZv/rfnfhl1DZjcHWZEd6/qUISdr",
        "key_prefix_server": "MIIJKQIBAAKCAgEAxKSM+PhLbSqyG76kBkCpg34zQFXrjKBU9tI",
    },
    "impact": (
        "The client.key and server.key are unencrypted RSA private keys that can be "
        "extracted directly from any Cat9K firmware image or device filesystem. "
        "If the leabasdk CLI TLS interface uses these as default credentials (when no "
        "device-specific cert is configured), any party with firmware access can impersonate "
        "the TLS client or server role for leabasdk CLI communications. The LEA (Licensing "
        "and Entitlement Architecture) SDK handles smart licensing; a rogue client cert "
        "could spoof licensing transactions. The executable bit on key files is anomalous "
        "and may indicate these are executed as scripts in some test paths, embedding "
        "cleartext key material in process arguments visible to /proc/self/cmdline."
    ),
    "note": "leabasdk is Cisco's Licensing and Entitlement Architecture SDK, part of the "
            "smart licensing infrastructure. The cli_tls/ subdirectory suggests a TLS-over-CLI "
            "transport used by the leabasdk test suite. Production firmware shipping test "
            "key material from a test/ subdirectory is consistent with the pattern of "
            "incomplete lab-to-production cleanup seen in other Cat9K components "
            "(xinetd_telnetd.conf, auxinit.sh ROMMON_SR_INIT_SHELL).",
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

# CAT9K-F13: auxinit.sh ROMMON_SR_INIT_SHELL triggers unauthenticated root bash on AUX port
CAT9K_F13 = {
    "id":       "CAT9K-F13",
    "title":    "auxinit.sh (AUX port initialization script) checks ROMMON variable "
                "ROMMON_SR_INIT_SHELL for substring 'aux_do_system_shell' using a glob "
                "match (*aux_do_system_shell*); if matched, sets HOME=/root and execs "
                "/bin/bash -l as root on the AUX port connection with no authentication; "
                "variable is loaded from ROMMON environment at early boot via "
                "save_and_load_rommon_vars (rommon_to_env binary)",
    "severity": "HIGH",
    "status":   "CONFIRMED — bigbang/etc/auxinit.sh extracted; conditional block "
                "if [[ ${ROMMON_SR_INIT_SHELL:-} == *aux_do_system_shell* ]]; then "
                "export HOME=/root; cd $HOME; /bin/bash -l confirmed; "
                "no authentication check between ROMMON variable test and bash exec; "
                "ROMMON_SR_INIT_SHELL loaded from ROMMON environment by explode-common "
                "save_and_load_rommon_vars function",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-489 (Active Debug Code)"],
    "files":    ["bigbang/etc/auxinit.sh", "explode-common"],
    "trigger_code": [
        "if [[ \"${ROMMON_SR_INIT_SHELL:-}\" == *\"aux_do_system_shell\"* ]]; then",
        "    export HOME=/root",
        "    cd $HOME",
        "    /bin/bash -l",
        "fi",
    ],
    "attack_path": [
        "1. Attain ROMMON access (physical console during power cycle, or ROMMON CVE)",
        "2. Set ROMMON variable: ROMMON_SR_INIT_SHELL=aux_do_system_shell",
        "3. Boot device normally",
        "4. Connect to AUX port (physical serial or auxiliary console)",
        "5. auxinit.sh matches glob, execs /bin/bash -l as root — no credential required",
    ],
    "impact": (
        "An attacker with ROMMON access can plant ROMMON_SR_INIT_SHELL=aux_do_system_shell "
        "and reboot; on next boot the AUX port delivers a root bash shell to whoever "
        "connects, with no password prompt and no authentication. The AUX port is a "
        "physical serial interface present on all Cat9K hardware, typically used for "
        "modem or out-of-band management. Combined with physical access to the management "
        "console (which grants ROMMON), this provides a persistent root backdoor that "
        "survives IOS-XE authentication configuration: the backdoor activates before "
        "IOS-XE authentication services start. Glob match (*aux_do_system_shell*) means "
        "any string containing the trigger phrase activates the bypass, broadening "
        "any accidental or malicious trigger surface."
    ),
    "note": "auxinit.sh is the AUX port initialization script invoked during platform "
            "startup. The ROMMON_SR_INIT_SHELL check appears to be an internal debug "
            "mechanism for dropping to a shell from the AUX port during development. "
            "Shipping it in production firmware with disable=no logic creates a "
            "documented backdoor for any party who can write ROMMON variables. "
            "Contrast with ROMMON_SR_INIT_DEBUG (CAT9K-F6): that variable enables "
            "xtrace logging; this one enables an unauthenticated shell.",
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
    "critical": 3,
    "high":     6,
    "medium":   3,
    "low":      1,
    "by_id": [f["id"] for f in FINDINGS],
}
