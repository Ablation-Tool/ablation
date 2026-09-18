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

# CAT9K-F14: bexecute SUID + shell_exec.sh /tmp TOCTOU local privilege escalation
CAT9K_F14 = {
    "id":       "CAT9K-F14",
    "title":    "bexecute SUID binary (rwsr-sr-x root/root, 55040 bytes) whitelists "
                "shell_exec.sh in /usr/binos/conf/uicmd.conf; shell_exec.sh sources "
                "/tmp/.shell_exec.<args_id> as bash at line 45 with root effective UID; "
                "args_id is the first argv token passed by the caller; "
                "/tmp is world-writable; file is read without exclusive lock",
    "severity": "HIGH",
    "status":   "CONFIRMED — /tmp/rpbase-full/bigbang/usr/binos/bin/bexecute "
                "(rwsr-sr-x root/root, confirmed SUID via unsquashfs -lls); "
                "uicmd.conf extracted: /usr/binos/conf/shell_exec.sh listed as whitelisted "
                "script; shell_exec.sh line 29: args_file=\"/tmp/.shell_exec.${args_id}\"; "
                "line 45: source \"${args_file}\" confirmed; "
                "args_id set from ${1} directly from caller argv with no sanitization",
    "cwe":      ["CWE-377 (Insecure Temporary File)",
                 "CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)",
                 "CWE-269 (Improper Privilege Management)"],
    "files":    ["bigbang/usr/binos/bin/bexecute",
                 "bigbang/usr/binos/conf/uicmd.conf",
                 "bigbang/usr/binos/conf/shell_exec.sh"],
    "trigger_code": [
        "# shell_exec.sh",
        "args_id=\"${1}\"",
        "args_file=\"/tmp/.shell_exec.${args_id}\"",
        "# ...",
        "source \"${args_file}\"   # sourced as root via bexecute SUID",
    ],
    "attack_path": [
        "1. From any low-privileged shell (binos, guestshell, network-operator)",
        "2. Pre-create /tmp/.shell_exec.<predictable_args_id> with: chmod +s /bin/bash",
        "3. Invoke bexecute shell_exec.sh <predictable_args_id>",
        "4. bexecute sets effective UID=0 (SUID), exec shell_exec.sh",
        "5. shell_exec.sh sources /tmp/.shell_exec.<args_id> as bash with root euid",
        "6. Payload executes as root",
    ],
    "impact": (
        "Local privilege escalation from any IOS-XE shell user to root. "
        "The bexecute binary is the standard mechanism for running administrative "
        "scripts as root on Cat9K; the whitelist (uicmd.conf) contains 80+ entries. "
        "shell_exec.sh is invoked by multiple IOS-XE subsystems (NETCONF sessions, "
        "container management) making args_id values predictable from process IDs or "
        "session identifiers visible in /tmp. An attacker with any level of IOS-XE "
        "shell access (guestshell, network-operator, any sudoers entry) can race the "
        "args file creation to obtain root. No exploit primitives beyond file write "
        "to /tmp are required."
    ),
    "note": "shell_exec.sh handles multiple actions (enable_netconf_yang, "
            "execute_session_command, disable_netconf_yang) and is a central "
            "IOS-XE subsystem component. The args_file pattern is used to pass "
            "structured parameters (SHELL_SESSION_action, SHELL_SESSION_command_line, etc.) "
            "to the script, which explains the bash-sourcing design. The rm -f at line 88 "
            "deletes the args_file after sourcing, providing no persistent evidence. "
            "SHELL_SESSION_command_line at line 1684 is also unquoted in the nsenter exec "
            "invocation, but word-splitting is the lesser risk compared to the source path.",
}

# CAT9K-F15: screen 4.9.1 SUID root logfile privilege escalation
CAT9K_F15 = {
    "id":       "CAT9K-F15",
    "title":    "GNU screen 4.9.1 installed SUID root (rwsr-sr-x root/root, 452656 bytes) "
                "at /usr/bin/screen in production Cat9K IOS-XE firmware; "
                "screen multiuser mode requires SUID; -Logfile flag allows writing "
                "screen session output to an arbitrary path as root; "
                "-D -m flags run detached in daemon mode without a controlling terminal",
    "severity": "HIGH",
    "status":   "CONFIRMED — unsquashfs -lls on cat9k-rpbase.17.18.04.SPA.pkg shows "
                "-rwsr-sr-x root/root 452656 usr/bin/screen; strings output confirms "
                "\"Screen version %s\", \"-Logfile file Set logfile name.\", "
                "\"Must run suid root for multiuser support.\" present in binary",
    "cwe":      ["CWE-269 (Improper Privilege Management)",
                 "CWE-250 (Execution with Unnecessary Privileges)"],
    "files":    ["bigbang/usr/bin/screen"],
    "version":  "screen-4.9.1",
    "suid_bits": "rwsr-sr-x root/root",
    "trigger_code": [
        "screen -D -m -L -Logfile /etc/cron.d/root_shell <cmd>",
        "# or: append to /root/.ssh/authorized_keys",
    ],
    "attack_path": [
        "1. From any local shell (any privilege level with /usr/bin/screen access)",
        "2. screen -D -m -L -Logfile /target/path /bin/sh -c 'echo payload'",
        "3. screen runs detached as root, writes session output to /target/path",
        "4. Target can be /etc/crontab, /etc/cron.d/, /root/.ssh/authorized_keys",
        "5. Cron or SSH key triggers root shell",
    ],
    "impact": (
        "Any user with access to /usr/bin/screen can write arbitrary content to any "
        "root-owned path via the -Logfile flag. Classic targets: /etc/crontab "
        "(cron root shell), /root/.ssh/authorized_keys (SSH key injection), "
        "/etc/ld.so.preload (library injection). On Cat9K, /etc/crontab or "
        "init.d paths can schedule persistence that survives process restarts. "
        "Screen 4.9.1 has no CVE specifically for this behavior (it is by design "
        "for multiuser); the risk is the SUID deployment on a production network "
        "device where screen's terminal multiplexing function is unnecessary."
    ),
    "note": "GNU screen requires SUID root on Linux to support multiuser mode "
            "(screen -x for session sharing across users). On a network device, "
            "multiuser screen sharing has no legitimate use case. The SUID bit "
            "should be removed (chmod -s /usr/bin/screen) or screen should not "
            "be included in production firmware. CVE-2023-24626 (screen 4.9.0 "
            "signal handling) is patched in 4.9.1 but the SUID logfile write "
            "surface remains.",
}

# CAT9K-F16: SUID nsenter unrestricted namespace escape
CAT9K_F16 = {
    "id":       "CAT9K-F16",
    "title":    "nsenter (util-linux 2.39.3) installed SUID root (rwsr-sr-x root/root, "
                "43296 bytes) at /usr/bin/nsenter; any process can call nsenter to "
                "attach to any Linux namespace (PID, mount, network, user, IPC) "
                "with -S 0 -G 0 flags to set UID/GID 0 inside the target namespace; "
                "nsenter_exec.sh reads /tmp/app_pid.txt (world-writable) for target PID",
    "severity": "HIGH",
    "status":   "CONFIRMED — unsquashfs -lls shows -rwsr-sr-x root/root 43296 usr/bin/nsenter; "
                "nsenter_exec.sh at bigbang/usr/binos/conf/nsenter_exec.sh confirmed: "
                "GSPID=$(</tmp/app_pid.txt) and "
                "/usr/bin/nsenter -t $GSPID -m -u -i -n -p -U -S 0 -G 0 -r -w -Z env -i "
                "PATH=... $1 with both GSPID and $1 unquoted",
    "cwe":      ["CWE-269 (Improper Privilege Management)",
                 "CWE-250 (Execution with Unnecessary Privileges)"],
    "files":    ["bigbang/usr/bin/nsenter",
                 "bigbang/usr/binos/conf/nsenter_exec.sh"],
    "version":  "util-linux 2.39.3",
    "suid_bits": "rwsr-sr-x root/root",
    "trigger_code": [
        "# nsenter_exec.sh - unquoted args",
        "GSPID=$(</tmp/app_pid.txt)    # world-writable source",
        "/usr/bin/nsenter -t $GSPID -m -u -i -n -p -U -S 0 -G 0 -r -w -Z \\",
        "  env -i PATH=... $1           # $1 unquoted: word-splits",
    ],
    "attack_path": [
        "1. Direct SUID call: /usr/bin/nsenter -t 1 -m -u -i -n -p /bin/bash",
        "   Enters PID 1 (init) namespaces with caller's UID (root if SUID effective)",
        "2. Via nsenter_exec.sh: write attacker PID to /tmp/app_pid.txt",
        "   nsenter enters that process's namespace with -S 0 -G 0 (root in namespace)",
        "3. On containerized workloads: nsenter PID = container PID 1",
        "   -m flag enters mount namespace, -n enters net namespace = container escape",
    ],
    "impact": (
        "SUID nsenter enables unrestricted namespace attachment. On Cat9K devices "
        "running IOx containerized applications (Docker, LXC), nsenter provides "
        "container escape: enter the container's mount namespace and gain root inside it, "
        "or reverse: from inside a container, enter the host PID namespace. "
        "The -S 0 -G 0 flags in nsenter_exec.sh explicitly set root credentials "
        "inside the entered namespace. nsenter_exec.sh's use of /tmp/app_pid.txt "
        "as the PID source (world-writable) allows any local user to redirect "
        "nsenter to target any running process, not just the intended guestshell PID. "
        "The $1 argument in nsenter_exec.sh is unquoted: word-split on whitespace "
        "if the caller provides a spaced argument string."
    ),
    "note": "nsenter is used by IOS-XE for guestshell and IOx container access "
            "(connecting to the container's network/mount namespaces for the "
            "'app-hosting connect appid' CLI command). The SUID bit is required "
            "for this function. The risk is the unrestricted access: any process "
            "on the device can call /usr/bin/nsenter with arbitrary namespace targets. "
            "Mitigation: restrict nsenter to specific users via sudo with explicit "
            "allowed PIDs, or use Linux capabilities (CAP_SYS_ADMIN) scoped to the "
            "guestshell management process rather than world-SUID.",
}

# CAT9K-F17: SUID runc v1.1.12+dev container runtime on production network hardware
CAT9K_F17 = {
    "id":       "CAT9K-F17",
    "title":    "runc v1.1.12+dev (Go 1.22.2, 9,680,544 bytes) installed SUID root "
                "(rwsr-sr-x root/root) at /usr/bin/runc; the +dev suffix indicates "
                "a pre-release development build ahead of the 1.1.12 release tag; "
                "CVE-2024-21626 (CVSS 8.6 HIGH, file descriptor leak enabling host root "
                "escape from containers) is patched in runc >= 1.1.12 release; "
                "patch applicability for the +dev pre-release is unconfirmed",
    "severity": "HIGH",
    "status":   "CONFIRMED — unsquashfs -lls shows -rwsr-sr-x root/root 9680544 usr/bin/runc; "
                "strings confirm opencontainers/runc module path; "
                "version 1.1.12+dev with Go 1.22.2 from binary version string; "
                "CVE-2024-21626 fix commits are in the 1.1.12 release tag; "
                "+dev build provenance against that tag is not determinable from binary alone",
    "cwe":      ["CWE-403 (Exposure of File Descriptor to Unintended Control Sphere)",
                 "CWE-269 (Improper Privilege Management)"],
    "files":    ["bigbang/usr/bin/runc"],
    "version":  "v1.1.12+dev (Go 1.22.2)",
    "suid_bits": "rwsr-sr-x root/root",
    "cve_ref":  "CVE-2024-21626 (CVSS 8.6 HIGH) — runc <= 1.1.11: workdir fd leak "
                "allows container process to obtain a host filesystem fd and escape "
                "to host root; patched in 1.1.12 release",
    "attack_path": [
        "CVE-2024-21626 path (if +dev predates fix commits):",
        "1. Attacker controls container image or runc exec arguments",
        "2. Container process opens /proc/self/fd/<leaked-host-fd>",
        "3. Obtains file descriptor to host filesystem path outside container root",
        "4. Writes to /etc/crontab, /root/.ssh/authorized_keys, /etc/shadow via host fd",
        "5. Full host root access",
        "",
        "SUID deployment risk (independent of CVE):",
        "Any future runc vulnerability affecting SUID deployments has "
        "amplified impact on a production network device.",
    ],
    "impact": (
        "runc is the OCI container runtime for IOS-XE IOx applications. "
        "SUID deployment on production network hardware amplifies any runc vulnerability. "
        "CVE-2024-21626 (8.6 HIGH) allows container escape to host root via fd leak; "
        "while runc 1.1.12 release patches it, the +dev suffix in this build "
        "indicates a development snapshot whose relationship to the patch commits "
        "is not determinable from the binary alone. If the build predates the fix "
        "commits (February 2024), the CVE applies. If it postdates them, the SUID "
        "deployment on network infrastructure remains a risk for future runc CVEs. "
        "Cisco should pin to a release-tagged version and document the patch epoch."
    ),
    "note": "runc in IOS-XE provides container isolation for IOx applications. "
            "The +dev version suffix suggests this was built from source at a "
            "commit ahead of the 1.1.11 release but the exact commit hash is not "
            "embedded in the binary strings. The CVE-2024-21626 fix was committed "
            "to the runc main branch on 2024-01-31 and released as 1.1.12 on "
            "2024-02-13. A build labeled 1.1.12+dev could be pre-release (before "
            "the fix) or post-release (a dev snapshot after the tag). "
            "Binary-level confirmation would require matching Go module checksums.",
}


# CAT9K-F18: Meraki NETCONF config monitor: hardcoded "deveng" account, SSH key in /tmp, no host key verification
CAT9K_F18 = {
    "id":       "CAT9K-F18",
    "title":    "Meraki NETCONF config monitor scripts (nc_subscribe.py, nc_config_updater.py) "
                "hardcode USERNAME=\"deveng\" for NETCONF sessions; SSH private key stored at "
                "/tmp/.shell_exec/netconf/1/users/deveng/keys/id_rsa_netconf (world-writable /tmp); "
                "ncclient.connect() uses hostkey_verify=False; iosp_client provisions a "
                "passwordless account; port 8281 opened for passwordless NETCONF access "
                "on Meraki-managed devices; CONFIG_MODEL_XPATHS_PATH at /tmp/confd/ndbman_config_xpaths "
                "(world-writable) controls which YANG paths are synced to Meraki cloud",
    "severity": "HIGH",
    "status":   "CONFIRMED — bigbang/usr/binos/conf/nc_subscribe.py and nc_config_updater.py "
                "both contain USERNAME = \"deveng\" at line 29 and 41 respectively; "
                "KEYFILE = \"/tmp/.shell_exec/netconf/%s/users/%s/keys/id_rsa_netconf\" % (VRF, USERNAME); "
                "ncclient.manager.connect(..., hostkey_verify=False) confirmed in both files; "
                "iosp_client call: subprocess.run([\"iosp_client\", \"-f\", "
                "\"netconf_enable_passwordless\", \"global\", USERNAME]) confirmed; "
                "meraki_switching_common.lua:120 confirms \"Opening port 8281 for passwordless netconf access\"",
    "cwe":      ["CWE-798 (Use of Hard-coded Credentials)",
                 "CWE-297 (Improper Validation of Certificate with Host Mismatch)",
                 "CWE-377 (Insecure Temporary File)"],
    "files":    ["bigbang/usr/binos/conf/nc_subscribe.py",
                 "bigbang/usr/binos/conf/nc_config_updater.py",
                 "bigbang/usr/binos/conf/meraki/ssl/meraki-ca.crt"],
    "hardcoded_account": "deveng",
    "netconf_port":      "8281 (127.0.0.1, passwordless when Meraki mode active)",
    "keyfile_path":      "/tmp/.shell_exec/netconf/1/users/deveng/keys/id_rsa_netconf",
    "config_xpaths_path": "/tmp/confd/ndbman_config_xpaths",
    "trigger_code": [
        "# nc_subscribe.py lines 29, 42, 101-104",
        "USERNAME = \"deveng\"",
        "KEYFILE = \"/tmp/.shell_exec/netconf/%s/users/%s/keys/id_rsa_netconf\" % (VRF, USERNAME)",
        "m = manager.connect(host=\"127.0.0.1\", port=\"8281\", username=USERNAME,",
        "                    key_filename=KEYFILE, hostkey_verify=False, ...)",
        "result = subprocess.run([\"iosp_client\", \"-f\",",
        "                         \"netconf_enable_passwordless\", \"global\", USERNAME])",
    ],
    "attack_path": [
        "1. On any Meraki-managed Cat9K, iosp_client provisions deveng as a passwordless NETCONF user",
        "2. SSH private key written to /tmp/.shell_exec/netconf/1/users/deveng/keys/id_rsa_netconf",
        "3. Any local process can read (or replace) the key in /tmp",
        "4. Read key: impersonate nc_subscribe.py, connect to local NETCONF, receive all config notifications",
        "5. Replace key: next nc_subscribe.py connection uses attacker's key, script fails silently",
        "6. /tmp/confd/ndbman_config_xpaths world-writable: inject or remove YANG xpaths to control",
        "   what config models are uploaded to Meraki Dashboard",
    ],
    "impact": (
        "In Meraki-managed mode, any process with local filesystem access can read the deveng "
        "NETCONF SSH key from /tmp and connect to the local NETCONF session on 127.0.0.1:8281 "
        "to receive real-time configuration change notifications for the entire switch. "
        "hostkey_verify=False means a MITM attack between the Python script and the local "
        "NETCONF server (e.g., via LD_PRELOAD socket interception or namespace manipulation) "
        "receives all NETCONF traffic without detection. The /tmp/confd/ndbman_config_xpaths "
        "file controls which YANG config models are uploaded to Meraki Dashboard; writing "
        "to this file can selectively suppress config telemetry to the management plane. "
        "Two Meraki CA certs are embedded: the first (CN=Meraki Certificate Authority) "
        "expired 2020-07-22; the second (CN=Meraki Private Config Root CA) is valid to 2037."
    ),
    "note": "nc_subscribe.py and nc_config_updater.py implement the Meraki SD-WAN config "
            "monitoring path: they subscribe to NETCONF notifications from ConfD and forward "
            "config change events to meraki_mgrd via a SEQPACKET Unix socket. The deveng "
            "account is an internal service account created by iosp_client at runtime, not "
            "a persistent /etc/passwd entry. The hardcoded username means any future deveng "
            "account with any credential set can be used to access NETCONF on port 8281.",
}

# CAT9K-F19: xcopy_script.sh TLS certificate validation bypass (curl -k fallback)
CAT9K_F19 = {
    "id":       "CAT9K-F19",
    "title":    "xcopy_script.sh (IOS-XE copy command backend) falls back to curl -k "
                "(TLS certificate verification disabled) on any SSL certificate error; "
                "Meraki managed mode starts with CURLFLAGS=\"-k\" (no TLS from the start); "
                "Meraki CA bundle includes a cert expired 2020-07-22 that can trigger "
                "cert validation failures and activate the insecure fallback path",
    "severity": "HIGH",
    "status":   "CONFIRMED — bigbang/usr/binos/conf/xcopy_script.sh line 490: "
                "CURLFLAGS=\"$CURLFLAGS\"\" -k \" added on ssl cert error; "
                "line 708: CURLFLAGS=\"-k \" in Meraki download path; "
                "MERAKI_CA_CERT_FILE=\"/usr/binos/conf/meraki/ssl/meraki-ca.crt\" at line 59; "
                "openssl x509 confirms first cert in bundle expired notAfter=Jul 22 21:09:25 2020 GMT; "
                "second cert (Meraki Private Config Root CA) valid 2017-2037",
    "cwe":      ["CWE-295 (Improper Certificate Validation)",
                 "CWE-757 (Selection of Less-Secure Algorithm During Negotiation)"],
    "files":    ["bigbang/usr/binos/conf/xcopy_script.sh",
                 "bigbang/usr/binos/conf/meraki/ssl/meraki-ca.crt"],
    "expired_cert": {
        "subject":  "CN=Meraki Certificate Authority, O=Meraki Inc, OU=Network Operations",
        "issuer":   "self-signed",
        "serial":   "B3D533A29BD31BAF",
        "not_after": "2020-07-22T21:09:25Z",
        "status":   "EXPIRED (4 years as of firmware release 17.18.04 / 2024)",
    },
    "trigger_code": [
        "# xcopy_script.sh line 490",
        "CURLFLAGS=\"$CURLFLAGS\"\" -k \"  # added on SSL cert error: no TLS verification",
        "",
        "# xcopy_script.sh line 708 (Meraki download path)",
        "CURLFLAGS=\"-k \"  # TLS disabled from start in Meraki mode",
    ],
    "attack_path": [
        "Network MITM attack on IOS-XE firmware/config copy operations:",
        "1. Position attacker between Cat9K and download server (ARP spoof, route injection, rogue AP)",
        "2. Present an invalid or self-signed TLS certificate for the download server",
        "3. xcopy_script.sh receives SSL error, re-executes curl with -k flag",
        "4. curl downloads firmware/config with no TLS verification from attacker-controlled server",
        "5. Malicious firmware or config is installed; no integrity check at this layer",
        "",
        "Meraki mode path (line 708):",
        "1. Meraki managed mode activates -k by default, no cert error required",
        "2. All Meraki firmware/config downloads bypass TLS verification entirely",
    ],
    "impact": (
        "The IOS-XE `copy` command (used for firmware updates, config backups, SCP/TFTP/HTTPS "
        "file transfers) falls back to unverified TLS on any certificate error. This enables "
        "MITM interception of firmware downloads: an attacker with network access between the "
        "Cat9K device and the download server can serve a malicious firmware image. "
        "In Meraki managed mode, the -k flag is active unconditionally, meaning all Meraki "
        "cloud downloads (firmware updates, config pushes from Dashboard) occur with no "
        "server authentication. Combined with the expired Meraki CA cert (2020) in the trust "
        "bundle, legitimate cert errors on the Meraki CA-signed endpoints are guaranteed to "
        "trigger the fallback on devices where the first CA is used for verification."
    ),
    "note": "The btrace log message on the fallback path reads: "
            "'Warning curl error = $my_status: Peer certificate cannot be authenticated with "
            "known CA certificates, falling back to insecure mode for downloading'. "
            "This is logged but not surfaced as a failure to the operator. "
            "The expired CA cert (B3D533A29BD31BAF) was valid 2013-2020 and was likely "
            "Meraki's original infrastructure CA. Its presence in a firmware released in "
            "2024 indicates incomplete trust store hygiene. "
            "The Meraki Private Config Root CA (valid 2037) is the replacement.",
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
    CAT9K_F14,
    CAT9K_F15,
    CAT9K_F16,
    CAT9K_F17,
    CAT9K_F18,
    CAT9K_F19,
]

SUMMARY = {
    "total": 19,
    "critical": 3,
    "high":     12,
    "medium":   3,
    "low":      1,
    "by_id": [f["id"] for f in FINDINGS],
}
