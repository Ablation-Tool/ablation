"""
Cisco UCS 6500 Series Fabric Interconnect — UCSM / NX-OS RE findings
Source: ucs-6500-k9-bundle-infra.6.0.2b.A.bin
Cross-verified: ucs-x-direct-k9-infra.6.0.2b.A.bin ships identical ucsfi.10.5.1.I60.2b.F.bin payload
Format: Cisco SN header (magic d\\x01SN, 808 bytes for 6500 / 812 for X-Direct) + gzip tar
Payload: ucsfi.10.5.1.I60.2b.F.bin (mknbi-linux-1.2-6, 1515MB, 1589095936 bytes, same in both bundles)
  PE bootloader at 0x400
  gzip kernel at 0x3FB1 → x86-64 Linux ELF, statically linked, stripped
  gzip CPIO rootfs at 0x8EE800 (177MB NX-OS rootfs)
NX-OS version: 10.5.1.I60.2b.F
"""

FIRMWARE = {
    "target":      "Cisco UCS 6500 Series and X-Direct Fabric Interconnect — UCSM Management Plane",
    "nxos_ver":    "10.5.1.I60.2b.F",
    "source_pkg":  "ucs-6500-k9-bundle-infra.6.0.2b.A.bin",
    "also_in":     "ucs-x-direct-k9-infra.6.0.2b.A.bin (same ucsfi payload, identical byte count)",
    "payload":     "ucsfi.10.5.1.I60.2b.F.bin (mknbi-linux-1.2-6, 1515MB)",
    "rootfs":      "gzip CPIO at ucsfi offset 0x8EE800 (177MB)",
    "kernel":      "gzip x86-64 ELF at ucsfi offset 0x3FB1 — statically linked, stripped",
    "arch":        "x86-64, little-endian",
    "boot_modes":  ["NATIVE", "DOCKERS", "DOCKERC", "UCS", "CONVERGED_TOR"],
    "tmpfs_size":  "9048M — rootfs copied to tmpfs on boot",
    "codebase":    "Includes Andiamo Systems (2002) xinetd infrastructure — acquired by Cisco 2004",
    "findings":    ["UCSFI-F1", "UCSFI-F2", "UCSFI-F3", "UCSFI-F4", "UCSFI-F5",
                    "UCSFI-F6", "UCSFI-F7", "UCSFI-F8", "UCSFI-F9", "UCSFI-F10"],
}

# ─────────────────────────────────────────────────────────
# UCSFI-F1 — rlogin PAM: pam_permit.so sufficient = unconditional auth bypass
# ─────────────────────────────────────────────────────────
UCSFI_F1 = {
    "id":       "UCSFI-F1",
    "title":    "rlogin service active with pam_permit.so sufficient — unconditional authentication bypass for localhost callers",
    "status":   "CONFIRMED — /etc/pam.d/rlogin + /etc/xinetd.d/rlogin in UCSM 10.5.1 rootfs",
    "severity": "CRITICAL",

    "pam_config":    "/etc/pam.d/rlogin",
    "pam_auth_line": "auth    sufficient    pam_permit.so",
    "pam_note":      "pam_permit.so always returns PAM_SUCCESS; 'sufficient' exits the auth stack immediately. "
                     "All subsequent auth modules (securetty, rhosts, unix) are skipped. "
                     "Any caller reaching the daemon is granted access unconditionally.",

    "xinetd_config": {
        "service":   "login",
        "user":      "root",
        "server":    "/usr/sbin/in.rlogind",
        "disable":   "no",
        "only_from": "127.0.0.0/8",
        "server_args": "-o",
    },

    "attack_surface": "Restricted to 127.0.0.0/8 (localhost). Any local process can rlogin without credentials.",
    "privilege":      "rlogind spawns shell as the requested user; combined with root-trusted accounts in hosts.equiv enables root shell.",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F2 — rexec PAM: pam_permit.so sufficient = unconditional auth bypass
# ─────────────────────────────────────────────────────────
UCSFI_F2 = {
    "id":       "UCSFI-F2",
    "title":    "rexec service active with pam_permit.so sufficient — unconditional authentication bypass for localhost callers",
    "status":   "CONFIRMED — /etc/pam.d/rexec + /etc/xinetd.d/rexec in UCSM 10.5.1 rootfs",
    "severity": "CRITICAL",

    "pam_config":     "/etc/pam.d/rexec",
    "pam_auth_lines": [
        "auth    sufficient    pam_permit.so",
        "auth    required      pam_unix_auth.so shadow nullok",
    ],
    "pam_note": "First module pam_permit.so always succeeds; 'sufficient' exits the stack. "
                "Password check via pam_unix_auth.so is never reached. "
                "rexecd accepts any username+password combination from localhost.",

    "xinetd_config": {
        "service":   "exec",
        "user":      "root",
        "server":    "/usr/sbin/in.rexecd",
        "disable":   "no",
        "only_from": "127.0.0.0/8",
    },

    "attack_surface": "Restricted to 127.0.0.0/8. Any local process can execute arbitrary commands via rexecd without credentials.",
    "privilege":      "rexecd runs as root; command execution in the security context of the requested user.",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F3 — /etc/hosts.equiv wildcard: sup27/sup28 any-user trust
# ─────────────────────────────────────────────────────────
UCSFI_F3 = {
    "id":       "UCSFI-F3",
    "title":    "hosts.equiv grants wildcard user trust from supervisor module hostnames — any process on sup27/sup28 authenticates to rsh/rlogin without credentials",
    "status":   "CONFIRMED — /etc/hosts.equiv in UCSM 10.5.1 rootfs",
    "severity": "HIGH",

    "hosts_equiv_entries": [
        "sup27 root",
        "sup28 root",
        "sup27 admin",
        "sup28 admin",
        "sup27 +",
        "sup28 +",
        "sup27-18-slot root",
        "sup28-18-slot root",
        "sup27-18-slot admin",
        "sup28-18-slot admin",
        "sup27-18-slot +",
        "sup28-18-slot +",
    ],

    "wildcard_semantics": "The '+' user entry matches ALL users — any process on sup27 or sup28 is trusted unconditionally by pam_rhosts.so.",
    "csc_note":           "# CSCvh25047 — line card entries (lc1/lc2) were commented out by a prior bug fix; "
                          "supervisor entries remain active. Cisco acknowledged the risk class but applied a partial fix.",

    "affected_services": ["rsh", "rlogin"],
    "rsh_pam":           "/etc/pam.d/rsh uses pam_rhosts.so — hosts.equiv grants automatic auth pass.",
    "rlogin_pam":        "rlogin PAM bypasses rhosts entirely via pam_permit.so (see UCSFI-F1).",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F4 — rsync daemon on EOBC exposes SAM DB, core dumps, certificates
# ─────────────────────────────────────────────────────────
UCSFI_F4 = {
    "id":       "UCSFI-F4",
    "title":    "rsync daemon active on EOBC addresses exposes SAM database, core dumps, and certificate store read-only",
    "status":   "CONFIRMED — /isan/etc/rsyncd.conf + /etc/xinetd.d/rsync in UCSM 10.5.1 rootfs",
    "severity": "HIGH",

    "rsync_config": {
        "hosts_allow": ["127.12.0.1", "127.12.0.2", "127.12.0.100"],
        "max_connections": 5,
        "log_file": "/var/log/rsync.log",
    },

    "exposed_modules": {
        "samdb":            "/opt/db/flash (SAM Database — user credentials, management state)",
        "installables":     "/bootflash/installables (firmware images)",
        "distributables":   "/bootflash/distributables (CA images)",
        "certstore":        "/opt/certstore (CA certificates)",
        "techsupport":      "/workspace/techsupport/tmp (tech-support files — configs, logs)",
        "corefile":         "/bootflash/sysdebug/coremgmt/logs/tmp (process core dumps)",
        "debugplugin":      "/workspace/debug_plugin (UCS debug plugin)",
    },

    "access_control":   "All modules read only = yes; no auth configured in rsyncd.conf beyond hosts allow.",
    "eobc_addresses":   "127.12.0.x is Cisco EOBC (External Out-of-Band Channel) fabric — internal intra-chassis management network.",
    "key_risk":         "Core dumps at /bootflash/sysdebug/coremgmt/logs/tmp readable from EOBC — may contain in-memory credentials, session tokens, or key material from crashed processes.",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F5 — dcos_sshd PAM fallback: nullok when AAA unavailable
# ─────────────────────────────────────────────────────────
UCSFI_F5 = {
    "id":       "UCSFI-F5",
    "title":    "Custom SSH daemon (dcos_sshd) falls back to pam_unix.so nullok when AAA service is unavailable",
    "status":   "CONFIRMED — /etc/pam.d/dcos_sshd in UCSM 10.5.1 rootfs",
    "severity": "HIGH",

    "pam_config":  "/etc/pam.d/dcos_sshd",
    "pam_stack": [
        "auth   requisite  pam_nologin.so",
        "auth   required   pam_env.so",
        "auth   [authinfo_unavail=ignore auth_err=done success=done default=ok]  /isan/lib/libpam_aaa_auth.so",
        "auth   required   pam_unix.so nullok likeauth try_first_pass",
    ],

    "fallback_condition":  "authinfo_unavail=ignore — if libpam_aaa_auth.so cannot contact the AAA daemon, PAM continues to pam_unix.so",
    "nullok_implication":  "pam_unix.so nullok accepts accounts with empty password fields in /etc/passwd without a password",
    "ssh_binary":          "/isan/sbin/dcos_sshd (custom Cisco SSH daemon, not OpenSSH)",
    "xinetd_config":       {"server": "/isan/sbin/dcos_sshd", "server_args": "-i -f /isan/etc/dcos_sshd_config", "user": "root", "disable": "no"},
    "password_hash_algo":  "sha256 (from pam_unix.so ... shadow sha256 in password section — upgrade from MD5 used in nginx/dme-auth PAM)",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F6 — nginx/dme-auth PAM share identical configs; both fall back to nullok
# ─────────────────────────────────────────────────────────
UCSFI_F6 = {
    "id":       "UCSFI-F6",
    "title":    "nginx and dme-auth PAM configurations are identical files, both falling back to pam_unix.so nullok when UCSM AAA is unavailable",
    "status":   "CONFIRMED — /etc/pam.d/nginx == /etc/pam.d/dme-auth (identical content) in UCSM 10.5.1 rootfs",
    "severity": "HIGH",

    "pam_configs_identical": ["/etc/pam.d/nginx", "/etc/pam.d/dme-auth"],
    "shared_pam_stack": [
        "auth   [authinfo_unavail=ignore auth_err=done success=done default=ok]  /isan/lib/libpam_aaa_auth.so",
        "auth   required   pam_unix.so nullok likeauth try_first_pass",
    ],

    "services_affected": [
        "nginx — UCSM web management interface (HTTPS management plane)",
        "dme-auth — Data Management Engine (DME) auth layer (core UCSM data model)",
    ],

    "pam_module_delta": "nginx and dme-auth use libpam_aaa_auth.so; wbem uses libpam_aaa.so (different module). "
                        "If libpam_aaa_auth.so fails/exits for any reason, both the web UI and DME auth fall through to pam_unix.",

    "password_hash_algo": "pam_unix.so ... shadow md5 (web management plane uses MD5 for local password storage)",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F7 — ftpuser account bypasses FTP authentication
# ─────────────────────────────────────────────────────────
UCSFI_F7 = {
    "id":       "UCSFI-F7",
    "title":    "ftpuser system account listed in /etc/ftpusers.nopass — FTP access granted without password via pam_ftp.so sufficient",
    "status":   "CONFIRMED — /etc/pam.d/ftp + /etc/ftpusers.nopass in UCSM 10.5.1 rootfs",
    "severity": "MEDIUM",

    "ftpusers_nopass":  ["ftpuser"],
    "ftpusers_denied":  ["root", "nobody", "anonymous"],

    "pam_ftp_config": [
        "auth    required    pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=fail",
        "auth    sufficient  pam_ftp.so",
        "auth    required    pam_listfile.so item=user sense=allow file=/etc/ftpusers.nopass onerr=fail",
        "account required    pam_unix_acct.so",
        "session required    pam_limits.so",
    ],

    "pam_ftp_note":   "pam_ftp.so with 'sufficient' grants access to users in ftpusers.nopass without a password. "
                      "ftpuser (UID 16, GID 14) is a system-level account with home /var/ftp.",
    "ftp_server":     "/usr/sbin/in.ftpd --auth=pam",
    "bind_restrict":  "only_from = 127.0.0.0/8 — FTP limited to EOBC/loopback interfaces",
    "ftp_note":       "Comment in xinetd config states 'Make sure the FTP server can be used only by EOBC' — design intent is intra-chassis only.",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F8 — nginx DME backend runs as root
# ─────────────────────────────────────────────────────────
UCSFI_F8 = {
    "id":       "UCSFI-F8",
    "title":    "UCSM nginx DME backend process runs as root — any nginx exploit or path traversal grants root access",
    "status":   "CONFIRMED — /isan/etc/dme/nginx.tar.gz → nginx/conf/sysmgr_be_dme.conf in UCSM 10.5.1",
    "severity": "HIGH",

    "config_file":    "nginx/conf/sysmgr_be_dme.conf (extracted from /isan/etc/dme/nginx.tar.gz)",
    "user_directive": "user  root;",
    "note":           "The production UCSM nginx config (sysmgr_be_dme.conf) sets user=root. "
                      "This overrides the default nginx behavior of dropping privileges after bind. "
                      "Worker processes handle all API requests as root.",

    "load_module":    "/isan/lib/ngx_http_reqfwder_module.so",
    "module_routes":  ["/api/", "/api_local/"],
    "module_note":    "Custom closed-source module handles DME API routing. "
                      "Any vulnerability in ngx_http_reqfwder_module.so executes as root.",

    "master_process": "off — no master/worker privilege separation; single process runs as root.",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F9 — X-Real-IP trusted from 0.0.0.0/0 — IP access control bypass
# ─────────────────────────────────────────────────────────
UCSFI_F9 = {
    "id":       "UCSFI-F9",
    "title":    "nginx DME backend trusts X-Real-IP from any source — IP-based access controls can be spoofed",
    "status":   "CONFIRMED — nginx/conf/sysmgr_be_dme.conf in UCSM 10.5.1",
    "severity": "MEDIUM",

    "nginx_directives": [
        "set_real_ip_from 0.0.0.0/0;",
        "real_ip_header X-Real-IP;",
        "real_ip_recursive on;",
    ],

    "note": "set_real_ip_from 0.0.0.0/0 instructs nginx to replace $remote_addr with the X-Real-IP header value "
            "for connections from ANY source IP. If the upstream proxy or any inline component makes access decisions "
            "based on $remote_addr (e.g., restricting /api/ to management subnets), an attacker can override the "
            "apparent source IP by injecting X-Real-IP.",

    "cors_origin":   "Access-Control-Allow-Origin: http://127.0.0.1:8000 — globally applied to all responses.",
    "cors_headers":  "Access-Control-Allow-Headers includes 'devcookie' — non-standard auth header.",
}

# ─────────────────────────────────────────────────────────
# UCSFI-F10 — Visore DevCookie stored in localStorage; ACI codebase debug artifacts
# ─────────────────────────────────────────────────────────
UCSFI_F10 = {
    "id":       "UCSFI-F10",
    "title":    "UCSM REST API auth token stored in localStorage and sent as DevCookie header — XSS yields full API access; production JS contains debugger statement and commented eval with double-unescape",
    "status":   "CONFIRMED — nginx/html/visore/js/visore.js in UCSM 10.5.1",
    "severity": "MEDIUM",

    "auth_mechanism": {
        "login_endpoint":   "/api/aaaLogin.xml?gui-token-request=yes",
        "login_body":       "<aaaUser pwd='...' name='...'/>",
        "token_storage":    "localStorage['apic-cookie'] (not httpOnly cookie — XSS-readable)",
        "token_header":     "'DevCookie' : State.token  (sent with every API request)",
        "challenge_token":  "localStorage['apic-challenge'] (CSRF challenge token)",
    },

    "codebase_origin": "visore.html copyright: '(c) 2012-2013 Insieme Networks, Inc.' "
                       "Insieme was acquired by Cisco for ACI (~$863M, 2012). "
                       "The UCSM object model browser reuses ACI's Visore tool.",

    "debug_artifacts": {
        "debugger_statement":    "debugger; — active breakpoint in production JS path",
        "commented_eval":        "//eval('Resolver.' + lFunc)(lQuery ? unescape(unescape(lQuery)) : '')",
        "double_unescape_note":  "Commented eval with double-unescape of URL query param — if re-enabled: URL → double-decoded JS eval injection",
        "document_write_sink":   "layer.document.write('<p>' + text + '</p>') — unescaped text in document.write path",
    },

    "jquery_versions": ["jquery-ui-1.7.1 (2009)", "jquery-ui-1.10.4 (both present in CSS includes)"],
}

FINDINGS = [UCSFI_F1, UCSFI_F2, UCSFI_F3, UCSFI_F4, UCSFI_F5, UCSFI_F6, UCSFI_F7, UCSFI_F8, UCSFI_F9, UCSFI_F10]
