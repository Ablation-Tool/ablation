"""
Cisco UCS FI NX-OS SPM Layer RE

Target:  ucsfi.10.5.1.I60.2b.F.bin (1.5GB MBR disk image, FI 6.0.2b.A bundles)
         NX-OS base image for all FI 6400/6500/6600/x-direct variants
         SPM = Service Proxy Module; runs Apache HTTPD + SAM service + operations CGI
         Extracted: spm/ layer from ucsfi.bin MBR image
         Architecture: i686 NX-OS Linux base; custom PAM, custom Apache handlers
         Key components: httpd-common.conf, PAM stack, sudoers.defaults, connector_ctl.sh
         connector.db: SQLite, stores Intersight device connector credentials
Files:   spm/isan/apache/conf/extra/httpd-common.conf
         spm/isan/apache/operations/recvimage.cgi
         spm/isan/apache/operations/importconfig.cgi
         spm/isan/apache/operations/sendfile.cgi
         spm/etc/pam.d/sam_pam_proxy
         spm/etc/sudoers.defaults
         ficonn/bin/connector_ctl (shell script controlling ucsfi connector daemon)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi_nxos_spm_re",
    "firmware": "ucsfi.10.5.1.I60.2b.F.bin (NX-OS FI 6.0.2b.A, all FI 6400/6500/6600/x-direct variants)",
    "components": {
        "spm/isan/apache/conf/extra/httpd-common.conf": (
            "ScriptAliasMatch for 9 operations endpoints: recvimage.cgi, recvimagechunk.cgi, "
            "importconfig.cgi, sendfile.cgi (x3: /techsupport/, /corefile/, /backupfile/), "
            "cert.cgi (x3: /keyring/, /certreq/, /tp/); "
            "<Directory /isan/apache/operations>: SetHandler sam-cgi + Require all granted; "
            "Apache-level auth explicitly disabled for all operations CGI"
        ),
        "spm/isan/apache/operations/recvimage.cgi + importconfig.cgi": (
            "Perl CGI; recvimage.cgi: STDIN -> /bootflash/received/<file> up to 2GB; "
            "importconfig.cgi: STDIN -> /bootflash/received/<file> up to 1GB; "
            "filename sanitized to [a-zA-Z0-9_.-]; no auth logic in scripts; "
            "importconfig.cgi: open(INF, '$file') opens client filename as filehandle "
            "(data from STDIN regardless); dead filehandle, attacker path opened but not read"
        ),
        "spm/etc/pam.d/sam_pam_proxy": (
            "auth [authinfo_unavail=ignore auth_err=done success=done default=ok] "
            "/isan/lib/libpam_aaa_auth.so; "
            "auth required pam_unix.so nullok likeauth try_first_pass; "
            "account required pam_unix.so debug; "
            "nullok: empty password accepted if shadow entry is empty"
        ),
        "spm/etc/sudoers.defaults": (
            "Defaults env_keep += 'HOME SHELL SSH_CLIENT SSH_TTY LESSSECURE "
            "SYSMGR_VDC_ID UCSM_SESSION_LOCALES UCSM_SESSION_ROLES UCSM_IS_REMOTE_LOGIN'; "
            "UCSM_SESSION_ROLES and UCSM_SESSION_LOCALES preserved through sudo boundary"
        ),
        "ficonn/bin/connector_ctl (connector control script)": (
            "backup op: DISABLED; comment: 'connector db contains the devices un-encrypted "
            "access keys for authenticating with Intersight. As ucsm backup is currently "
            "weakly encrypted (with a fixed-key) removing the connector database from the "
            "backup to avoid security issues arising from the backup being misused/stolen.'; "
            "connector.db stores un-encrypted Intersight AccessKeyId and AccessKey; "
            "restore op: tar xzf $3 -C / (extract to filesystem root, no decryption, "
            "# TODO - decrypt comment present)"
        ),
    },
    "finding_count": "6F [0C+3H+2M+1L]",
    "cumulative": "855 [81C+294H+277M+202L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Operations CGI directory has Require all granted; Apache-level auth disabled for recvimage.cgi (2GB write to /bootflash/received/) and importconfig.cgi (1GB config write)",
        "description": (
            "spm/isan/apache/conf/extra/httpd-common.conf: "
            "<Directory /isan/apache/operations> block contains: "
            "'SetHandler sam-cgi' and 'Require all granted'. "
            "'Require all granted' is Apache mod_authz_core directive that unconditionally "
            "grants access, bypassing all Apache authentication modules. "
            "This covers all nine operations CGI endpoints served from that directory: "
            "recvimage.cgi (mapped from ^/operations/file-(.*)/image.txt), "
            "recvimagechunk.cgi (mapped from ^/operations/file-(.*)/(.*)imagechunk.txt), "
            "importconfig.cgi (mapped from ^/operations/file-(.*)/importconfig.txt), "
            "sendfile.cgi (mapped from /techsupport/, /corefile/, /backupfile/ prefixes), "
            "cert.cgi (mapped from /keyring/, /certreq/, /tp/ prefixes). "
            "recvimage.cgi accepts up to 2GB from STDIN and writes to "
            "/bootflash/received/<sanitized_filename>. "
            "importconfig.cgi accepts up to 1GB from STDIN and writes to "
            "/bootflash/received/<sanitized_filename>. "
            "Neither CGI script contains any auth logic -- they rely entirely on the "
            "sam-cgi handler in the Apache module layer. "
            "sam-cgi is a custom Apache handler (not Apache's standard mod_cgi). "
            "The explicit 'Require all granted' means Apache itself performs no auth "
            "before dispatching to sam-cgi, and sam-cgi's auth behavior is not "
            "verifiable from the httpd-common.conf configuration alone. "
            "/bootflash/received/ is the staging location for FI firmware upgrades "
            "and config imports; writing an arbitrary file to this directory with "
            "a .bin or .tgz extension positions it for use in the upgrade/restore flow."
        ),
        "evidence": {
            "file": "spm/isan/apache/conf/extra/httpd-common.conf",
            "config": (
                "<Directory /isan/apache/operations>\n"
                "    SetHandler sam-cgi\n"
                "    Require all granted\n"
                "</Directory>"
            ),
            "mapped_endpoints": (
                "recvimage.cgi -> ^/operations/file-(.*)/image.txt (2GB STDIN)\n"
                "importconfig.cgi -> ^/operations/file-(.*)/importconfig.txt (1GB STDIN)\n"
                "sendfile.cgi -> ^/techsupport/(.*), ^/corefile/(.*), ^/backupfile/(.*)\n"
                "cert.cgi -> ^/keyring/(.*), ^/certreq/(.*), ^/tp/(.*)"
            ),
        },
        "impact": (
            "Apache-level auth absent for all operations CGI endpoints. "
            "recvimage.cgi and importconfig.cgi write attacker data to /bootflash/received/. "
            "If sam-cgi provides no additional auth gate, unauthenticated firmware and config "
            "injection to FI bootflash is possible from any network-reachable host."
        ),
        "remediation": (
            "Replace 'Require all granted' with authentication requirements "
            "(Require valid-user or equivalent) in the operations directory block. "
            "Validate sam-cgi provides auth independent of Apache directives."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "connector_ctl backup disabled in source because UCSM backup uses fixed-key encryption; connector.db stores Intersight access keys unencrypted",
        "description": (
            "ficonn/bin/connector_ctl (shell script managing the ucsfi connector daemon): "
            "The 'backup' operation contains a comment explaining why connector.db is "
            "excluded from UCSM config backups: "
            "'Connector db contains the devices un-encrypted access keys for authenticating "
            "with Intersight. As ucsm backup is currently weakly encrypted (with a fixed-key) "
            "removing the connector database from the backup to avoid security issues arising "
            "from the backup being misused/stolen.' "
            "This comment is load-bearing: it confirms two independent findings: "
            "(1) connector.db stores Intersight AccessKeyId and AccessKey in plaintext "
            "(no per-record encryption, no symmetric key wrapping per the comment). "
            "(2) UCSM config backup encryption uses a hardcoded fixed key -- not a per-appliance "
            "or per-user key -- meaning any UCSM config backup can be decrypted by any party "
            "who knows or recovers the fixed key. "
            "The decision to exclude connector.db from backup is a compensating control, "
            "not a fix: it leaves Intersight access keys unprotected at rest on the FI filesystem "
            "and requires that UCSM backups never be restored to recover the connector state. "
            "connector.db path confirmed: /var/db/ucs/connector.db (ficonn working dir). "
            "tech_support operation strips AccessKeyId/AccessKey/Password from the connector.db "
            "copy via sed before including it in a tech support bundle, confirming the field names."
        ),
        "evidence": {
            "file": "ficonn/bin/connector_ctl",
            "comment": (
                "# Connector db contains the devices un-encrypted access keys for "
                "authenticating with Intersight. As ucsm backup is currently weakly "
                "encrypted (with a fixed-key) removing the connector database from "
                "the backup to avoid security issues arising from the backup being "
                "misused/stolen."
            ),
            "tech_support_strip": (
                "sed -e s/AccessKeyId.*/AccessKeyId/ "
                "-e s/AccessKey.*/AccessKey/ "
                "-e s/Password.*/Password/ connector.db"
            ),
        },
        "impact": (
            "Intersight access keys (AccessKeyId + AccessKey) stored unencrypted on FI filesystem. "
            "UCSM config backup encryption uses a fixed (not per-appliance) key -- "
            "any UCSM backup file is decryptable by any party with the fixed key."
        ),
        "remediation": (
            "Encrypt connector.db fields with a per-appliance key derived from hardware identity. "
            "Replace UCSM backup fixed-key encryption with per-backup key derivation or "
            "a user-supplied passphrase."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "connector_ctl restore executes tar xzf $3 -C / with no decryption and no path traversal validation on the input tarball",
        "description": (
            "ficonn/bin/connector_ctl 'restore' operation: "
            "'tar xzf $3 -C /'. "
            "$3 is the path to the tarball argument. "
            "The '-C /' flag directs tar to extract relative to the filesystem root. "
            "A tarball containing entries with relative paths such as "
            "'./etc/cron.d/backdoor' or './isan/bin/vsh' would be extracted to "
            "/etc/cron.d/backdoor or /isan/bin/vsh respectively. "
            "GNU tar does not strip leading path components by default -- "
            "path traversal via absolute or relative paths in the tarball archive is "
            "not mitigated. "
            "The script also contains '# TODO - decrypt' immediately above this line, "
            "confirming the intended design was to decrypt before extracting, "
            "and that the decryption step was never implemented. "
            "Consequence: a connector state restore from a malicious tarball (delivered "
            "via any management interface that can invoke connector_ctl restore) writes "
            "arbitrary files to the FI root filesystem as the connector daemon user. "
            "The connector daemon runs with elevated privileges (manages Vault tokens, "
            "device state, and Intersight credential material)."
        ),
        "evidence": {
            "file": "ficonn/bin/connector_ctl",
            "code": (
                "# TODO - decrypt\n"
                "# extract the tgz\n"
                "tar xzf $3 -C /"
            ),
        },
        "impact": (
            "Malicious tarball supplied to connector_ctl restore writes arbitrary files "
            "to / on the FI. Combined with elevated connector daemon privileges: "
            "arbitrary write to FI root filesystem via connector restore path."
        ),
        "remediation": (
            "Implement the TODO: add decryption with a verified key before extraction. "
            "Add '--strip-components=N' and a sandbox chroot or explicit prefix whitelist "
            "to prevent path traversal in the input archive."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "pam_unix.so nullok in sam_pam_proxy PAM stack; empty shadow password accepted for SAM proxy authentication",
        "description": (
            "spm/etc/pam.d/sam_pam_proxy PAM configuration: "
            "'auth required pam_unix.so nullok likeauth try_first_pass'. "
            "The 'nullok' option to pam_unix.so enables authentication with an empty password "
            "when the /etc/shadow entry for the user has no password hash (empty field). "
            "sam_pam_proxy is the PAM service used by the SAM proxy daemon "
            "for authenticating management-plane requests. "
            "The auth stack is: "
            "(1) libpam_aaa_auth.so (Cisco AAA module) with flags "
            "[authinfo_unavail=ignore auth_err=done success=done default=ok]; "
            "(2) pam_unix.so nullok as required fallback. "
            "If libpam_aaa_auth.so is unavailable (returns authinfo_unavail) or returns "
            "the default=ok path, execution falls through to pam_unix.so nullok. "
            "Any local account on the FI with an empty shadow password field -- "
            "including service accounts created during FI initialization or leftover "
            "from firmware upgrades -- can authenticate to the SAM proxy with no password. "
            "pam_unix.so account module includes 'debug', logging auth activity to syslog "
            "but not blocking empty-password auth."
        ),
        "evidence": {
            "file": "spm/etc/pam.d/sam_pam_proxy",
            "config": (
                "auth [authinfo_unavail=ignore auth_err=done success=done default=ok] "
                "/isan/lib/libpam_aaa_auth.so\n"
                "auth required pam_unix.so nullok likeauth try_first_pass\n"
                "account required pam_unix.so debug"
            ),
        },
        "impact": "Local accounts with empty shadow entries authenticate to SAM proxy with no password.",
        "remediation": "Remove 'nullok' from pam_unix.so in sam_pam_proxy. Audit all local FI accounts for empty shadow entries.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "UCSM_SESSION_ROLES and UCSM_SESSION_LOCALES preserved through sudo boundary via sudoers env_keep; session role context crosses privilege boundary",
        "description": (
            "spm/etc/sudoers.defaults: "
            "'Defaults env_keep += \"HOME SHELL SSH_CLIENT SSH_TTY LESSSECURE "
            "SYSMGR_VDC_ID UCSM_SESSION_LOCALES UCSM_SESSION_ROLES UCSM_IS_REMOTE_LOGIN\"'. "
            "UCSM_SESSION_ROLES and UCSM_SESSION_LOCALES are UCSM-specific environment "
            "variables that encode the authenticated user's role set and locale for the "
            "current management session. "
            "sudo's env_keep directive preserves these variables through privilege escalation "
            "into the target (root) execution context. "
            "UCSM management plane components that read UCSM_SESSION_ROLES to make "
            "authorization decisions (role-based access, feature gates, audit logging) "
            "will observe whatever role string was present in the calling user's environment -- "
            "including a role string forged or injected before the sudo call. "
            "A low-privilege UCSM session that can execute sudo-enabled commands can "
            "set UCSM_SESSION_ROLES='network-admin' in the environment before invoking sudo, "
            "and any target binary that trusts UCSM_SESSION_ROLES will see elevated roles "
            "even though the sudo grant may be limited to a specific command. "
            "SYSMGR_VDC_ID (virtual device context ID) is also preserved, "
            "enabling VDC context confusion across the privilege boundary."
        ),
        "evidence": {
            "file": "spm/etc/sudoers.defaults",
            "env_keep": (
                "UCSM_SESSION_LOCALES UCSM_SESSION_ROLES UCSM_IS_REMOTE_LOGIN SYSMGR_VDC_ID"
            ),
        },
        "impact": (
            "Forged UCSM_SESSION_ROLES survives sudo into root context. "
            "Management plane binaries that authorize based on this variable "
            "observe attacker-supplied role strings."
        ),
        "remediation": (
            "Remove UCSM_SESSION_ROLES, UCSM_SESSION_LOCALES, UCSM_IS_REMOTE_LOGIN, "
            "and SYSMGR_VDC_ID from sudoers env_keep. "
            "Re-derive session roles from authenticated session state, not environment variables, "
            "in any binary that makes authorization decisions."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "importconfig.cgi opens client-supplied filename as a filehandle (open INF, '$file') but reads data exclusively from STDIN; dead filehandle on attacker-controlled path",
        "description": (
            "spm/isan/apache/operations/importconfig.cgi (Perl CGI): "
            "Accepts a 'filename' CGI parameter from the HTTP client. "
            "The script opens: 'open(INF, \"$file\")' where $file is the client-supplied "
            "filename parameter. "
            "The actual import data is read from STDIN (the HTTP body), not from INF. "
            "The open(INF, ...) filehandle is never read -- INF is a dead handle. "
            "The Perl open() call with a two-argument form and no mode prefix will: "
            "- Open a file for reading if $file is a plain path. "
            "- Execute a shell command and pipe its output if $file ends with '|'. "
            "- Run a command and pipe input to it if $file begins with '|'. "
            "In the two-argument form, a $file value of '| /bin/sh -c cmd' or 'cmd |' "
            "triggers command execution in the Apache process context. "
            "The filehandle result is never used, meaning this is either dead code from "
            "a refactored implementation or an unintentional artifact. "
            "The open() call itself still executes, so command injection via the filename "
            "parameter is possible even though the handle output is discarded. "
            "Filename sanitization in the final write path ([a-zA-Z0-9_.-]) does not "
            "apply to the open(INF, '$file') call -- that call uses the raw CGI parameter."
        ),
        "evidence": {
            "file": "spm/isan/apache/operations/importconfig.cgi",
            "dead_call": "open(INF, \"$file\") -- $file is client CGI param, INF never read",
            "data_source": "read(STDIN, $buf, BUFSIZE) -- actual data from HTTP body",
            "two_arg_risk": "open(INF, '| cmd') executes cmd in Apache process context",
        },
        "impact": (
            "Two-argument Perl open() with unsanitized client input enables command injection "
            "in the Apache worker process context via the filename CGI parameter."
        ),
        "remediation": (
            "Remove the open(INF, '$file') call -- the filehandle is unused and the call is dead code. "
            "If a filename parameter is needed, validate with an allowlist before any open() call. "
            "Use three-argument open() form: open(INF, '<', $file) to prevent command injection."
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
