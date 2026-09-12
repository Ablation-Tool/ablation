"""
Cisco UCS FI NX-OS Backup/Restore/Upgrade Infrastructure RE

Target:  ucsfi.10.5.1.I60.2b.F.bin (1.5GB MBR disk image, FI 6.0.2b.A bundles)
         Same NX-OS image as cisco_ucs_fi_nxos_spm_re; different component set:
         backup/restore pipeline, connector upgrade, log export infrastructure
         Architecture: i686 NX-OS Linux, UCSM service layer scripts + exec wrapper ELF
Key files: spm/isan/bin/samcrypt.sh (AES-256 UCSM config backup encryption)
           spm/isan/bin/log_export_ctrl.sh (log export config + passphrase)
           spm/isan/bin/initial_restore_lib (UCSM restore pipeline library)
           spm/isan/bin/sam_restore_check.sh (peer SSH restore validation)
           spm/isan/bin/exec_sam_upgrade (ELF upgrade wrapper, i686 PIE)
           ficonn/install-connector.sh (connector upgrade script)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi_nxos_backup_re",
    "firmware": "ucsfi.10.5.1.I60.2b.F.bin (NX-OS FI 6.0.2b.A, all FI 6400/6500/6600/x-direct)",
    "components": {
        "spm/isan/bin/samcrypt.sh (UCSM backup AES-256 encrypt/decrypt)": (
            "encrypt op: ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-); "
            "/isan/bin/openssl enc -in $in -out $out -e -aes256 -pass pass:${ENC_KEY}; "
            "generatehash op: echo -n ${ENC_KEY} | /usr/bin/sha512sum > ${path}/verification.data; "
            "decrypt op: passkey=$3 (positional arg); "
            "KEY_VALUE is the only source of the backup encryption key -- from process environment"
        ),
        "spm/isan/bin/initial_restore_lib (UCSM restore pipeline)": (
            "prepare(): keyfile=/tmp/key.config; KEY=`cat $keyfile`; "
            "restore $restore_file $KEY; $RM $RMFLAGS $keyfile; KEY=''; "
            "validatekey(): cat '/tmp/key.config' for SHA512 comparison + decryptData call; "
            "KEY passed as positional arg to restore() -> decryptData $file $out $key; "
            "decryptData: openssl enc -d -aes256 -pass pass:${passkey}"
        ),
        "spm/isan/bin/sam_restore_check.sh (expect peer SSH validation)": (
            "Usage: $0 <peer_ip> <admin_passwd>; "
            "admin_passwd=$argv[1] (CLI arg, ps-visible); "
            "expect script: send 'yes\\r' to 'The authenticity' (no host key check); "
            "send admin_passwd to Password: prompt"
        ),
        "spm/isan/bin/exec_sam_upgrade (i686 PIE ELF upgrade wrapper)": (
            "BuildID: 055ffda6173ad760715728692fd0cb03d7095820; "
            "symbols: setuid, setgid, execl, fork, chdir, dup2, setsid, access, strtol; "
            "0x1246: push $0x0 -> call setuid@plt; "
            "0x124d: movl $0x0,(%esp) -> call setgid@plt; "
            "0x1a33: call execl@plt; "
            "no observable credential or capability check before setuid(0)+setgid(0)"
        ),
        "ficonn/install-connector.sh (connector install/upgrade script)": (
            "compareVersion(): if [[ ${1:0:5} == '0.1.0' ]]; then return 1; fi "
            "(return 1 = incoming > existing = upgrade allowed); "
            "comment: 'If incoming version is a development override the version check'; "
            "any version string starting with '0.1.0' bypasses downgrade protection"
        ),
        "spm/isan/bin/log_export_ctrl.sh (log export configuration)": (
            "LOG_EXPORT_SSH_ID_FILE=${LOG_EXPORT_SSH_DIR}/id_rsa; "
            "passphrase: ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-); "
            "echo -n ${ENC_KEY} | /usr/bin/sha512sum | tr -d ' ' > $LOG_EXPORT_PASS_PHRASE_FILE; "
            "log export SSH key + passphrase both derived from same KEY_VALUE backup key material"
        ),
    },
    "finding_count": "6F [0C+2H+3M+1L]",
    "cumulative": "861 [81C+296H+280M+203L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "samcrypt.sh derives UCSM backup AES-256 encryption key exclusively from KEY_VALUE environment variable; no static key or KDF -- all backup protection depends on environment secrecy",
        "description": (
            "spm/isan/bin/samcrypt.sh encrypt and generatehash operations: "
            "'ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-)'. "
            "The AES-256 key used for UCSM config backup encryption is sourced entirely from "
            "the KEY_VALUE environment variable of the samcrypt.sh process. "
            "There is no static hardcoded key, no PBKDF2/HKDF derivation from a master secret, "
            "and no hardware-bound key material in the script. "
            "The security of every UCSM config backup (dme.db.crypt, certstore, sam.config.crypt) "
            "depends entirely on KEY_VALUE being present in the environment and not being readable "
            "by co-resident processes. "
            "From cisco_ucs_fi_bundle_602b_re F3 (same firmware layer): svc_sam_dme reads "
            "/proc/*/environ to extract KEY_VALUE -- the key is recoverable from any process "
            "that can read the DME process environment. "
            "connector_ctl.sh backup comment (cisco_ucs_fi_nxos_spm_re F2): "
            "'ucsm backup is currently weakly encrypted (with a fixed-key)' -- the comment "
            "describes KEY_VALUE as a fixed key, meaning it is not rotated per backup. "
            "log_export_ctrl.sh also reads KEY_VALUE and uses SHA512(ENC_KEY) as the log export "
            "passphrase, binding log export security to the same key material as backup."
        ),
        "evidence": {
            "file": "spm/isan/bin/samcrypt.sh",
            "encrypt_key": "ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-)",
            "openssl_call": "/isan/bin/openssl enc -in $in -out $out -e -aes256 -pass pass:${ENC_KEY}",
            "log_export_link": "log_export_ctrl.sh: ENC_KEY=$(env | grep KEY_VALUE ...) -> SHA512(ENC_KEY) = log passphrase",
        },
        "impact": (
            "AES-256 backup encryption key is a fixed env variable readable from process space. "
            "Recovery of KEY_VALUE (via /proc/*/environ or memory forensics) decrypts all "
            "UCSM config backups and log export material from the fleet."
        ),
        "remediation": (
            "Derive per-backup keys using HKDF with a hardware-bound root key and a per-backup nonce. "
            "Remove KEY_VALUE from the process environment; use a sealed key store or Vault transit API."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "initial_restore_lib stores UCSM backup decryption key in /tmp/key.config during restore operations; world-readable tmp path, race window, and key passed as CLI arg",
        "description": (
            "spm/isan/bin/initial_restore_lib prepare() function: "
            "'keyfile=/tmp/key.config; KEY=`cat $keyfile`; restore $restore_file $KEY'. "
            "/tmp/ is world-readable on NX-OS Linux (mode 1777 sticky bit, readable by all users). "
            "During the restore window (from when /tmp/key.config is written to when it is removed "
            "with '$RM $RMFLAGS $keyfile'), any co-resident process or local user can read "
            "the backup decryption key from /tmp/key.config. "
            "The key is then passed as a positional argument to restore() which calls "
            "'decryptData $file $out $key' with 'openssl enc -d -aes256 -pass pass:${passkey}'. "
            "CLI argument passing makes the key visible in /proc/<pid>/cmdline and process listings "
            "for the duration of the openssl call. "
            "validatekey() also reads the key directly from /tmp/key.config: "
            "'decryptData ... `cat \"/tmp/key.config\"`' -- a second exposure point. "
            "The RM call that deletes /tmp/key.config is in the prepare() success path but "
            "may not execute if restore() fails early (error exits do not guarantee cleanup). "
            "There is no mkstemp()/O_EXCL creation -- the filename is fixed, enabling "
            "a symlink attack: a local attacker creates /tmp/key.config -> /etc/passwd "
            "before the restore starts to redirect the key write."
        ),
        "evidence": {
            "file": "spm/isan/bin/initial_restore_lib lines 354-360",
            "key_path": "/tmp/key.config (fixed filename, /tmp world-readable)",
            "prepare_flow": (
                "keyfile=/tmp/key.config\n"
                "KEY=`cat $keyfile`\n"
                "restore $restore_file $KEY\n"
                "$RM $RMFLAGS $keyfile"
            ),
            "validate_flow": "decryptData ... `cat \"/tmp/key.config\"`",
        },
        "impact": (
            "UCSM backup decryption key in /tmp/key.config readable by any co-resident process "
            "during restore window. Key also exposed in ps/cmdline during openssl decrypt calls. "
            "Fixed filename enables symlink attack to redirect key material."
        ),
        "remediation": (
            "Use a Unix domain socket or sealed pipe to pass the key to the decrypt process. "
            "If a file is necessary, use mkstemp() with mode 0600. "
            "Wipe the file in an ERR trap, not just the success path."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "sam_restore_check.sh passes admin password as CLI positional arg visible in ps; expect script sends 'yes' to unknown SSH host key without verification",
        "description": (
            "spm/isan/bin/sam_restore_check.sh (expect script): "
            "Usage: '$0 <peer_ip> <admin_passwd>'. "
            "admin_passwd is $argv[1] -- the second command line argument. "
            "Command line arguments are visible in /proc/<pid>/cmdline to any user "
            "who can access the process listing, and are logged by process accounting. "
            "The admin password for the peer FI is in the clear for the duration of the "
            "expect session. "
            "SSH host key validation: the expect script handles 'The authenticity' prompt "
            "(SSH's unknown-host-key message) by unconditionally sending 'yes\\r': "
            "'\"The authenticity \" { send \"yes\\r\"; sleep 1; expect { \"Password:\" { ... } } }'. "
            "This is equivalent to StrictHostKeyChecking=no -- an attacker who can ARP-spoof "
            "the peer FI's IP receives the admin password without triggering any warning. "
            "The script also falls back to reading from /tmp/tp if it exists: "
            "'if {[file exists $authFile]} { login }' where authFile=/tmp/tp. "
            "/tmp/tp is another fixed-path file in /tmp; an attacker who creates /tmp/tp "
            "first can influence the password sent by intercepting the auth flow."
        ),
        "evidence": {
            "file": "spm/isan/bin/sam_restore_check.sh",
            "cli_arg": "set admin_passwd [lindex $argv 1] -- CLI arg, visible in ps",
            "host_key_bypass": "\"The authenticity \" { send \"yes\\r\" } -- unconditional yes",
            "fallback_path": "/tmp/tp (fixed path, attacker-writeable before script runs)",
        },
        "impact": (
            "Admin password for peer FI visible in process listing during peer restore check. "
            "SSH host key bypass enables admin credential harvest via ARP spoofing of peer IP."
        ),
        "remediation": (
            "Pass credentials via a file descriptor or stdin pipe, not CLI args. "
            "Use ssh -o StrictHostKeyChecking=yes with a pre-enrolled known_hosts entry. "
            "Use a unique path for the auth token file, not /tmp/tp."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "exec_sam_upgrade calls setuid(0)+setgid(0)+execl with no observable credential or capability check; unconditional root execution chain in upgrade wrapper",
        "description": (
            "spm/isan/bin/exec_sam_upgrade (i686 PIE ELF, BuildID 055ffda6173ad760715728692fd0cb03d7095820): "
            "Disassembly shows: "
            "0x1246: push $0x0; call setuid@plt (setuid(0)) -- set UID to root. "
            "0x124d: movl $0x0,(%esp); call setgid@plt (setgid(0)) -- set GID to root. "
            "0x1a33: call execl@plt -- exec a new process as root. "
            "Imported symbols: setuid, setgid, execl, fork, chdir, dup2, setsid, access, "
            "strtol, strncpy, sigaction, sigprocmask. "
            "The strtol + strncpy imports suggest argument parsing before the execl. "
            "No symbols present that indicate an auth check (no pam_authenticate, "
            "no getpwnam/shadow read, no capability check via cap_get_proc). "
            "access() is imported -- it checks file existence/permission, "
            "not user authentication. "
            "The binary transitions directly from argument parsing to setuid(0)/setgid(0)/execl. "
            "If exec_sam_upgrade is deployed with SUID root on the FI filesystem "
            "or called from a management interface accessible to non-admin roles, "
            "any caller can execute arbitrary commands as root via the execl path."
        ),
        "evidence": {
            "file": "spm/isan/bin/exec_sam_upgrade",
            "disasm": (
                "0x1246: push $0x0 -> call setuid@plt\n"
                "0x124d: movl $0x0,(%esp) -> call setgid@plt\n"
                "0x1a33: call execl@plt"
            ),
            "missing_symbols": "no pam_authenticate, no cap_get_proc, no shadow read",
        },
        "impact": (
            "Unconditional setuid(0)+setgid(0) before execl with no auth gate. "
            "If accessible from a non-admin context or deployed SUID, full root execution. "
            "Argument parsing (strtol/strncpy) before execl may allow command injection "
            "via the argument passed to the wrapper."
        ),
        "remediation": (
            "Add an explicit capability check or PAM auth before setuid(0)/setgid(0). "
            "Constrain execl target to a fixed path allowlist. "
            "Audit SUID deployment of this binary on FI filesystem."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "install-connector.sh version check bypassed by any connector package with version string matching '0.1.0*'; hardcoded dev version pattern allows downgrade/sidegrade",
        "description": (
            "ficonn/install-connector.sh compareVersion() function: "
            "'if [[ ${1:0:5} == '0.1.0' ]]; then return 1; fi' "
            "(before any numeric comparison is performed). "
            "The comment on the preceding line: 'If incoming version is a development override "
            "the version check'. "
            "compareVersion() return value semantics: "
            "return 0 = versions equal, return 1 = incoming newer, return 2 = incoming older. "
            "Returning 1 when the first 5 chars of the new version are '0.1.0' means "
            "the validation check reports 'incoming is newer' for ANY version starting with '0.1.0', "
            "regardless of the currently installed version. "
            "A malicious connector package signed (or unsigned -- no signature check evident "
            "in install-connector.sh) with version '0.1.0-malicious' will be accepted for "
            "install by upgrade() since validate_upgrade() calls compareVersion() and returns 0 "
            "(proceed). "
            "This bypasses the downgrade protection that would otherwise prevent installing "
            "an older or attacker-controlled connector version. "
            "The connector (ucsfi_dc) is the Intersight device connector -- it manages Vault "
            "tokens, Intersight access keys, and cluster state. "
            "A downgraded connector can expose older CVEs or remove security hardening."
        ),
        "evidence": {
            "file": "ficonn/install-connector.sh line 154",
            "bypass": "if [[ ${1:0:5} == '0.1.0' ]]; then return 1; fi",
            "comment": "# If incoming version is a development override the version check",
            "consequence": "any version 0.1.0.* is treated as newer than any installed version",
        },
        "impact": (
            "Attacker-supplied connector package with version 0.1.0.* bypasses version gate "
            "and installs unconditionally over any running connector version."
        ),
        "remediation": (
            "Remove the 0.1.0 dev override from production code. "
            "If dev override is necessary, gate on a build flag set only in non-production images."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "log_export_ctrl.sh derives log export passphrase as SHA512(ENC_KEY) written to a file; ties log export security to backup key material",
        "description": (
            "spm/isan/bin/log_export_ctrl.sh: "
            "'ENC_KEY=$(env | grep KEY_VALUE | cut -d= -f2-)' "
            "'echo -n ${ENC_KEY} | /usr/bin/sha512sum | tr -d \" \" > $LOG_EXPORT_PASS_PHRASE_FILE'. "
            "The log export passphrase is SHA512(KEY_VALUE), where KEY_VALUE is the same "
            "backup encryption key used by samcrypt.sh (F1). "
            "SHA512 is a one-way hash -- SHA512(ENC_KEY) is not directly reversible to ENC_KEY. "
            "However, the passphrase is written to $LOG_EXPORT_PASS_PHRASE_FILE (a file in the "
            "log export config directory), and log export also creates an SSH private key at "
            "$LOG_EXPORT_SSH_ID_FILE (id_rsa path). "
            "Consequence: (1) All logs exported from the FI are encrypted with a passphrase "
            "derived from the backup key -- an attacker who knows KEY_VALUE can derive the "
            "log export passphrase and decrypt all exported FI logs; "
            "(2) The log export passphrase file and id_rsa are generated in the same directory "
            "and share the lifecycle of the log export config; "
            "(3) Key reuse across contexts (backup + log) means compromise of KEY_VALUE "
            "has broader impact than backup decryption alone."
        ),
        "evidence": {
            "file": "spm/isan/bin/log_export_ctrl.sh",
            "passphrase": "echo -n ${ENC_KEY} | /usr/bin/sha512sum | tr -d ' ' > $LOG_EXPORT_PASS_PHRASE_FILE",
            "ssh_key": "LOG_EXPORT_SSH_ID_FILE=${LOG_EXPORT_SSH_DIR}/id_rsa",
            "key_source": "ENC_KEY from KEY_VALUE env var (same as samcrypt.sh F1)",
        },
        "impact": (
            "Recovery of KEY_VALUE decrypts UCSM backups (F1) and allows derivation "
            "of the log export passphrase (SHA512 is deterministic from the key). "
            "Single key material compromise has cross-subsystem impact."
        ),
        "remediation": (
            "Generate a log export passphrase independently of the backup key. "
            "Use separate key derivation contexts (HKDF with purpose labels) for each subsystem."
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
