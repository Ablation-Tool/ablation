"""
Cisco UCS FI NX-OS Firmware Activation and Security Configuration RE

Target:  ucsfi.10.5.1.I60.2b.F.bin (1.5GB MBR disk image, FI 6.0.2b.A bundles)
         Same NX-OS image; this module covers firmware activation, cluster join,
         and FI security configuration (FIPS, shadow, log permissions)
Key files: spm/isan/bin/sp_activatefw.sh (service pack firmware activation)
           spm/isan/bin/cluster_add.sh (HA cluster join expect script)
           spm/isan/bin/sam_activatefw_helper.sh (post-activation config restore)
           spm/isan/bin/modify_fips_mode.sh (FIPS enable/disable)
           spm/isan/bin/cinitial-setup.sh (container initial setup)
           spm/isan/bin/sp_upgrade_helper.sh (service pack upgrade orchestrator)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi_nxos_activation_re",
    "firmware": "ucsfi.10.5.1.I60.2b.F.bin (NX-OS FI 6.0.2b.A, all FI 6400/6500/6600/x-direct)",
    "components": {
        "spm/isan/bin/cluster_add.sh (expect cluster join)": (
            "Usage: $0 <peer_ip> <peer_serial> <admin_passwd>; "
            "admin_passwd=lindex $argv 2 (CLI arg, ps-visible); "
            "SSH host key bypass: send 'yes\\r' to 'The authenticity'; "
            "/tmp/tp fallback auth path (same as sam_restore_check.sh)"
        ),
        "spm/isan/bin/sp_activatefw.sh (service pack activation)": (
            "ttysuffix=`tty|tr '/' '_'`; "
            "cmdscriptfile=/tmp/actspfirmwarecmds$ttysuffix; "
            "peerswitchstatusfile=/tmp/other_sp_update_status$ttysuffix; "
            "flow: rm -f $cmdscriptfile -> echo commands > cmdscriptfile "
            "-> eval $UCSSHELL -f $cmdscriptfile -p admin; "
            "race window between rm and write at fixed-TTY /tmp path"
        ),
        "spm/isan/bin/sam_activatefw_helper.sh (post-activation config)": (
            "chmod 640 /etc/shadow (comment: 'Handle downgrade/upgrade scenario'); "
            "sam_startup_main.sh later sets shadow to 600 (only on UCSM restart); "
            "ln -sf /isan/plugin/0/isan/bin/vsh_perm ${UCS_ISAN_CMD_VSH_PERM} "
            "(re-links vsh_perm on every activation); "
            "modify_fips_mode.sh disable (unconditional during activation)"
        ),
        "spm/isan/bin/modify_fips_mode.sh disable path": (
            "RM -f ${FIPS_CONFIG_FILE} (removes FIPS enabled marker); "
            "config_file=/tmp/fips_config_file_disable (fixed /tmp path); "
            "echo 'no fips mode enable' > $config_file -> $VSHBIN -r $config_file; "
            "FIPS_CONFIG_FILE=/mnt/pss/fips_enabled"
        ),
        "spm/isan/bin/cinitial-setup.sh (container initial setup)": (
            "chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.klog; "
            "chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.log; "
            "(UCSM controller logs set to world-writable)"
        ),
        "spm/isan/bin/sp_upgrade_helper.sh (service pack upgrade)": (
            "SP_RESTORE_IMAGE_CAT=/tmp/sp_restore_image.cat; "
            "SP_DELETE_FILES_CAT=/tmp/sp_delete_files.cat; "
            "fixed /tmp paths for restore catalog and file deletion list"
        ),
    },
    "finding_count": "6F [0C+1H+3M+2L]",
    "cumulative": "873 [81C+299H+286M+206L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "cluster_add.sh passes admin password as CLI positional arg visible in ps; sends 'yes' to unknown SSH host key; same /tmp/tp auth fallback as restore_check.sh",
        "description": (
            "spm/isan/bin/cluster_add.sh (expect script, 135 lines): "
            "Usage: '$0 <peer_ip> <peer_serial> <admin_passwd>'. "
            "admin_passwd is '$argv[2]' -- the third command line argument. "
            "Command line arguments are visible in /proc/<pid>/cmdline to local users "
            "and in process listing to any user with ps access. "
            "The admin password for the peer FI is in the clear for the duration of "
            "the expect session during cluster join. "
            "SSH host key bypass: the script handles 'The authenticity' host key prompt "
            "by unconditionally sending 'yes\\r', identical to the pattern in "
            "sam_restore_check.sh (cisco_ucs_fi_nxos_backup_re F3). "
            "An attacker who can ARP-spoof the peer FI's IP at cluster join time "
            "receives the admin password without triggering any warning. "
            "Auth fallback to /tmp/tp: "
            "'if {[file exists $authFile]} { login }' where authFile='/tmp/tp'. "
            "If /tmp/tp exists, it supersedes the admin_passwd argument. "
            "A local attacker who creates /tmp/tp before cluster_add.sh runs can "
            "control what password is sent to the peer SSH, enabling auth to a "
            "compromised peer or redirecting auth to a spoofed host."
        ),
        "evidence": {
            "file": "spm/isan/bin/cluster_add.sh lines 33-40",
            "cli_arg": "set admin_passwd [lindex $argv 2] -- third CLI arg, ps-visible",
            "host_key_bypass": "\"The authenticity \" { send \"yes\\r\" }",
            "fallback": "set authFile \"/tmp/tp\" -- fixed-path pre-auth takeover",
        },
        "impact": (
            "Admin password for peer FI exposed in process listing during cluster join. "
            "SSH host key bypass enables admin credential exfiltration via ARP spoof. "
            "Pre-created /tmp/tp overrides the password argument entirely."
        ),
        "remediation": (
            "Pass credentials via stdin pipe or file descriptor, not CLI args. "
            "Use SSH certificates with StrictHostKeyChecking=yes for cluster join auth. "
            "Delete /tmp/tp if it exists before using it as an auth file."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "sp_activatefw.sh writes UCSM CLI command script to /tmp with TTY-derived filename; eval executes it without integrity check; race window between rm and write",
        "description": (
            "spm/isan/bin/sp_activatefw.sh: "
            "'ttysuffix=`tty|tr '/' '_'`' -- suffix derived from the current TTY path. "
            "For TTY /dev/pts/0, ttysuffix='_dev_pts_0'. "
            "'cmdscriptfile=/tmp/actspfirmwarecmds$ttysuffix' -- script built in /tmp. "
            "Execution flow: "
            "(1) 'rm -f $cmdscriptfile' -- remove any existing file. "
            "(2) 'echo $scopesystem_clisyntax > $cmdscriptfile' -- write CLI commands. "
            "(3) 'echo $actfw_clisyntax $newversion >> $cmdscriptfile' -- append. "
            "(4) 'cmd=\"$UCSSHELL -f $cmdscriptfile -p admin\"' -- build command. "
            "(5) 'eval $cmd | grep -v ...' -- execute UCSM shell with the file as input. "
            "Race window: between the rm (step 1) and the first write (step 2), "
            "another process on the FI can create $cmdscriptfile with malicious content. "
            "If the attacker's file is created before step 2, step 2 overwrites it. "
            "The usable window is between rm and the open() in step 2's redirection. "
            "The file is also created in /tmp/ (world-writable, sticky bit), "
            "but the sticky bit prevents other users from deleting the file "
            "unless they own it -- it does not prevent creation before the script. "
            "Additionally: $newversion (the firmware version string) is passed "
            "to actfw_clisyntax and written to the CLI script -- if $newversion "
            "contains NXOS CLI injection characters (semicolons, newlines), "
            "additional CLI commands can be injected into the script file "
            "if version validation is absent."
        ),
        "evidence": {
            "file": "spm/isan/bin/sp_activatefw.sh lines 29-31, 151-161",
            "tty_derived": "ttysuffix=`tty|tr '/' '_'`; cmdscriptfile=/tmp/actspfirmwarecmds$ttysuffix",
            "race": "rm -f $cmdscriptfile -> [window] -> echo commands > $cmdscriptfile",
            "exec": "eval $UCSSHELL -f $cmdscriptfile -p admin",
        },
        "impact": (
            "Pre-creation of /tmp/actspfirmwarecmds<tty> before sp_activatefw.sh runs "
            "injects arbitrary UCSM CLI commands executed under the admin profile (-p admin). "
            "Version string injection enables UCSM CLI command injection if $newversion "
            "is not sanitized before being written to the script file."
        ),
        "remediation": (
            "Use mkstemp() or a process-unique temp path (e.g., /tmp/.$$.tmp) "
            "rather than a TTY-derived filename. "
            "Validate $newversion against a strict version-string regex before use."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "sam_activatefw_helper.sh sets /etc/shadow to 640 during firmware activation; persists until UCSM restart; shadow group members can read password hashes",
        "description": (
            "spm/isan/bin/sam_activatefw_helper.sh: "
            "'$SUDO chmod 640 /etc/shadow' with comment: "
            "'Handle downgrade/upgrade scenario, change /etc/shadow permissions back to 640'. "
            "Mode 640 means: owner root (read/write), group shadow (read-only), others none. "
            "Members of the shadow group on the FI can read /etc/shadow and access "
            "all UCSM user account password hashes while this mode is in effect. "
            "The correct permission is 600 (owner-only read): "
            "sam_startup_main.sh references CSCtf23195 ('shadow permissions too open') "
            "and sets 'chmod 600 /etc/shadow' -- but sam_startup_main.sh runs at UCSM startup, "
            "not immediately after activation. "
            "Timeline: "
            "(1) Firmware activation runs sam_activatefw_helper.sh -> shadow = 640; "
            "(2) UCSM continues operating with shadow = 640; "
            "(3) At next UCSM restart, sam_startup_main.sh sets shadow = 600. "
            "Duration of exposure: until the next UCSM restart following activation. "
            "In a high-availability FI pair, the FI may not restart for extended periods. "
            "NX-OS uses /etc/shadow for the local management-plane user database "
            "including admin and any local UCSM user accounts."
        ),
        "evidence": {
            "file": "spm/isan/bin/sam_activatefw_helper.sh line 29-30",
            "chmod": "$SUDO chmod 640 /etc/shadow",
            "comment": "# Handle downgrade/upgrade scenario, change /etc/shadow permissions back to 640",
            "correction": "sam_startup_main.sh line 800: chmod 600 /etc/shadow (on UCSM restart only)",
        },
        "impact": (
            "Shadow group members can read UCSM user password hashes after firmware activation "
            "until the next UCSM restart. "
            "Local UCSM user accounts including admin hash are readable."
        ),
        "remediation": (
            "Set shadow to 600 immediately in sam_activatefw_helper.sh, not 640. "
            "Remove the 'back to 640' pattern -- there is no valid reason for group readability."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "sam_activatefw_helper.sh unconditionally calls modify_fips_mode.sh disable during firmware activation; FIPS disabled as side effect of every activation regardless of FIPS policy",
        "description": (
            "spm/isan/bin/sam_activatefw_helper.sh final line: "
            "'/isan/bin/modify_fips_mode.sh disable'. "
            "This call is unconditional -- it runs for every firmware activation "
            "regardless of whether FIPS mode was enabled before activation. "
            "modify_fips_mode.sh disable: "
            "(1) Removes /mnt/pss/fips_enabled (the FIPS enabled marker on persistent storage). "
            "(2) Writes 'no fips mode enable' to a temp config file. "
            "(3) Executes VSHBIN with that file to apply the FIPS disable command. "
            "A FI that was in FIPS mode before a firmware upgrade/activation will exit "
            "FIPS mode after the activation completes, without any notification or "
            "operator confirmation. "
            "The operator re-enabling FIPS must be a deliberate step after activation; "
            "if this step is missed, the FI operates without FIPS mode indefinitely. "
            "For FIs serving FIPS 140-2 compliant environments (government, healthcare), "
            "this is a compliance gap. "
            "Note: inside container (4GFI), modify_fips_mode.sh disable is a no-op "
            "(returns 0 immediately). Non-container FI variants are affected."
        ),
        "evidence": {
            "file": "spm/isan/bin/sam_activatefw_helper.sh line 37",
            "call": "/isan/bin/modify_fips_mode.sh disable",
            "condition": "unconditional -- no check if FIPS was enabled before activation",
            "marker": "FIPS_CONFIG_FILE=/mnt/pss/fips_enabled (deleted on disable)",
        },
        "impact": (
            "Every firmware activation on a non-container FI disables FIPS mode. "
            "FIPS-compliant deployments lose their FIPS posture silently after activation."
        ),
        "remediation": (
            "Check if FIPS was enabled before activation; if so, re-enable it after activation "
            "completes. Remove the unconditional disable call."
        ),
    },
    {
        "id": "F5",
        "severity": "LOW",
        "title": "cinitial-setup.sh sets SAM controller log files to mode 666 (world-writable); any local process can inject or overwrite UCSM audit log entries",
        "description": (
            "spm/isan/bin/cinitial-setup.sh: "
            "'chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.klog' "
            "'chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.log'. "
            "Mode 666 = world-readable + world-writable (no execute). "
            "svc_sam_controller is the UCSM SAM controller service -- its logs record "
            "management plane operations, configuration changes, and service events. "
            "World-writable log files allow any local process or user on the FI to: "
            "(1) Append fabricated entries to hide real audit events or confuse forensics; "
            "(2) Truncate the log file to destroy audit history; "
            "(3) Write garbage data to corrupt the log format. "
            "The log files are in /var/sysmgr/sam_logs/ which is the primary UCSM "
            "management logging directory. "
            "Cisco FI management policy requires log integrity for compliance (audit trail). "
            "chmod 666 is applied during container initial setup, meaning it is set "
            "at every container initialization."
        ),
        "evidence": {
            "file": "spm/isan/bin/cinitial-setup.sh",
            "chmod": (
                "chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.klog\n"
                "chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.log"
            ),
        },
        "impact": (
            "Local processes can overwrite or append to UCSM SAM controller logs. "
            "Audit trail integrity cannot be assured on any FI running this init script."
        ),
        "remediation": (
            "Set log files to mode 640 or 600. "
            "UCSM controller should own its logs; other processes should not write them."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "sp_upgrade_helper.sh uses fixed /tmp paths for service pack restore catalog and file deletion list; race attack enables manipulating which files are deleted or restored during SP upgrade",
        "description": (
            "spm/isan/bin/sp_upgrade_helper.sh (690 lines): "
            "'SP_RESTORE_IMAGE_CAT=/tmp/sp_restore_image.cat' "
            "(catalog of files to restore during SP upgrade). "
            "'SP_DELETE_FILES_CAT=/tmp/sp_delete_files.cat' "
            "(list of files to delete during SP upgrade). "
            "Both paths use fixed filenames in /tmp/ (world-writable). "
            "If an attacker can create these files in /tmp/ before "
            "sp_upgrade_helper.sh runs, and the script does not O_EXCL-create them "
            "(no mkstemp usage evident), the attacker's content is used for: "
            "(1) sp_restore_image.cat: controls which FI image files are restored "
            "during service pack installation, potentially substituting malicious images; "
            "(2) sp_delete_files.cat: controls which files are deleted from the FI "
            "during SP installation, potentially removing security controls or binaries. "
            "sp_upgrade_helper.sh runs as root (called from firmware upgrade flow with "
            "elevated privileges). "
            "The race window is the time between FI boot/SP-trigger and the script "
            "creating or using these catalog files."
        ),
        "evidence": {
            "file": "spm/isan/bin/sp_upgrade_helper.sh lines ~35-38",
            "paths": (
                "SP_RESTORE_IMAGE_CAT=/tmp/sp_restore_image.cat\n"
                "SP_DELETE_FILES_CAT=/tmp/sp_delete_files.cat"
            ),
        },
        "impact": (
            "Pre-created /tmp/sp_restore_image.cat or /tmp/sp_delete_files.cat "
            "manipulates which files are installed/deleted during SP upgrade as root."
        ),
        "remediation": (
            "Use mkstemp() or PID-unique temp paths for catalog files. "
            "Verify catalog file integrity (hash) before using contents."
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
