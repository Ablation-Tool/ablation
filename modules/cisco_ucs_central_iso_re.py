"""
Cisco UCS Central Installation ISO RE

Targets: ucs-central.1.5.1c.iso        (RHEL 5 base install, productVersion=1.5(1c))
         ucs-central-passreset.1.5.1c.iso  (recovery/passreset ISO, same build date)
         ucs-central.2.1.2b_EVAL.iso    (AlmaLinux 9, productVersion=2.1(2b) EVAL)
Files:   ks.cfg, ks_upgrade.cfg          (kickstart install/upgrade configs, all ISOs)
         ucsCentral/passwordChange.sh     (2.1.2b admin password reset logic)
         ucsCentral/csl_update.sh         (2.1.2b package upgrade mechanism)
Session: 38
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_central_iso_re",
    "firmware": (
        "ucs-central.1.5.1c.iso + ucs-central-passreset.1.5.1c.iso + "
        "ucs-central.2.1.2b_EVAL.iso"
    ),
    "components": {
        "ks.cfg (1.5.1c install)": (
            "Kickstart install config; rootpw --iscrypted <MD5-crypt hash>; "
            "authconfig --enablemd5; selinux --disabled"
        ),
        "ks_upgrade.cfg (1.5.1c install + passreset)": (
            "Kickstart upgrade config in both main and passreset ISOs; "
            "same hardcoded rootpw hash; selinux --disabled; eval post-install script"
        ),
        "kickstart.cfg (2.1.2b)": (
            "AlmaLinux 9 kickstart; auth --passalgo=sha512; selinux --enforcing; "
            "same bcrypt hash for root AND cisco wheel user"
        ),
        "ucsCentral/passwordChange.sh (2.1.2b)": (
            "Admin password reset script; inverted pass_validate logic "
            "rejects passwords with characters ?=$ space"
        ),
    },
    "finding_counts": {"CRITICAL": 2, "HIGH": 2, "MEDIUM": 2, "LOW": 0},
    "cumulative_counts": {"CRITICAL": 66, "HIGH": 237, "MEDIUM": 228, "LOW": 192},
    "cumulative_total": 723,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": (
            "Identical Hardcoded MD5-Crypt Root Hash Across All 1.5.1c Installation "
            "and Recovery Paths (ks.cfg, ks_upgrade.cfg, passreset ks_upgrade.cfg)"
        ),
        "component": "ks.cfg + ks_upgrade.cfg (1.5.1c) + passreset ks_upgrade.cfg",
        "evidence": {
            "hash": "$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
            "occurrences": [
                "ucs-central.1.5.1c.iso ks.cfg: rootpw --iscrypted $1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
                "ucs-central.1.5.1c.iso ks_upgrade.cfg: rootpw --iscrypted $1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
                "ucs-central-passreset.1.5.1c.iso ks_upgrade.cfg: rootpw --iscrypted $1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
                "ucs-central.1.5.1c.ova /etc/shadow (pre-deploy): root:$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
            ],
            "hash_algorithm": "MD5-crypt ($1$), salt=ToWcsC4R",
            "passreset_scope": (
                "The passreset ISO is the official Cisco mechanism for recovering "
                "access to a UCS Central instance where the admin password is lost. "
                "The recovery process applies ks_upgrade.cfg, which reinstates the "
                "known root hash. After passreset, root is accessible with the factory "
                "credential until the customer explicitly changes it."
            ),
        },
        "impact": (
            "Every UCS Central 1.5.1c installation, upgrade, and password recovery operation "
            "installs the same root password hash across all customers. "
            "The MD5-crypt hash '$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/' is present in the "
            "OVA image shadow file, the bare-metal install kickstart, the upgrade kickstart, "
            "AND the password recovery ISO. "
            "Any customer who uses the passreset ISO to recover admin access gets a system "
            "with the shared factory root hash re-applied -- the recovery mechanism itself "
            "re-installs the backdoor credential. "
            "An attacker who cracks the MD5-crypt hash offline has persistent root access "
            "to all 1.5.1c instances regardless of whether the customer has changed the "
            "admin password, because the root account is a separate OS-level credential "
            "from the UCS Central admin account."
        ),
        "remediation": (
            "Generate a unique random root password per-installation at kickstart %post time: "
            "'rootpw $(openssl rand -base64 24)' instead of a hardcoded hash. "
            "The root account should be locked immediately after installation; "
            "UCS Central management uses the admin account via ucssh, not root SSH. "
            "For the passreset ISO: instead of reinstating a fixed hash, generate a "
            "random one-time recovery credential and display it on the console once."
        ),
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": (
            "UCS Central 2.1.2b Kickstart Creates root and cisco User with "
            "Identical Bcrypt Password Hash"
        ),
        "component": "kickstart.cfg (2.1.2b)",
        "evidence": {
            "user_line": (
                "user --name=cisco --groups=wheel --iscrypted "
                "--password=$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu"
            ),
            "rootpw_line": (
                "rootpw $2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu --iscrypted"
            ),
            "identical_hashes": (
                "Both entries use the identical hash string: "
                "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu. "
                "Since bcrypt hashes include the password but not a separate salt field "
                "in the output (the salt is embedded), identical hash strings mean "
                "both accounts share the same plaintext password."
            ),
            "cisco_privileges": (
                "The cisco user is in the 'wheel' group. "
                "On AlmaLinux 9, wheel group members have sudo access. "
                "If the cisco user's sudo is NOPASSWD (or if the kickstart post-install "
                "adds NOPASSWD:ALL as in 1.5.1c), the cisco wheel account provides "
                "an equivalent root path to the root account itself."
            ),
        },
        "impact": (
            "Both the root account and the cisco (wheel) user on every 2.1.2b installation "
            "share a single password. "
            "Cracking the bcrypt hash once compromises both accounts simultaneously. "
            "If either account's password is discovered (via phishing, credential stuffing, "
            "or an offline crack), the attacker has two independent authentication paths "
            "to full root access. "
            "The cisco user's wheel group membership provides a sudo path to root, "
            "making it functionally equivalent to direct root SSH. "
            "Deployers who change the root password without changing the cisco user password "
            "(or vice versa) still leave one account with the factory credential."
        ),
        "remediation": (
            "Generate distinct random passwords for root and the cisco user at kickstart time. "
            "Never reuse the same hash for two accounts in a kickstart config. "
            "Consider locking the root account entirely on 2.1.2b and using only "
            "the cisco user + sudo path, with per-instance credentials set at first boot. "
            "Force mandatory password change on both accounts at initial login."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": (
            "1.5.1c Kickstart Mandates MD5-Crypt Password Hashing System-Wide "
            "via authconfig --enablemd5"
        ),
        "component": "ks.cfg + ks_upgrade.cfg (1.5.1c)",
        "evidence": {
            "authconfig_line": "authconfig --enableshadow --enablemd5",
            "scope": (
                "This line appears in ks.cfg (install), ks_upgrade.cfg (upgrade), "
                "and the passreset ks_upgrade.cfg. "
                "It configures the entire OS to use MD5 for all password hashing, "
                "including any new accounts created post-install."
            ),
            "system_effect": (
                "After install, /etc/pam.d/system-auth contains: "
                "'password sufficient pam_unix.so md5 shadow nullok try_first_pass use_authtok'. "
                "All passwords on the system use MD5-crypt regardless of what algorithm "
                "OpenSSL or pam_unix supports."
            ),
        },
        "impact": (
            "The authconfig --enablemd5 kickstart directive pins the system-wide password "
            "hashing algorithm to MD5-crypt for the lifetime of the installation. "
            "Even if a customer changes admin, root, or service account passwords after install, "
            "all new passwords are stored as MD5-crypt hashes. "
            "MD5-crypt achieves 5-10 million hashes/second on a commodity GPU (hashcat mode 500). "
            "An attacker with access to /etc/shadow (via F2 CRITICAL in the OVA analysis -- "
            "sudo /bin/chown -R * allows any user to read shadow) "
            "can crack all account passwords offline within hours regardless of password complexity."
        ),
        "remediation": (
            "Replace 'authconfig --enableshadow --enablemd5' with "
            "'authconfig --enableshadow --passalgo=sha512' or preferably "
            "'authconfig --enableshadow --passalgo=yescrypt'. "
            "RHEL 5 supports SHA-512 crypt ($6$) via pam_unix. "
            "If MD5 cannot be changed for compatibility reasons, "
            "migrate stored hashes by requiring a password change on next login."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": (
            "SELinux Explicitly Disabled in All 1.5.1c Kickstart Paths "
            "(Install, Upgrade, passreset)"
        ),
        "component": "ks.cfg + ks_upgrade.cfg (1.5.1c) + passreset ks_upgrade.cfg",
        "evidence": {
            "selinux_lines": [
                "ucs-central.1.5.1c.iso ks.cfg: selinux --disabled",
                "ucs-central.1.5.1c.iso ks_upgrade.cfg: selinux --disabled",
                "ucs-central-passreset.1.5.1c.iso ks_upgrade.cfg: selinux --disabled",
            ],
            "persistent": (
                "The selinux --disabled kickstart directive writes 'SELINUX=disabled' to "
                "/etc/sysconfig/selinux, persisting across reboots. "
                "SELinux cannot be re-enabled without a full filesystem relabel."
            ),
            "2_1_2b_contrast": (
                "The 2.1.2b kickstart uses 'selinux --enforcing' -- confirming that "
                "1.5.1c's selinux --disabled is a policy choice that was later corrected."
            ),
        },
        "impact": (
            "With SELinux disabled, no mandatory access control policy constrains "
            "UCS Central application processes. "
            "A compromised samdme process, apache web server, or PostgreSQL instance "
            "has full discretionary access to the OS file system, devices, and network. "
            "The privilege escalation paths identified in the OVA analysis "
            "(sudo /bin/chown -R *, sudo decryptpasswd.pl) rely on DAC alone; "
            "SELinux in enforcing mode would add a containment layer that limits "
            "the blast radius of any single process compromise. "
            "Every 1.5.1c deployment is without this protection by design."
        ),
        "remediation": (
            "Remove 'selinux --disabled' from all kickstart files and replace with "
            "'selinux --enforcing'. "
            "Develop a UCS Central SELinux policy module that labels UCS Central "
            "processes and files appropriately. "
            "For existing deployments: re-enable SELinux (SELINUX=permissive first, "
            "then enforcing after policy validation)."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": (
            "passwordChange.sh (2.1.2b) Inverted Validator Logic Rejects "
            "Passwords Containing '?', '=', '$', or Space"
        ),
        "component": "ucsCentral/passwordChange.sh (2.1.2b)",
        "evidence": {
            "validator_code": (
                "check_special=$(echo \"$passwd\" | grep -q \"[?=$ ]\" && echo \"Found\" || echo \"Not Found\")\n"
                "...\n"
                "# Check if at least 3 conditions are met and special character condition is satisfied\n"
                "if [[ $found_conditions -lt 3 || \"$special_found\" == true ]]; then\n"
                "    echo \"Must have 3/4: [A-Z], [a-z], [0-9], any but ? = $ space\"\n"
                "    return 1  # REJECT\n"
                "fi"
            ),
            "logic_inversion": (
                "The condition '$found_conditions -lt 3 || $special_found == true' rejects "
                "any password where the 'special' pattern `[?=$ ]` is matched. "
                "The characters `?`, `=`, `$`, and space are in the regex, so a "
                "password containing any of these characters will set special_found=true "
                "and be rejected. "
                "The error message says 'any but ? = $ space' -- confirming the intent "
                "was to ALLOW these characters, but the condition has the wrong test. "
                "The intended condition was likely: "
                "  if [[ $found_conditions -lt 3 && $special_found == false ]]; then"
            ),
            "real_world_effect": (
                "An admin attempting to set the password 'Admin1234$' would be rejected. "
                "An admin attempting to set 'MyPass word1' (with a space) would be rejected. "
                "The allowed characters include all special chars EXCEPT ?=$ space. "
                "The effective policy is less permissive than documented."
            ),
        },
        "impact": (
            "Administrators using the passreset boot process on 2.1.2b cannot set passwords "
            "containing '$', '=', '?', or space -- characters that are common in enterprise "
            "password policies and password managers. "
            "Forced to choose from the reduced character set, admins may choose weaker passwords "
            "or reuse passwords that meet the narrower requirements. "
            "The validator is the only complexity check in the passreset flow; "
            "a broken validator silently accepts passwords that wouldn't meet the "
            "documented policy."
        ),
        "remediation": (
            "Fix the condition to:\n"
            "  if [[ $found_conditions -lt 3 && \"$special_found\" == false ]]; then\n"
            "This rejects passwords that have fewer than 3 character classes AND "
            "no special characters (the intended policy). "
            "Also update the 'special' character class to explicitly include all "
            "common special chars rather than a deny-list approach."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": (
            "eval /bin/sed with Attacker-Influenced TIMEZONE_LINE Variable "
            "in Kickstart Post-Install Script"
        ),
        "component": "ks_upgrade.cfg %post (1.5.1c install + passreset ISOs)",
        "evidence": {
            "vulnerable_code": (
                "%post --log /root/post-install.log\n"
                "TIMEZONE=`/usr/bin/readlink -f /var/empty/sshd/etc/localtime`\n"
                "if [[ $TIMEZONE == /usr/share/zoneinfo/* ]]; then\n"
                "    TIMEZONE=`/usr/bin/readlink -f /var/empty/sshd/etc/localtime | cut -d'/' -f5-`\n"
                "    TIMEZONE_LINE=\"ZONE=\\\"$TIMEZONE\\\"\"\n"
                "    eval /bin/sed -i 's,^ZONE=.*,$TIMEZONE_LINE,' /etc/sysconfig/clock\n"
                "fi"
            ),
            "injection_path": (
                "TIMEZONE is derived from the symlink target of /var/empty/sshd/etc/localtime. "
                "If an attacker can modify the symlink target (e.g., by pre-creating the "
                "/var/empty/sshd directory before install, or through a manipulated timezone "
                "configuration), they can inject arbitrary content into $TIMEZONE_LINE, "
                "which is then passed to eval as part of a sed command. "
                "A TIMEZONE value containing a single quote and shell metacharacters "
                "breaks the sed quoting and allows arbitrary commands to run via eval."
            ),
            "eval_risk": (
                "The eval call expands $TIMEZONE_LINE in a shell context. "
                "If TIMEZONE = \"X' $(id > /tmp/pwned);echo 'Y\", then TIMEZONE_LINE = "
                "ZONE=\"X' $(id > /tmp/pwned);echo 'Y\", and the eval'd sed command "
                "would close the sed pattern early and execute the embedded command."
            ),
        },
        "impact": (
            "The %post script runs as root in the kickstart environment. "
            "An attacker who can influence the timezone symlink (by supplying a "
            "malicious system image or by being positioned to modify the filesystem "
            "during the upgrade kickstart) can inject shell commands into the eval "
            "context and execute arbitrary code as root during the upgrade/recovery "
            "installation. "
            "The attack surface is limited to the kickstart execution environment, "
            "but it represents a supply-chain-style risk in automated deployment pipelines "
            "where the input to the post-install script is not controlled."
        ),
        "remediation": (
            "Replace the eval /bin/sed pattern with a direct sed call using "
            "bash string substitution that does not require eval:\n"
            "  /bin/sed -i \"s|^ZONE=.*|ZONE=\\\"$TIMEZONE\\\"|\" /etc/sysconfig/clock\n"
            "Validate $TIMEZONE against an allowlist of known timezone names before "
            "using it in any command: "
            "[[ $TIMEZONE =~ ^[A-Za-z0-9/_+-]+$ ]] || exit 1"
        ),
    },
]


def run_module():
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Firmware: {MODULE_SUMMARY['firmware']}")
    for component, desc in MODULE_SUMMARY["components"].items():
        print(f"  {component}: {desc}")
    counts = MODULE_SUMMARY["finding_counts"]
    print(
        f"Findings: {sum(counts.values())} "
        f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
        f"{counts['MEDIUM']}M/{counts['LOW']}L]"
    )
    cc = MODULE_SUMMARY["cumulative_counts"]
    print(
        f"Cumulative: {MODULE_SUMMARY['cumulative_total']} "
        f"[{cc['CRITICAL']}C+{cc['HIGH']}H+{cc['MEDIUM']}M+{cc['LOW']}L]"
    )
    print()
    for f in FINDINGS:
        sev = f["severity"]
        print(f"  {f['id']} [{sev}] {f['title']}")
        print(f"    Component: {f['component']}")
        print(f"    Impact: {f['impact'][:120]}...")
        print()


if __name__ == "__main__":
    run_module()
