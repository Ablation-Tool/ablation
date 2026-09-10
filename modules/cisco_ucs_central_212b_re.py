"""
Cisco UCS Central 2.1.2b_EVAL — Reverse Engineering Module
Source: ucs-central.2.1.2b_EVAL.iso (/media/cowboy/research/Cisco-UCS/)
Base OS: AlmaLinux 9 (x86_64)
"""

FIRMWARE = {
    "target":   "Cisco UCS Central 2.1.2b_EVAL",
    "source":   "ucs-central.2.1.2b_EVAL.iso",
    "base_os":  "AlmaLinux 9 (x86_64)",
    "installer": "kickstart.cfg + ucsCentral/ payload directory on ISO",
    "findings":  ["UCSC21-F1", "UCSC21-F2", "UCSC21-F3", "UCSC21-F4", "UCSC21-F5"],
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC21-F1: Universal credential reuse — root and cisco user share identical
#             bcrypt hash in kickstart.cfg
# ─────────────────────────────────────────────────────────────────────────────
UCSC21_F1 = {
    "id":       "UCSC21-F1",
    "title":    "Identical bcrypt hash for root and cisco (wheel) user in kickstart.cfg — "
                "single credential compromise grants all privilege levels",
    "status":   "CONFIRMED — kickstart.cfg in ucs-central.2.1.2b_EVAL.iso",
    "severity": "HIGH",
    "affected_accounts": {
        "root":  "rootpw $2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu --iscrypted",
        "cisco": "user --name=cisco --groups=wheel --iscrypted "
                 "--password=$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
    },
    "shared_hash":    "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
    "hash_algorithm": "bcrypt cost 10",
    "cisco_group":    "wheel (unrestricted sudo)",
    "impact": (
        "The cisco user is in the wheel group (unrestricted sudo). "
        "Identical hash means both accounts are set to the same password at install time. "
        "Cracking the hash once compromises root directly and via sudo through cisco. "
        "All EVAL deployments provisioned from this ISO share the same static credential baseline."
    ),
    "source_file": "kickstart.cfg (lines: rootpw + user --name=cisco)",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC21-F2: PostgreSQL standard_conforming_strings forcibly set to off,
#             re-enabling escape-sequence SQL injection on AlmaLinux 9
# ─────────────────────────────────────────────────────────────────────────────
UCSC21_F2 = {
    "id":       "UCSC21-F2",
    "title":    "kickstart.cfg post-install explicitly sets PostgreSQL standard_conforming_strings=off, "
                "overriding AlmaLinux 9 default and re-enabling escape-sequence SQL injection",
    "status":   "CONFIRMED — kickstart.cfg %post section in ucs-central.2.1.2b_EVAL.iso",
    "severity": "HIGH",
    "sed_command": (
        r"sed -i 's/\#standard_conforming_strings\ =\ on/standard_conforming_strings\ =\ off/' "
        r"/var/lib/pgsql/data/postgresql.conf"
    ),
    "background": (
        "PostgreSQL has defaulted standard_conforming_strings=on since version 9.1 (2011). "
        "When on, backslash is treated as a literal character in string literals; "
        "when off, backslash is an escape prefix, enabling escape-sequence injection. "
        "AlmaLinux 9 ships PostgreSQL 13+ with on as the default. "
        "The kickstart post-install script unconditionally comments-in the off value, "
        "restoring the pre-9.1 behavior on every 2.1.2b installation."
    ),
    "injection_class": (
        "With standard_conforming_strings=off, applications that construct SQL queries "
        "using user-controlled string data and pass them through the PostgreSQL wire protocol "
        "become vulnerable to escape-sequence injection: a backslash in user input can "
        "terminate a string literal and inject arbitrary SQL. "
        "UCS Central is a management plane that processes user-supplied hostnames, credentials, "
        "policy names, and LDAP attributes — all plausible injection points."
    ),
    "source_file": "kickstart.cfg (%post section)",
    "postgresql_conf": "/var/lib/pgsql/data/postgresql.conf",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC21-F3: CiscoSSL 1.1.1l (OpenSSL 1.1.x fork) bundled in ucsCentral/
#             alongside AlmaLinux 9 system OpenSSL 3.x
# ─────────────────────────────────────────────────────────────────────────────
UCSC21_F3 = {
    "id":       "UCSC21-F3",
    "title":    "CiscoSSL 1.1.1l.7.2.289-fips bundled in ucsCentral/ alongside AlmaLinux 9 "
                "system OpenSSL 3.x — parallel 1.1.x library in production install",
    "status":   "CONFIRMED — ucsCentral/libcrypto.so.1.1 in ucs-central.2.1.2b_EVAL.iso",
    "severity": "MEDIUM",
    "version_string": "CiscoSSL 1.1.1l.7.2.289-fips",
    "library":        "ucsCentral/libcrypto.so.1.1 (2.5MB, x86_64 ELF shared object)",
    "system_openssl": "AlmaLinux 9 ships OpenSSL 3.x (system default)",
    "upstream_eol":   "OpenSSL 1.1.1 community EOL: September 2023",
    "notes": (
        "Cisco ships a private OpenSSL 1.1.x fork ('CiscoSSL') with FIPS designation. "
        "The 7.2.289 patch suffix indicates Cisco-internal maintenance beyond the upstream EOL. "
        "The library is loaded by UCS Central application code via ucsCentral/ LD path rather than "
        "the AlmaLinux 9 system OpenSSL 3.x. Any vulnerabilities in OpenSSL 1.1.1l base not "
        "addressed in Cisco's private patch branch (undisclosed patch delta) apply to the "
        "bundled library."
    ),
    "companion_libs": [
        "ucsCentral/libglib-2.0.so.0.1600.3",
        "ucsCentral/libosc.so (32-bit ELF)",
        "ucsCentral/libsafelibc.so (32-bit ELF)",
    ],
    "source_file": "ucsCentral/libcrypto.so.1.1",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC21-F4: passwordChange.sh pass_validate inverted — special characters
#             are rejected rather than required; policy weaker than stated
# ─────────────────────────────────────────────────────────────────────────────
UCSC21_F4 = {
    "id":       "UCSC21-F4",
    "title":    "passwordChange.sh pass_validate rejects special characters instead of requiring them "
                "— inverted password complexity logic; policy enforces uppercase+lowercase+number only",
    "status":   "CONFIRMED — ucsCentral/passwordChange.sh in ucs-central.2.1.2b_EVAL.iso",
    "severity": "LOW",
    "source_file":   "ucsCentral/passwordChange.sh",
    "installed_path": "/passwordChange.sh (chmod 755, called from passreset ISO recovery flow)",
    "defective_logic": {
        "code": (
            "check_special=$(echo \"$passwd\" | grep -q \"[?=$ ]\" && echo \"Found\" || echo \"Not Found\")\n"
            "if [[ $found_conditions -lt 3 || \"$special_found\" == true ]]; then\n"
            "    echo \"Must have 3/4: [A-Z], [a-z], [0-9], any but ? = $ space\"\n"
            "    return 1\n"
            "fi"
        ),
        "actual_behavior": (
            "Returns failure (1) when password CONTAINS any of: ? = $ space. "
            "Returns success (0) when password has 3/3 of uppercase+lowercase+number and "
            "does NOT contain any of those characters. "
            "Special characters from the allowed set are never checked for presence."
        ),
        "intended_behavior": (
            "Error message implies: require 3 of 4 complexity classes (upper, lower, number, "
            "special char), where forbidden specials are ? = $ and space. "
            "Code inverts this: forbids the tracked specials rather than requiring any special."
        ),
    },
    "secondary_issue": (
        "After password change, script does: "
        "ADMIN_PASS_SAM=$(grep 'admin' /etc/shadow | cut -d: -f2); "
        "sed -i 's|adminPasswd=[^ ]*|adminPasswd=$ADMIN_PASS_SAM|g' /opt/cisco/sam.config — "
        "writes the admin shadow hash directly into sam.config. "
        "If sam.config is world-readable at runtime (as confirmed in 1.5.1c), hash is extractable "
        "by any local OS user."
    ),
    "context": "passwordChange.sh executes from passreset ISO recovery; requires console/boot access.",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC21-F5: imghdrScript.sh prepends /tmp/cisco/ to LD_LIBRARY_PATH
#             before executing imghdr — local attacker can inject library
# ─────────────────────────────────────────────────────────────────────────────
UCSC21_F5 = {
    "id":       "UCSC21-F5",
    "title":    "imghdrScript.sh prepends /tmp/cisco/ to LD_LIBRARY_PATH before executing "
                "imghdr binary — library injection during ISAN firmware image verification",
    "status":   "CONFIRMED — ucsCentral/imghdrScript.sh in ucs-central.2.1.2b_EVAL.iso",
    "severity": "MEDIUM",

    "vulnerable_code": (
        "# imghdrScript.sh:\n"
        "export LD_LIBRARY_PATH=\"/opt/cisco/operation-mgr/sam/lib/libimghdr/:"
        "/tmp/cisco/:$OLD_LD_LIBRARY_PATH\""
    ),

    "impact": (
        "/tmp/cisco/ is under world-writable /tmp/. "
        "A local attacker with write access to /tmp can create /tmp/cisco/ and place "
        "a malicious .so matching any library that imghdr loads. "
        "The dynamic linker finds the malicious library first. "
        "imghdrScript.sh is invoked by isanadd during ISAN firmware image verification. "
        "During a UCS Central software update, update scripts run as root — "
        "library injection executes as root."
    ),

    "imghdr_symbols": (
        "imghdr is a 32-bit ELF with full debug symbols. "
        "Key exports: cs_dc3sup2_verify_image, cs_verify_key_signature, "
        "rsalib_signature_verify, cs_bios_verify_digital_signature. "
        "Debug symbols provide a complete map of the verification API."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC21-F6: OVA signing certificate expired 2026-06-29 while 2.1.2b remains
#             the current distributed version — 73+ days with expired code-signing cert
# ─────────────────────────────────────────────────────────────────────────────
UCSC21_F6 = {
    "id":       "UCSC21-F6",
    "title":    "UCS Central 2.1.2b OVA signing certificate expired 2026-06-29 (IdenTrust EV, "
                "Cisco Systems Inc.) — current release distributed with expired signature cert",
    "status":   "CONFIRMED — ucs-central.2.1.2b.cert (openssl x509 -noout -text); cert expired 73+ days ago",
    "severity": "LOW",

    "cert_subject":   "C=US, ST=California, L=San Jose, O=Cisco Systems Inc., CN=Cisco Systems Inc.",
    "cert_issuer":    "C=US, O=IdenTrust, CN=TrustID EV Code Signing CA 4",
    "cert_not_before": "2023-06-30",
    "cert_not_after":  "2026-06-29",
    "confirmed_expired": "2026-09-10 (73 days past expiry)",

    "ova_manifest":  "ucs-central.2.1.2b.mf — SHA256 hashes of OVF + disk1.vmdk + disk2.vmdk",
    "sig_algorithm": "sha256WithRSAEncryption (cert signing); SHA256 (manifest file hashes)",

    "impact": (
        "VMware vCenter and ESXi OVA import validates the signing certificate at import time. "
        "When the cert is expired and no RFC 3161 countersignature timestamp is present, "
        "strict certificate enforcement will reject the OVA or require the operator to "
        "explicitly bypass signature verification — a security downgrade step. "
        "The expiry also means Cisco can no longer use this certificate to re-sign future "
        "builds of 2.1.2b or issue corrected OVAs with the same identity anchor. "
        "As of 2026-09-10, 2.1.2b_EVAL.iso is the only available installer; the OVA with "
        "the expired cert is the only VM deployment artifact for this version."
    ),
}

FINDINGS = [UCSC21_F1, UCSC21_F2, UCSC21_F3, UCSC21_F4, UCSC21_F5, UCSC21_F6]
FIRMWARE["findings"] = [f["id"] for f in FINDINGS]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
