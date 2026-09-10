"""
Cisco UCS Central 2.1.2b EVAL ISO — RE Module
Source: ucs-central.2.1.2b_EVAL.iso (/media/cowboy/research/Cisco-UCS/)
ISO date: 2025-05-14
Base OS: AlmaLinux 9 (upgrade from CentOS 6 in 1.5.1c)

Contents:
  kickstart.cfg     — installer kickstart (AlmaLinux 9 base)
  ucsCentral/       — Cisco UCS Central installer files
    passwordChange.sh — admin password reset script (interactive, run from recovery ISO)
    imghdr            — image header verification binary (RSA code-signing)
    bashfunctions.sh  — shell library for install/upgrade scripts
    bundle_unpack.sh  — firmware bundle unpacking
    csl_update.sh     — CSL update utility

Key architecture changes vs 1.5.1c:
  1.5.1c: CentOS 6, MD5-crypt root hash, sam.config uses AES-128 openssl enc with hardcoded key
  2.1.2b: AlmaLinux 9, bcrypt root hash, sam.config stores shadow hash directly (passwordChange.sh evidence)
"""

FIRMWARE = {
    "target":  "Cisco UCS Central",
    "version": "2.1.2b (EVAL)",
    "source":  "ucs-central.2.1.2b_EVAL.iso",
    "os_base": "AlmaLinux 9",
    "build":   "2025-05-14",
    "findings": ["UCSC2-F1", "UCSC2-F2"],
}

# ─────────────────────────────────────────────────────────
# UCSC2-F1: Identical bcrypt hash for root AND cisco user in kickstart
#           — cisco user is in wheel group (sudo); same password across both accounts
# ─────────────────────────────────────────────────────────
UCSC2_F1 = {
    "id":       "UCSC2-F1",
    "title":    "UCS Central 2.1.2b kickstart deploys root and 'cisco' user with identical bcrypt hash — "
                "both accounts share the same password; cisco has wheel (sudo) membership",
    "status":   "CONFIRMED — kickstart.cfg from ucs-central.2.1.2b_EVAL.iso",
    "severity": "HIGH",

    "hash":              "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
    "algorithm":         "bcrypt cost factor 10",

    "kickstart_lines": [
        "user --name=cisco --groups=wheel --iscrypted --password=$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
        "rootpw $2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu --iscrypted",
    ],

    "credential_impact": {
        "root":  "full root via bcrypt hash; hash is identical across all 2.1.2b EVAL deployments",
        "cisco": "wheel member → full sudo; same password as root; same hash in kickstart",
        "note":  "If the plaintext is recovered (offline bcrypt crack), both accounts are compromised simultaneously.",
    },

    "hash_not_cracked": True,
    "wordlist_tried": [
        "cisco", "Cisco", "admin", "Admin", "cisco123", "Cisco123",
        "UCSCentral", "ironport", "Welcome1", "Cisco123!", "VMware1!",
        "c1sc0", "C1sco!", "changeme", "password", "password1",
    ],

    "postgres_config_in_kickstart": {
        "change": "sed -i 's/\\#standard_conforming_strings = on/standard_conforming_strings = off/' /var/lib/pgsql/data/postgresql.conf",
        "effect": "Disables PostgreSQL standard-conforming strings; re-enables backslash escape sequences in SQL literals. "
                  "If UCS Central constructs any SQL queries with unsanitized user input, "
                  "the backslash escape path becomes available — a requirement for some SQL injection variants "
                  "that are otherwise blocked by standard conforming mode.",
        "severity": "informational — requires a separate SQL injection vector to be exploitable",
    },

    "analysis": (
        "The EVAL ISO uses a fixed bcrypt hash for both root and the wheel-group cisco account. "
        "All EVAL deployments from this ISO share identical credential state until the password "
        "is changed post-install. The presence of the same hash for two accounts with different "
        "privilege paths (root directly vs sudo via wheel) means a single credential breach "
        "grants both. The EVAL tag does not guarantee this differs from production ISOs — "
        "the passwordChange.sh recovery script is the same across both EVAL and release artifacts."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC2-F2: passwordChange.sh writes shadow hash directly to sam.config
#           — any local read of sam.config gives an offline-crackable credential
# ─────────────────────────────────────────────────────────
UCSC2_F2 = {
    "id":       "UCSC2-F2",
    "title":    "UCS Central 2.1.2b passwordChange.sh stores admin shadow hash in sam.config "
                "— sam.config readers obtain an offline-crackable credential",
    "status":   "CONFIRMED — passwordChange.sh from ucsCentral/ on 2.1.2b_EVAL.iso",
    "severity": "MEDIUM",

    "vulnerable_code": {
        "file":    "ucsCentral/passwordChange.sh",
        "snippet": (
            "ADMIN_PASS_SAM=$(grep 'admin' $SHADOW_FILE | cut -d: -f 2)\n"
            "sed -i 's|adminPasswd=[^ ]*|adminPasswd=$ADMIN_PASS_SAM|g' \"$SAMCFG\""
        ),
    },

    "credential_flow": {
        "step1": "Admin changes password via passwordChange.sh → passwd --stdin 'admin' updates /etc/shadow",
        "step2": "grep 'admin' /etc/shadow → shadow hash extracted (bcrypt)",
        "step3": "sam.config updated: adminPasswd=<bcrypt_hash>",
        "step4": "Any process/user with read access to sam.config gets the bcrypt hash for offline crack",
    },

    "sam_config_path": "/opt/cisco/sam.config",

    "grep_partial_match": {
        "pattern": "grep 'admin' $SHADOW_FILE",
        "note": "Pattern 'admin' is not anchored (not '^admin:'). Any shadow entry whose username "
                "contains the substring 'admin' (e.g. 'samadmin', 'localadmin') would also match — "
                "first match wins; incorrect hash written to sam.config. In practice unlikely to "
                "matter given the controlled account namespace, but the pattern is fragile."
    },

    "contrast_with_151c": (
        "In 1.5.1c, sam.config stores passwords encrypted with the hardcoded AES-128 key "
        "'theKeyForEncryptingTheSharedSecret' (UCSC-F1). The 2.1.2b architecture changes "
        "this to store the shadow hash directly — avoiding the hardcoded encryption key problem "
        "but instead converting sam.config into a shadow equivalent for the admin account. "
        "The effective security difference depends on which is harder to crack: "
        "AES-128 with a known key (trivial) vs bcrypt cost-10 (computationally expensive but finite)."
    ),

    "analysis": (
        "The 2.1.2b password reset flow writes the bcrypt shadow hash of the admin account "
        "into sam.config, which is readable by multiple service processes. "
        "An attacker with local filesystem access or backup file access to sam.config "
        "obtains a bcrypt hash crackable offline. Cost-10 bcrypt on modern GPU: ~150k hashes/sec. "
        "With a targeted wordlist (Cisco defaults, product names, common enterprise patterns) "
        "a weak passphrase will fall within hours. The exposure surface is broader than /etc/shadow: "
        "sam.config is replicated to multiple service directories, each copy exposing the credential."
    ),
}

PASSWORD_CHANGE_NOTES = {
    "validation_bug": (
        "pass_validate() checks uppercase/lowercase/digit (3 conditions) and separately "
        "REJECTS passwords containing '?', '=', '$', or space. "
        "The comment says '3/4' but the counter only tracks 3 classes. "
        "The effective policy: must have all of upper+lower+digit AND no forbidden specials. "
        "This prevents strong passwords using the common '!' or '$' special characters "
        "($ecure1T is rejected; Secure1T is accepted)."
    ),
}

FINDINGS = [UCSC2_F1, UCSC2_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
