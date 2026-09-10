"""
Cisco UCS Central 1.5.1c OVA — Runtime Confirmation Sub-Module
Sources: ucs-central.1.5.1c.ova, ucs-central-passreset.1.5.1c.iso (/media/cowboy/research/Cisco-UCS/)
Canonical module: cisco_ucs_central_151_re.py (17 findings; UCSC-F1 through UCSC-F17)

Sub-module purpose: confirm that kickstart-level findings from cisco_ucs_central_151_re.py
survive to the deployed running system. Evidence source is the mounted OVA disk (disk1.raw),
not the installer ISO. Findings here are not additive to the total count — they are
runtime-layer evidence for UCSC-F1, UCSC-F3, UCSC-F7, UCSC-F11, and UCSC-F3 respectively.
IDs use UCSC-OVA-* prefix to avoid namespace collision with the canonical module.

OVA date: 2015 (CentOS 6 base)
Contents:
  disk1.vmdk (40GB virtual) — CentOS 6 root: OS + UCS Central application stack
  disk2.vmdk (40GB virtual) — data volume

disk1 analysis:
  Format: VMDK sparse → raw → loop device → LVM (VolGroup00/LogVol00 XFS)
  Mounted: /mnt/ucsc-ova-root

OS: CentOS 6 / RHEL 6 (anaconda kickstart build)
Application: Cisco UCS Central 1.5.1c (sam.config credential store, /opt/cisco/ service tree)
"""

FIRMWARE = {
    "target":        "Cisco UCS Central",
    "version":       "1.5.1c",
    "source":        "ucs-central.1.5.1c.ova",
    "disk1":         "40GB virtual (CentOS 6 root + UCS Central app)",
    "disk2":         "40GB virtual (data volume)",
    "role":          "runtime-confirmation sub-module — see cisco_ucs_central_151_re.py for canonical findings",
    "findings":      ["UCSC-OVA-F1", "UCSC-OVA-F2", "UCSC-OVA-F3", "UCSC-OVA-F4", "UCSC-OVA-F5"],
    "canonical_ref": "cisco_ucs_central_151_re.py (UCSC-F1, UCSC-F3, UCSC-F7, UCSC-F11, UCSC-F3)",
}

# ─────────────────────────────────────────────────────────
# UCSC-OVA-F1: Hardcoded AES-128 passphrase for all sam.config credential encryption
#               — runtime confirmation from mounted disk1.raw; canonical: UCSC-F1
# ─────────────────────────────────────────────────────────
UCSC_F1 = {
    "id":           "UCSC-OVA-F1",
    "canonical_ref": "UCSC-F1 in cisco_ucs_central_151_re.py",
    "evidence_source": "deployed OVA disk (disk1.raw mounted at /mnt/ucsc-ova-root)",
    "title":    "UCS Central sam.config credential encryption uses hardcoded passphrase "
                "'theKeyForEncryptingTheSharedSecret' — AES-128-CBC via openssl enc; "
                "decrypts adminPasswd and sharedSecret on every deployment",
    "status":   "CONFIRMED — /opt/cisco/bin/vm-common.pl line 462, strings extracted from mounted disk1.raw",
    "severity": "CRITICAL",

    "hardcoded_key": "theKeyForEncryptingTheSharedSecret",

    "source_location": {
        "file":     "/opt/cisco/bin/vm-common.pl",
        "line":     462,
        "snippet":  "my $encKey = \"theKeyForEncryptingTheSharedSecret\";",
    },

    "decrypt_function": {
        "source":    "/opt/cisco/bin/vm-common.pl lines 1684-1694",
        "algorithm": "openssl enc -d -k $encKey -a -aes128",
        "call_path": "decryptpasswd.pl -> vpod::decryptPass(vpod::getValFromSamConfig($vpod::secret))",
        "note": (
            "AES-128-CBC with password-derived key (EVP_BytesToKey, MD5, 1 iteration). "
            "-a flag = base64 I/O. No -nosalt → ciphertext begins with Salted__ + 8-byte salt. "
            "Salt per ciphertext but passphrase is static — brute-force cost is single openssl call."
        ),
    },

    "sam_config_keys_encrypted": [
        "adminPasswd  — UCS Central admin account password",
        "sharedSecret — cluster-wide shared secret for inter-service auth",
    ],

    "sam_config_locations": [
        "/opt/cisco/sam.config",
        "/opt/cisco/core/env/sam.config",
        "/opt/cisco/gch/env/sam.config",
        "/opt/cisco/resource-mgr/env/sam.config",
        # + 6 additional service-tree copies under /opt/cisco/*/env/sam.config
    ],

    "decrypt_one_liner": (
        "echo '<base64_ciphertext>' | "
        "openssl enc -d -k theKeyForEncryptingTheSharedSecret -a -aes128"
    ),

    "analysis": (
        "Every UCS Central deployment, every version, uses the same passphrase to encrypt "
        "the admin password and shared secret in sam.config. The passphrase is embedded in "
        "vm-common.pl, which is shipped in the OVA — not generated at install time, not "
        "unique per appliance. Any operator with read access to sam.config (via backup, "
        "snapshot, or local filesystem access) can recover the admin password with a single "
        "openssl invocation. The sam.config files replicate across 10+ service directories, "
        "each a copy of the encrypted credentials, widening the read surface."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-OVA-F2: Hardcoded root password hash in kickstart AND deployed OVA
#               — runtime confirmation from mounted disk1.raw; canonical: UCSC-F3
# ─────────────────────────────────────────────────────────
UCSC_F2 = {
    "id":            "UCSC-OVA-F2",
    "canonical_ref": "UCSC-F3 in cisco_ucs_central_151_re.py",
    "evidence_source": "deployed OVA disk — /root/anaconda-ks.cfg AND /etc/shadow confirm kickstart hash survives to runtime",
    "title":    "UCS Central 1.5.1c root MD5-crypt hash '$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/' "
                "hardcoded in kickstart and deployed unchanged to /etc/shadow",
    "status":   "CONFIRMED — /root/anaconda-ks.cfg AND /etc/shadow from mounted disk1.raw",
    "severity": "CRITICAL",

    "hash":              "$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
    "algorithm":         "MD5-crypt ($1$)",
    "kickstart_line":    "rootpw --iscrypted $1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
    "shadow_entry":      "root:$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/:14959:0:99999:7:::",
    "last_changed":      "14959 (days since epoch = 2010-12-06 — hash never rotated)",

    "confirmed_in_4_artifacts": [
        "ucs-central.1.5.1c.ova       — /root/anaconda-ks.cfg (kickstart) AND /etc/shadow (deployed)",
        "ucs-central.1.5.1c.iso       — ks.cfg (fresh install path) AND ks_upgrade.cfg (upgrade path)",
        "ucs-central-passreset.1.5.1c.iso — ks_upgrade.cfg (recovery/passreset upgrade path)",
    ],

    "analysis": (
        "The build-time kickstart hash is identical to the deployed shadow entry. "
        "The hash was never rotated post-install. MD5-crypt is crackable on commodity hardware "
        "(hashcat -m 500): once cracked, the plaintext gives root console access on every "
        "unmodified 1.5.1c deployment. Date field 14959 (2010-12-06) predates the OVA build — "
        "this is the original Cisco engineering hash, not a generated-at-boot value."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-OVA-F3: admin account has empty password field in deployed OVA
#               — runtime confirmation from mounted disk1.raw; canonical: UCSC-F7
# ─────────────────────────────────────────────────────────
UCSC_F3 = {
    "id":            "UCSC-OVA-F3",
    "canonical_ref": "UCSC-F7 in cisco_ucs_central_151_re.py",
    "evidence_source": "deployed OVA disk — /etc/shadow confirms empty admin password in running system",
    "title":    "UCS Central 1.5.1c admin account deployed with empty /etc/shadow password field "
                "('admin::17223') — local console login requires no password",
    "status":   "CONFIRMED — /etc/shadow from mounted disk1.raw",
    "severity": "HIGH",

    "shadow_entry": "admin::17223:0:99999:7:::",
    "last_changed": "17223 (2017-03-08)",

    "note_on_ssh": (
        "sshd_config PermitEmptyPasswords defaults to 'no' — SSH login blocked. "
        "Local console (IPMI/KVM/physical) and su from another shell have no barrier. "
        "admin has NOPASSWD:ALL sudo (UCSC-F4), so console access → root in one command."
    ),

    "analysis": (
        "An empty shadow password field (distinct from '!!' locked) means PAM accepts any "
        "password or no password at the pam_unix level for local authentication. "
        "Combined with NOPASSWD:ALL sudo, an attacker with local console access (IPMI KVM, "
        "physical serial) can login as admin with no credential and immediately escalate to root. "
        "The 2017-03-08 date indicates this was the shipped state, not the result of a post-deploy "
        "password clear — Cisco shipped the appliance with no admin password."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-OVA-F4: Three accounts with unrestricted NOPASSWD sudo + ALL users allowed credential scripts
#               — runtime confirmation from mounted disk1.raw; canonical: UCSC-F11
# ─────────────────────────────────────────────────────────
UCSC_F4 = {
    "id":            "UCSC-OVA-F4",
    "canonical_ref": "UCSC-F11 in cisco_ucs_central_151_re.py",
    "evidence_source": "deployed OVA disk — /etc/sudoers.d/cisco-sudo confirms sudoers in running system",
    "title":    "UCS Central sudoers grants NOPASSWD:ALL to admin, root, and samdme; "
                "ALL users allowed NOPASSWD execution of decryptpasswd.pl and credential management scripts",
    "status":   "CONFIRMED — /etc/sudoers.d/cisco-sudo from mounted disk1.raw",
    "severity": "HIGH",

    "unrestricted_sudo": [
        "admin ALL = NOPASSWD:ALL",
        "root  ALL = NOPASSWD:ALL",
        "samdme ALL = NOPASSWD:ALL",
    ],

    "all_users_credential_scripts": {
        "rule": "ALL ALL = NOPASSWD:SUDO_CMNDS",
        "scripts_in_SUDO_CMNDS": [
            "/opt/cisco/bin/decryptpasswd.pl",
            "/opt/cisco/bin/update-secret.pl",
            "/opt/cisco/bin/regenerate-certs.pl",
            "/opt/cisco/bin/vm-add-user.sh",
            "/opt/cisco/bin/vm-change-pass.sh",
        ],
        "note": (
            "Any local user can sudo decryptpasswd.pl without a password. "
            "decryptpasswd.pl calls decryptPass(getValFromSamConfig(sharedSecret)) — "
            "it reads the encrypted sharedSecret from sam.config and decrypts it to stdout "
            "using the hardcoded key from UCSC-F1. This creates a direct path from any "
            "local shell to the plaintext shared secret with zero authentication."
        ),
    },

    "accounts": {
        "root": {
            "shadow":  "$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/ (MD5-crypt, hardcoded — UCSC-F2)",
            "shell":   "/bin/bash",
            "sudo":    "NOPASSWD:ALL",
        },
        "admin": {
            "shadow":  ":: (empty — UCSC-F3)",
            "shell":   "/bin/bash",
            "sudo":    "NOPASSWD:ALL",
        },
        "samdme": {
            "shadow":  "locked (!!) in base OVA",
            "shell":   "/bin/bash",
            "home":    "/home/samdme",
            "ssh_dir": ".ssh/ exists, authorized_keys absent in base OVA (populated at deploy)",
            "sudo":    "NOPASSWD:ALL",
        },
        "postgres": {
            "shadow":  "x (PAM external)",
            "shell":   "/bin/bash",
            "note":    "database account; no sudo entry",
        },
    },

    "analysis": (
        "UCS Central runs an internal service account (samdme) for the SAM/domain management "
        "subsystem with full unrestricted sudo. samdme's authorized_keys is empty in the base "
        "OVA but populated at deployment from the management infrastructure — any key "
        "registered there provides a direct root path. "
        "Combined with UCSC-F1 (hardcoded decryption key) and UCSC-F3 (empty admin password), "
        "the privilege escalation surface is: "
        "(a) console → admin login (no password) → sudo su root, or "
        "(b) any shell → sudo /opt/cisco/bin/decryptpasswd.pl → plaintext sharedSecret, or "
        "(c) samdme SSH (if key registered) → sudo su root."
    ),
}

# ─────────────────────────────────────────────────────────
# sam.config architecture (reference)
# ─────────────────────────────────────────────────────────
SAM_CONFIG_ARCH = {
    "master_config":  "/opt/cisco/sam.config",
    "service_copies": "/opt/cisco/<service>/env/sam.config",
    "encrypted_keys": ["adminPasswd", "sharedSecret"],
    "plaintext_keys": ["oobIpAddr", "oobIpNetmask", "oobIpGateway", "virtualIp", "regIp",
                       "cacert", "vmcert", "combinedcert", "vccert", "keyfile"],
    "decrypt_path":   (
        "vpod::decryptPass(vpod::getValFromSamConfig($vpod::secret)) in vm-common.pl; "
        "openssl enc -d -k theKeyForEncryptingTheSharedSecret -a -aes128"
    ),
    "privkey_path":   "/opt/cisco/certs/privKey.pem",
}

# ─────────────────────────────────────────────────────────
# UCSC-OVA-F5: passreset ISO ks_upgrade.cfg resets root to the same known hardcoded hash
#               — runtime confirmation from passreset ISO; canonical: UCSC-F3
# ─────────────────────────────────────────────────────────
UCSC_F5 = {
    "id":            "UCSC-OVA-F5",
    "canonical_ref": "UCSC-F3 in cisco_ucs_central_151_re.py",
    "evidence_source": "ucs-central-passreset.1.5.1c.iso — ks_upgrade.cfg confirms passreset restores same hash",
    "title":    "UCS Central 1.5.1c passreset ISO ks_upgrade.cfg resets root to the same "
                "hardcoded MD5-crypt hash '$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/' — "
                "the recovery procedure restores a known-plaintext credential state",
    "status":   "CONFIRMED — ks_upgrade.cfg from ucs-central-passreset.1.5.1c.iso (146MB, bootable)",
    "severity": "HIGH",

    "passreset_iso": "ucs-central-passreset.1.5.1c.iso",
    "iso_label":     "UCSCentral-Reset",

    "ks_upgrade_cfg_rootpw": "rootpw --iscrypted $1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
    "hash":                  "$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/ (same as OVA root, UCSC-F2)",

    "isolinux_boot_path": {
        "default_label": "ks=cdrom:/ks.cfg (ks.cfg has no rootpw — fresh install path)",
        "upgrade_path":  "ks=cdrom:/ks_upgrade.cfg triggered manually for upgrade/recovery (sets root hash)",
    },

    "analysis": (
        "The passreset ISO is Cisco's documented recovery mechanism for locked-out UCS Central "
        "1.5.1c deployments. The upgrade kickstart (ks_upgrade.cfg) resets root to the same "
        "static MD5-crypt hash documented in UCSC-F2. Any operator who runs the passreset procedure "
        "returns their deployment to the known-hash state, regardless of what password root had before. "
        "An attacker who has cracked the hash (or knows the plaintext from prior compromise of any "
        "1.5.1c deployment) can predict the post-recovery credential state. "
        "The passreset tool, designed as a security recovery mechanism, is itself a credential backdoor "
        "that re-instates a Cisco engineering default with known distribution."
    ),
}

FINDINGS = [UCSC_F1, UCSC_F2, UCSC_F3, UCSC_F4, UCSC_F5]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
        print(f"              canonical: {f['canonical_ref']}")
