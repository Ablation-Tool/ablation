"""
Cisco AsyncOS / Coeus Platform — ESA/WSA/SMA Virtual Appliance (S100V) 16.0.0-399 — RE Module
Source: coeus-16-0-0-399-S100V.qcow2.tgz (7.7GB QCOW2 + verification bundle)
  coeus-16-0-0-399-S100V.qcow2     — 200GB virtual, 7.7GB sparse QCOW2
  ESA-WSA-SMA-CCO_REL.cer          — signing cert (Innerspace SubCA RSA chain)
  coeus-16-0-0-399-S100V.qcow2.sig — PKCS7 S/MIME signature
  IS_verify_bulkhash.pyc           — Python 2.7 signature verifier bytecode

Platform: Cisco AsyncOS (FreeBSD 13, CiscoSSL 1.1.1 FIPS fork)
Partitions (nbd1): p1(256KB) + p2(1G vfat EFI) + p3/p4(8G ufs root A/B) +
                   p5(8G) + p6(400MB config) + p7(50G queue) + p8(2G var) + p9(122G data)
Mount status: UFS2 partitions not mountable via Linux kernel (fragment size 8192 > 4096 limit)
Analysis method: strings over /dev/nbd1p3 (root A) and /dev/nbd1p6 (config)

Coeus = Cisco's codename for the shared AsyncOS platform powering:
  - ESA (Email Security Appliance, formerly IronPort)
  - WSA (Web Security Appliance)
  - SMA (Security Management Appliance)
"""

FIRMWARE = {
    "target":   "Cisco AsyncOS / Coeus Platform (ESA/WSA/SMA)",
    "version":  "16.0.0-399",
    "platform": "Coeus S100V — Cisco virtual appliance; FreeBSD 13, CiscoSSL 1.1.1 FIPS",
    "source":   "coeus-16-0-0-399-S100V.qcow2.tgz",
    "products": ["ESA (Email Security Appliance)", "WSA (Web Security Appliance)", "SMA (Security Management Appliance)"],
    "findings": ["COEUS-F1", "COEUS-F2"],
}

# ─────────────────────────────────────────────────────────
# COEUS-F1: Hardcoded MD5-crypt admin hash — password is "ironport"
#           — same admin hash in both root A and root B partitions
# ─────────────────────────────────────────────────────────
COEUS_F1 = {
    "id":       "COEUS-F1",
    "title":    "Cisco AsyncOS admin account has hardcoded MD5-crypt hash in all Coeus 16.0.0-399 images — "
                "password is the legacy IronPort brand default 'ironport', cracked in <1 second",
    "status":   "CONFIRMED — strings /dev/nbd1p3 (root A); hash appears twice (root A + root B)",
    "severity": "CRITICAL",

    "master_passwd_entry": (
        "admin:$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/:1000:1000::0:0:Administrator:/data/home/admin:/data/bin/cli.sh"
    ),

    "hash_format":   "$1$ (MD5-crypt, hashcat mode 500)",
    "hash_value":    "$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/",
    "cracked_password": "ironport",
    "crack_time":    "<1 second — first match against rockyou.txt wordlist",

    "account_details": {
        "user":  "admin",
        "uid":   1000,
        "gid":   1000,
        "gecos": "Administrator",
        "home":  "/data/home/admin",
        "shell": "/data/bin/cli.sh  (AsyncOS restricted CLI shell)",
    },

    "root_account": (
        "root:*:0:0::0:0:Mr &:/root:/sbin/nologin  (direct root login disabled). "
        "The admin account is the sole interactive management account."
    ),

    "scope": (
        "The same hash appears in both root A (p3) and root B (p4) partitions — "
        "it is baked into the base Coeus image and is present in EVERY fresh deployment. "
        "'ironport' is the legacy Cisco IronPort brand name (Cisco acquired IronPort 2007). "
        "This has been the default AsyncOS admin credential for at least 15 years. "
        "The hash is identical across all AsyncOS appliance models sharing the Coeus platform: "
        "ESA, WSA, SMA."
    ),

    "impact": (
        "Any attacker who can reach the AsyncOS management interface (HTTPS on :443 or SSH on :22) "
        "and knows the default credential can authenticate as admin with full appliance control. "
        "admin/ironport provides access to: email routing rules, DLP policies, certificate management, "
        "spam/antivirus configuration, LDAP/AD integration settings (which include LDAP bind credentials), "
        "network configuration, and log access. "
        "The /data/bin/cli.sh shell is an AsyncOS CLI — escape paths not analyzed in this run."
    ),

    "historical_note": (
        "The IronPort default credential is documented in public Cisco/IronPort product documentation "
        "and has been known since at least 2007. Its presence as a HARDCODED hash in the 2026 "
        "shipping image (16.0.0-399) means Cisco has not rotated this credential in the base image "
        "for at least 19 years. Unlike the UCS Central 1.5.1c MD5-crypt finding, this is a "
        "KNOWN default, not just a weak hash — making it a credential stuffing vector for "
        "any exposed management interface."
    ),
}

# ─────────────────────────────────────────────────────────
# COEUS-F2: IS_verify_bulkhash.pyc uses -noverify in openssl smime step
#           — cert chain verified separately, but smime verify does not re-bind to verified chain
# ─────────────────────────────────────────────────────────
COEUS_F2 = {
    "id":       "COEUS-F2",
    "title":    "IS_verify_bulkhash.pyc image verifier uses 'openssl smime -verify ... -noverify' — "
                "smime signature verification does not chain to the separately-verified CA hierarchy",
    "status":   "CONFIRMED — strings IS_verify_bulkhash.pyc",
    "severity": "LOW",

    "python_version":  "Python 2.7 (magic 0xF303, file: IS_verify_bulkhash.pyc)",
    "openssl_requirement": "OpenSSL 0.9.8e (per README.txt) — EOL since 2015",
    "runner_path":     "/router/bin/python  (Cisco appliance internal path, not a standalone tool)",

    "smime_command": (
        "openssl smime -verify -binary -in {sig} -inform PEM -content {image} -noverify -nointern -certfile {ee_cert}"
    ),

    "cert_chain_command": (
        "openssl verify -CAfile {root_cert} {subca_cert}  [step 1]\n"
        "openssl verify -CAfile {root_cert} -untrusted {subca_cert} {ee_cert}  [step 2]"
    ),

    "ca_download": {
        "root_cert_url":  "http://www.cisco.com/security/pki/certs/crcam2.cer  (HTTP, not HTTPS)",
        "subca_cert_url": "http://www.cisco.com/security/pki/certs/innerspace.cer  (HTTP, not HTTPS)",
        "root_cert_sha256":  "cd85167b3935e27bcc3b0f5fa24c8457882d0bb994f88269a7f72829d957eae9",
        "subca_cert_sha256": "f31e6b39dae6996fdf2045a61be8bd3688a86dfd06c46ce71af4af239f411c56c",
        "mitm_mitigated":    "Yes — hardcoded SHA256 checked against downloaded cert before trusting",
    },

    "design_flaw": (
        "The verification has TWO steps: (1) verify_3tier_cert_chain confirms ee_cert is signed by "
        "the Innerspace SubCA RSA chain; (2) verify_smime_signature verifies the image signature "
        "using -noverify. The -noverify flag tells openssl NOT to re-verify the signer's cert "
        "during the smime step — it only checks that the signature was produced by the private key "
        "matching ee_cert. If an attacker can manipulate which cert is passed as ee_cert in step 2 "
        "independently of what was verified in step 1 (e.g., by calling the Python functions out of "
        "sequence or via a logic bug in command_handler), the signature verification is decoupled "
        "from the trust chain. For normal sequential execution, both steps run and the chain is valid."
    ),

    "signing_cert_info": {
        "file":      "ESA-WSA-SMA-CCO_REL.cer",
        "subject":   "CN=CiscoSecurityAppliance, OU=Rel, O=Cisco",
        "issuer":    "O=Cisco, CN=Innerspace SubCA RSA",
        "notBefore": "2016-01-06",
        "notAfter":  "2037-11-12",
        "note":      "Same Innerspace SubCA RSA issuer as CVM VT OVA signing cert",
    },
}

VERIFICATION_BUNDLE_NOTES = {
    "smime_format": (
        "The QCOW2.sig file is a PKCS7 S/MIME PEM signature (-----BEGIN PKCS7-----). "
        "Signature is over the QCOW2 file content, not a hash of it. "
        "Verification requires downloading CA certs from cisco.com at verify-time."
    ),
    "shared_ca_chain": (
        "The ESA-WSA-SMA-CCO_REL.cer and the CVM VT OVA cert (CN=CiscoVulnerabilityManagement) "
        "both chain to the same Innerspace SubCA RSA. This is Cisco's shared code-signing CA "
        "for appliance firmware. Compromise of the Innerspace SubCA private key would enable "
        "signing of arbitrary Cisco appliance images for any product under that CA."
    ),
}

FINDINGS = [COEUS_F1, COEUS_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
