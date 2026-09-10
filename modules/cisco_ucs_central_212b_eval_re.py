"""
Cisco UCS Central 2.1.2b EVAL — RE Module
Source: ucs-central.2.1.2b_EVAL.iso (4.2GB, /media/cowboy/research/Cisco-UCS/)
Format: AlmaLinux 9 kickstart installer ISO (Anaconda)
Base OS: AlmaLinux 9 (upgrade from RHEL6-era in 1.5.1c)
Key files:
  kickstart.cfg       — primary kickstart (hardcoded bcrypt hashes for root AND cisco user)
  ks-rpm-val.cfg      — RPM validation kickstart fragment
  ucsCentral/         — update bundle scripts + binaries
    passwordChange.sh — admin password recovery with sam.config write
    imghdrScript.sh   — ISAN image verification wrapper (sets LD_LIBRARY_PATH)
    imghdr            — ISAN image header/signature verification ELF (32-bit, NOT stripped)
    isanadd           — ISAN firmware image packaging shell script
    libsafelibc.so    — safe C library (32-bit, stripped)
    libosc.so         — OSC library (32-bit, stripped)
    libcrypto.so.1.1  — OpenSSL 1.1 (upgrade from 1.0.x in 1.5.1c)
  images/             — install.img (Anaconda), pxeboot, efiboot.img (NO stage2.img with ucscentral.py)
"""

FIRMWARE = {
    "target":   "Cisco UCS Central 2.1.2b EVAL",
    "version":  "2.1.2b",
    "source":   "ucs-central.2.1.2b_EVAL.iso",
    "base_os":  "AlmaLinux 9 (csl-almalinux9 hostname)",
    "type":     "EVAL (evaluation license)",
    "findings": ["UCSC2-F1", "UCSC2-F2", "UCSC2-F3"],
}

# ─────────────────────────────────────────────────────────
# UCSC2-F1: Hardcoded bcrypt root AND cisco (wheel) user password hashes in kickstart.cfg
#           — ALL UCS Central 2.1.2b installations share the same root and cisco passwords
# ─────────────────────────────────────────────────────────
UCSC2_F1 = {
    "id":       "UCSC2-F1",
    "title":    "kickstart.cfg in UCS Central 2.1.2b sets identical hardcoded bcrypt hash for both "
                "root and 'cisco' (wheel/sudo) user — every 2.1.2b installation shares the same credential pair",
    "status":   "CONFIRMED — kickstart.cfg:user and kickstart.cfg:rootpw in ucs-central.2.1.2b_EVAL.iso",
    "severity": "HIGH",

    "kickstart_lines": {
        "user":   "user --name=cisco --groups=wheel --iscrypted "
                  "--password=$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
        "rootpw": "rootpw $2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu --iscrypted",
    },

    "hash_details": {
        "format":     "bcrypt ($2b$ prefix, cost factor 10 — hashcat mode 3200)",
        "hash_value": "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
        "crackability": (
            "bcrypt cost-10 is ~100ms per attempt on modern GPU — substantially harder than "
            "1.5.1c MD5-crypt ($1$). Offline crack via hashcat mode 3200 is feasible only with "
            "extended GPU time and a wordlist containing the password. "
            "Status: NOT CRACKED with rockyou.txt or common Cisco masks."
        ),
    },

    "scope": (
        "Both root AND the 'cisco' user (member of 'wheel' — full sudo access) share the same hash. "
        "This means cracking the hash once yields two accounts: direct root login + "
        "cisco user with sudo. "
        "SSH is enabled: 'firewall --enabled --ssh'. "
        "SELinux is enforcing (improvement from 1.5.1c which had --disabled). "
        "This is an EVAL ISO — the production ISO may use a different hash. "
        "If the EVAL ISO ships the same hash as production, all 2.1.2b deployments are affected."
    ),

    "comparison_with_151c": (
        "UCS Central 1.5.1c used MD5-crypt ($1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/) which is "
        "trivially crackable. 2.1.2b uses bcrypt cost-10 — a meaningful security improvement "
        "in hash strength, but the fundamental architectural flaw persists: "
        "a static shared credential is baked into every installation."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC2-F2: passwordChange.sh writes admin hash from /etc/shadow to sam.config
#           — sam.config stores admin credential hash in a Cisco SAM config file
# ─────────────────────────────────────────────────────────
UCSC2_F2 = {
    "id":       "UCSC2-F2",
    "title":    "UCS Central 2.1.2b passwordChange.sh reads admin hash from /etc/shadow and "
                "writes it to /opt/cisco/sam.config via sed — sam.config persists the admin credential hash",
    "status":   "CONFIRMED — ucsCentral/passwordChange.sh in ucs-central.2.1.2b_EVAL.iso",
    "severity": "MEDIUM",

    "vulnerable_code": (
        "# passwordChange.sh:\n"
        "SHADOW_FILE='/etc/shadow'\n"
        "SAMCFG='/opt/cisco/sam.config'\n"
        "ADMIN_PASS_SAM=$(grep 'admin' $SHADOW_FILE | cut -d: -f 2)\n"
        "sed -i 's|adminPasswd=[^ ]*|adminPasswd=$ADMIN_PASS_SAM|g' \"$SAMCFG\""
    ),

    "impact": (
        "/opt/cisco/sam.config is the UCS Central SAM (Session Account Manager) configuration file. "
        "The passwordChange.sh (admin password recovery workflow) extracts the admin password hash "
        "from /etc/shadow and writes it directly into sam.config as a plaintext (within the config) field. "
        "The sam.config file path (/opt/cisco/sam.config) is the same path referenced in the UCSM "
        "module (UCSM-F2 Credential Store) — the credential storage architecture is shared. "
        "Any vulnerability that allows reading /opt/cisco/sam.config (world-readable, accessible to "
        "service processes, or exposed via a path traversal) yields the admin password hash. "
        "The password change script is used during the admin account recovery boot — "
        "it runs as root after mounting the /opt volume."
    ),

    "sam_config_reference": (
        "The sam.config pattern (admin credentials stored in a plaintext config) is documented "
        "in cisco_ucsm_602b_re.py (UCSM-F2) for UCS Manager. The same file at the same path "
        "is referenced in UCS Central scripts — this is a cross-product architectural decision "
        "to store SAM credentials in /opt/cisco/sam.config."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC2-F3: imghdrScript.sh includes /tmp/cisco/ in LD_LIBRARY_PATH
#           — library injection during ISAN firmware image verification
# ─────────────────────────────────────────────────────────
UCSC2_F3 = {
    "id":       "UCSC2-F3",
    "title":    "imghdrScript.sh prepends /tmp/cisco/ to LD_LIBRARY_PATH before executing imghdr — "
                "any file in world-writable /tmp/cisco/ matching a library name is loaded by the image verifier",
    "status":   "CONFIRMED — ucsCentral/imghdrScript.sh:7 in ucs-central.2.1.2b_EVAL.iso",
    "severity": "MEDIUM",

    "vulnerable_code": (
        "# imghdrScript.sh:7:\n"
        "export LD_LIBRARY_PATH=\"/opt/cisco/operation-mgr/sam/lib/libimghdr/:/tmp/cisco/:$OLD_LD_LIBRARY_PATH\""
    ),

    "impact": (
        "The imghdrScript.sh is invoked by isanadd during ISAN firmware image verification. "
        "The LD_LIBRARY_PATH includes /tmp/cisco/ — a path under the world-writable /tmp/ directory. "
        "A local attacker with write access to /tmp/ (any user, or any process running as non-root) "
        "can create /tmp/cisco/ and place a malicious shared library matching any library that "
        "imghdr dynamically loads. When imghdrScript.sh executes imghdr, the dynamic linker "
        "will find the malicious library before the legitimate one in /opt/cisco/..., "
        "executing attacker-controlled code with the privileges of the imghdr process. "
        "During a UCS Central software update, the update process runs as root, so "
        "the injected library executes as root."
    ),

    "imghdr_debug_symbols": (
        "imghdr is a 32-bit ELF with FULL debug symbols (nm reveals all function names, addresses). "
        "Key exports: cs_dc3sup2_verify_image, cs_verify_key_signature, rsalib_signature_verify, "
        "cs_calc_hashkeyfromImage, cs_bios_verify_digital_signature. "
        "The debug symbols provide a complete map of the signature verification API, "
        "making it trivial to identify the exact verification functions for targeted bypass."
    ),
}

SECURITY_IMPROVEMENTS_VS_151C = {
    "selinux": "enforcing (was --disabled in 1.5.1c)",
    "hash":    "bcrypt cost-10 (was MD5-crypt in 1.5.1c)",
    "base_os": "AlmaLinux 9 (was RHEL6/CentOS 6 in 1.5.1c)",
    "ssl":     "libcrypto.so.1.1 (OpenSSL 1.1 — was OpenSSL 1.0.x in 1.5.1c)",
    "no_stage2_img": (
        "No stage2.img/ucscentral.py found in 2.1.2b images/ — "
        "UCSC-F1 AES-128 hardcoded key was in 1.5.1c Anaconda Python module; "
        "2.1.2b uses a different installer flow, no equivalent key found"
    ),
}

VROPS_INTERSIGHT_MP_NOTES = {
    "file":    "cisco_vrops_intersight_mp_1.1.1.pak (623KB ZIP)",
    "content": "IntersightManager.conf + manifest.txt + alert definition XMLs + icons",
    "adapter_delivery": (
        "IntersightManager.conf references Docker image: "
        "docker.io/intersight/vrops@sha256:20d93e601ecc2ebd98eb488c4f2699026aaf5143be3cc987b8ac5946db11dff3. "
        "The PAK contains no code — only adapter metadata; all logic is in the Docker image."
    ),
    "findings": "No standalone credential or auth findings in the PAK itself. Docker image not retrieved.",
}

FINDINGS = [UCSC2_F1, UCSC2_F2, UCSC2_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
